"""Hybrid detection engine: fuses signatures, supervised models and the autoencoder.

Fusion by priority, for each source:
  1. A signature hit raises an alert immediately (packet path, no ML needed).
  2. Otherwise a supervised prediction of an attack class raises an alert. The
     full CICFlowMeter model is consulted first, then the lite model; the alert
     records which model produced it. Confidence >= SUPERVISED_CONFIDENCE is
     "high" (block); >= SUPERVISED_MIN_CONFIDENCE is "medium" (quarantine).
     Anomalies are "medium" (quarantine) at confidence >= 0.5, else "low" (logged only).
  3. Otherwise, if the autoencoder reconstruction error is above its threshold,
     an "Anomaly (unknown)" alert is raised (quarantine).

Signature hits and high-confidence predictions of the full model act on a single
flow. Weaker evidence (lite model, medium confidence, anomaly) must be seen on at
least CORROBORATION_FLOWS flows from the same source within
CORROBORATION_WINDOW_S before an alert is raised, which suppresses isolated
false positives on benign hosts.

Alerts are aggregated per (source, attack, detector) over a cooldown window, so a
flood of thousands of flows appears as one alert whose ``count`` keeps rising.
Everything the engine does is published on an ``EventBus`` that the API server
(and through it the desktop app) subscribes to.
"""

from __future__ import annotations

import itertools
import json
import logging
import queue
import threading
import time
from collections import Counter, deque
from typing import Callable

import joblib
import numpy as np

from src import config
from src.detection.signatures import SignatureEngine, SignatureHit
from src.features.flow_features import FlowRecord, PacketInfo, align_to_schema
from src.models.explain import describe
from src.response.responder import Responder, action_logger

log = logging.getLogger(__name__)

ALERT_COOLDOWN_S = 10.0
# Weak detections need this many flagged flows from one source within the window.
CORROBORATION_FLOWS = 3
CORROBORATION_WINDOW_S = 10.0
ANOMALY_LABEL = "Anomaly (unknown)"


class EventBus:
    """Thread-safe publish/subscribe with a bounded history of alerts and actions."""

    def __init__(self, history: int = config.ALERT_HISTORY):
        self._subs: list[Callable[[dict], None]] = []
        self._lock = threading.Lock()
        self.history: deque = deque(maxlen=history)

    def subscribe(self, cb: Callable[[dict], None]) -> Callable[[], None]:
        with self._lock:
            self._subs.append(cb)
        return lambda: self._unsubscribe(cb)

    def _unsubscribe(self, cb) -> None:
        with self._lock:
            if cb in self._subs:
                self._subs.remove(cb)

    def publish(self, event: dict) -> None:
        if event.get("type") in ("alert", "action"):
            self.history.append(event)
        with self._lock:
            subs = list(self._subs)
        for cb in subs:
            try:
                cb(event)
            except Exception:
                log.exception("event subscriber failed")


class Models:
    """Loads every trained artifact that exists. Missing ones are reported, not fatal."""

    def __init__(self):
        from src.data.preprocess import load_feature_spec

        spec = load_feature_spec()
        self.features: list[str] = spec["features"]
        self.lite_features: list[str] = spec["lite_features"]
        self.classes: list[str] = spec["classes"]
        self.benign_idx = self.classes.index(config.BENIGN_LABEL)
        self.status: dict[str, str] = {}
        self.full = self.lite = self.autoencoder = None
        self.full_name = self.lite_name = None

        try:
            meta = json.loads(config.SUPERVISED_META_PATH.read_text())
            self.full = joblib.load(config.model_path("full", meta["best"]))
            self.full_scaler = joblib.load(config.SCALER_PATH)
            self.full_name = f"full/{meta['best']}"
            self.status["full"] = f"loaded ({meta['best']}, {len(self.features)} features)"
        except FileNotFoundError as e:
            self.status["full"] = f"missing ({e.filename})"
        try:
            meta = json.loads(config.LITE_META_PATH.read_text())
            self.lite = joblib.load(config.model_path("lite", meta["best"]))
            self.lite_scaler = joblib.load(config.LITE_SCALER_PATH)
            self.lite_name = f"lite/{meta['best']}"
            self.status["lite"] = f"loaded ({meta['best']}, {len(self.lite_features)} features)"
        except FileNotFoundError as e:
            self.status["lite"] = f"missing ({e.filename})"
        try:
            from src.models.autoencoder import AutoencoderScorer

            self.autoencoder = AutoencoderScorer()
            self.status["autoencoder"] = f"loaded (threshold {self.autoencoder.threshold:.4f})"
        except FileNotFoundError as e:
            self.status["autoencoder"] = f"missing ({e.filename})"
        for model in (self.full, self.lite):
            if model is not None and hasattr(model, "n_jobs"):
                model.n_jobs = 1  # small live batches: threads cost more than they save

        # Per-alert explanations. Optional: a missing or unsupported model just
        # means alerts carry no explanation.
        self.full_explainer = self.lite_explainer = None
        if config.EXPLAIN_ENABLED:
            from src.models.explain import Explainer

            if self.full is not None:
                self.full_explainer = Explainer(self.full, self.features)
            if self.lite is not None:
                self.lite_explainer = Explainer(self.lite, self.lite_features)

    def explainer_for(self, model_name: str | None):
        """The explainer matching the model that produced a verdict, if any."""
        if model_name == self.full_name:
            return self.full_explainer, self.features
        if model_name == self.lite_name:
            return self.lite_explainer, self.lite_features
        return None, None


class DetectionEngine:
    def __init__(self, responder: Responder | None = None, bus: EventBus | None = None,
                 models: Models | None = None, mode: str = "live"):
        self.bus = bus or EventBus()
        self.models = models or Models()
        self.responder = responder or Responder()
        self.responder.listeners.append(self._on_action)
        self.signatures = SignatureEngine()
        self.mode = mode
        self.started = time.time()
        self._ids = itertools.count(1)
        self._queue: queue.Queue[FlowRecord] = queue.Queue(maxsize=200_000)
        self._stop = threading.Event()
        self._open_alerts: dict[tuple, dict] = {}
        self._weak_evidence: dict[tuple, deque] = {}
        self._lock = threading.Lock()
        self._events = action_logger()
        # statistics for the current second
        self._pkts = self._bytes = self._flows = 0
        self.totals = Counter()
        self.class_counts = Counter()
        self.flows_dropped = 0

    # -- inputs ---------------------------------------------------------------
    def on_packet(self, p: PacketInfo) -> None:
        with self._lock:
            self._pkts += 1
            self._bytes += p.wire_len or (p.payload_len + p.header_len + 20)
        for hit in self.signatures.observe(p, now=time.time()):
            self._raise_from_signature(hit)

    def on_flow(self, flow: FlowRecord) -> None:
        try:
            self._queue.put_nowait(flow)
        except queue.Full:
            self.flows_dropped += 1

    # -- scoring --------------------------------------------------------------
    def score(self, flows: list[FlowRecord]) -> list[dict]:
        """Score a batch of flows. Returns one verdict dict per flow."""
        m = self.models
        n = len(flows)
        verdicts = [{"attack": config.BENIGN_LABEL, "confidence": 0.0, "detector": None, "model": None}
                    for _ in range(n)]
        # Scaled matrices feed the models; the raw ones are kept so an
        # explanation can quote the value a person would recognise.
        X_full = raw_full = X_lite = raw_lite = None
        if m.full is not None:
            raw_full = np.vstack([align_to_schema(f.cic, m.features) for f in flows])
            X_full = m.full_scaler.transform(raw_full).astype(np.float32)
            proba = m.full.predict_proba(X_full)
            self._apply_supervised(verdicts, proba, m.full_name)
        if m.lite is not None:
            raw_lite = np.vstack([align_to_schema(f.lite, m.lite_features) for f in flows])
            X_lite = m.lite_scaler.transform(raw_lite).astype(np.float32)
            proba = m.lite.predict_proba(X_lite)
            self._apply_supervised(verdicts, proba, m.lite_name)
        if m.autoencoder is not None and X_full is not None:
            err = m.autoencoder.score(X_full)
            for v, e in zip(verdicts, err):
                v["ae_error"] = float(e)
                if v["detector"] is None and e > m.autoencoder.threshold:
                    # 0 at the threshold, 0.5 at twice the threshold, 0.9 at ten times.
                    v.update(attack=ANOMALY_LABEL, detector="anomaly", model="autoencoder",
                             confidence=float(min(0.99, 1.0 - m.autoencoder.threshold / e)))
        if config.EXPLAIN_ENABLED:
            self._explain(flows, verdicts, {m.full_name: (X_full, raw_full),
                                            m.lite_name: (X_lite, raw_lite)})
        return verdicts

    def _explain(self, flows, verdicts, matrices) -> None:
        """Attach feature attributions to verdicts that will open a new alert.

        Explaining costs a few milliseconds per flow, so flows that would only
        increment an already-open alert are skipped, and the batch is capped.
        That keeps a flood of thousands of flows from stalling the scoring loop.
        """
        m = self.models
        done = 0
        for i, v in enumerate(verdicts):
            if done >= config.EXPLAIN_MAX_PER_BATCH:
                return
            if v["detector"] != "ml":
                continue
            explainer, feature_names = m.explainer_for(v["model"])
            if explainer is None or not explainer.available:
                continue
            X, raw = matrices.get(v["model"], (None, None))
            if X is None:
                continue
            with self._lock:
                already_open = (flows[i].src, v["attack"], "ml") in self._open_alerts
            if already_open:
                continue
            try:
                class_idx = m.classes.index(v["attack"])
            except ValueError:
                continue
            try:
                v["explain"] = explainer.explain(
                    X[i], class_idx, raw=dict(zip(feature_names, raw[i])),
                    top_k=config.EXPLAIN_TOP_K)
            except Exception:
                log.debug("explanation failed for flow %d", i, exc_info=True)
                continue
            done += 1

    def _apply_supervised(self, verdicts, proba, model_name) -> None:
        m = self.models
        pred = proba.argmax(axis=1)
        conf = proba.max(axis=1)
        for v, k, c in zip(verdicts, pred, conf):
            if v["detector"] is not None:
                continue  # an earlier (higher-priority) model already decided
            if k != m.benign_idx and c >= config.SUPERVISED_MIN_CONFIDENCE:
                v.update(attack=m.classes[k], confidence=float(c), detector="ml", model=model_name)

    def _worker(self) -> None:
        while not self._stop.is_set():
            batch = []
            try:
                batch.append(self._queue.get(timeout=0.5))
                while len(batch) < 2000:
                    batch.append(self._queue.get_nowait())
            except queue.Empty:
                pass
            if not batch:
                continue
            try:
                verdicts = self.score(batch)
            except Exception:
                log.exception("scoring failed")
                continue
            with self._lock:
                self._flows += len(batch)
            for flow, v in zip(batch, verdicts):
                self.class_counts[v["attack"]] += 1
                if v["detector"] is not None:
                    self._raise_from_flow(flow, v)

    # -- alerts ---------------------------------------------------------------
    def _raise_from_signature(self, hit: SignatureHit) -> None:
        self._raise(src=hit.src, dst=hit.dst, dport=hit.dport, attack=hit.attack, confidence=1.0,
                    detector=f"signature:{hit.rule}", model="rules", description=hit.description,
                    severity="high", evidence=hit.evidence)

    def _corroborated(self, flow: FlowRecord, v: dict) -> bool:
        """Weak evidence (lite model, medium confidence, anomaly) must repeat before it alerts."""
        strong = (v["detector"] == "ml" and v["model"] == self.models.full_name
                  and v["confidence"] >= config.SUPERVISED_CONFIDENCE)
        if strong:
            return True
        now = time.time()
        q = self._weak_evidence.setdefault((flow.src, v["attack"]), deque())
        q.append(now)
        while q and q[0] < now - CORROBORATION_WINDOW_S:
            q.popleft()
        return len(q) >= CORROBORATION_FLOWS

    def _raise_from_flow(self, flow: FlowRecord, v: dict) -> None:
        if not self._corroborated(flow, v):
            return
        if v["detector"] == "anomaly":
            # Barely above threshold: record it but take no firewall action.
            severity = "medium" if v["confidence"] >= 0.5 else "low"
            desc = (f"Unusual flow: reconstruction error {v['ae_error']:.3f} above threshold "
                    f"{self.models.autoencoder.threshold:.3f}")
        else:
            severity = "high" if v["confidence"] >= config.SUPERVISED_CONFIDENCE else "medium"
            desc = f"{v['attack']} predicted by {v['model']} with confidence {v['confidence']:.2f}"
            reason = describe(v.get("explain") or [])
            if reason:
                desc = f"{desc}, {reason}"
        self._raise(src=flow.src, dst=flow.dst, dport=flow.dport, attack=v["attack"],
                    confidence=v["confidence"], detector=v["detector"], model=v["model"],
                    description=desc, severity=severity,
                    evidence={"packets": flow.n_packets, "bytes": flow.n_bytes},
                    explain=v.get("explain"))

    def _raise(self, src, dst, dport, attack, confidence, detector, model, description, severity,
               evidence, explain=None):
        now = time.time()
        key = (src, attack, detector.split(":")[0])
        with self._lock:
            open_alert = self._open_alerts.get(key)
            if open_alert and now - open_alert["last_seen"] < ALERT_COOLDOWN_S:
                open_alert["count"] += 1
                open_alert["last_seen"] = now
                open_alert["confidence"] = max(open_alert["confidence"], round(confidence, 3))
                update = {"type": "alert_update", "id": open_alert["id"], "count": open_alert["count"],
                          "last_seen": now, "confidence": open_alert["confidence"]}
                self.bus.publish(update)
                return
            alert = {
                "type": "alert", "id": next(self._ids), "time": now, "last_seen": now,
                "src": src, "dst": dst, "dport": int(dport), "attack": attack,
                "confidence": round(float(confidence), 3), "detector": detector, "model": model,
                "severity": severity, "description": description, "evidence": evidence,
                "explain": explain or [], "count": 1, "action": "pending",
            }
            self._open_alerts[key] = alert
            self.totals["alerts"] += 1
        # Respond outside the lock (firewall commands can be slow).
        kind = {"high": "block", "medium": "quarantine"}.get(severity)
        if kind is None:
            alert["action"] = "logged"
        else:
            alert["action"] = self.responder.respond(src, kind, f"{attack} via {detector}")["action"]
        self._events.info(json.dumps({k: v for k, v in alert.items()}))
        log.warning("ALERT %s %s -> %s:%s %s (%s, conf %.2f) action=%s", severity.upper(), src, dst,
                    dport, attack, detector, confidence, alert["action"])
        self.bus.publish(dict(alert))

    def _on_action(self, rec: dict) -> None:
        self.bus.publish(rec)
        self.bus.publish({"type": "blocks", "blocks": self.responder.active()})

    # -- periodic stats -------------------------------------------------------
    def _stats_loop(self) -> None:
        while not self._stop.wait(1.0):
            with self._lock:
                pkts, byts, flows = self._pkts, self._bytes, self._flows
                self._pkts = self._bytes = self._flows = 0
                for key, a in list(self._open_alerts.items()):
                    if time.time() - a["last_seen"] > 5 * ALERT_COOLDOWN_S:
                        del self._open_alerts[key]
                for key, q in list(self._weak_evidence.items()):
                    if not q or q[-1] < time.time() - CORROBORATION_WINDOW_S:
                        del self._weak_evidence[key]
            self.totals["packets"] += pkts
            self.totals["flows"] += flows
            self.signatures.prune(time.time())
            self.bus.publish({
                "type": "stats", "time": time.time(), "packets_per_s": pkts, "bytes_per_s": byts,
                "flows_per_s": flows, "queue": self._queue.qsize(), "totals": dict(self.totals),
                "class_counts": dict(self.class_counts), "flows_dropped": self.flows_dropped,
            })
            self.bus.publish({"type": "blocks", "blocks": self.responder.active()})

    def status(self) -> dict:
        importance = []
        if self.models.full_explainer is not None:
            importance = self.models.full_explainer.global_importance(top_k=8)
        elif self.models.lite_explainer is not None:
            importance = self.models.lite_explainer.global_importance(top_k=8)
        return {"type": "status", "mode": self.mode, "started": self.started, "models": self.models.status,
                "classes": self.models.classes, "firewall_backend": self.responder.backend,
                "response_enabled": self.responder.enabled, "feature_importance": importance,
                "thresholds": {"supervised_high": config.SUPERVISED_CONFIDENCE,
                               "supervised_min": config.SUPERVISED_MIN_CONFIDENCE,
                               "syn_rate": config.SYN_RATE_THRESHOLD,
                               "portscan_ports": config.PORTSCAN_PORT_THRESHOLD,
                               "block_seconds": config.BLOCK_DURATION_S}}

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        self.responder.start()
        for target, name in ((self._worker, "scoring"), (self._stats_loop, "stats")):
            threading.Thread(target=target, name=name, daemon=True).start()
        self.bus.publish(self.status())

    def stop(self) -> None:
        self._stop.set()
        self.responder.stop()

    def drain(self, timeout_s: float = 30.0) -> None:
        """Wait until queued flows are scored (used by replay and tests)."""
        deadline = time.time() + timeout_s
        while not self._queue.empty() and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.6)
