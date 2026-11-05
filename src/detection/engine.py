"""Hybrid detection engine: fuses signatures, supervised models, the open-set
test, the clusterer and the autoencoder.

Fusion by priority, for each source:
  1. A signature hit raises an alert immediately (packet path, no ML needed).
  2. Otherwise a supervised prediction of an attack class raises an alert. The
     full CICFlowMeter model is consulted first, then the lite model; the alert
     records which model produced it. Confidence >= SUPERVISED_CONFIDENCE is
     "high" (block); >= SUPERVISED_MIN_CONFIDENCE is "medium" (quarantine).
  3. Otherwise the open-set test is applied. The classifiers are closed-set, so
     step 2 can only ever return one of the eight trained classes; this step is
     what lets the engine conclude that a flow matches none of them. A rejected
     flow is not an alert. It goes to the clusterer, which groups it with
     earlier rejected flows, and only once a family has collected
     DISCOVERY_MIN_FLOWS flows does it become an alert naming that family.
  4. Otherwise, if the autoencoder reconstruction error is above its threshold,
     the flow goes to the same clusterer by the other route, and its per-feature
     reconstruction errors become the family's fingerprint.

Steps 3 and 4 both produce an alert named after a family (``NETRA-U001``, or
whatever an operator has promoted it to) and described by the features that make
it unusual. Neither can produce the old "Anomaly (unknown)" with nothing in it.

Signature hits and high-confidence predictions of the full model act on a single
flow. Weaker evidence (lite model, medium confidence) must be seen on at least
CORROBORATION_FLOWS flows from the same source within CORROBORATION_WINDOW_S
before an alert is raised, which suppresses isolated false positives on benign
hosts. Unknown families carry their own corroboration: the family has to grow.

Response is decided by an explicit policy (``ACTION_FOR_SEVERITY``) rather than
being inferred at the point of use, so what the engine does about each class of
evidence can be read in one place and changed in one place.

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
# Fallback label for a flow that matched nothing and could not be clustered,
# which happens only when the clusterer is disabled or unavailable.
ANOMALY_LABEL = "Anomaly (unknown)"
# What the engine does about each severity. "low" is recorded and shown but
# touches no firewall rule.
ACTION_FOR_SEVERITY = {"high": "block", "medium": "quarantine", "low": None}


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

        # The open-set recogniser. Which feature set it uses follows the
        # classifier that is actually loaded, because its reference flows and
        # calibration are tied to that feature space.
        self.openset = None
        self.openset_kind = None
        if config.OPENSET_ENABLED:
            wanted = [config.OPENSET_KIND] + [k for k in ("full", "lite") if k != config.OPENSET_KIND]
            for kind in wanted:
                if (kind == "full" and self.full is None) or (kind == "lite" and self.lite is None):
                    continue
                try:
                    from src.models.openset import OpenSetRecognizer

                    self.openset = OpenSetRecognizer.load(kind)
                    self.openset.alpha = config.OPENSET_ALPHA
                    self.openset_kind = kind
                    self.status["openset"] = (f"loaded ({kind}, {self.openset.score_name} score, "
                                              f"alpha {self.openset.alpha})")
                    break
                except FileNotFoundError as e:
                    self.status["openset"] = f"missing ({e.filename})"
        else:
            self.status["openset"] = "disabled"
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
        self.families = None
        if config.DISCOVERY_ENABLED and self.models.openset is not None:
            from src.detection.discovery import FamilyTracker

            self.families = FamilyTracker(self.models.openset, kind=self.models.openset_kind)
            self.models.status["discovery"] = (
                f"active (radius {self.families.radius:.2f}, "
                f"{config.DISCOVERY_MIN_FLOWS} flows to report)")
        elif not config.DISCOVERY_ENABLED:
            self.models.status["discovery"] = "disabled (open-set routing inactive without it)"
        else:
            self.models.status["discovery"] = "unavailable (no open-set recogniser)"
        self.mode = mode
        self.started = time.time()
        self._ids = itertools.count(1)
        self._queue: queue.Queue[FlowRecord] = queue.Queue(maxsize=200_000)
        self._stop = threading.Event()
        self._open_alerts: dict[tuple, dict] = {}
        self._weak_evidence: dict[tuple, deque] = {}
        self._lock = threading.Lock()
        self._events = action_logger()
        self._last_families: list | None = None
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
        # Open-set test on whatever the classifiers left as benign. This is the
        # only step that can conclude "none of the trained classes", so it runs
        # before the autoencoder and feeds the same clusterer.
        # Without a clusterer there is nowhere to route a rejected flow and
        # nothing to name it, so the test is skipped rather than producing an
        # unnamed verdict the alert path cannot describe.
        if m.openset is not None and self.families is not None:
            X_os, raw_os = (X_full, raw_full) if m.openset_kind == "full" else (X_lite, raw_lite)
            if X_os is not None:
                undecided = [i for i, v in enumerate(verdicts) if v["detector"] is None]
                if undecided:
                    rows = X_os[undecided]
                    rejected = ~m.openset.known(rows, alpha=config.OPENSET_ALPHA)
                    for i, is_rejected in zip(undecided, rejected):
                        if is_rejected:
                            verdicts[i].update(detector="openset", model=f"openset/{m.openset_kind}",
                                               confidence=0.0)
                            verdicts[i]["_os_row"] = X_os[i]
                            verdicts[i]["_raw_row"] = raw_os[i] if raw_os is not None else None
        if m.autoencoder is not None and X_full is not None:
            err = m.autoencoder.score(X_full)
            for i, (v, e) in enumerate(zip(verdicts, err)):
                v["ae_error"] = float(e)
                if v["detector"] is None and e > m.autoencoder.threshold:
                    # 0 at the threshold, 0.5 at twice the threshold, 0.9 at ten times.
                    v.update(attack=ANOMALY_LABEL, detector="anomaly", model="autoencoder",
                             confidence=float(min(0.99, 1.0 - m.autoencoder.threshold / e)))
                    v["_ae_errors"] = m.autoencoder.errors_per_feature(X_full[i:i + 1])[0]
                    # The autoencoder works in the full feature space, so it can
                    # only reach the clusterer when the recogniser does too.
                    # With a lite-only recogniser this falls back to the plain
                    # anomaly alert, which is logged and takes no action.
                    if m.openset is not None and m.openset_kind == "full":
                        v["_os_row"] = X_full[i]
                        v["_raw_row"] = raw_full[i] if raw_full is not None else None
        if self.families is not None:
            self._cluster(flows, verdicts)
        if config.EXPLAIN_ENABLED:
            self._explain(flows, verdicts, {m.full_name: (X_full, raw_full),
                                            m.lite_name: (X_lite, raw_lite)})
        # Feature rows are carried between the steps above but are not part of a
        # verdict, so they do not leave this method.
        for v in verdicts:
            for key in ("_os_row", "_raw_row", "_ae_errors"):
                v.pop(key, None)
        return verdicts

    def _cluster(self, flows, verdicts) -> None:
        """Send every unrecognised flow to the clusterer and take its family.

        The flow's verdict is rewritten to name the family, so from here on it
        travels through the engine like any other verdict. The full p-value row
        is computed here rather than during scoring because only the rejected
        flows need it, and they are a small minority.
        """
        pending = [i for i, v in enumerate(verdicts)
                   if v["detector"] in ("openset", "anomaly") and v.get("_os_row") is not None]
        if not pending:
            return
        rows = np.vstack([verdicts[i]["_os_row"] for i in pending])
        try:
            p = self.models.openset.p_values(rows)
        except Exception:
            log.debug("open-set p-values failed", exc_info=True)
            p = [None] * len(pending)
        for n, i in enumerate(pending):
            v, flow = verdicts[i], flows[i]
            raw = v.get("_raw_row")
            feature_names = (self.models.features if self.models.openset_kind == "full"
                             else self.models.lite_features)
            try:
                family = self.families.observe(
                    v["_os_row"], raw=dict(zip(feature_names, raw)) if raw is not None else None,
                    src=flow.src, dst=flow.dst, dport=flow.dport,
                    route=v["detector"], p_values=p[n], ae_errors=v.get("_ae_errors"))
            except Exception:
                log.debug("clustering failed for flow %d", i, exc_info=True)
                continue
            v["family"] = family
            v["attack"] = family["label"]
            v["description"] = family["description"]
            # The family decides: it needs enough flows rejected at the alert
            # level, not merely routed to the clusterer.
            v["reportable"] = bool(family["alertable"])
            if v["detector"] == "openset":
                # Confidence here is the strength of the rejection, not of a
                # class prediction: 1 - the best p-value any known class gave.
                v["confidence"] = round(1.0 - float(family["nearest_p"]), 3)

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
        if v.get("family") is not None:
            self._raise_from_family(flow, v)
            return
        if not self._corroborated(flow, v):
            return
        if v["detector"] == "anomaly":
            # No clusterer available, so this is the old bare anomaly: there is
            # nothing to name it with, and nothing to act on either.
            severity = "low"
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

    def _raise_from_family(self, flow: FlowRecord, v: dict) -> None:
        """Alert on an unknown family, once it has repeated enough to be real.

        The family's own flow count is the corroboration, so the per-source
        window used for the other weak detectors does not apply: a novel attack
        spread over several sources should still be reported as one family, and
        a one-off flow from the benign tail should not be reported at all.
        """
        family = v["family"]
        if not v.get("reportable"):
            return
        severity = "medium" if config.DISCOVERY_ACTION != "none" else "low"
        self._raise(src=flow.src, dst=flow.dst, dport=flow.dport, attack=family["label"],
                    confidence=v["confidence"], detector=v["detector"],
                    model=v["model"] or "discovery", description=family["description"],
                    severity=severity,
                    evidence={"packets": flow.n_packets, "bytes": flow.n_bytes,
                              "family_flows": family["flows"],
                              "family_sources": family["n_sources"],
                              "nearest_class": family["nearest_class"],
                              "nearest_p": family["nearest_p"],
                              "best_p": family["best_p"]},
                    explain=family["fingerprint"], family=family["id"],
                    action_kind=None if config.DISCOVERY_ACTION == "none" else config.DISCOVERY_ACTION)

    def _raise(self, src, dst, dport, attack, confidence, detector, model, description, severity,
               evidence, explain=None, family=None, action_kind="by-severity"):
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
                "family": family,
            }
            self._open_alerts[key] = alert
            self.totals["alerts"] += 1
        # Respond outside the lock (firewall commands can be slow).
        kind = ACTION_FOR_SEVERITY.get(severity) if action_kind == "by-severity" else action_kind
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
            if self.families is not None:
                # Only publish when something actually changed. The snapshot is
                # a large payload and every subscriber rebuilds its view from
                # it, so sending an identical copy once a second is pure cost.
                snapshot = self.families.snapshot()
                fingerprint = [(f["id"], f["flows"], f["label"]) for f in snapshot]
                if fingerprint != self._last_families:
                    self._last_families = fingerprint
                    self.bus.publish({"type": "families", "families": snapshot})

    def status(self) -> dict:
        importance = []
        if self.models.full_explainer is not None:
            importance = self.models.full_explainer.global_importance(top_k=8)
        elif self.models.lite_explainer is not None:
            importance = self.models.lite_explainer.global_importance(top_k=8)
        return {"type": "status", "mode": self.mode, "started": self.started, "models": self.models.status,
                "classes": self.models.classes, "firewall_backend": self.responder.backend,
                "response_enabled": self.responder.enabled, "feature_importance": importance,
                "families": self.families.snapshot() if self.families is not None else [],
                "thresholds": {"supervised_high": config.SUPERVISED_CONFIDENCE,
                               "supervised_min": config.SUPERVISED_MIN_CONFIDENCE,
                               "syn_rate": config.SYN_RATE_THRESHOLD,
                               "portscan_ports": config.PORTSCAN_PORT_THRESHOLD,
                               "block_seconds": config.BLOCK_DURATION_S,
                               "openset_alpha": config.OPENSET_ALPHA,
                               "discovery_min_flows": config.DISCOVERY_MIN_FLOWS}}

    def promote_family(self, family_id: str, name: str) -> dict:
        """Give a discovered family a real name and announce it.

        This is the operator's half of the loop: Netra finds and groups
        something it has no name for, a person identifies it, and the name
        sticks to every later alert about that family.
        """
        if self.families is None:
            raise RuntimeError("discovery is not enabled")
        family = self.families.promote(family_id, name)
        self.bus.publish({"type": "family_promoted", "family": family})
        self.bus.publish({"type": "families", "families": self.families.snapshot()})
        return family

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
