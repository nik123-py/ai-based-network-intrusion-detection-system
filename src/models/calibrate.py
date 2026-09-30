"""Recalibrate the autoencoder threshold against the deployment network.

The threshold shipped with the model is the 99th percentile of reconstruction
error over CIC-IDS2017 benign flows. That is the right starting point, but it
describes the *dataset's* idea of normal, not the network Netra is actually
watching. A quiet office LAN and a busy campus link have different traffic
shapes, so the same threshold gives a different false-alarm rate on each.

This module observes real traffic for a while, collects the reconstruction
errors, and sets the threshold to the chosen percentile of *those* errors. The
false-alarm rate then means what it claims to mean on this network.

This directly addresses the failure documented in docs/REPORT.md section 7.1: a
model tuned only against its training dataset inherits that dataset's quirks.
Calibration moves the one tunable that matters onto local evidence.

IMPORTANT: calibration assumes the observed traffic is benign. Anything hostile
captured during the window raises the threshold and teaches Netra to ignore it.
Run it on a known-quiet network, and check the reported summary before keeping
the result.
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter

import numpy as np

from src import config

log = logging.getLogger(__name__)

# Too few flows and a high percentile is just the maximum of a small sample.
MIN_FLOWS = 200


# A flow emitted because capture stopped was cut off mid-connection, so its
# duration, rates and packet counts describe the capture window rather than the
# traffic. Including those would calibrate against an artifact.
SKIPPED_REASONS = frozenset({"flush"})


class ErrorCollector:
    """Turns captured flows into autoencoder reconstruction errors."""

    def __init__(self, skip_reasons: frozenset[str] = SKIPPED_REASONS):
        import joblib

        from src.data.preprocess import load_feature_spec
        from src.models.autoencoder import AutoencoderScorer

        self.features = load_feature_spec()["features"]
        self.scaler = joblib.load(config.SCALER_PATH)
        self.scorer = AutoencoderScorer()
        self.skip_reasons = skip_reasons
        self.errors: list[float] = []
        self.reasons: Counter = Counter()
        self._pending: list[np.ndarray] = []

    def on_flow(self, flow) -> None:
        from src.features.flow_features import align_to_schema

        self.reasons[flow.reason] += 1
        if flow.reason in self.skip_reasons:
            return
        self._pending.append(align_to_schema(flow.cic, self.features))
        if len(self._pending) >= 256:
            self.flush()

    def flush(self) -> None:
        if not self._pending:
            return
        raw = np.vstack(self._pending)
        self._pending.clear()
        X = self.scaler.transform(raw).astype(np.float32)
        self.errors.extend(float(e) for e in self.scorer.score(X))

    @property
    def count(self) -> int:
        return len(self.errors) + len(self._pending)


def collect_live(seconds: float, iface: str | None = None) -> tuple[list[float], str]:
    """Capture on an interface for ``seconds`` and return reconstruction errors."""
    from src.detection.sniffer import Sniffer, resolve_interface

    iface = resolve_interface(iface or config.CAPTURE_INTERFACE)
    collector = ErrorCollector()
    sniffer = Sniffer(iface=iface)
    sniffer.on_flow(collector.on_flow)
    sniffer.start()
    log.info("calibrating on %s for %.0f s (traffic must be benign)", iface, seconds)
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            time.sleep(min(5.0, max(0.1, deadline - time.time())))
            log.info("  %.0f s remaining, %d flows so far",
                     max(0.0, deadline - time.time()), collector.count)
    except KeyboardInterrupt:
        log.warning("calibration interrupted; using what was captured")
    sniffer.stop()
    time.sleep(1.0)  # let the flow table emit anything still open
    collector.flush()
    _log_reasons(collector)
    return collector.errors, f"live:{iface}"


def collect_pcap(path: str, speed: float = 0.0) -> tuple[list[float], str]:
    """Read a capture file and return reconstruction errors for its flows."""
    from src.detection.sniffer import Sniffer

    collector = ErrorCollector()
    sniffer = Sniffer(pcap=path)
    sniffer.on_flow(collector.on_flow)
    sniffer.replay_pcap(speed=speed or 0.0)
    collector.flush()
    _log_reasons(collector)
    return collector.errors, f"pcap:{path}"


def _log_reasons(collector: ErrorCollector) -> None:
    kept = sum(n for r, n in collector.reasons.items() if r not in collector.skip_reasons)
    skipped = sum(n for r, n in collector.reasons.items() if r in collector.skip_reasons)
    log.info("flows observed: %s", dict(collector.reasons))
    log.info("using %d completed flows; ignored %d cut off when capture stopped", kept, skipped)


def summarise(errors: list[float], percentile: float) -> dict:
    a = np.asarray(errors, dtype=np.float64)
    stats = {
        "flows": int(a.size),
        "median": float(np.median(a)),
        "p95": float(np.percentile(a, 95)),
        "p99": float(np.percentile(a, 99)),
        "max": float(a.max()),
        "threshold": float(np.percentile(a, percentile)),
        "distinct_values": int(np.unique(np.round(a, 6)).size),
    }
    stats["degenerate"] = is_degenerate(stats)
    return stats


def is_degenerate(stats: dict) -> bool:
    """True when the observed errors carry too little variety to set a threshold.

    If the median equals the 99th percentile, or almost every flow produced the
    same error, then the capture was not a sample of ordinary traffic: it is one
    repeated pattern. A percentile of that is meaningless, so calibration should
    not be trusted.
    """
    if stats["flows"] < MIN_FLOWS:
        return True
    if stats["distinct_values"] < 20:
        return True
    return stats["median"] >= stats["p99"] * 0.999


def apply(errors: list[float], source: str, percentile: float | None = None,
          dry_run: bool = False) -> dict:
    """Compute the new threshold and write it into the autoencoder metadata.

    The dataset threshold is preserved as ``threshold_dataset`` so the change is
    reversible and so the report can quote both numbers.
    """
    percentile = config.AE_THRESHOLD_PERCENTILE if percentile is None else percentile
    if len(errors) < MIN_FLOWS:
        raise ValueError(
            f"only {len(errors)} flows observed, need at least {MIN_FLOWS} for a "
            f"meaningful {percentile:g}th percentile. Capture for longer, or generate "
            f"some ordinary traffic while it runs.")

    meta = json.loads(config.AUTOENCODER_META_PATH.read_text())
    stats = summarise(errors, percentile)
    if stats["degenerate"]:
        raise ValueError(
            f"the {stats['flows']} observed flows are too uniform to calibrate against "
            f"(only {stats['distinct_values']} distinct error values; median "
            f"{stats['median']:.5f} vs 99th percentile {stats['p99']:.5f}). That means the "
            f"capture saw one repeated pattern rather than a sample of ordinary traffic. "
            f"Capture for longer on a network with real, varied activity.")
    previous = float(meta["threshold"])
    # Keep the original dataset-derived threshold the first time we calibrate.
    meta.setdefault("threshold_dataset", previous)

    result = {
        "source": source,
        "time": time.time(),
        "percentile": percentile,
        "previous_threshold": previous,
        "threshold": stats["threshold"],
        "ratio": stats["threshold"] / previous if previous else float("inf"),
        **stats,
    }
    if not dry_run:
        meta["threshold"] = stats["threshold"]
        meta["threshold_percentile"] = percentile
        meta["calibration"] = result
        config.AUTOENCODER_META_PATH.write_text(json.dumps(meta, indent=2))
    return result


def reset() -> dict:
    """Restore the threshold derived from the CIC-IDS2017 benign validation flows."""
    meta = json.loads(config.AUTOENCODER_META_PATH.read_text())
    original = meta.get("threshold_dataset")
    if original is None:
        raise ValueError("this model has never been calibrated; the threshold is already "
                         "the dataset one.")
    previous = float(meta["threshold"])
    meta["threshold"] = float(original)
    meta["threshold_percentile"] = config.AE_THRESHOLD_PERCENTILE
    meta.pop("calibration", None)
    config.AUTOENCODER_META_PATH.write_text(json.dumps(meta, indent=2))
    return {"threshold": float(original), "previous_threshold": previous}


def print_summary(result: dict, dry_run: bool = False) -> None:
    ratio = result["ratio"]
    direction = "more" if ratio > 1 else "less"
    print(f"\nObserved {result['flows']:,} flows from {result['source']}")
    print(f"  median error       {result['median']:.5f}")
    print(f"  95th percentile    {result['p95']:.5f}")
    print(f"  99th percentile    {result['p99']:.5f}")
    print(f"  maximum            {result['max']:.5f}")
    print(f"\nThreshold at the {result['percentile']:g}th percentile of this network:")
    print(f"  was (dataset)      {result['previous_threshold']:.5f}")
    print(f"  now (calibrated)   {result['threshold']:.5f}   ({ratio:.2f}x, {direction} tolerant)")
    if dry_run:
        print("\nDry run: nothing was written. Re-run without --dry-run to keep it.")
    else:
        print("\nWritten to models/autoencoder_meta.json. Restore with: "
              "python -m src.cli calibrate --reset")
    if ratio > 3:
        print("\nWarning: the new threshold is much higher than the dataset one. That is "
              "expected if this network is busier than CIC-IDS2017, but it also happens "
              "if something hostile was captured during the window. Check the traffic "
              "before relying on it.")
