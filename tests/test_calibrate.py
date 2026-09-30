"""Tests for autoencoder threshold calibration (src/models/calibrate.py).

These cover the arithmetic and the safety rails. Live capture is not exercised
here; it needs an interface and real traffic, and is verified by running
``python -m src.cli calibrate`` against the Docker lab.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from src import config
from src.models import calibrate

DATASET_THRESHOLD = 0.14632


@pytest.fixture
def meta_file(tmp_path, monkeypatch):
    """Point the calibrator at a throwaway metadata file."""
    path = tmp_path / "autoencoder_meta.json"
    path.write_text(json.dumps({
        "architecture": [59, 32, 16, 8, 16, 32, 59],
        "threshold": DATASET_THRESHOLD,
        "threshold_percentile": 99.0,
    }, indent=2))
    monkeypatch.setattr(config, "AUTOENCODER_META_PATH", path)
    return path


def quiet_errors(n=2000, scale=0.004, seed=0):
    """Reconstruction errors resembling a calmer network than the dataset."""
    return list(np.abs(np.random.default_rng(seed).normal(0, scale, n)))


def test_summarise_matches_numpy():
    errors = quiet_errors()
    s = calibrate.summarise(errors, 99.0)
    assert s["flows"] == len(errors)
    assert s["threshold"] == pytest.approx(np.percentile(errors, 99.0))
    assert s["median"] == pytest.approx(np.median(errors))
    assert s["median"] <= s["p95"] <= s["p99"] <= s["max"]


def test_apply_writes_threshold_and_keeps_the_dataset_value(meta_file):
    errors = quiet_errors()
    result = calibrate.apply(errors, source="pcap:test", percentile=99.0)

    meta = json.loads(meta_file.read_text())
    assert meta["threshold"] == pytest.approx(result["threshold"])
    # The original must be preserved so the change is reversible.
    assert meta["threshold_dataset"] == pytest.approx(DATASET_THRESHOLD)
    assert meta["calibration"]["source"] == "pcap:test"
    assert result["previous_threshold"] == pytest.approx(DATASET_THRESHOLD)
    # A quieter network should give a tighter threshold.
    assert result["threshold"] < DATASET_THRESHOLD
    assert result["ratio"] < 1.0


def test_dry_run_changes_nothing(meta_file):
    before = meta_file.read_text()
    result = calibrate.apply(quiet_errors(), source="pcap:test", dry_run=True)
    assert result["threshold"] > 0
    assert meta_file.read_text() == before


def test_repeated_calibration_keeps_the_original_dataset_threshold(meta_file):
    calibrate.apply(quiet_errors(seed=1), source="pcap:a")
    first = json.loads(meta_file.read_text())["threshold"]
    calibrate.apply(quiet_errors(seed=2, scale=0.02), source="pcap:b")
    meta = json.loads(meta_file.read_text())
    # threshold_dataset must still be the CIC-IDS2017 one, not the first calibration.
    assert meta["threshold_dataset"] == pytest.approx(DATASET_THRESHOLD)
    assert meta["threshold"] != pytest.approx(first)


def test_reset_restores_the_dataset_threshold(meta_file):
    calibrate.apply(quiet_errors(), source="pcap:test")
    r = calibrate.reset()
    meta = json.loads(meta_file.read_text())
    assert r["threshold"] == pytest.approx(DATASET_THRESHOLD)
    assert meta["threshold"] == pytest.approx(DATASET_THRESHOLD)
    assert meta["threshold_percentile"] == config.AE_THRESHOLD_PERCENTILE
    assert "calibration" not in meta


def test_reset_without_calibration_is_refused(meta_file):
    with pytest.raises(ValueError, match="never been calibrated"):
        calibrate.reset()


def test_too_few_flows_is_refused(meta_file):
    """A high percentile over a handful of flows is meaningless, so refuse it."""
    with pytest.raises(ValueError, match="at least"):
        calibrate.apply(quiet_errors(n=calibrate.MIN_FLOWS - 1), source="pcap:tiny")
    # Nothing should have been written.
    assert "calibration" not in json.loads(meta_file.read_text())


def test_percentile_is_honoured(meta_file):
    errors = quiet_errors()
    low = calibrate.apply(errors, source="pcap:a", percentile=90.0, dry_run=True)
    high = calibrate.apply(errors, source="pcap:b", percentile=99.9, dry_run=True)
    assert low["threshold"] < high["threshold"]


def test_uniform_traffic_is_refused(meta_file):
    """Thousands of identical flows are one repeated pattern, not a sample of
    normal traffic. A percentile of that is meaningless, so refuse it."""
    identical = [0.432] * 5000
    with pytest.raises(ValueError, match="too uniform"):
        calibrate.apply(identical, source="live:eth0")
    assert "calibration" not in json.loads(meta_file.read_text())


def test_nearly_uniform_traffic_is_refused(meta_file):
    """A handful of distinct values among thousands of flows is still degenerate."""
    errors = [0.432] * 4990 + [0.44, 0.45, 0.43, 0.431, 0.433] * 2
    with pytest.raises(ValueError, match="too uniform"):
        calibrate.apply(errors, source="live:eth0")


def test_varied_traffic_is_not_degenerate():
    stats = calibrate.summarise(quiet_errors(), 99.0)
    assert stats["degenerate"] is False
    assert stats["distinct_values"] > 100


def test_busy_network_raises_the_threshold(meta_file):
    """A noisier network than the dataset should widen, not narrow, tolerance."""
    noisy = list(np.abs(np.random.default_rng(3).normal(0, 0.2, 3000)))
    result = calibrate.apply(noisy, source="pcap:busy")
    assert result["threshold"] > DATASET_THRESHOLD
    assert result["ratio"] > 1.0
