"""Tests for unknown-family discovery (src/detection/discovery.py).

What has to be true for the layer to be worth anything:

* repeated flows of the same novel thing land in one family, so an operator sees
  one object and not one alert per flow;
* different novel things do not get merged into the same family;
* a family does not become reportable until it has actually repeated, which is
  what keeps the benign tail that alpha lets through from raising alerts;
* identifiers are stable, names survive a restart, and the fingerprint names
  the feature that is actually unusual.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.detection.discovery import MIN_FAMILY_FLOWS, FamilyTracker, calibrated_radius
from src.models.openset import OpenSetRecognizer

FEATURES = ["duration", "packets_per_s", "bytes_per_s", "mean_size"]
CENTRES = {
    "Benign": (5.0, 10.0, 900.0, 120.0),
    "Flood": (1.0, 900.0, 40000.0, 44.0),
    "Scan": (0.2, 60.0, 300.0, 10.0),
}
# Two distinct novel shapes, far from the known classes and from each other.
NOVEL_A = (60.0, 2.0, 20.0, 1400.0)
NOVEL_B = (0.05, 4000.0, 10.0, 2.0)


def _sample(centre, n, rng, spread=0.03):
    centre = np.asarray(centre, dtype=np.float64)
    return centre * (1.0 + rng.normal(0, spread, size=(n, len(centre))))


@pytest.fixture(scope="module")
def recognizer():
    rng = np.random.default_rng(1)
    classes = list(CENTRES)
    fit_X, fit_y, cal_X, cal_y = [], [], [], []
    for i, name in enumerate(classes):
        fit_X.append(_sample(CENTRES[name], 500, rng))
        fit_y += [i] * 500
        cal_X.append(_sample(CENTRES[name], 500, rng))
        cal_y += [i] * 500
    return OpenSetRecognizer.fit(np.vstack(fit_X), np.array(fit_y), np.vstack(cal_X),
                                 np.array(cal_y), classes, alpha=0.05, features=FEATURES,
                                 kind="test", max_reference=250)


@pytest.fixture
def tracker(recognizer):
    return FamilyTracker(recognizer, kind="test", persist=False)


def test_repeated_novel_flows_form_one_family(tracker, recognizer):
    """Many flows of one novel shape are one object, not one alert each."""
    rng = np.random.default_rng(2)
    n = MIN_FAMILY_FLOWS + 5
    ids = {tracker.observe(row)["id"] for row in _sample(NOVEL_A, n, rng)}
    assert len(ids) == 1
    family = tracker.families[ids.pop()]
    assert family.n_flows == n
    assert family.alertable


def test_distinct_novel_shapes_are_separate_families(tracker):
    rng = np.random.default_rng(3)
    a = {tracker.observe(row)["id"] for row in _sample(NOVEL_A, 12, rng)}
    b = {tracker.observe(row)["id"] for row in _sample(NOVEL_B, 12, rng)}
    assert len(a) == 1 and len(b) == 1
    assert a != b


def test_family_is_not_reportable_until_it_repeats(tracker):
    """One flow short of the threshold reports nothing; the threshold reports."""
    rng = np.random.default_rng(4)
    rows = _sample(NOVEL_A, MIN_FAMILY_FLOWS - 1, rng)
    for row in rows:
        tracker.observe(row)
    assert not next(iter(tracker.families.values())).alertable
    rows = _sample(NOVEL_A, 1, rng)
    assert tracker.observe(rows[0])["flows"] == MIN_FAMILY_FLOWS
    family = next(iter(tracker.families.values()))
    assert family.alertable          # exactly at the threshold
    assert family.n_flows == MIN_FAMILY_FLOWS


def test_scattered_flows_never_become_reportable(tracker):
    """The benign tail that alpha lets through is scattered: each flow is
    unusual in its own direction, so no family accumulates and nothing is
    reported. This is what pays for a loose alpha."""
    rng = np.random.default_rng(5)
    base = np.asarray(CENTRES["Benign"], dtype=np.float64)
    # Orthogonal-ish directions, one per flow, as unrelated outliers are.
    for direction in rng.normal(0, 1, size=(12, 4)) * 400.0:
        tracker.observe(base + direction)
    assert len(tracker.families) == 12
    assert not any(f.alertable for f in tracker.families.values())


def test_reporting_needs_size_not_rejection_strength(recognizer):
    """Size is the criterion, and a firm rejection does not substitute for it.

    This is the corrected policy. An earlier version counted only flows
    rejected at a stricter conformal level, which the leave-one-class-out sweep
    showed reports almost no real discovery, because novel attack flows mostly
    land between the two levels. A few deeply rejected flows are still only a
    few flows."""
    tracker = FamilyTracker(recognizer, kind="test", persist=False, min_flows=20)
    rng = np.random.default_rng(16)
    base = np.asarray(CENTRES["Benign"], dtype=np.float64)
    direction = np.asarray(NOVEL_A) - base
    for _ in range(5):
        state = tracker.observe(base + direction, p_values=np.array([0.0, 0.0, 0.0]))
    assert state["flows"] == 5
    assert state["best_p"] == 0.0        # as firmly rejected as possible
    assert not state["alertable"]        # and still not worth reporting
    for _ in range(15):
        state = tracker.observe(base + direction, p_values=np.array([0.04, 0.02, 0.01]))
    assert state["flows"] == 20
    assert state["alertable"]


def test_same_direction_at_different_intensity_is_one_family(tracker):
    """The point of using direction: the same attack run gently and run hard
    belongs to one family, not two."""
    rng = np.random.default_rng(15)
    base = np.asarray(CENTRES["Benign"], dtype=np.float64)
    direction = np.asarray(NOVEL_A) - base
    ids = {tracker.observe(base + direction * scale)["id"]
           for scale in (0.5, 1.0, 2.0, 5.0, 20.0)}
    assert len(ids) == 1


def test_fingerprint_names_the_unusual_feature(tracker, recognizer):
    """NOVEL_A differs from benign mostly in mean_size and duration, so the
    fingerprint has to put one of those first, with the readable value."""
    rng = np.random.default_rng(6)
    row = _sample(NOVEL_A, 1, rng)[0]
    raw = dict(zip(FEATURES, row))
    state = tracker.observe(row, raw=raw)
    assert state["fingerprint"]
    top = state["fingerprint"][0]
    assert top["feature"] in ("mean_size", "duration")
    assert "value" in top
    assert "deviation" in top


def test_autoencoder_route_uses_reconstruction_error(tracker):
    """When a flow arrives through the autoencoder, the fingerprint is the
    error decomposition, so the alert can say which feature failed."""
    rng = np.random.default_rng(7)
    row = _sample(NOVEL_A, 1, rng)[0]
    errors = np.array([0.01, 0.01, 0.01, 5.0])     # all the error in mean_size
    state = tracker.observe(row, raw=dict(zip(FEATURES, row)), route="anomaly",
                            ae_errors=errors)
    top = state["fingerprint"][0]
    assert top["feature"] == "mean_size"
    assert top["basis"] == "reconstruction error"
    assert top["share"] > 0.9


def test_description_mentions_nearest_known_class(tracker, recognizer):
    rng = np.random.default_rng(8)
    row = _sample(NOVEL_A, 1, rng)[0]
    p = recognizer.p_values(row[None, :])[0]
    tracker.observe(row, raw=dict(zip(FEATURES, row)), p_values=p)
    family = next(iter(tracker.families.values()))
    text = family.describe()
    assert family.id in text
    assert "nearest known class" in text
    assert family.nearest_class in recognizer.classes


def test_promote_renames_the_family_everywhere(tracker):
    rng = np.random.default_rng(9)
    for row in _sample(NOVEL_A, 5, rng):
        state = tracker.observe(row)
    family_id = state["id"]
    out = tracker.promote(family_id, "Slow TLS beacon")
    assert out["label"] == "Slow TLS beacon"
    assert tracker.families[family_id].describe().startswith("Slow TLS beacon")
    later = tracker.observe(_sample(NOVEL_A, 1, rng)[0])
    assert later["label"] == "Slow TLS beacon"


def test_promote_rejects_unknown_id_and_empty_name(tracker):
    rng = np.random.default_rng(10)
    state = tracker.observe(_sample(NOVEL_A, 1, rng)[0])
    with pytest.raises(KeyError):
        tracker.promote("NETRA-U999", "whatever")
    with pytest.raises(ValueError):
        tracker.promote(state["id"], "   ")


def test_names_survive_a_restart(recognizer, tmp_path):
    store = tmp_path / "unknown_families.json"
    rng = np.random.default_rng(11)
    first = FamilyTracker(recognizer, kind="test", store_path=store)
    for row in _sample(NOVEL_A, 6, rng):
        state = first.observe(row)
    first.promote(state["id"], "Slow TLS beacon")

    second = FamilyTracker(recognizer, kind="test", store_path=store)
    assert state["id"] in second.families
    assert second.families[state["id"]].promoted_name == "Slow TLS beacon"
    # The restored centroid still attracts the same traffic, so the family does
    # not fragment across restarts.
    assert second.observe(_sample(NOVEL_A, 1, rng)[0])["id"] == state["id"]


def test_store_from_another_feature_set_is_ignored(recognizer, tmp_path):
    """A stored family whose centroid has the wrong width belongs to a
    different feature set and must not be loaded into this one."""
    store = tmp_path / "unknown_families.json"
    store.write_text('{"kind": "other", "radius": 1.0, "next_id": 7, "promoted": {}, '
                     '"families": [{"id": "NETRA-U006", "flows": 9, "centroid": [1, 2]}]}')
    tracker = FamilyTracker(recognizer, kind="test", store_path=store)
    assert tracker.families == {}


def test_unreadable_store_is_ignored(recognizer, tmp_path):
    store = tmp_path / "unknown_families.json"
    store.write_text("{not json")
    assert FamilyTracker(recognizer, kind="test", store_path=store).families == {}


def test_radius_comes_from_calibration(recognizer):
    r = calibrated_radius(recognizer)
    assert r > 0
    medians = [float(np.median(c)) for c in recognizer.calibration["knn"] if len(c)]
    assert r == pytest.approx(float(np.median(medians)))
