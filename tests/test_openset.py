"""Tests for the open-set layer (src/models/openset.py).

The claims that matter here are not about accuracy, they are about honesty, so
they can be checked exactly rather than measured:

* the conformal p-value is valid, so the share of genuine known-class flows
  rejected at level alpha is alpha and not something discovered after the fact;
* the fast accept/reject path the engine uses agrees with the p-value test it
  replaces, on every row;
* a class the recogniser was never fitted on is rejected far more often than one
  it was, which is the whole point of the layer.

The synthetic traffic below has three well-separated known classes and a fourth
that is held out, standing in for an attack nobody trained on.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.models.openset import SCORES, OpenSetRecognizer

FEATURES = ["duration", "packets_per_s", "bytes_per_s", "mean_size"]
CENTRES = {
    "Benign": (5.0, 10.0, 900.0, 120.0),
    "Flood": (1.0, 900.0, 40000.0, 44.0),
    "Scan": (0.2, 60.0, 300.0, 10.0),
    "Novel": (60.0, 2.0, 20.0, 1400.0),   # held out of every fit
}


def _sample(centre, n, rng, spread=0.05):
    centre = np.asarray(centre, dtype=np.float64)
    return centre * (1.0 + rng.normal(0, spread, size=(n, len(centre))))


@pytest.fixture(scope="module")
def fitted():
    """A recogniser fitted on three classes, plus held-out flows of a fourth."""
    rng = np.random.default_rng(0)
    classes = ["Benign", "Flood", "Scan"]
    fit_X, fit_y, cal_X, cal_y = [], [], [], []
    for i, name in enumerate(classes):
        fit_X.append(_sample(CENTRES[name], 600, rng))
        fit_y += [i] * 600
        cal_X.append(_sample(CENTRES[name], 600, rng))
        cal_y += [i] * 600
    rec = OpenSetRecognizer.fit(np.vstack(fit_X), np.array(fit_y), np.vstack(cal_X),
                                np.array(cal_y), classes, alpha=0.05, features=FEATURES,
                                kind="test", max_reference=300)
    known = np.vstack([_sample(CENTRES[c], 500, rng) for c in classes])
    novel = _sample(CENTRES["Novel"], 500, rng)
    return rec, known, novel


@pytest.mark.parametrize("score", SCORES)
def test_p_values_are_calibrated(fitted, score):
    """On flows of a known class, rejection at level alpha happens about alpha
    of the time. This is the promise the whole layer rests on."""
    rec, known, _ = fitted
    for alpha in (0.05, 0.1, 0.25):
        rejected = (rec.p_values(known, score=score).max(axis=1) < alpha).mean()
        # Sampling noise on 1500 flows at alpha 0.05 is about 0.006, so a
        # tolerance of 0.03 is loose enough to never flake and tight enough to
        # catch a calibration that is simply wrong.
        assert rejected == pytest.approx(alpha, abs=0.03), f"{score} at alpha {alpha}"


@pytest.mark.parametrize("score", SCORES)
def test_fast_path_matches_p_value_test(fitted, score):
    """``known`` short-circuits over classes; it must still give the same answer
    as thresholding the p-values, which is what the engine assumes."""
    rec, known, novel = fitted
    X = np.vstack([known, novel])
    for alpha in (0.01, 0.05, 0.2):
        fast = rec.known(X, score=score, alpha=alpha)
        slow = rec.p_values(X, score=score).max(axis=1) >= alpha
        assert np.array_equal(fast, slow), f"{score} at alpha {alpha}"


@pytest.mark.parametrize("score", SCORES)
def test_novel_class_is_rejected(fitted, score):
    """A class that was never fitted is rejected far more than one that was."""
    rec, known, novel = fitted
    novel_rejected = (~rec.known(novel, score=score)).mean()
    known_rejected = (~rec.known(known, score=score)).mean()
    assert novel_rejected > 0.9
    assert known_rejected < 0.1
    assert novel_rejected > known_rejected


def test_nearest_class_is_named(fitted):
    """A rejected flow still reports which known class came closest, which is
    what lets an alert say "almost DoS-Slow" instead of only "unknown"."""
    rec, _, novel = fitted
    out = rec.score(novel)
    assert len(out["nearest_class"]) == len(novel)
    assert set(out["nearest_class"]) <= set(rec.classes)
    assert out["p_max"].max() < 0.5


def test_thresholds_bracket_the_calibration(fitted):
    """The accept threshold must sit inside the calibration distribution, near
    its (1 - alpha) quantile; otherwise the fast path is not the same test."""
    rec, _, _ = fitted
    t = rec.thresholds("knn", 0.05)
    for i, cal in enumerate(rec.calibration["knn"]):
        assert t[i] == pytest.approx(np.quantile(cal, 0.95), rel=0.15)


def test_whitened_distance_is_mahalanobis(fitted):
    """Clustering uses Euclidean distance in the whitened space and claims it is
    Mahalanobis distance under the mean class precision. Check the identity."""
    rec, known, _ = fitted
    pooled = rec.precisions.mean(axis=0)
    a, b = known[0], known[700]
    delta = a - b
    expected = np.sqrt(delta @ pooled @ delta)
    got = np.linalg.norm(rec.whiten(a)[0] - rec.whiten(b)[0])
    assert got == pytest.approx(expected, rel=1e-8)


def test_save_and_load_round_trip(fitted, tmp_path):
    rec, known, novel = fitted
    path = tmp_path / "openset_test.joblib"
    rec.save(path)
    again = OpenSetRecognizer.load(path=path)
    assert again.classes == rec.classes
    assert again.alpha == rec.alpha
    assert np.array_equal(again.known(np.vstack([known, novel])),
                          rec.known(np.vstack([known, novel])))


def test_unknown_score_name_is_rejected(fitted):
    rec, known, _ = fitted
    with pytest.raises(ValueError):
        rec.p_values(known, score="nonsense")
