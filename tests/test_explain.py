"""Tests for per-alert explanations (src/models/explain.py).

The central property is exactness: the feature contributions plus the bias must
reproduce the model's own predict_proba. If that holds, the explanation is a
faithful decomposition of the prediction and not a plausible-looking guess.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from src.models.explain import Explainer, describe

FEATURES = ["duration", "packets_per_s", "bytes_per_s", "mean_size"]


@pytest.fixture(scope="module")
def forest():
    """A small forest on separable synthetic traffic: class 1 is fast and small."""
    rng = np.random.default_rng(0)
    n = 400
    benign = np.column_stack([rng.normal(5, 1, n), rng.normal(10, 2, n),
                              rng.normal(900, 50, n), rng.normal(120, 10, n)])
    attack = np.column_stack([rng.normal(5, 1, n), rng.normal(900, 40, n),
                              rng.normal(950, 50, n), rng.normal(44, 4, n)])
    X = np.vstack([benign, attack]).astype(np.float32)
    y = np.array([0] * n + [1] * n)
    model = RandomForestClassifier(n_estimators=25, random_state=0, min_samples_leaf=2)
    model.fit(X, y)
    return model, X, y


def test_contributions_reproduce_predict_proba(forest):
    """bias + sum(contributions) must equal predict_proba exactly."""
    model, X, _ = forest
    ex = Explainer(model, FEATURES)
    assert ex.available

    rows = X[::37]
    proba = model.predict_proba(rows)
    for i, row in enumerate(rows):
        contrib, bias = ex.contributions(row)
        assert contrib.shape == (len(FEATURES), model.n_classes_)
        reconstructed = bias + contrib.sum(axis=0)
        np.testing.assert_allclose(reconstructed, proba[i], atol=1e-9)


def test_explain_picks_the_discriminating_feature(forest):
    """On this data the attack class is defined by packet rate and size."""
    model, X, y = forest
    ex = Explainer(model, FEATURES)
    attack_row = X[y == 1][0]
    top = ex.explain(attack_row, class_idx=1, top_k=2)
    assert top, "expected at least one contributing feature"
    named = {e["feature"] for e in top}
    assert named & {"packets_per_s", "mean_size"}
    # Contributions towards the predicted class are positive and ranked.
    shares = [e["share"] for e in top]
    assert all(s > 0 for s in shares)
    assert shares == sorted(shares, reverse=True)


def test_explain_reports_raw_values(forest):
    model, X, y = forest
    ex = Explainer(model, FEATURES)
    row = X[y == 1][0]
    raw = dict(zip(FEATURES, [1.0, 950.0, 1000.0, 44.0]))
    top = ex.explain(row, class_idx=1, raw=raw, top_k=4)
    for e in top:
        assert "value" in e
        assert e["value"] == pytest.approx(raw[e["feature"]], rel=1e-6)


def test_unsupported_model_degrades_quietly():
    """A non-tree model must not raise; it simply has no explanation."""
    rng = np.random.default_rng(1)
    X = rng.normal(size=(50, len(FEATURES)))
    y = (X[:, 1] > 0).astype(int)
    ex = Explainer(LogisticRegression().fit(X, y), FEATURES)
    assert ex.available is False
    assert ex.explain(X[0], class_idx=1) == []
    assert ex.global_importance() == []


def test_global_importance_is_sorted(forest):
    model, _, _ = forest
    ex = Explainer(model, FEATURES)
    imp = ex.global_importance(top_k=4)
    assert len(imp) == 4
    values = [e["importance"] for e in imp]
    assert values == sorted(values, reverse=True)


def test_describe_is_readable(forest):
    assert describe([]) == ""
    text = describe([{"feature": "packets_per_s", "value": 950.0},
                     {"feature": "mean_size", "value": 44.0}])
    assert text == "driven by packets_per_s=950.0, mean_size=44.0"


def test_non_finite_values_do_not_break_formatting(forest):
    model, X, y = forest
    ex = Explainer(model, FEATURES)
    raw = dict(zip(FEATURES, [np.inf, np.nan, 1e9, 44.0]))
    top = ex.explain(X[y == 1][0], class_idx=1, raw=raw, top_k=4)
    for e in top:
        if "value" in e:
            assert np.isfinite(float(e["value"]))
