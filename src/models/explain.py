"""Per-alert explanations: which features drove a Random Forest prediction.

A detection that cannot be explained is hard to act on and hard to trust. This
module answers "why was this flow called an attack?" for the supervised models,
by attributing the predicted probability to individual features.

Method. For one decision tree, following a sample from the root to its leaf
passes through a sequence of nodes, and each node holds the class distribution
of the training samples that reached it. Moving from a parent to a child changes
that distribution, and the change is caused by exactly one feature: the one the
parent splits on. Summing those changes along the path decomposes the tree's
output into a bias term (the root distribution) plus one contribution per
feature. Averaging over the trees in the forest gives the same decomposition for
the whole model:

    predict_proba(x)[c] = bias[c] + sum over features of contribution[f][c]

This is exact, not an approximation, and it is the decomposition described by
Saabas and used by the ``treeinterpreter`` package. It is implemented here
directly so the detection container needs no extra dependency, and
``tests/test_explain.py`` checks it reproduces ``predict_proba``.

Only tree ensembles with this structure are supported. For any other estimator
``Explainer.available`` is False and the engine omits the explanation rather
than guessing.
"""

from __future__ import annotations

import logging

import numpy as np

log = logging.getLogger(__name__)

# Contributions below this share of the total positive push are noise, not signal.
MIN_SHARE = 0.01


class Explainer:
    """Exact per-prediction feature attribution for a Random Forest classifier."""

    def __init__(self, model, feature_names: list[str]):
        self.model = model
        self.features = list(feature_names)
        self.available = hasattr(model, "estimators_") and hasattr(model, "n_classes_")
        if not self.available:
            log.info("explanations unavailable for %s (not a tree ensemble)", type(model).__name__)
            self.n_classes = 0
            self._trees = []
            return
        self.n_classes = int(model.n_classes_)
        # Flatten each tree once, so explaining a flow does no attribute lookups.
        self._trees = []
        for est in model.estimators_:
            t = est.tree_
            value = np.asarray(t.value, dtype=np.float64).reshape(t.node_count, -1)
            totals = value.sum(axis=1, keepdims=True)
            # sklearn >= 1.3 stores normalised fractions; older versions store counts.
            value = np.divide(value, totals, out=np.zeros_like(value), where=totals > 0)
            self._trees.append((
                np.asarray(t.feature),
                np.asarray(t.threshold, dtype=np.float64),
                np.asarray(t.children_left),
                np.asarray(t.children_right),
                value,
            ))

    def contributions(self, x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Attribution for one scaled feature vector.

        Returns ``(contributions, bias)``, where contributions has shape
        (n_features, n_classes) and ``bias + contributions.sum(axis=0)``
        reproduces ``model.predict_proba([x])[0]``.
        """
        x = np.asarray(x, dtype=np.float64).ravel()
        contrib = np.zeros((len(self.features), self.n_classes), dtype=np.float64)
        bias = np.zeros(self.n_classes, dtype=np.float64)
        if not self._trees:
            return contrib, bias

        for feature, threshold, left, right, value in self._trees:
            bias += value[0]
            node = 0
            while feature[node] >= 0:                       # a leaf is marked -2
                f = int(feature[node])
                nxt = int(left[node]) if x[f] <= threshold[node] else int(right[node])
                contrib[f] += value[nxt] - value[node]
                node = nxt
        n = len(self._trees)
        return contrib / n, bias / n

    def explain(self, x: np.ndarray, class_idx: int, raw: dict | None = None,
                top_k: int = 4) -> list[dict]:
        """The ``top_k`` features that pushed this prediction towards ``class_idx``.

        ``raw`` optionally maps feature name to unscaled value, so the
        explanation can quote the number a human would recognise rather than a
        standardised one.
        """
        if not self.available:
            return []
        contrib, _ = self.contributions(x)
        col = contrib[:, class_idx]
        total = float(col[col > 0].sum())
        if total <= 0:
            return []
        out = []
        for i in np.argsort(-col)[:top_k]:
            c = float(col[i])
            if c <= 0 or c / total < MIN_SHARE:
                continue
            name = self.features[int(i)]
            item = {"feature": name, "contribution": round(c, 4), "share": round(c / total, 3)}
            if raw is not None and name in raw:
                item["value"] = _round(raw[name])
            out.append(item)
        return out

    def global_importance(self, top_k: int = 10) -> list[dict]:
        """Overall feature importance of the forest, for the model status panel."""
        if not self.available or not hasattr(self.model, "feature_importances_"):
            return []
        imp = np.asarray(self.model.feature_importances_, dtype=float)
        return [{"feature": self.features[int(i)], "importance": round(float(imp[i]), 4)}
                for i in np.argsort(-imp)[:top_k]]


def _round(v):
    """Present a feature value the way a person would read it."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return v
    if not np.isfinite(f):
        return 0.0
    return round(f, 3) if abs(f) < 1000 else int(round(f))


def describe(explanation: list[dict]) -> str:
    """One human-readable clause for the alert description and the log."""
    if not explanation:
        return ""
    parts = [f"{e['feature']}={e['value']}" if "value" in e else e["feature"]
             for e in explanation]
    return "driven by " + ", ".join(parts)
