"""Open-set recognition: let the classifier say "I have not seen this before".

The supervised models in this project are closed-set. ``predict_proba`` is a
distribution over the eight classes the training data contained, so whatever
arrives is forced into one of them. The cross-dataset run shows what that costs:
on UNSW-NB15 every attack category is confidently reported as Benign
(``reports/CROSS_DATASET.md``). The model has no way to express that a flow lies
outside everything it was taught.

This module adds that way. It is a geometric test layered on top of the
classifier, not a replacement for it.

Method
------
1. **A metric.** Each class is summarised by its mean and a covariance estimated
   with Ledoit-Wolf shrinkage, in the scaled feature space the models already
   see (``signed_log1p`` then standardisation). Shrinkage matters because the
   classes are very unevenly sized: Bot has 977 training flows against 59
   features, where a raw sample covariance is singular. Averaging the class
   precisions gives one global shape whose Cholesky-like factor (``whitener``)
   turns that Mahalanobis metric into plain Euclidean distance, so everything
   downstream can use ordinary distances.

2. **A non-conformity score.** Two are implemented, and the choice between them
   is the single most consequential decision in this module:

   * ``gaussian``: Mahalanobis distance to the class mean. One ellipsoid per
     class.
   * ``knn``: distance to the k-th nearest training flow of that class, in the
     whitened metric. A local density estimate.

   The ``knn`` score is the default, and the reason is measured, not assumed.
   CIC-IDS2017 benign traffic is strongly multi-modal: idle connections, DNS
   lookups, web browsing and bulk transfers are separate clouds, and a single
   Gaussian fitted to all of them describes an ellipsoid that covers the empty
   space between the clouds as well. Under the ``gaussian`` score, UNSW-NB15
   attack flows land at a median p-value of 0.52 against Benign, which is to say
   perfectly ordinary benign traffic, and nothing is ever rejected. Under
   ``knn`` the same flows sit at four times the 10-NN distance of real benign
   flows. ``src.models.openset_eval`` reports both so the gap is on the record.

3. **Conformal calibration.** A raw score is not comparable between classes,
   because the classes have different spreads, so each score is turned into a
   p-value against held-out flows of the same class:

       p_c(x) = (1 + #{i in cal_c : s_c(x_i) >= s_c(x)}) / (n_cal_c + 1)

   The metric and the reference flows come from the training split and the
   calibration scores from the validation split, which are disjoint, so this is
   a valid conformal p-value: for a genuine member of class ``c``, p_c is
   approximately uniform on (0, 1].

4. **Decision.** A flow is *known* if any class accepts it at level ``alpha``:

       known(x)  <=>  max_c p_c(x) >= alpha

   The conformal property gives alpha a direct operational meaning rather than
   being a tuned number: on traffic that really does belong to a known class,
   the expected share routed to the unknown path is alpha. The measured rates
   track it closely: 0.0093 at alpha 0.01, 0.0481 at 0.05 and 0.0975 at 0.1, on
   the held-out test split.

A rejected flow is not an alert on its own, and this is what makes alpha
affordable. It goes to ``src.detection.discovery``, which groups rejected flows
into recurring families and only names one once it recurs. The benign tail that
alpha lets through is scattered, so it forms no cluster and raises nothing; a
novel attack repeats, so it does. The operator sees "NETRA-U001, 47 flows,
nearest known family DoS-Slow" instead of "Anomaly (unknown)".

References: Lee et al. (2018) for the class-conditional Gaussian score, Papernot
and McDaniel (2018) for nearest-neighbour non-conformity, Vovk et al. (2005) for
conformal p-values.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.covariance import LedoitWolf

from src import config

log = logging.getLogger(__name__)

# Default conformal significance level: the share of genuine known-class traffic
# routed to the unknown path. This is a routing decision, not an alert, so it is
# set for recall of novel traffic rather than precision. At 0.01 the measured
# share of held-out novel attack flows rejected is 0.55 for DoS-Slow and near
# zero for PortScan and Bot; at 0.05 it is 0.98 and 0.39, for a measured cost of
# 4.8% of known flows entering the discovery funnel, where scattered benign tail
# flows do not form a cluster and so never produce an alert. The whole curve is
# in reports/OPENSET.md.
DEFAULT_ALPHA = 0.05
SCORES = ("knn", "gaussian")
DEFAULT_SCORE = "knn"
# Neighbours used by the knn score. 10 is far enough from 1 to ignore a single
# duplicate flow and close enough to stay local.
DEFAULT_K = 10
# Reference flows kept per class for the knn score. The score is brute-forced
# with one matrix product per batch, so this bounds both the artifact size and
# the per-batch cost: 4000 x 59 is 0.9 MB per class and about 0.1 s per 2000
# flows scored.
#
# It also coarsens the density estimate, unevenly. Benign has 400,000 training
# flows, so 4000 references describe a large and diverse region with 1% of what
# is available, and its measured 10-NN calibration median is 19.8 against 0.15
# for WebAttack, whose 1500 flows are all kept. Conformal validity is unaffected,
# because the calibration scores are computed against the same references, but
# the shape of the benign acceptance region is approximate. Raising this is the
# first thing to try if the weaker per-class AUCs in reports/OPENSET.md matter.
MAX_REFERENCE = 4000
# Ridge added to a shrunk covariance before inversion, in units of its mean
# diagonal. Guards against a class whose features are constant in training.
RIDGE = 1e-6
# Below this many calibration flows the p-value grid is too coarse to resolve
# alpha (the smallest p-value available is 1/(n+1)), so the class is flagged.
MIN_CALIBRATION = 50
# Rows per chunk when brute-forcing knn distances, to bound peak memory.
CHUNK = 4096


def artifact_path(kind: str):
    """Where the fitted recogniser for a feature set is stored."""
    return config.MODELS_DIR / f"openset_{kind}.joblib"


class OpenSetRecognizer:
    """Conformal open-set test over class-conditional non-conformity scores."""

    def __init__(self, classes, means, precisions, whitener, reference, calibration,
                 alpha=DEFAULT_ALPHA, k=DEFAULT_K, score=DEFAULT_SCORE, features=None,
                 kind="full", meta=None):
        self.classes = list(classes)
        self.means = np.asarray(means, dtype=np.float64)              # (C, F)
        self.precisions = np.asarray(precisions, dtype=np.float64)    # (C, F, F)
        self._whitener = np.asarray(whitener, dtype=np.float64)       # (F, F)
        # Pre-whitened reference flows per class, for the knn score.
        self.reference = [np.asarray(r, dtype=np.float32) for r in reference]
        self._ref_sq = [np.einsum("ij,ij->i", r, r) for r in self.reference]
        # calibration[score][class] = sorted ascending non-conformity scores.
        self.calibration = {s: [np.asarray(c, dtype=np.float64) for c in calibration[s]]
                            for s in calibration}
        self.alpha = float(alpha)
        self.k = int(k)
        self.score_name = score
        self.features = list(features or [])
        self.kind = kind
        self.meta = dict(meta or {})

    # -- fitting --------------------------------------------------------------
    @classmethod
    def fit(cls, X_fit, y_fit, X_cal, y_cal, classes, alpha=DEFAULT_ALPHA, k=DEFAULT_K,
            score=DEFAULT_SCORE, features=None, kind="full",
            max_reference=MAX_REFERENCE) -> "OpenSetRecognizer":
        """Fit the metric and reference flows on one split, calibrate on another.

        ``X_fit``/``X_cal`` are scaled feature matrices and ``y_fit``/``y_cal``
        the matching integer labels. The two splits must be disjoint for the
        p-values to be valid; in practice they are the train and validation
        splits. Both score types are calibrated, so the choice can be changed
        later without refitting.
        """
        X_fit = np.asarray(X_fit, dtype=np.float64)
        X_cal = np.asarray(X_cal, dtype=np.float64)
        y_fit = np.asarray(y_fit)
        y_cal = np.asarray(y_cal)
        n_features = X_fit.shape[1]
        rng = np.random.default_rng(config.RANDOM_STATE)

        means = np.zeros((len(classes), n_features))
        precisions = np.zeros((len(classes), n_features, n_features))
        shrinkage = {}
        for i, name in enumerate(classes):
            rows = X_fit[y_fit == i]
            if len(rows) < 2:
                raise ValueError(f"class {name} has {len(rows)} fitting rows, need at least 2")
            means[i] = rows.mean(axis=0)
            cov = LedoitWolf(assume_centered=False).fit(rows)
            sigma = cov.covariance_ + np.eye(n_features) * (
                RIDGE * float(np.mean(np.diag(cov.covariance_))) + np.finfo(float).tiny)
            precisions[i] = np.linalg.pinv(sigma)
            shrinkage[name] = round(float(cov.shrinkage_), 4)

        whitener = _whitener_from(precisions)

        # Reference flows for the knn score: a fixed random subsample per class.
        reference, per_class = [], {}
        for i, name in enumerate(classes):
            rows = X_fit[y_fit == i]
            if len(rows) > max_reference:
                rows = rows[rng.choice(len(rows), max_reference, replace=False)]
            reference.append((rows @ whitener.T).astype(np.float32))
            per_class[name] = {
                "fit_rows": int((y_fit == i).sum()),
                "reference_rows": int(len(rows)),
                "calibration_rows": int((y_cal == i).sum()),
                "shrinkage": shrinkage[name],
                "sufficient_calibration": bool((y_cal == i).sum() >= MIN_CALIBRATION),
            }
            if per_class[name]["calibration_rows"] < MIN_CALIBRATION:
                n = per_class[name]["calibration_rows"]
                log.warning("class %s has only %d calibration flows; its smallest p-value is %.3f",
                            name, n, 1.0 / (n + 1))

        rec = cls(classes, means, precisions, whitener, reference,
                  {s: [np.array([])] * len(classes) for s in SCORES},
                  alpha=alpha, k=k, score=score, features=features, kind=kind)

        # Calibrate every score type, so switching needs no refit.
        for s in SCORES:
            cal = []
            for i, name in enumerate(classes):
                rows = X_cal[y_cal == i]
                if not len(rows):
                    cal.append(np.array([]))
                    continue
                cal.append(np.sort(rec._nonconformity(rows, s, which=[i])[:, 0]))
                per_class[name][f"{s}_calibration_median"] = round(float(np.median(cal[-1])), 4)
            rec.calibration[s] = cal

        rec.meta = {
            "kind": kind, "alpha": float(alpha), "score": score, "k": int(k),
            "n_features": int(n_features), "fit_rows": int(len(X_fit)),
            "calibration_rows": int(len(X_cal)),
            "metric": "Euclidean in the space whitened by the mean class precision",
            "covariance": "Ledoit-Wolf shrinkage, per class",
            "scores_calibrated": list(SCORES), "per_class": per_class,
        }
        return rec

    # -- scoring --------------------------------------------------------------
    def _nonconformity(self, X, score: str, which=None) -> np.ndarray:
        """Non-conformity of every row against the classes in ``which``.

        Shape (n, len(which)); ``which`` defaults to every class. Calibration
        only ever needs one column, and computing just that column is eight
        times less work on the 279,000 benign validation flows.
        """
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        which = list(range(len(self.classes))) if which is None else list(which)
        if score == "gaussian":
            out = np.empty((len(X), len(which)))
            for col, i in enumerate(which):
                out[:, col] = _mahalanobis(X, self.means[i], self.precisions[i])
            return out
        if score == "knn":
            return self._knn_distance(X @ self._whitener.T, which)
        raise ValueError(f"score must be one of {SCORES}, got {score!r}")

    def _knn_distance(self, Z, which) -> np.ndarray:
        """Distance from each whitened row to the k-th nearest reference flow
        of each requested class, brute-forced in chunks."""
        Z = np.asarray(Z, dtype=np.float32)
        out = np.empty((len(Z), len(which)), dtype=np.float64)
        for start in range(0, len(Z), CHUNK):
            z = Z[start:start + CHUNK]
            z_sq = np.einsum("ij,ij->i", z, z)
            for col, i in enumerate(which):
                ref = self.reference[i]
                # Squared Euclidean distance without materialising differences.
                d2 = z_sq[:, None] - 2.0 * (z @ ref.T) + self._ref_sq[i][None, :]
                np.clip(d2, 0.0, None, out=d2)
                k = min(self.k, d2.shape[1])
                part = np.partition(d2, k - 1, axis=1)[:, k - 1]
                out[start:start + len(z), col] = np.sqrt(part)
        return out

    def nonconformity(self, X, score: str | None = None) -> np.ndarray:
        return self._nonconformity(X, score or self.score_name)

    def p_values(self, X, score: str | None = None) -> np.ndarray:
        """Conformal p-value of every row under every class. Shape (n, C)."""
        score = score or self.score_name
        s = self._nonconformity(X, score)
        p = np.empty_like(s)
        for i, cal in enumerate(self.calibration[score]):
            n = len(cal)
            if n == 0:
                p[:, i] = 0.0
                continue
            # #{cal >= s} = n - searchsorted(cal, s, side="left")
            ge = n - np.searchsorted(cal, s[:, i], side="left")
            p[:, i] = (1.0 + ge) / (n + 1.0)
        return p

    def score(self, X, score: str | None = None, alpha: float | None = None) -> dict:
        """Open-set verdict for a batch.

        Returns ``p`` (the whole p-value matrix), ``p_max``, ``nearest`` (the
        index of the most accepting class), ``nearest_class`` (its name) and
        ``known`` (p_max >= alpha).
        """
        alpha = self.alpha if alpha is None else alpha
        p = self.p_values(X, score)
        nearest = p.argmax(axis=1)
        p_max = p[np.arange(len(p)), nearest]
        return {"p": p, "p_max": p_max, "nearest": nearest,
                "nearest_class": [self.classes[i] for i in nearest],
                "known": p_max >= alpha}

    def thresholds(self, score: str | None = None, alpha: float | None = None) -> np.ndarray:
        """Non-conformity score above which each class rejects a flow.

        The p-value test ``p_c(x) >= alpha`` is equivalent to comparing the raw
        score against a fixed per-class quantile of the calibration scores, so
        the accept/reject decision needs no p-value at all. ``test_openset.py``
        checks the two agree exactly. The engine uses this form because it can
        then stop at the first class that accepts the flow.
        """
        score = score or self.score_name
        alpha = self.alpha if alpha is None else alpha
        out = np.empty(len(self.classes))
        for i, cal in enumerate(self.calibration[score]):
            n = len(cal)
            if n == 0:
                out[i] = -np.inf          # a class with no calibration never accepts
                continue
            m = int(np.floor(n + 1 - alpha * (n + 1)))
            out[i] = cal[m] if m < n else np.inf
        return out

    def known(self, X, score: str | None = None, alpha: float | None = None) -> np.ndarray:
        """Accept/reject only, stopping at the first class that accepts.

        Equivalent to ``score(X)["known"]`` but much cheaper on live traffic:
        classes are tried largest first, so an ordinary benign flow is resolved
        after one class instead of eight.
        """
        score = score or self.score_name
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        t = self.thresholds(score, alpha)
        out = np.zeros(len(X), dtype=bool)
        todo = np.arange(len(X))
        for i in self._check_order():
            if not len(todo):
                break
            s = self._nonconformity(X[todo], score, which=[i])[:, 0]
            accepted = s <= t[i]
            out[todo[accepted]] = True
            todo = todo[~accepted]
        return out

    def _check_order(self) -> list[int]:
        """Classes ordered by calibration size, so the commonest is tried first."""
        return sorted(range(len(self.classes)),
                      key=lambda i: -len(self.calibration[self.score_name][i]))

    def is_known(self, X) -> np.ndarray:
        return self.known(X)

    def whiten(self, X) -> np.ndarray:
        """Project scaled features into the metric space used for clustering."""
        return np.atleast_2d(np.asarray(X, dtype=np.float64)) @ self._whitener.T

    @property
    def whitener(self) -> np.ndarray:
        return self._whitener

    # -- persistence ----------------------------------------------------------
    def save(self, path=None) -> None:
        path = Path(path) if path is not None else artifact_path(self.kind)
        joblib.dump({
            "classes": self.classes, "means": self.means, "precisions": self.precisions,
            "whitener": self._whitener, "reference": self.reference,
            "calibration": self.calibration, "alpha": self.alpha, "k": self.k,
            "score": self.score_name, "features": self.features, "kind": self.kind,
            "meta": self.meta,
        }, path, compress=3)
        # The readable metadata sits beside the artifact, wherever that is.
        path.with_name(f"{path.stem}_meta.json").write_text(json.dumps(self.meta, indent=2))

    @classmethod
    def load(cls, kind: str = "full", path=None) -> "OpenSetRecognizer":
        d = joblib.load(path or artifact_path(kind))
        return cls(d["classes"], d["means"], d["precisions"], d["whitener"], d["reference"],
                   d["calibration"], alpha=d["alpha"], k=d["k"], score=d["score"],
                   features=d["features"], kind=d["kind"], meta=d["meta"])


def _whitener_from(precisions) -> np.ndarray:
    """Matrix W with Euclidean distance in ``x @ W.T`` equal to Mahalanobis
    distance under the mean class precision."""
    pooled = np.asarray(precisions, dtype=np.float64).mean(axis=0)
    pooled = (pooled + pooled.T) / 2.0
    vals, vecs = np.linalg.eigh(pooled)
    vals = np.clip(vals, 0.0, None)
    return (vecs * np.sqrt(vals)).T


def _mahalanobis(X, mean, precision) -> np.ndarray:
    """Mahalanobis distance of each row of X to one centroid."""
    X = np.atleast_2d(np.asarray(X, dtype=np.float64))
    delta = X - mean
    sq = np.einsum("ij,jk,ik->i", delta, precision, delta)
    return np.sqrt(np.clip(sq, 0.0, None))


def fit_from_splits(kind: str = "full", alpha: float = DEFAULT_ALPHA, k: int = DEFAULT_K,
                    score: str = DEFAULT_SCORE) -> OpenSetRecognizer:
    """Fit on the train split, calibrate on the validation split and save."""
    from src.data.preprocess import load_feature_spec
    from src.models.train_supervised import load_xy

    spec = load_feature_spec()
    features = spec["features"] if kind == "full" else spec["lite_features"]
    X_fit, y_fit, _ = load_xy("train", kind)
    X_cal, y_cal, _ = load_xy("val", kind)
    rec = OpenSetRecognizer.fit(X_fit, y_fit, X_cal, y_cal, spec["classes"], alpha=alpha, k=k,
                                score=score, features=features, kind=kind)
    rec.save()
    log.info("[%s] open-set recogniser fitted on %d flows, calibrated on %d, score %s, alpha %.3f",
             kind, len(X_fit), len(X_cal), score, alpha)
    return rec
