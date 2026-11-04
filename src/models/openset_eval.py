"""Measure the open-set layer. Three experiments, all on held-out data.

**1. Conformal validity (`known_rejection`).** On the ordinary test split, every
flow belongs to a class the recogniser was fitted on, so the share it rejects is
pure cost: traffic sent to the unknown path for no reason. The conformal
construction promises that share is at most ``alpha``. This measures it, per
class, for both non-conformity scores.

**2. Zero-day detection (`leave_one_class_out`).** One attack class is removed
from training, scaling, calibration and the open-set fit, then its test flows
are replayed. Nothing in the fold has ever seen that attack, so it stands in for
a genuinely novel one. The question is not whether it is classified correctly,
which is impossible, but whether the system admits it does not recognise it:

* The closed-set baseline is the Random Forest the project already uses. Its
  softmax has no "none of these" option, so the held-out attack is absorbed into
  whichever class is nearest, and when that class is Benign the attack passes in
  silence.
* The open-set layer can reject it. ``unknown_rate`` is the share rejected.
* ``surfaced_rate`` is the honest bottom line: the share of held-out flows the
  operator would see at all, either because the open-set layer rejected them or
  because the classifier flagged them as some attack, correct name or not.

Each fold refits the scaler, the classifier and the recogniser on its own seven
classes, so the held-out class leaks nowhere, not even through feature scaling.

**3. Domain shift (`domain_shift`).** The same test on UNSW-NB15, a different
network entirely. Here the open-set layer is not being asked to find individual
attacks; the lite feature set provably cannot do that, because UNSW attack flows
sit inside the CIC benign cloud (``reports/CROSS_DATASET.md`` has the feature
medians). It is being asked whether it notices that the whole network is unlike
anything it was trained on. The in-domain unknown rate is the reference point:
anything far above ``alpha`` means the sensor is reporting, correctly, that it is
out of its depth, which is a thing a closed-set softmax cannot express at all.
"""

from __future__ import annotations

import json
import logging
import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from src import config
from src.models.openset import DEFAULT_ALPHA, SCORES, OpenSetRecognizer

log = logging.getLogger(__name__)

RESULT_PATH = config.REPORTS_DIR / "openset.json"
# Known-class test flows sampled when measuring the rejection rate of a fold.
# The full split is 329,000 flows and each fold refits everything, so a sample
# keeps the sweep to minutes while leaving the estimate tight: at 25,000 flows
# the standard error on a rate near 0.05 is 0.0014. Section 1 of the report
# measures the same quantity on the whole split without sampling.
KNOWN_SAMPLE = 25_000
# Significance levels the per-fold operating curve is reported at. alpha is a
# dial with an exact meaning, so the honest result is the whole curve, not one
# point on it.
ALPHA_CURVE = (0.01, 0.02, 0.05, 0.10, 0.25, 0.50)


# ---------------------------------------------------------------------------
# 1. Conformal validity on known classes
# ---------------------------------------------------------------------------
def known_rejection(kind: str = "full", alpha: float | None = None) -> dict:
    """Rejection rate on the test split, where every flow is of a known class."""
    from src.models.train_supervised import load_xy

    rec = OpenSetRecognizer.load(kind)
    alpha = rec.alpha if alpha is None else alpha
    X, y, _ = load_xy("test", kind)
    out = {"kind": kind, "alpha": alpha, "test_flows": int(len(X)), "scores": {}}
    for score in SCORES:
        start = time.time()
        rejected = ~rec.known(X, score=score, alpha=alpha)
        out["scores"][score] = {
            "rejection_rate": float(rejected.mean()),
            "within_alpha": bool(rejected.mean() <= alpha),
            "seconds": round(time.time() - start, 1),
            "per_class": {name: float(rejected[y == i].mean())
                          for i, name in enumerate(rec.classes)},
        }
        log.info("[%s] %s rejection on known flows %.4f (alpha %.3f)",
                 kind, score, rejected.mean(), alpha)
    return out


# ---------------------------------------------------------------------------
# 2. Leave one class out
# ---------------------------------------------------------------------------
class Fold:
    """Everything refitted without one class, so that class is genuinely novel.

    The scaler is refitted too, not only the models, so the held-out class
    reaches the fold through no route at all, not even feature scaling. Shared
    with ``src.models.discovery_eval``, which clusters what this rejects.
    """

    def __init__(self, held_out: str, kind: str = "full", alpha: float = DEFAULT_ALPHA,
                 score: str = "knn", with_forest: bool = True):
        from src.data.preprocess import CLASS_COLUMN, load_feature_spec, load_split, make_scaler

        spec = load_feature_spec()
        self.held_out = held_out
        self.kind = kind
        self.alpha = alpha
        self.score = score
        self.cols = spec["features"] if kind == "full" else spec["lite_features"]
        self.train, self.val, self.test = (load_split(s) for s in ("train", "val", "test"))
        self.class_column = CLASS_COLUMN

        keep_train = (self.train[CLASS_COLUMN] != held_out).to_numpy()
        keep_val = (self.val[CLASS_COLUMN] != held_out).to_numpy()
        self.classes = [c for c in spec["classes"] if c != held_out]
        self.encoder = LabelEncoder().fit(self.classes)
        self.scaler = make_scaler().fit(self.train.loc[keep_train, self.cols].to_numpy(np.float64))

        X_tr = self.scaled(self.train, keep_train)
        y_tr = self.encoder.transform(self.train.loc[keep_train, CLASS_COLUMN])
        X_va = self.scaled(self.val, keep_val)
        y_va = self.encoder.transform(self.val.loc[keep_val, CLASS_COLUMN])

        start = time.time()
        self.rec = OpenSetRecognizer.fit(X_tr, y_tr, X_va, y_va, self.classes, alpha=alpha,
                                         score=score, features=self.cols, kind=kind)
        self.forest = None
        if with_forest:
            self.forest = RandomForestClassifier(
                n_estimators=100, max_features="sqrt", min_samples_leaf=2,
                class_weight="balanced_subsample", n_jobs=-1,
                random_state=config.RANDOM_STATE).fit(X_tr, y_tr)
        self.fit_seconds = time.time() - start

    def scaled(self, df, mask=None) -> np.ndarray:
        rows = df if mask is None else df[mask]
        return self.scaler.transform(rows[self.cols].to_numpy(np.float64)).astype(np.float32)

    def scaled_rows(self, idx) -> np.ndarray:
        return self.scaler.transform(
            self.test.iloc[idx][self.cols].to_numpy(np.float64)).astype(np.float32)


def _fold(held_out: str, kind: str, alpha: float, score: str, rng) -> dict:
    """One fold of the leave-one-class-out sweep."""
    fold = Fold(held_out, kind=kind, alpha=alpha, score=score)
    rec, forest, test = fold.rec, fold.forest, fold.test
    CLASS_COLUMN, encoder, scaler, cols = (fold.class_column, fold.encoder, fold.scaler, fold.cols)
    fit_s = fold.fit_seconds

    def scaled(df, mask=None):
        return fold.scaled(df, mask)

    # The held-out class, which this fold has never seen.
    novel = (test[CLASS_COLUMN] == held_out).to_numpy()
    X_novel = scaled(test, novel)
    # Known classes in the same fold, to confirm alpha still holds without it.
    known_rows = (test[CLASS_COLUMN] != held_out).to_numpy()
    idx = np.where(known_rows)[0]
    if len(idx) > KNOWN_SAMPLE:
        idx = rng.choice(idx, KNOWN_SAMPLE, replace=False)
    X_known = scaler.transform(test.iloc[idx][cols].to_numpy(np.float64)).astype(np.float32)

    # p_max is computed once per group and thresholded at every alpha, which is
    # both faster than one pass per alpha and the only way to get the curve.
    p_novel = rec.score(X_novel, score=score)["p_max"]
    p_known = rec.score(X_known, score=score)["p_max"]
    unknown = p_novel < alpha
    known_rejected = p_known < alpha
    curve = [{"alpha": a,
              "unknown_rate": float((p_novel < a).mean()),
              "known_rejection_rate": float((p_known < a).mean())}
             for a in ALPHA_CURVE]

    proba = forest.predict_proba(X_novel)
    pred = proba.argmax(axis=1)
    conf = proba.max(axis=1)
    benign_idx = int(np.where(encoder.classes_ == config.BENIGN_LABEL)[0][0])
    flagged = (pred != benign_idx) & (conf >= config.SUPERVISED_MIN_CONFIDENCE)
    names, counts = np.unique(pred, return_counts=True)
    absorbed = sorted(zip(counts.tolist(), encoder.inverse_transform(names).tolist()), reverse=True)

    result = {
        "held_out": held_out,
        "novel_flows": int(novel.sum()),
        "novelty_auc": _auc(p_known, p_novel),
        "unknown_rate": float(unknown.mean()),
        "closed_set_called_benign": float((pred == benign_idx).mean()),
        "closed_set_flagged_as_attack": float(flagged.mean()),
        "surfaced_rate": float((unknown | flagged).mean()),
        # Silence is the share of the attack an operator would never see. Before
        # this layer that is everything the classifier did not flag, which is
        # more than the share it called Benign: a flow predicted as an attack
        # below the alert confidence is just as invisible. The two fields are
        # defined to be directly comparable.
        "silent_before": float(1.0 - flagged.mean()),
        "silent_after": float(1.0 - (unknown | flagged).mean()),
        "absorbed_into": [{"class": n, "share": round(c / int(novel.sum()), 4)}
                          for c, n in absorbed[:3]],
        "known_flows_sampled": int(len(idx)),
        "known_rejection_rate": float(known_rejected.mean()),
        "alpha_curve": curve,
        "fit_seconds": round(fit_s, 1),
    }
    log.info("[%s] held out %-10s n=%6d AUC=%.3f unknown=%.3f closed-set benign=%.3f "
             "surfaced=%.3f known-rejection=%.4f", kind, held_out, result["novel_flows"],
             result["novelty_auc"], result["unknown_rate"],
             result["closed_set_called_benign"], result["surfaced_rate"],
             result["known_rejection_rate"])
    return result


def _auc(p_known, p_novel) -> float:
    """Probability that a novel flow gets a lower p-value than a known one.

    This is the rank statistic behind the whole alpha curve: it says how well
    the non-conformity score separates novel traffic from known traffic,
    independently of where the threshold is put. Ties count as half, so a score
    with no information gives 0.5. Computed by rank rather than by the outer
    product, which would need a matrix of len(known) x len(novel) entries.
    """
    p_known = np.asarray(p_known, dtype=np.float64)
    p_novel = np.asarray(p_novel, dtype=np.float64)
    n_k, n_n = len(p_known), len(p_novel)
    if not n_k or not n_n:
        return float("nan")
    both = np.concatenate([p_known, p_novel])
    order = both.argsort(kind="mergesort")
    ranks = np.empty(len(both), dtype=np.float64)
    ranks[order] = np.arange(1, len(both) + 1)
    # Average the ranks inside each group of equal values, so ties score 0.5.
    uniq, inv, counts = np.unique(both, return_inverse=True, return_counts=True)
    sums = np.zeros(len(uniq))
    np.add.at(sums, inv, ranks)
    ranks = (sums / counts)[inv]
    r_novel = ranks[n_k:].sum()
    # U counts pairs where the novel flow ranks higher, so the probability we
    # want (novel ranks lower, meaning more anomalous) is its complement.
    u = r_novel - n_n * (n_n + 1) / 2
    return float(1.0 - u / (n_k * n_n))


def leave_one_class_out(kind: str = "full", alpha: float = DEFAULT_ALPHA, score: str = "knn",
                        classes: list[str] | None = None) -> dict:
    """Hold out each attack class in turn and measure what the system does with it."""
    from src.data.preprocess import load_feature_spec

    spec = load_feature_spec()
    targets = classes or [c for c in spec["classes"] if c != config.BENIGN_LABEL]
    rng = np.random.default_rng(config.RANDOM_STATE)
    folds = [_fold(c, kind, alpha, score, rng) for c in targets]
    totals = {
        "mean_novelty_auc": float(np.mean([f["novelty_auc"] for f in folds])),
        "mean_unknown_rate": float(np.mean([f["unknown_rate"] for f in folds])),
        "mean_closed_set_called_benign": float(np.mean([f["closed_set_called_benign"] for f in folds])),
        "mean_surfaced_rate": float(np.mean([f["surfaced_rate"] for f in folds])),
        "mean_known_rejection_rate": float(np.mean([f["known_rejection_rate"] for f in folds])),
        "folds_where_closed_set_silent": int(sum(f["closed_set_called_benign"] > 0.5 for f in folds)),
        "folds_where_open_set_surfaces": int(sum(f["surfaced_rate"] > 0.5 for f in folds)),
        "mean_curve": [{
            "alpha": a,
            "unknown_rate": float(np.mean([c["unknown_rate"] for f in folds
                                           for c in f["alpha_curve"] if c["alpha"] == a])),
            "known_rejection_rate": float(np.mean([c["known_rejection_rate"] for f in folds
                                                   for c in f["alpha_curve"] if c["alpha"] == a])),
        } for a in ALPHA_CURVE],
    }
    return {"kind": kind, "alpha": alpha, "score": score, "folds": folds, "totals": totals}


# ---------------------------------------------------------------------------
# 3. Domain shift
# ---------------------------------------------------------------------------
def domain_shift(limit: int | None = None, alpha: float | None = None) -> dict:
    """Unknown rate on UNSW-NB15, a network the models were not trained on."""
    import joblib

    from src.data import unsw

    if not unsw.available():
        return {"available": False, "path": str(unsw.UNSW_PARQUET)}

    rec = OpenSetRecognizer.load("lite")
    alpha = rec.alpha if alpha is None else alpha
    df = unsw.load(limit=limit)
    X = joblib.load(config.LITE_SCALER_PATH).transform(
        df[config.LITE_FEATURES].to_numpy(np.float64)).astype(np.float32)
    is_attack = df["is_attack"].to_numpy()

    out = {"available": True, "alpha": alpha, "scored_flows": int(len(df)), "scores": {}}
    for score in SCORES:
        start = time.time()
        unknown = ~rec.known(X, score=score, alpha=alpha)
        out["scores"][score] = {
            "unknown_rate": float(unknown.mean()),
            "unknown_rate_attacks": float(unknown[is_attack].mean()),
            "unknown_rate_normal": float(unknown[~is_attack].mean()),
            "seconds": round(time.time() - start, 1),
            "per_category": {str(cat): {
                "flows": int(((df["category"] == cat).to_numpy()).sum()),
                "unknown_rate": float(unknown[(df["category"] == cat).to_numpy()].mean()),
            } for cat in sorted(df["category"].unique())},
        }
        log.info("UNSW %s unknown rate %.4f (attacks %.4f, normal %.4f)", score,
                 unknown.mean(), unknown[is_attack].mean(), unknown[~is_attack].mean())
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def run(kind: str = "full", alpha: float = DEFAULT_ALPHA, score: str = "knn",
        unsw_limit: int | None = None, skip_loco: bool = False) -> dict:
    config.ensure_dirs()
    result = {
        "alpha": alpha, "score": score, "kind": kind,
        "known_rejection": known_rejection(kind, alpha),
        "leave_one_class_out": None if skip_loco else leave_one_class_out(kind, alpha, score),
        "domain_shift": domain_shift(limit=unsw_limit, alpha=alpha),
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2))
    log.info("open-set results written to %s", RESULT_PATH)
    return result


def write_markdown(r: dict, discovery: dict | None = None) -> None:
    """Write reports/OPENSET.md from the measured results."""
    kr = r["known_rejection"]
    loco = r.get("leave_one_class_out")
    ds = r.get("domain_shift") or {}
    lines = [
        "# Open-set recognition and unknown-family discovery",
        "",
        "The classifiers in this project are closed-set: `predict_proba` is a distribution",
        "over the eight classes the training data contained, so every flow is forced into",
        "one of them. This layer adds the verdict they cannot produce, \"none of these\",",
        "and names what it finds. Generated by `python -m src.cli openset-eval`.",
        "",
        f"- Non-conformity score: **{r['score']}**, k = 10 neighbours",
        f"- Conformal significance level: **alpha = {r['alpha']}**",
        f"- Feature set: **{r['kind']}** ({kr['test_flows']:,} test flows)",
        "",
        "## 1. Is the test honest? Conformal validity on known classes",
        "",
        "Every flow in the test split belongs to a class the recogniser was fitted on, so",
        "anything it rejects is pure cost. The conformal construction promises that share",
        "is alpha, and alpha is therefore a known price rather than a tuned threshold.",
        "",
        "| Score | Rejection rate on known flows | Promised (alpha) | Within bound |",
        "|---|---|---|---|",
    ]
    for score, s in kr["scores"].items():
        lines.append(f"| {score} | {s['rejection_rate']:.4f} | {kr['alpha']} | "
                     f"{'yes' if s['within_alpha'] else 'NO'} |")
    lines += ["", "Per class, for the selected score:", "",
              "| Class | Rejected |", "|---|---|"]
    for name, v in kr["scores"][r["score"]]["per_class"].items():
        lines.append(f"| {name} | {v:.4f} |")

    if loco:
        lines += [
            "",
            "## 2. Zero-day detection: leave one class out",
            "",
            "Each row is a separate experiment in which that attack class is removed from",
            "the training data, from the feature scaling and from the open-set calibration,",
            "then its test flows are replayed. Nothing in the fold has ever seen it, so it",
            "stands in for a genuinely novel attack.",
            "",
            "- **AUC** is the probability that a novel flow is ranked more anomalous than a",
            "  known one. It does not depend on where the threshold is put.",
            "- **Closed-set -> Benign** is the share the Random Forest calls Benign, which is",
            "  the silent failure this layer exists to remove.",
            "- **Surfaced** is the share an operator would see at all: rejected as unknown, or",
            "  flagged as some attack class, right name or wrong.",
            "- **Silent** is its complement, the share of the attack nobody would ever see. The",
            "  before figure counts everything the classifier did not flag, not only what it called",
            "  Benign, because a flow predicted as an attack below the alert confidence is just as",
            "  invisible. The two columns are therefore directly comparable.",
            "",
            "| Held out | Test flows | AUC | Unknown (open-set) | Closed-set -> Benign | Surfaced | "
            "Silent before | Silent after | Known rejected |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for f in loco["folds"]:
            # Derived rather than read, so this is right for results written
            # before the two fields were defined to be comparable.
            silent_before = 1.0 - f["closed_set_flagged_as_attack"]
            silent_after = 1.0 - f["surfaced_rate"]
            lines.append(
                f"| {f['held_out']} | {f['novel_flows']:,} | {f['novelty_auc']:.3f} | "
                f"{f['unknown_rate']:.3f} | {f['closed_set_called_benign']:.3f} | "
                f"{f['surfaced_rate']:.3f} | {silent_before:.3f} | {silent_after:.3f} | "
                f"{f['known_rejection_rate']:.4f} |")
        t = loco["totals"]
        mean_before = float(np.mean([1.0 - f["closed_set_flagged_as_attack"]
                                     for f in loco["folds"]]))
        lines.append(f"| **mean** | | **{t['mean_novelty_auc']:.3f}** | "
                     f"**{t['mean_unknown_rate']:.3f}** | "
                     f"**{t['mean_closed_set_called_benign']:.3f}** | "
                     f"**{t['mean_surfaced_rate']:.3f}** | "
                     f"**{mean_before:.3f}** | "
                     f"**{1.0 - t['mean_surfaced_rate']:.3f}** | "
                     f"**{t['mean_known_rejection_rate']:.4f}** |")
        lines += [
            "",
            "### The operating curve",
            "",
            "alpha is a dial, so the honest result is the curve rather than one point on it.",
            "Averaged over the folds:",
            "",
            "| alpha | Novel flows rejected | Known flows rejected |",
            "|---|---|---|",
        ]
        for c in t["mean_curve"]:
            lines.append(f"| {c['alpha']:g} | {c['unknown_rate']:.3f} | "
                         f"{c['known_rejection_rate']:.3f} |")
        lines += [
            "",
            "The known-rejection column tracking alpha to three decimals is the conformal",
            "guarantee holding in practice. The cost of a loose alpha is bounded and known",
            "in advance, which is why this layer can afford one: a rejected flow raises no",
            "alert by itself, it only enters the clusterer below.",
            "",
            "![Open-set operating curve](openset.png)",
        ]

    if discovery:
        dt = discovery["totals"]
        lines += [
            "",
            "## 3. Are the discovered families real?",
            "",
            "The same folds, with the held-out class mixed back into ordinary traffic and the",
            "whole mixture replayed through the open-set test and the clusterer in arrival",
            "order. Ground truth is the true class of every flow the clusterer was handed,",
            "which it never sees.",
            "",
            f"- A family becomes reportable at {discovery['min_family_flows']} flows.",
            f"- Known traffic mixed in per fold: {discovery['known_mix']:,} flows.",
            "",
            "| Held out | Rejected | of those novel | Families | Reportable | Purity "
            "(class / tool) | ARI (class / tool) | Recall into one family | That family's "
            "precision | Flows to discovery | Reportable, ordinary traffic |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for f in discovery["folds"]:
            latency = f["flows_to_discovery"]
            lines.append(
                f"| {f['held_out']} | {f['rejected_flows']:,} | {f['rejected_novel']:,} | "
                f"{f['families']} | {f['families_reportable']} | "
                f"{f['purity']:.3f} / {f.get('purity_by_tool', float('nan')):.3f} | "
                f"{f['adjusted_rand_index']:.3f} / "
                f"{f.get('adjusted_rand_index_by_tool', float('nan')):.3f} | "
                f"{f['dominant_family_recall']:.3f} | "
                f"{f['dominant_family_precision']:.3f} | {latency if latency else 'n/a'} | "
                f"{f['false_alarm_families']} |")
        lines.append(f"| **mean** | | | | | **{dt['mean_purity']:.3f} / "
                     f"{dt.get('mean_purity_by_tool', float('nan')):.3f}** | "
                     f"**{dt['mean_adjusted_rand_index']:.3f} / "
                     f"{dt.get('mean_adjusted_rand_index_by_tool', float('nan')):.3f}** | "
                     f"**{dt['mean_dominant_recall']:.3f}** | "
                     f"**{dt['mean_dominant_precision']:.3f}** | "
                     f"**{dt['median_flows_to_discovery']:.0f}** | "
                     f"**{dt['total_false_alarm_families']} total** |")
        lines += [
            "",
            "**Recall into one family** is the share of the rejected novel flows that landed in",
            "the single family that best represents the attack, and **precision** is the share of",
            "that family's members that really were the novel attack. Recall below 1 is not",
            "necessarily a failure: three of the eight classes are unions of two attack tools",
            "(BruteForce is ftp-patator and ssh-patator, DoS is hulk and goldeneye, DoS-Slow is",
            "slowloris and slowhttptest), so splitting one class into several pure families is the",
            "clusterer making a distinction the label map erased. That is why purity and the",
            "adjusted Rand index are reported against the fine-grained tool labels as well.",
            "**Reportable families made of ordinary traffic** are families large enough to report",
            "whose members are mostly not the held-out attack. **Flows to discovery** is how many",
            "rejected flows had arrived before the attack's family became reportable.",
            "",
            f"The novel family was reported in {dt['folds_where_novel_family_reported']} of "
            f"{len(discovery['folds'])} folds. This is the number that matters operationally, and",
            "it is higher than the per-flow unknown rate in section 2 would suggest: an attack",
            "produces many flows and a family needs only a few of them, so a per-flow rate of 0.2",
            "still means the attack is found.",
            "",
        ]
        curve = dt.get("threshold_curve")
        if curve:
            n_folds = len(discovery["folds"])
            lines += [
                "",
                "### Choosing the reporting threshold",
                "",
                "A family is reported once it holds this many flows. The threshold is read off",
                "this curve rather than argued for, and the curve is what an earlier design got",
                "wrong: requiring a number of flows rejected at a stricter conformal level",
                "reported the novel family in 1 fold of 7 while still admitting 164 families of",
                "ordinary traffic. The p-value cannot do this job, because the routing level has",
                "already conditioned on it. Among flows that reached the clusterer, a rejected",
                "benign flow and a rejected novel flow have p-values drawn from much the same",
                "range, so the p-value adds little. Size does.",
                "",
                "| Flows to report | Novel family found | Families of ordinary traffic | "
                "Families reported in total |",
                "|---|---|---|---|",
            ]
            for c in curve:
                mark = " **(default)**" if c["min_flows"] == discovery["min_family_flows"] else ""
                lines.append(
                    f"| {c['min_flows']}{mark} | {c['folds_where_novel_family_reported']} of "
                    f"{n_folds} | {c['total_false_alarm_families']} | "
                    f"{c['total_families_reported']} |")
            lines += [
                "",
                "The families of ordinary traffic are not errors in the way a misclassification",
                "is. They are patterns the deployment has and the training data did not describe,",
                "unusual in the same way every time, which is why they cluster at all. An operator",
                "names such a family once and it stops being an unexplained alert. That is the",
                "ordinary baselining cost of any anomaly detector, and the column above measures",
                "it rather than estimating it.",
            ]
        lines += [
            "",
            "What the operator reads, taken verbatim from the clusterer:",
            "",
        ]
        for f in discovery["folds"]:
            if f["example_description"]:
                lines.append(f"- *{f['held_out']} held out*: `{f['example_description']}`")

    if ds.get("available"):
        selected = ds["scores"].get(r["score"], {})
        lines += [
            "",
            "## 4. Domain shift: a network the models were never trained on",
            "",
            f"The same test over {ds['scored_flows']:,} UNSW-NB15 flows. This is not a search for",
            "individual attacks, and it cannot be: the lite feature set provably does not",
            "separate UNSW attacks from CIC benign traffic, because UNSW attack flows run at",
            "79 packets/s against CIC benign traffic's 66, so they sit inside the benign",
            "cloud (see CROSS_DATASET.md). The question here is whether the sensor notices",
            "that the whole network is unlike anything it was trained on.",
            "",
            "| Score | All flows unknown | UNSW attacks | UNSW normal | In domain, same test |",
            "|---|---|---|---|---|",
        ]
        for score, s in ds["scores"].items():
            in_domain = kr["scores"][score]["rejection_rate"]
            lines.append(f"| {score} | {s['unknown_rate']:.4f} | {s['unknown_rate_attacks']:.4f} | "
                         f"{s['unknown_rate_normal']:.4f} | {in_domain:.4f} |")
        if selected:
            ratio = selected["unknown_rate"] / max(1e-9, kr["scores"][r["score"]]["rejection_rate"])
            lines += [
                "",
                f"The unknown rate is {ratio:.0f} times the in-domain rate. A closed-set softmax",
                "has no way to report this at all: on the same flows it returns Benign with high",
                "confidence, which is the result recorded in CROSS_DATASET.md. Reporting \"this",
                "traffic matches nothing I know\" is the honest answer, and it is actionable:",
                "it says the sensor needs retraining for this network, not that the network is",
                "quiet.",
            ]

    lines += [
        "",
        "## What this does not claim",
        "",
        "- The open-set layer does not improve classification accuracy on known attacks, and",
        "  is not meant to. It changes what happens to traffic the classifier has no class",
        "  for.",
        "- Novelty detection is uneven across attack types. The AUC column shows which are",
        "  hard, and Bot is the hardest here, which is also the class the supervised model",
        "  handles worst (precision 0.62 in RESULTS.md). Flows whose features genuinely lie",
        "  inside the benign distribution cannot be separated by any method using those",
        "  features, and no threshold fixes that.",
        "- A discovered family is a cluster with a fingerprint, not an identification. Naming",
        "  it is the operator's judgement; Netra's contribution is that there is one object",
        "  to name instead of hundreds of unlabelled anomaly lines.",
        "",
    ]
    (config.REPORTS_DIR / "OPENSET.md").write_text("\n".join(lines), encoding="utf-8")
    log.info("wrote %s", config.REPORTS_DIR / "OPENSET.md")


def plot(r: dict, path=None) -> None:
    """The operating curve: novel flows rejected against the price paid."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from src.models.evaluate import GRID, INK_2, SURFACE, _style

    loco = r.get("leave_one_class_out")
    if not loco:
        return
    path = path or (config.REPORTS_DIR / "openset.png")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.8), facecolor=SURFACE,
                                   gridspec_kw={"width_ratios": [1.15, 1]})
    for ax in (ax1, ax2):
        _style(ax)

    alphas = [c["alpha"] for c in loco["totals"]["mean_curve"]]
    for fold in loco["folds"]:
        ax1.plot(alphas, [c["unknown_rate"] for c in fold["alpha_curve"]],
                 marker="o", markersize=3.5, linewidth=1.2, alpha=0.75,
                 label=fold["held_out"])
    ax1.plot(alphas, alphas, linestyle="--", linewidth=1.2, color=GRID,
             label="price paid (known flows)")
    ax1.axvline(r["alpha"], color="#eb6834", linewidth=1.0, linestyle=":")
    ax1.set_xscale("log")
    ax1.set_xlabel("alpha (share of known traffic routed to discovery)", color=INK_2)
    ax1.set_ylabel("Share of held-out novel flows rejected", color=INK_2)
    ax1.set_title("Novel attack detection against its price", color=INK_2, fontsize=11)
    ax1.legend(frameon=False, fontsize=8, labelcolor=INK_2, ncol=2)

    names = [f["held_out"] for f in loco["folds"]]
    y = np.arange(len(names))
    ax2.barh(y - 0.2, [f["closed_set_called_benign"] for f in loco["folds"]],
             height=0.38, color="#eb6834", label="closed-set: called Benign")
    ax2.barh(y + 0.2, [f["surfaced_rate"] for f in loco["folds"]],
             height=0.38, color="#2a78d6", label="open-set: surfaced to operator")
    ax2.set_yticks(y, names, color=INK_2)
    ax2.set_xlim(0, 1)
    ax2.set_xlabel("Share of the held-out attack's flows", color=INK_2)
    ax2.set_title("What happens to an attack nobody trained on", color=INK_2, fontsize=11)
    ax2.legend(frameon=False, fontsize=8.5, labelcolor=INK_2)

    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    log.info("wrote %s", path)


def print_summary(r: dict) -> None:
    kr = r["known_rejection"]
    print(f"\nConformal validity on known classes (alpha {kr['alpha']}, "
          f"{kr['test_flows']:,} test flows)")
    for score, s in kr["scores"].items():
        print(f"  {score:9s} rejection {s['rejection_rate']:.4f}  "
              f"{'within alpha' if s['within_alpha'] else 'ABOVE ALPHA'}")

    loco = r.get("leave_one_class_out")
    if loco:
        print(f"\nLeave one class out ({loco['score']} score). Each row: that class removed "
              f"from training entirely.")
        print(f"  {'held out':<11} {'flows':>7} {'AUC':>6} {'unknown':>8} {'closed-set':>11} "
              f"{'surfaced':>9} {'known rej.':>11}")
        print(f"  {'':<11} {'':>7} {'':>6} {'(open)':>8} {'-> Benign':>11} {'':>9} {'':>11}")
        for f in loco["folds"]:
            print(f"  {f['held_out']:<11} {f['novel_flows']:>7,} {f['novelty_auc']:>6.3f} "
                  f"{f['unknown_rate']:>8.3f} {f['closed_set_called_benign']:>11.3f} "
                  f"{f['surfaced_rate']:>9.3f} {f['known_rejection_rate']:>11.4f}")
        t = loco["totals"]
        print(f"  {'mean':<11} {'':>7} {t['mean_novelty_auc']:>6.3f} "
              f"{t['mean_unknown_rate']:>8.3f} {t['mean_closed_set_called_benign']:>11.3f} "
              f"{t['mean_surfaced_rate']:>9.3f} {t['mean_known_rejection_rate']:>11.4f}")
        print("\n  Operating curve, averaged over folds (alpha: novel rejected / known rejected)")
        print("   " + "  ".join(f"{c['alpha']:g}: {c['unknown_rate']:.3f}/{c['known_rejection_rate']:.3f}"
                                for c in t["mean_curve"]))

    ds = r["domain_shift"]
    if ds.get("available"):
        print(f"\nDomain shift, UNSW-NB15 ({ds['scored_flows']:,} flows), unknown rate")
        for score, s in ds["scores"].items():
            print(f"  {score:9s} all {s['unknown_rate']:.4f}  attacks {s['unknown_rate_attacks']:.4f}  "
                  f"normal {s['unknown_rate_normal']:.4f}")
        print(f"  in domain, same test: {r['known_rejection']['scores'][r['score']]['rejection_rate']:.4f}")
