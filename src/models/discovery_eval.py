"""Measure the discovery layer: are the unknown families real?

The open-set layer routes flows it does not recognise to
``src.detection.discovery``, which clusters them. That only earns its place if
the clusters correspond to something. This measures whether they do, using the
same leave-one-class-out folds as ``src.models.openset_eval``: one attack class
is removed from training, scaling and calibration, its test flows are mixed back
into ordinary known traffic, and the whole mixture is replayed through the
open-set test and the clusterer in arrival order, exactly as the live engine
would.

The ground truth is the true class of every flow the clusterer was given, which
it never sees. Reported per fold:

* **families** formed, and how many pass ``MIN_FAMILY_FLOWS``.
* **purity**: assign each family its commonest true class and take the share of
  flows that agree. 1.0 means no family mixes the novel attack with benign tail
  traffic.
* **adjusted Rand index**: agreement between the clustering and the true classes,
  corrected for chance, so it cannot be inflated by splitting everything into
  singletons the way purity can.
* **recall** of the novel class into its dominant family, and that family's
  **precision**: the two numbers that decide whether an operator looking at one
  family is looking at the attack.
* **flows to discovery**: how many flows arrived before the family that ends up
  dominant first crossed ``MIN_FAMILY_FLOWS`` and became reportable. This is the
  detection latency of a novel attack, measured in flows.

Known traffic is subsampled per fold (``KNOWN_MIX``), because replaying 279,000
benign flows one at a time through a Python loop would dominate the runtime
without changing the result: what matters is the ratio of benign tail flows to
attack flows in the rejected stream, and that is preserved.
"""

from __future__ import annotations

import json
import logging
import time

import numpy as np

from src import config
from src.detection.discovery import (
    COSINE_RADIUS,
    DEFAULT_METRIC,
    MIN_FAMILY_FLOWS,
    FamilyTracker,
    calibrated_radius,
)
from src.models.openset import DEFAULT_ALPHA
from src.models.openset_eval import Fold

log = logging.getLogger(__name__)

RESULT_PATH = config.REPORTS_DIR / "discovery.json"
# Known-class flows mixed in with the novel ones, sampled from the test split.
KNOWN_MIX = 30_000
# Thresholds the reporting curve is measured at. A family is reported once it
# holds this many flows, and the curve says what each choice costs: how many of
# the held-out novel families reach it, against how many families of ordinary
# traffic do. config.DISCOVERY_MIN_FLOWS is chosen from this.
THRESHOLD_CURVE = (3, 5, 10, 15, 20, 30, 50, 100)


def _cluster_fold(fold: Fold, rng, radius_factor: float = 1.0,
                  metric: str = DEFAULT_METRIC) -> dict:
    """Replay one fold's rejected flows through the clusterer."""
    test, CLASS_COLUMN = fold.test, fold.class_column
    novel_mask = (test[CLASS_COLUMN] == fold.held_out).to_numpy()
    novel_idx = np.where(novel_mask)[0]
    known_idx = np.where(~novel_mask)[0]
    if len(known_idx) > KNOWN_MIX:
        known_idx = rng.choice(known_idx, KNOWN_MIX, replace=False)

    # Mix and shuffle, so the clusterer sees a realistic arrival order rather
    # than every attack flow in a block.
    idx = np.concatenate([novel_idx, known_idx])
    rng.shuffle(idx)
    X = fold.scaled_rows(idx)
    truth = test.iloc[idx][CLASS_COLUMN].to_numpy()
    src = test.iloc[idx]["Source IP"].to_numpy() if "Source IP" in test.columns else [None] * len(idx)

    # The coarse class is what the models were trained on, but three of the
    # classes merge two attack tools each (BruteForce is ftp-patator and
    # ssh-patator, DoS is hulk and goldeneye, DoS-Slow is slowloris and
    # slowhttptest; see config.LABEL_MAP). Splitting those apart is the right
    # behaviour for a clusterer and a label-level score penalises it for doing
    # so, so both ground truths are measured.
    fine = (test.iloc[idx]["Label"].to_numpy() if "Label" in test.columns else truth)

    p = fold.rec.score(X, score=fold.score)["p"]
    p_max = p.max(axis=1)
    rejected = np.where(p_max < fold.alpha)[0]

    radius = radius_factor * (COSINE_RADIUS if metric == "cosine"
                              else calibrated_radius(fold.rec))
    tracker = FamilyTracker(fold.rec, radius=radius, kind=fold.kind, persist=False,
                            metric=metric)
    assigned, first_reportable = [], {}
    start = time.time()
    for n, i in enumerate(rejected, start=1):
        raw = dict(zip(fold.cols, test.iloc[idx[i]][fold.cols].to_numpy()))
        state = tracker.observe(X[i], raw=raw, src=src[i], p_values=p[i], now=float(n))
        assigned.append(state["id"])
        if state["alertable"] and state["id"] not in first_reportable:
            first_reportable[state["id"]] = n
    seconds = time.time() - start

    assigned = np.asarray(assigned)
    truth_rejected = truth[rejected]
    novel_rejected = truth_rejected == fold.held_out

    # Which family best represents the novel class, and how good is it?
    dominant, recall, precision, latency = None, 0.0, 0.0, None
    if novel_rejected.any():
        ids, counts = np.unique(assigned[novel_rejected], return_counts=True)
        dominant = str(ids[counts.argmax()])
        in_dominant = assigned == dominant
        recall = float(counts.max() / novel_rejected.sum())
        precision = float((truth_rejected[in_dominant] == fold.held_out).mean())
        latency = first_reportable.get(dominant)

    sizes = {fid: int((assigned == fid).sum()) for fid in np.unique(assigned)} if len(assigned) else {}
    result = {
        "held_out": fold.held_out,
        "novel_flows": int(novel_mask.sum()),
        "known_flows_mixed": int(len(known_idx)),
        "radius": round(tracker.radius, 4),
        "rejected_flows": int(len(rejected)),
        "rejected_novel": int(novel_rejected.sum()),
        "rejected_known": int((~novel_rejected).sum()),
        "novel_rejection_rate": float(novel_rejected.sum() / max(1, novel_mask.sum())),
        "families": len(sizes),
        "families_reportable": int(sum(f.alertable for f in tracker.families.values())),
        "dominant_family_reported": bool(dominant in first_reportable),
        "false_alarm_families": _false_alarms(assigned, truth_rejected, fold.held_out,
                                              MIN_FAMILY_FLOWS),
        "threshold_curve": [
            {"min_flows": n,
             "families_reported": int(sum(v >= n for v in sizes.values())),
             "novel_family_reported": bool(dominant is not None
                                           and sizes.get(dominant, 0) >= n),
             "false_alarm_families": _false_alarms(assigned, truth_rejected, fold.held_out, n)}
            for n in THRESHOLD_CURVE],
        "purity": _purity(assigned, truth_rejected),
        "adjusted_rand_index": _ari(assigned, truth_rejected),
        "purity_by_tool": _purity(assigned, fine[rejected]),
        "adjusted_rand_index_by_tool": _ari(assigned, fine[rejected]),
        "novel_tools": sorted({str(t) for t in fine[rejected][novel_rejected]}),
        "dominant_family_tools": _composition(assigned, fine[rejected], dominant),
        "dominant_family": dominant,
        "dominant_family_recall": recall,
        "dominant_family_precision": precision,
        "flows_to_discovery": latency,
        "largest_families": _largest(assigned, truth_rejected, sizes),
        "clustering_seconds": round(seconds, 1),
        "example_description": _example(tracker, dominant),
    }
    log.info("[discovery] %-10s rejected %5d (%4d novel) -> %3d families (%d reportable, "
             "%d false), purity %.3f/%.3f, ARI %.3f/%.3f, dominant %s recall %.3f precision %.3f",
             fold.held_out, result["rejected_flows"], result["rejected_novel"],
             result["families"], result["families_reportable"], result["false_alarm_families"],
             result["purity"], result["purity_by_tool"], result["adjusted_rand_index"],
             result["adjusted_rand_index_by_tool"], dominant, recall, precision)
    return result


def _false_alarms(assigned, truth, held_out: str, min_flows: int) -> int:
    """Families that would be reported but are made of known traffic.

    Each one is an alert about a host that was doing nothing new, so this is the
    number that decides whether the layer is usable at a given threshold. It is
    computed from the recorded assignments rather than from the tracker, so the
    whole threshold curve comes out of one clustering pass.
    """
    if not len(assigned):
        return 0
    bad = 0
    for family_id in np.unique(assigned):
        members = truth[assigned == family_id]
        if len(members) < min_flows:
            continue
        names, counts = np.unique(members, return_counts=True)
        if names[counts.argmax()] != held_out:
            bad += 1
    return bad


def _example(tracker: FamilyTracker, family_id) -> str | None:
    """The line the operator would actually read for the dominant family."""
    if family_id is None:
        return None
    family = tracker.families.get(family_id)
    return family.describe() if family else None


def _composition(assigned, truth, family_id) -> dict:
    """What one family is actually made of, by the given ground truth."""
    if family_id is None or not len(assigned):
        return {}
    members = truth[assigned == family_id]
    if not len(members):
        return {}
    names, counts = np.unique(members, return_counts=True)
    return {str(names[i]): int(counts[i]) for i in np.argsort(-counts)[:4]}


def _largest(assigned, truth, sizes, top: int = 3) -> list[dict]:
    out = []
    for fid, n in sorted(sizes.items(), key=lambda kv: -kv[1])[:top]:
        members = truth[assigned == fid]
        names, counts = np.unique(members, return_counts=True)
        out.append({"family": str(fid), "flows": int(n),
                    "composition": {str(names[i]): int(counts[i])
                                    for i in np.argsort(-counts)[:3]}})
    return out


def _purity(assigned, truth) -> float:
    """Share of flows whose family's commonest true class is their own."""
    if not len(assigned):
        return float("nan")
    total = 0
    for fid in np.unique(assigned):
        members = truth[assigned == fid]
        _, counts = np.unique(members, return_counts=True)
        total += int(counts.max())
    return float(total / len(assigned))


def _ari(assigned, truth) -> float:
    """Adjusted Rand index between the clustering and the true classes."""
    if not len(assigned):
        return float("nan")
    from sklearn.metrics import adjusted_rand_score

    return float(adjusted_rand_score(truth, assigned))


def run(kind: str = "full", alpha: float = DEFAULT_ALPHA, score: str = "knn",
        classes: list[str] | None = None, radius_factor: float = 1.0,
        metric: str = DEFAULT_METRIC) -> dict:
    """Leave-one-class-out discovery sweep over every attack class."""
    from src.data.preprocess import load_feature_spec

    config.ensure_dirs()
    spec = load_feature_spec()
    targets = classes or [c for c in spec["classes"] if c != config.BENIGN_LABEL]
    rng = np.random.default_rng(config.RANDOM_STATE)
    folds = []
    for held_out in targets:
        fold = Fold(held_out, kind=kind, alpha=alpha, score=score, with_forest=False)
        folds.append(_cluster_fold(fold, rng, radius_factor=radius_factor, metric=metric))
    finite = lambda key: [f[key] for f in folds if f[key] == f[key]]  # noqa: E731
    result = {
        "kind": kind, "alpha": alpha, "score": score, "radius_factor": radius_factor,
        "metric": metric, "min_family_flows": MIN_FAMILY_FLOWS, "known_mix": KNOWN_MIX,
        "folds": folds,
        "totals": {
            "mean_purity": float(np.mean(finite("purity"))),
            "mean_adjusted_rand_index": float(np.mean(finite("adjusted_rand_index"))),
            "mean_purity_by_tool": float(np.mean(finite("purity_by_tool"))),
            "mean_adjusted_rand_index_by_tool": float(
                np.mean(finite("adjusted_rand_index_by_tool"))),
            "mean_dominant_recall": float(np.mean([f["dominant_family_recall"] for f in folds])),
            "mean_dominant_precision": float(np.mean([f["dominant_family_precision"] for f in folds])),
            "median_flows_to_discovery": float(np.median(
                [f["flows_to_discovery"] for f in folds if f["flows_to_discovery"]] or [np.nan])),
            "folds_where_novel_family_reported": int(sum(f["dominant_family_reported"]
                                                         for f in folds)),
            "total_false_alarm_families": int(sum(f["false_alarm_families"] for f in folds)),
            "threshold_curve": [{
                "min_flows": n,
                "folds_where_novel_family_reported": int(sum(
                    c["novel_family_reported"] for f in folds
                    for c in f["threshold_curve"] if c["min_flows"] == n)),
                "total_false_alarm_families": int(sum(
                    c["false_alarm_families"] for f in folds
                    for c in f["threshold_curve"] if c["min_flows"] == n)),
                "total_families_reported": int(sum(
                    c["families_reported"] for f in folds
                    for c in f["threshold_curve"] if c["min_flows"] == n)),
            } for n in THRESHOLD_CURVE],
        },
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2))
    log.info("discovery results written to %s", RESULT_PATH)
    return result


def print_summary(r: dict) -> None:
    print(f"\nUnknown-family discovery ({r.get('metric', 'cosine')} metric, alpha {r['alpha']}, "
          f"radius factor {r['radius_factor']}, reportable at {r['min_family_flows']} flows)")
    print(f"  {'held out':<11} {'rejected':>9} {'novel':>6} {'famil.':>7} {'rep.':>5} {'purity':>7} "
          f"{'ARI':>6} {'recall':>7} {'prec.':>7} {'flows':>6} {'false':>6}")
    for f in r["folds"]:
        latency = f["flows_to_discovery"]
        print(f"  {f['held_out']:<11} {f['rejected_flows']:>9,} {f['rejected_novel']:>6,} "
              f"{f['families']:>7} {f['families_reportable']:>5} {f['purity']:>7.3f} "
              f"{f['adjusted_rand_index']:>6.3f} {f['dominant_family_recall']:>7.3f} "
              f"{f['dominant_family_precision']:>7.3f} {(latency if latency else 0):>6} "
              f"{f['false_alarm_families']:>6}")
    t = r["totals"]
    print(f"  {'mean':<11} {'':>9} {'':>6} {'':>7} {'':>5} {t['mean_purity']:>7.3f} "
          f"{t['mean_adjusted_rand_index']:>6.3f} {t['mean_dominant_recall']:>7.3f} "
          f"{t['mean_dominant_precision']:>7.3f} {t['median_flows_to_discovery']:>6.0f} "
          f"{t['total_false_alarm_families']:>6}")
    print(f"  Novel family actually reported in {t['folds_where_novel_family_reported']} of "
          f"{len(r['folds'])} folds; {t['total_false_alarm_families']} reportable families "
          f"were known traffic.")
    print(f"\n  Reporting threshold curve ({len(r['folds'])} folds, "
          f"current default {r['min_family_flows']} flows)")
    print(f"  {'min flows':>10} {'novel families found':>21} {'false alarms':>13} "
          f"{'families reported':>18}")
    for c in t["threshold_curve"]:
        print(f"  {c['min_flows']:>10} {c['folds_where_novel_family_reported']:>13} of "
              f"{len(r['folds']):<5} {c['total_false_alarm_families']:>13} "
              f"{c['total_families_reported']:>18}")
    print("\n  What the operator reads, per fold:")
    for f in r["folds"]:
        if f["example_description"]:
            print(f"    [{f['held_out']} held out] {f['example_description']}")
