"""Evaluate the supervised classifiers on the held-out test split.

The test split keeps the natural class distribution of CIC-IDS2017 (it is never
capped or resampled), so the numbers reflect realistic traffic proportions.

Written to ``reports/``:
  metrics_<kind>.json              every metric for every candidate model
  confusion_<kind>_<model>.png     confusion matrix of each candidate
  per_class_f1_<kind>.png          per-class F1, Random Forest vs XGBoost
  RESULTS.md                       tables assembled from the JSON files
"""

from __future__ import annotations

import json
import logging
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from src import config  # noqa: E402
from src.models.train_supervised import KINDS, META_PATHS, load_model, load_xy  # noqa: E402

log = logging.getLogger(__name__)

# Chart tokens (light theme, from the project's reference palette).
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
SERIES = {"random_forest": "#2a78d6", "xgboost": "#eb6834"}  # categorical slots 1 and 2
DISPLAY = {"random_forest": "Random Forest", "xgboost": "XGBoost"}
BLUE_RAMP = ["#fcfcfb", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]


def _style(ax) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#c3c2b7")
    ax.tick_params(colors=INK_2, labelsize=9)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(y_true, y_pred, proba, classes: list[str]) -> dict:
    benign = classes.index(config.BENIGN_LABEL)
    p_macro, r_macro, f_macro, _ = precision_recall_fscore_support(y_true, y_pred, average="macro",
                                                                   zero_division=0)
    p_w, r_w, f_w, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted",
                                                       zero_division=0)
    per_class = classification_report(y_true, y_pred, labels=range(len(classes)), target_names=classes,
                                      output_dict=True, zero_division=0)
    per_class = {c: {k: float(v) for k, v in per_class[c].items()} for c in classes}

    # Binary view: any attack class versus benign.
    is_attack = y_true != benign
    flagged = y_pred != benign
    attack_score = 1.0 - proba[:, benign]
    tp = int((is_attack & flagged).sum())
    fn = int((is_attack & ~flagged).sum())
    fp = int((~is_attack & flagged).sum())
    tn = int((~is_attack & ~flagged).sum())

    return {
        "n_test": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro": {"precision": float(p_macro), "recall": float(r_macro), "f1": float(f_macro)},
        "weighted": {"precision": float(p_w), "recall": float(r_w), "f1": float(f_w)},
        "roc_auc_ovr_macro": float(roc_auc_score(y_true, proba, multi_class="ovr", average="macro")),
        "roc_auc_ovr_weighted": float(roc_auc_score(y_true, proba, multi_class="ovr", average="weighted")),
        "binary": {
            "detection_rate": tp / max(tp + fn, 1),
            "false_positive_rate": fp / max(fp + tn, 1),
            "precision": tp / max(tp + fp, 1),
            "roc_auc": float(roc_auc_score(is_attack, attack_score)),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        },
        "per_class": per_class,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=range(len(classes))).tolist(),
    }


def time_inference(model, X, n: int = 20_000) -> dict:
    """Single-thread-agnostic throughput estimate: batch predict_proba on n rows."""
    sample = X[:n]
    model.predict_proba(sample[:100])  # warm-up
    start = time.perf_counter()
    model.predict_proba(sample)
    elapsed = time.perf_counter() - start
    return {"rows": len(sample), "seconds": elapsed, "microseconds_per_flow": 1e6 * elapsed / len(sample)}


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------
def plot_confusion(cm: np.ndarray, classes: list[str], title: str, path) -> None:
    cm = np.asarray(cm)
    row_share = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    cmap = LinearSegmentedColormap.from_list("blue_seq", BLUE_RAMP)

    fig, ax = plt.subplots(figsize=(9, 7.5), facecolor=SURFACE)
    _style(ax)
    mesh = ax.pcolormesh(row_share, cmap=cmap, vmin=0, vmax=1, edgecolors=SURFACE, linewidth=2)
    ax.invert_yaxis()
    n = len(classes)
    ax.set_xticks(np.arange(n) + 0.5, classes, rotation=35, ha="right")
    ax.set_yticks(np.arange(n) + 0.5, classes)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    for i in range(n):
        for j in range(n):
            if cm[i, j] == 0:
                continue
            share = row_share[i, j]
            ax.text(j + 0.5, i + 0.5, f"{cm[i, j]:,}\n{share:.1%}", ha="center", va="center",
                    fontsize=8, color="#ffffff" if share > 0.55 else INK)
    ax.set_xlabel("Predicted class", color=INK_2, labelpad=8)
    ax.set_ylabel("True class", color=INK_2, labelpad=8)
    ax.set_title(title, color=INK, fontsize=12, loc="left", pad=12)
    cbar = fig.colorbar(mesh, ax=ax, fraction=0.04, pad=0.02)
    cbar.set_label("Share of true class (row-normalised)", color=INK_2, fontsize=9)
    cbar.outline.set_visible(False)
    cbar.ax.tick_params(colors=INK_2, labelsize=8)
    fig.text(0.01, 0.01, "Cell text: flow count and share of the true class. Colour: row share.",
             color=MUTED, fontsize=8)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def plot_per_class_f1(results: dict, classes: list[str], title: str, path) -> None:
    names = [n for n in ("random_forest", "xgboost") if n in results]
    y = np.arange(len(classes))
    height = 0.36
    fig, ax = plt.subplots(figsize=(8.5, 0.55 * len(classes) + 1.5), facecolor=SURFACE)
    _style(ax)
    for k, name in enumerate(names):
        scores = [results[name]["per_class"][c]["f1-score"] for c in classes]
        offset = (k - (len(names) - 1) / 2) * (height + 0.04)
        ax.barh(y + offset, scores, height=height, color=SERIES[name], label=DISPLAY[name])
        for yi, s in zip(y + offset, scores):
            ax.text(s + 0.005, yi, f"{s:.3f}", va="center", fontsize=7.5, color=INK_2)
    ax.set_yticks(y, classes)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.08)
    ax.set_xlabel("F1 score on test split", color=INK_2)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="lower right", fontsize=9, labelcolor=INK_2)
    ax.set_title(title, color=INK, fontsize=12, loc="left", pad=10)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def evaluate(kind: str = "full") -> dict:
    meta = json.loads(META_PATHS[kind].read_text())
    classes = meta["classes"]
    X, y, _ = load_xy("test", kind)
    log.info("[%s] evaluating on test split %s", kind, X.shape)

    results = {}
    for name in meta["candidates"]:
        model, _ = load_model(kind, name)
        proba = model.predict_proba(X)
        pred = proba.argmax(axis=1)
        m = compute_metrics(y, pred, proba, classes)
        m["inference"] = time_inference(model, X)
        m["validation_macro_f1"] = meta["candidates"][name]["val_macro_f1"]
        m["train_seconds"] = meta["candidates"][name]["train_seconds"]
        results[name] = m
        label = "full CICFlowMeter features" if kind == "full" else "lite live features"
        plot_confusion(m["confusion_matrix"], classes,
                       f"{DISPLAY[name]} confusion matrix, {label} (CIC-IDS2017 test split)",
                       config.REPORTS_DIR / f"confusion_{kind}_{name}.png")
        log.info("[%s] %-13s acc %.4f  macro F1 %.4f  DR %.4f  FPR %.5f", kind, name, m["accuracy"],
                 m["macro"]["f1"], m["binary"]["detection_rate"], m["binary"]["false_positive_rate"])

    plot_per_class_f1(results, classes,
                      f"Per-class F1, {'full' if kind == 'full' else 'lite'} feature set",
                      config.REPORTS_DIR / f"per_class_f1_{kind}.png")
    report = {"kind": kind, "selected": meta["best"], "classes": classes,
              "features": meta["features"], "models": results}
    (config.REPORTS_DIR / f"metrics_{kind}.json").write_text(json.dumps(report, indent=2))
    return report


def write_results_markdown() -> None:
    """Assemble reports/RESULTS.md from whichever metrics files exist."""
    lines = ["# Netra evaluation results", "",
             "All values are measured on the held-out CIC-IDS2017 test split, which keeps the",
             "natural class distribution. Generated by `python -m src.cli evaluate`.", ""]
    for kind in KINDS:
        path = config.REPORTS_DIR / f"metrics_{kind}.json"
        if not path.exists():
            continue
        r = json.loads(path.read_text())
        title = "Full CICFlowMeter feature set" if kind == "full" else "Lite live feature set"
        lines += [f"## {title} ({len(r['features'])} features)", "",
                  f"Selected model (by validation macro F1): **{DISPLAY[r['selected']]}**", "",
                  "| Model | Accuracy | Macro P | Macro R | Macro F1 | Weighted F1 | ROC-AUC (OvR macro) "
                  "| Detection rate | False-positive rate | Train time (s) | Inference (us/flow) |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for name, m in r["models"].items():
            b = m["binary"]
            lines.append(
                f"| {DISPLAY[name]} | {m['accuracy']:.4f} | {m['macro']['precision']:.4f} | "
                f"{m['macro']['recall']:.4f} | {m['macro']['f1']:.4f} | {m['weighted']['f1']:.4f} | "
                f"{m['roc_auc_ovr_macro']:.4f} | {b['detection_rate']:.4f} | {b['false_positive_rate']:.5f} | "
                f"{m['train_seconds']:.0f} | {m['inference']['microseconds_per_flow']:.2f} |")
        best = r["models"][r["selected"]]
        lines += ["", f"Per-class results for {DISPLAY[r['selected']]}:", "",
                  "| Class | Precision | Recall | F1 | Test flows |", "|---|---|---|---|---|"]
        for c in r["classes"]:
            pc = best["per_class"][c]
            lines.append(f"| {c} | {pc['precision']:.4f} | {pc['recall']:.4f} | {pc['f1-score']:.4f} | "
                         f"{int(pc['support']):,} |")
        b = best["binary"]
        lines += ["", f"Attack-versus-benign view: {b['tp']:,} of {b['tp'] + b['fn']:,} attack flows flagged, "
                      f"{b['fp']:,} of {b['fp'] + b['tn']:,} benign flows wrongly flagged.", "",
                  f"![Confusion matrix](confusion_{kind}_{r['selected']}.png)", "",
                  f"![Per-class F1](per_class_f1_{kind}.png)", ""]
    ae_path = config.REPORTS_DIR / "metrics_autoencoder.json"
    if ae_path.exists():
        a = json.loads(ae_path.read_text())
        lines += ["## Autoencoder anomaly detector (trained on benign flows only)", "",
                  f"Threshold: reconstruction error above the {a['threshold_percentile']:.0f}th percentile of "
                  f"benign validation flows ({a['threshold']:.5f}).", "",
                  "| ROC-AUC | Average precision | Detection rate | False-positive rate | Precision |",
                  "|---|---|---|---|---|",
                  f"| {a['roc_auc']:.4f} | {a['average_precision']:.4f} | {a['detection_rate']:.4f} | "
                  f"{a['false_positive_rate']:.5f} | {a['precision']:.4f} |", "",
                  "| Class | Test flows | Share flagged as anomalous |", "|---|---|---|"]
        for c, v in a["per_class"].items():
            lines.append(f"| {c} | {v['flows']:,} | {v['flagged_share']:.4f} |")
        lines += ["", "![Autoencoder errors](autoencoder_errors.png)", ""]
    (config.REPORTS_DIR / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
