"""Generate the extra figures the case study report embeds.

`src/models/evaluate.py` and `cross_eval.py` already write the confusion
matrices, per-class F1 charts, the autoencoder error histogram, the
cross-dataset chart and the open-set operating curve. This script adds the
exploratory and architectural figures that a report needs and an evaluation
script has no reason to produce:

    fig_class_distribution.png   class balance across the three splits
    fig_feature_importance.png   what the forest actually uses
    fig_roc_curves.png           one-vs-rest ROC per class
    fig_novelty_auc.png          how separable each unseen attack is
    fig_threshold_curve.png      the reporting-threshold trade-off
    fig_architecture.png         the six-layer pipeline
    fig_lab_topology.png         the Docker laboratory

    python presentation/build_figures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
REPORTS = ROOT / "reports"

SURFACE = "#FCFCFB"
INK = "#0B0B0B"
INK_2 = "#52514E"
MUTED = "#898781"
GRID = "#E1E0D9"
BLUE = "#2A78D6"
ORANGE = "#EB6834"
GREEN = "#15803D"
PURPLE = "#7C3AED"
RED = "#B91C1C"

PALETTE = [BLUE, ORANGE, GREEN, PURPLE, "#0891B2", "#CA8A04", "#DB2777", "#64748B"]


def style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=9)
    ax.grid(axis="y", color=GRID, linewidth=0.8, alpha=0.9)
    ax.set_axisbelow(True)


def save(fig, name):
    path = REPORTS / name
    fig.savefig(path, dpi=160, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {path.name}")
    return path


# ---------------------------------------------------------------------------
def fig_class_distribution():
    data = json.loads((REPORTS / "data_summary.json").read_text())
    splits = data["splits"]
    classes = sorted(splits["test"]["class_counts"],
                     key=lambda c: -splits["test"]["class_counts"][c])
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.4), facecolor=SURFACE)
    for ax in (ax1, ax2):
        style(ax)

    x = np.arange(len(classes))
    width = 0.27
    for i, (name, colour) in enumerate((("train", BLUE), ("val", ORANGE), ("test", GREEN))):
        vals = [splits[name]["class_counts"].get(c, 0) for c in classes]
        ax1.bar(x + (i - 1) * width, vals, width=width, color=colour, label=name)
    ax1.set_yscale("log")
    ax1.set_xticks(x, classes, rotation=30, ha="right")
    ax1.set_ylabel("Flows (log scale)", color=INK_2, fontsize=10)
    ax1.set_title("Class distribution across the three splits", color=INK, fontsize=11)
    ax1.legend(frameon=False, fontsize=9, labelcolor=INK_2)

    counts = [splits["test"]["class_counts"].get(c, 0) for c in classes]
    attack = sum(v for c, v in zip(classes, counts) if c != "Benign")
    benign = splits["test"]["class_counts"].get("Benign", 0)
    wedges, _, autotexts = ax2.pie(
        [benign, attack], labels=["Benign", "Attack"], colors=[BLUE, ORANGE],
        autopct=lambda p: f"{p:.1f}%", startangle=90,
        textprops={"color": INK, "fontsize": 10},
        wedgeprops={"edgecolor": SURFACE, "linewidth": 2})
    for t in autotexts:
        t.set_color("white")
        t.set_fontweight("bold")
    ax2.set_title(f"Test split balance ({benign + attack:,} flows)", color=INK, fontsize=11)
    ax2.grid(False)
    ax2.set_facecolor(SURFACE)
    fig.tight_layout()
    return save(fig, "fig_class_distribution.png")


def fig_feature_importance():
    import joblib

    from src import config
    from src.models.train_supervised import load_model

    model, meta = load_model("full")
    features = meta["features"]
    imp = np.asarray(model.feature_importances_, dtype=float)
    order = np.argsort(-imp)[:15][::-1]
    fig, ax = plt.subplots(figsize=(9.5, 5.4), facecolor=SURFACE)
    style(ax)
    ax.grid(axis="y", visible=False)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    y = np.arange(len(order))
    ax.barh(y, imp[order], color=BLUE, height=0.68)
    ax.set_yticks(y, [features[i] for i in order], fontsize=9)
    ax.set_xlabel("Gini importance", color=INK_2, fontsize=10)
    ax.set_title("Top 15 features used by the full Random Forest", color=INK, fontsize=11)
    for yi, v in zip(y, imp[order]):
        ax.text(v + imp.max() * 0.012, yi, f"{v:.3f}", va="center", fontsize=8, color=INK_2)
    fig.tight_layout()
    del joblib, config
    return save(fig, "fig_feature_importance.png")


def fig_roc_curves():
    from sklearn.metrics import auc, roc_curve

    from src.models.train_supervised import load_model, load_xy

    model, meta = load_model("full")
    X, y, _ = load_xy("test", "full")
    classes = meta["classes"]
    proba = model.predict_proba(X)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8), facecolor=SURFACE)
    for ax in (ax1, ax2):
        style(ax)
        ax.grid(True, color=GRID, linewidth=0.8)

    for i, name in enumerate(classes):
        fpr, tpr, _ = roc_curve((y == i).astype(int), proba[:, i])
        ax1.plot(fpr, tpr, linewidth=1.6, color=PALETTE[i % len(PALETTE)],
                 label=f"{name} ({auc(fpr, tpr):.4f})")
    ax1.plot([0, 1], [0, 1], linestyle="--", color=MUTED, linewidth=1)
    ax1.set_xlabel("False positive rate", color=INK_2, fontsize=10)
    ax1.set_ylabel("True positive rate", color=INK_2, fontsize=10)
    ax1.set_title("One-vs-rest ROC, full Random Forest", color=INK, fontsize=11)
    ax1.legend(frameon=False, fontsize=8, labelcolor=INK_2, loc="lower right")

    benign = classes.index("Benign")
    score = 1.0 - proba[:, benign]
    fpr, tpr, _ = roc_curve((y != benign).astype(int), score)
    ax2.plot(fpr, tpr, linewidth=2.2, color=ORANGE,
             label=f"attack vs benign (AUC {auc(fpr, tpr):.4f})")
    ax2.plot([0, 1], [0, 1], linestyle="--", color=MUTED, linewidth=1)
    ax2.set_xscale("log")
    ax2.set_xlim(1e-5, 1)
    ax2.set_xlabel("False positive rate (log scale)", color=INK_2, fontsize=10)
    ax2.set_ylabel("Detection rate", color=INK_2, fontsize=10)
    ax2.set_title("Binary view: any attack against benign", color=INK, fontsize=11)
    ax2.legend(frameon=False, fontsize=9, labelcolor=INK_2, loc="lower right")
    fig.tight_layout()
    return save(fig, "fig_roc_curves.png")


def fig_novelty_auc():
    r = json.loads((REPORTS / "openset.json").read_text())
    folds = sorted(r["leave_one_class_out"]["folds"], key=lambda f: f["novelty_auc"])
    names = [f["held_out"] for f in folds]
    aucs = [f["novelty_auc"] for f in folds]
    silent_before = [1 - f["closed_set_flagged_as_attack"] for f in folds]
    silent_after = [1 - f["surfaced_rate"] for f in folds]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.5, 4.6), facecolor=SURFACE)
    for ax in (ax1, ax2):
        style(ax)

    y = np.arange(len(names))
    colours = [RED if a < 0.5 else (ORANGE if a < 0.85 else GREEN) for a in aucs]
    ax1.grid(axis="y", visible=False)
    ax1.grid(axis="x", color=GRID, linewidth=0.8)
    ax1.barh(y, aucs, color=colours, height=0.62)
    ax1.axvline(0.5, color=MUTED, linestyle="--", linewidth=1)
    ax1.set_yticks(y, names, fontsize=9)
    ax1.set_xlim(0, 1.0)
    ax1.set_xlabel("Novelty AUC (0.5 = no information)", color=INK_2, fontsize=10)
    ax1.set_title("How separable is each unseen attack?", color=INK, fontsize=11)
    for yi, v in zip(y, aucs):
        ax1.text(v + 0.012, yi, f"{v:.3f}", va="center", fontsize=8, color=INK_2)

    width = 0.36
    x = np.arange(len(names))
    ax2.bar(x - width / 2, silent_before, width=width, color=RED,
            label="closed-set: share never seen")
    ax2.bar(x + width / 2, silent_after, width=width, color=GREEN,
            label="with open-set layer")
    ax2.set_xticks(x, names, rotation=30, ha="right", fontsize=9)
    ax2.set_ylim(0, 1.05)
    ax2.set_ylabel("Share of the attack that is silent", color=INK_2, fontsize=10)
    ax2.set_title("What reaches the operator", color=INK, fontsize=11)
    ax2.legend(frameon=False, fontsize=9, labelcolor=INK_2)
    fig.tight_layout()
    return save(fig, "fig_novelty_auc.png")


def fig_threshold_curve():
    d = json.loads((REPORTS / "discovery.json").read_text())
    curve = d["totals"]["threshold_curve"]
    n = [c["min_flows"] for c in curve]
    found = [c["folds_where_novel_family_reported"] for c in curve]
    false = [c["total_false_alarm_families"] for c in curve]
    chosen = d["min_family_flows"]

    fig, ax1 = plt.subplots(figsize=(9.5, 4.8), facecolor=SURFACE)
    style(ax1)
    ax1.plot(n, found, marker="o", color=GREEN, linewidth=2,
             label="novel families found (of 7)")
    ax1.set_xscale("log")
    ax1.set_xticks(n, [str(v) for v in n])
    ax1.set_ylim(0, 7.6)
    ax1.set_xlabel("Flows a family must hold before it is reported", color=INK_2, fontsize=10)
    ax1.set_ylabel("Novel families found (of 7)", color=GREEN, fontsize=10)
    ax1.tick_params(axis="y", colors=GREEN)

    ax2 = ax1.twinx()
    ax2.plot(n, false, marker="s", color=RED, linewidth=2,
             label="families of ordinary traffic")
    ax2.set_ylabel("Families of ordinary traffic reported", color=RED, fontsize=10)
    ax2.tick_params(axis="y", colors=RED, labelsize=9)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_color(GRID)
    ax2.grid(False)

    ax1.axvline(chosen, color=PURPLE, linestyle=":", linewidth=1.6)
    ax1.annotate(f"selected: {chosen}", xy=(chosen, 6.6), xytext=(chosen * 1.15, 6.8),
                 color=PURPLE, fontsize=9)
    lines = ax1.get_lines()[:1] + ax2.get_lines()[:1]
    ax1.legend(lines, [l.get_label() for l in lines], frameon=False,
               fontsize=9, labelcolor=INK_2, loc="center left")
    ax1.set_title("Choosing the reporting threshold: detection against baselining cost",
                  color=INK, fontsize=11)
    fig.tight_layout()
    return save(fig, "fig_threshold_curve.png")


# ---------------------------------------------------------------------------
# Diagrams
# ---------------------------------------------------------------------------
def _box(ax, x, y, w, h, text, fill, edge, fontsize=9, text_colour=INK, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                                facecolor=fill, edgecolor=edge, linewidth=1.2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fontsize,
            color=text_colour, fontweight="bold" if bold else "normal", linespacing=1.4)


def _arrow(ax, x1, y1, x2, y2, colour=MUTED):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=13,
                                 color=colour, linewidth=1.3, shrinkA=2, shrinkB=2))


def fig_architecture():
    fig, ax = plt.subplots(figsize=(12, 6.2), facecolor=SURFACE)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 6.2)
    ax.axis("off")
    ax.set_facecolor(SURFACE)

    _box(ax, 0.15, 4.6, 1.95, 1.1,
         "INGESTION\nlive capture / PCAP\n/ dataset replay", "#EFF6FF", BLUE, 8.5, INK, True)
    _box(ax, 2.45, 4.6, 1.95, 1.1,
         "FEATURE\nEXTRACTION\npackets → flows", "#EFF6FF", BLUE, 8.5, INK, True)
    _arrow(ax, 2.10, 5.15, 2.45, 5.15)

    _box(ax, 4.75, 4.6, 2.3, 1.1,
         "SIGNATURE RULES\nsyn_flood, port_scan,\nslow_dos, brute_force",
         "#FEF3C7", "#CA8A04", 8.5, INK, True)
    _arrow(ax, 4.40, 5.15, 4.75, 5.15)

    _box(ax, 4.75, 3.15, 2.3, 1.1,
         "ML SCORING\nfull RF (59 feat.)\nlite RF (6 feat.)", "#EFF6FF", BLUE, 8.5, INK, True)
    _arrow(ax, 3.42, 4.6, 3.42, 3.70)
    _arrow(ax, 3.42, 3.70, 4.75, 3.70)

    _box(ax, 4.75, 1.70, 2.3, 1.1,
         "OPEN-SET TEST\nconformal p-values\n“none of these”",
         "#F5F3FF", PURPLE, 8.5, INK, True)
    _arrow(ax, 5.90, 3.15, 5.90, 2.80)
    ax.text(6.02, 2.97, "still benign?", fontsize=7.5, color=MUTED, va="center")

    _box(ax, 4.75, 0.25, 2.3, 1.1,
         "FAMILY DISCOVERY\ncluster, fingerprint,\nname (NETRA-U001)",
         "#F5F3FF", PURPLE, 8.5, INK, True)
    _arrow(ax, 5.90, 1.70, 5.90, 1.35)
    ax.text(6.02, 1.52, "rejected", fontsize=7.5, color=MUTED, va="center")

    _box(ax, 7.45, 2.60, 2.0, 1.5,
         "FUSION\npriority order\n+ corroboration", "#ECFDF5", GREEN, 9, INK, True)
    for y0 in (5.15, 3.70, 2.25, 0.80):
        _arrow(ax, 7.05, y0, 7.45, 3.35)

    _box(ax, 9.80, 3.40, 2.05, 1.1,
         "RESPONSE\niptables NETRA chain\ntimed + reversible", "#FEF2F2", RED, 8.5, INK, True)
    _box(ax, 9.80, 1.80, 2.05, 1.1,
         "PRESENTATION\nWebSocket + REST\nPySide6 desktop app", "#ECFDF5", GREEN, 8.5, INK, True)
    _arrow(ax, 9.45, 3.50, 9.80, 3.90)
    _arrow(ax, 9.45, 3.20, 9.80, 2.40)

    ax.text(6.0, 5.95, "Netra: six-layer detection and response pipeline",
            ha="center", fontsize=12, color=INK, fontweight="bold")
    fig.tight_layout()
    return save(fig, "fig_architecture.png")


def fig_lab_topology():
    fig, ax = plt.subplots(figsize=(11, 5.2), facecolor=SURFACE)
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 5.2)
    ax.axis("off")
    ax.set_facecolor(SURFACE)

    ax.add_patch(FancyBboxPatch((0.3, 0.5), 10.4, 3.6,
                                boxstyle="round,pad=0.02,rounding_size=0.03",
                                facecolor="#F8FAFC", edgecolor=GRID, linewidth=1.4))
    ax.text(0.55, 3.82, "Docker bridge network   10.77.0.0/24   (isolated)",
            fontsize=9, color=MUTED, style="italic")

    _box(ax, 0.9, 1.9, 2.3, 1.35,
         "ATTACKER\nnmap  ·  hping3\nslowloris  ·  hydra\n10.77.0.66",
         "#FEF2F2", RED, 9, INK, True)

    _box(ax, 4.3, 1.9, 2.4, 1.35,
         "VICTIM\nnginx web server\n10.77.0.10",
         "#EFF6FF", BLUE, 9, INK, True)

    _box(ax, 4.3, 0.75, 2.4, 0.95,
         "NIDS SENSOR\nshares the victim's network namespace\nCAP_NET_ADMIN + CAP_NET_RAW",
         "#F5F3FF", PURPLE, 8, INK, True)

    _box(ax, 7.8, 1.9, 2.4, 1.35,
         "OPERATOR\nPySide6 desktop app\nWebSocket :8000",
         "#ECFDF5", GREEN, 9, INK, True)

    _arrow(ax, 3.2, 2.57, 4.3, 2.57, RED)
    ax.text(3.75, 2.72, "attack\ntraffic", ha="center", fontsize=7.5, color=RED)
    _arrow(ax, 5.5, 1.90, 5.5, 1.70, PURPLE)
    ax.text(5.62, 1.80, "captures", fontsize=7.5, color=PURPLE, va="center")
    _arrow(ax, 6.7, 2.57, 7.8, 2.57, GREEN)
    ax.text(7.25, 2.72, "events", ha="center", fontsize=7.5, color=GREEN)
    _arrow(ax, 4.30, 1.22, 3.20, 2.20, PURPLE)
    ax.text(3.35, 1.45, "iptables DROP", fontsize=7.5, color=PURPLE)

    ax.text(5.5, 4.72, "Isolated Docker laboratory used for live validation",
            ha="center", fontsize=12, color=INK, fontweight="bold")
    ax.text(5.5, 4.38, "All attack traffic is confined to this network and never leaves the host",
            ha="center", fontsize=8.5, color=MUTED)
    fig.tight_layout()
    return save(fig, "fig_lab_topology.png")


FIGURES = [fig_class_distribution, fig_feature_importance, fig_roc_curves,
           fig_novelty_auc, fig_threshold_curve, fig_architecture, fig_lab_topology]


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    print("Generating report figures:")
    for fn in FIGURES:
        try:
            fn()
        except Exception as e:  # a missing artifact should not stop the rest
            print(f"  SKIPPED {fn.__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
