"""Cross-dataset evaluation: CIC-IDS2017-trained models against UNSW-NB15.

This answers the question the in-domain metrics cannot: does the lite model
recognise attacks, or does it recognise CIC-IDS2017? Nothing is retrained and
nothing is refitted. The model, the scaler and the feature code are exactly the
artifacts the live system loads; only the data is new.

Reported:

* Binary detection: share of UNSW-NB15 attack flows flagged as any attack class,
  and share of benign flows wrongly flagged, next to the same two numbers
  measured in-domain on CIC-IDS2017. The gap between them is the result.
* Per-category detection, for all ten UNSW attack categories. Seven of them
  describe attacks with no class in Netra's label set, so they can only be
  counted as "flagged as something", which is the honest measure of transfer.
* A threshold sweep, because the deployed system requires confidence >=
  SUPERVISED_MIN_CONFIDENCE before it treats a prediction as evidence.

The byte-accounting difference between the datasets (payload versus whole
packets) is reported both uncorrected and corrected, so its effect is visible.
"""

from __future__ import annotations

import json
import logging
import time

import joblib
import numpy as np

from src import config
from src.data import unsw

log = logging.getLogger(__name__)

REPORT_JSON = config.REPORTS_DIR / "cross_dataset.json"
REPORT_MD = config.REPORTS_DIR / "CROSS_DATASET.md"
PLOT_PATH = config.REPORTS_DIR / "cross_dataset.png"


def _in_domain() -> dict:
    """The lite model's own CIC-IDS2017 test numbers, for side-by-side comparison."""
    path = config.REPORTS_DIR / "metrics_lite.json"
    if not path.exists():
        return {}
    m = json.loads(path.read_text())
    b = m["models"][m["selected"]]["binary"]
    return {"detection_rate": b["detection_rate"], "false_positive_rate": b["false_positive_rate"],
            "model": m["selected"]}


def evaluate(header_correction: bool = False, limit: int | None = None,
             min_confidence: float | None = None) -> dict:
    """Run the CIC-trained lite model over UNSW-NB15 and measure transfer."""
    from src.data.preprocess import load_feature_spec
    from src.models.train_supervised import load_model

    min_confidence = config.SUPERVISED_MIN_CONFIDENCE if min_confidence is None else min_confidence
    spec = load_feature_spec()
    classes = list(spec["classes"])
    benign_idx = classes.index(config.BENIGN_LABEL)

    model, meta = load_model("lite")
    scaler = joblib.load(config.LITE_SCALER_PATH)

    df = unsw.load(header_correction=header_correction, limit=limit)
    X = scaler.transform(df[config.LITE_FEATURES].to_numpy(np.float64)).astype(np.float32)
    is_attack = df["is_attack"].to_numpy()

    start = time.time()
    proba = model.predict_proba(X)
    elapsed = time.time() - start
    pred = proba.argmax(axis=1)
    conf = proba.max(axis=1)

    # "Flagged" means what the engine acts on: a non-benign class with at least
    # the minimum confidence the fusion policy requires.
    flagged = (pred != benign_idx) & (conf >= min_confidence)

    per_category = {}
    for category in sorted(df["category"].unique()):
        mask = (df["category"] == category).to_numpy()
        sub = pred[mask]
        names, counts = np.unique(sub, return_counts=True)
        top = sorted(zip(counts.tolist(), [classes[i] for i in names]), reverse=True)[:3]
        per_category[category] = {
            "flows": int(mask.sum()),
            "flagged_share": float(flagged[mask].mean()),
            "netra_class": unsw.CATEGORY_MAP.get(category),
            "predicted_as": [{"class": n, "share": round(c / int(mask.sum()), 4)} for c, n in top],
        }

    # Where a UNSW category maps onto a Netra class, did it get the right name?
    named = {}
    for category, target in unsw.CATEGORY_MAP.items():
        if not target or target == config.BENIGN_LABEL or category not in per_category:
            continue
        mask = (df["category"] == category).to_numpy()
        named[category] = {
            "netra_class": target,
            "flows": int(mask.sum()),
            "correct_class_share": float((pred[mask] == classes.index(target)).mean()),
            "flagged_share": float(flagged[mask].mean()),
        }

    sweep = []
    for t in (0.0, 0.5, 0.6, 0.7, 0.8, 0.9):
        f = (pred != benign_idx) & (conf >= t)
        sweep.append({"min_confidence": t,
                      "detection_rate": float(f[is_attack].mean()),
                      "false_positive_rate": float(f[~is_attack].mean())})

    result = {
        "dataset": "UNSW-NB15",
        "source": str(unsw.UNSW_PARQUET.name),
        "model": f"lite/{meta['best']}",
        "features": config.LITE_FEATURES,
        "header_correction": header_correction,
        "min_confidence": min_confidence,
        "scored_flows": int(len(df)),
        "seconds": round(elapsed, 1),
        "summary": unsw.summary(df),
        "binary": {
            "detection_rate": float(flagged[is_attack].mean()),
            "false_positive_rate": float(flagged[~is_attack].mean()),
            "attacks": int(is_attack.sum()),
            "attacks_flagged": int(flagged[is_attack].sum()),
            "benign": int((~is_attack).sum()),
            "benign_flagged": int(flagged[~is_attack].sum()),
        },
        "in_domain_cicids2017": _in_domain(),
        "per_category": per_category,
        "named_categories": named,
        "confidence_sweep": sweep,
    }
    return result


def feature_shift(df, limit: int | None = 400_000) -> list[dict]:
    """Compare each lite feature between the two datasets.

    A transfer failure is only half a result without the reason for it. This
    puts the median of every feature side by side, for benign and attack flows
    in each dataset, which is the evidence for whether the model was asked to
    generalise or asked to extrapolate.
    """
    from src.data.preprocess import CLASS_COLUMN, load_split

    try:
        cic = load_split("test")
    except FileNotFoundError:
        return []
    if limit:
        cic = cic.iloc[:limit]
    cic_benign = cic[cic[CLASS_COLUMN] == config.BENIGN_LABEL]
    cic_attack = cic[cic[CLASS_COLUMN] != config.BENIGN_LABEL]
    unsw_benign = df[~df["is_attack"]]
    unsw_attack = df[df["is_attack"]]

    rows = []
    for f in config.LITE_FEATURES:
        cb, ca = float(cic_benign[f].median()), float(cic_attack[f].median())
        ub, ua = float(unsw_benign[f].median()), float(unsw_attack[f].median())
        rows.append({
            "feature": f,
            "cic_benign": cb, "cic_attack": ca,
            "unsw_benign": ub, "unsw_attack": ua,
            # How far the benign baseline itself moves between datasets.
            "benign_ratio": (ub / cb) if cb else float("inf"),
        })
    return rows


def run(header_correction_variant: bool = True, limit: int | None = None) -> dict:
    """Main entry point: evaluate, write the report and the figure."""
    primary = evaluate(header_correction=False, limit=limit)
    variants = {"uncorrected": primary["binary"]}
    if header_correction_variant:
        corrected = evaluate(header_correction=True, limit=limit)
        variants["header_corrected"] = corrected["binary"]
        primary["header_corrected"] = corrected

    primary["variants"] = variants
    try:
        primary["feature_shift"] = feature_shift(unsw.load(limit=limit))
    except Exception:
        log.warning("feature shift comparison unavailable", exc_info=True)
        primary["feature_shift"] = []
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(primary, indent=2))
    write_markdown(primary)
    try:
        plot(primary, PLOT_PATH)
    except Exception:
        log.warning("cross-dataset figure could not be drawn", exc_info=True)
    return primary


def write_markdown(r: dict) -> None:
    b, dom = r["binary"], r.get("in_domain_cicids2017") or {}
    s = r["summary"]
    lines = [
        "# Cross-dataset evaluation: CIC-IDS2017 -> UNSW-NB15",
        "",
        "The lite model, its scaler and the feature code are used exactly as the live",
        "system loads them. Nothing was retrained or refitted; only the data is new.",
        "Generated by `python -m src.cli cross-eval`.",
        "",
        f"- Model: **{r['model']}**, {len(r['features'])} features",
        f"- Scored: **{r['scored_flows']:,}** UNSW-NB15 flows "
        f"({s['attacks']:,} attack, {s['benign']:,} benign) in {r['seconds']} s",
        f"- Counted as flagged: any non-benign class at confidence >= {r['min_confidence']}",
        "",
        "## Headline: does it transfer?",
        "",
        "| Measure | CIC-IDS2017 (in domain) | UNSW-NB15 (unseen) |",
        "|---|---|---|",
    ]
    if dom:
        lines.append(f"| Detection rate | {dom['detection_rate']:.4f} | "
                     f"**{b['detection_rate']:.4f}** |")
        lines.append(f"| False-positive rate | {dom['false_positive_rate']:.5f} | "
                     f"**{b['false_positive_rate']:.5f}** |")
    else:
        lines.append(f"| Detection rate | (run evaluate first) | **{b['detection_rate']:.4f}** |")
        lines.append(f"| False-positive rate | (run evaluate first) | "
                     f"**{b['false_positive_rate']:.5f}** |")
    lines += [
        "",
        f"{b['attacks_flagged']:,} of {b['attacks']:,} attack flows flagged; "
        f"{b['benign_flagged']:,} of {b['benign']:,} benign flows wrongly flagged.",
        "",
        "## By attack category",
        "",
        "Seven of the ten UNSW-NB15 categories describe attacks that have no class in",
        "Netra's label set, so for those the only meaningful question is whether the",
        "flow was flagged as *something*, not whether it was named correctly.",
        "",
        "| UNSW category | Flows | Flagged | Netra class | Most often predicted |",
        "|---|---|---|---|---|",
    ]
    for name, c in sorted(r["per_category"].items(), key=lambda kv: -kv[1]["flows"]):
        target = c["netra_class"] or "(no equivalent)"
        top = ", ".join(f"{p['class']} {p['share']:.0%}" for p in c["predicted_as"])
        lines.append(f"| {name} | {c['flows']:,} | {c['flagged_share']:.1%} | {target} | {top} |")

    if r.get("named_categories"):
        lines += ["", "### Categories with a direct Netra equivalent", "",
                  "| UNSW category | Netra class | Flows | Named correctly | Flagged at all |",
                  "|---|---|---|---|---|"]
        for name, c in r["named_categories"].items():
            lines.append(f"| {name} | {c['netra_class']} | {c['flows']:,} | "
                         f"{c['correct_class_share']:.1%} | {c['flagged_share']:.1%} |")

    lines += ["", "## Confidence threshold sweep", "",
              "| Minimum confidence | Detection rate | False-positive rate |", "|---|---|---|"]
    for row in r["confidence_sweep"]:
        lines.append(f"| {row['min_confidence']:.1f} | {row['detection_rate']:.4f} | "
                     f"{row['false_positive_rate']:.5f} |")

    if "header_corrected" in r:
        hc = r["header_corrected"]["binary"]
        lines += [
            "", "## Byte-accounting sensitivity", "",
            "CIC-IDS2017 counts transport payload bytes; UNSW-NB15 counts whole packets",
            "including headers. Subtracting an estimated 40 header bytes per packet",
            "approximates payload and isolates how much of the result is caused by that",
            "mismatch rather than by the traffic itself.",
            "",
            "| Byte accounting | Detection rate | False-positive rate |",
            "|---|---|---|",
            f"| As published (with headers) | {b['detection_rate']:.4f} | "
            f"{b['false_positive_rate']:.5f} |",
            f"| Header-corrected (approx. payload) | {hc['detection_rate']:.4f} | "
            f"{hc['false_positive_rate']:.5f} |",
        ]

    if r.get("feature_shift"):
        lines += [
            "", "## Why it fails: the features do not mean the same thing", "",
            "Median value of each feature, by dataset and by class. The model was not",
            "asked to generalise to new attacks; it was asked to extrapolate to a network",
            "whose ordinary traffic sits where its training data put attacks.",
            "",
            "| Feature | CIC benign | CIC attack | UNSW benign | UNSW attack | benign shift |",
            "|---|---|---|---|---|---|",
        ]
        for s in r["feature_shift"]:
            lines.append(
                f"| {s['feature']} | {s['cic_benign']:,.2f} | {s['cic_attack']:,.2f} | "
                f"{s['unsw_benign']:,.2f} | {s['unsw_attack']:,.2f} | {s['benign_ratio']:,.1f}x |")
        lines += [
            "",
            "The decisive row is `packets_per_sec`. In CIC-IDS2017 a benign flow runs at",
            "about 66 packets/s and attack flows are far slower, so the model learned that",
            "low rates are suspicious. In UNSW-NB15 ordinary traffic runs two orders of",
            "magnitude faster, and its *attacks* sit at roughly the rate CIC-IDS2017 calls",
            "normal. The learned boundary is not merely in the wrong place, it points the",
            "wrong way.",
        ]

    lines += ["", "![Cross-dataset results](cross_dataset.png)", ""]
    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")


def plot(r: dict, path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from src.models.evaluate import GRID, INK, INK_2, MUTED, SURFACE, _style

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.8), facecolor=SURFACE,
                                   gridspec_kw={"width_ratios": [1, 1.25]})
    for ax in (ax1, ax2):
        _style(ax)

    dom = r.get("in_domain_cicids2017") or {}
    b = r["binary"]
    labels = ["Detection rate", "False-positive rate"]
    here = [b["detection_rate"], b["false_positive_rate"]]
    there = [dom.get("detection_rate", 0.0), dom.get("false_positive_rate", 0.0)]
    x = np.arange(len(labels))
    ax1.bar(x - 0.19, there, width=0.36, color="#2a78d6", label="CIC-IDS2017 (in domain)")
    ax1.bar(x + 0.19, here, width=0.36, color="#eb6834", label="UNSW-NB15 (unseen)")
    for xi, v in zip(x - 0.19, there):
        ax1.text(xi, v + 0.02, f"{v:.3f}", ha="center", fontsize=8.5, color=INK_2)
    for xi, v in zip(x + 0.19, here):
        ax1.text(xi, v + 0.02, f"{v:.3f}", ha="center", fontsize=8.5, color=INK_2)
    ax1.set_xticks(x, labels, color=INK_2)
    ax1.set_ylim(0, 1.12)
    ax1.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax1.set_axisbelow(True)
    ax1.legend(frameon=False, fontsize=9, labelcolor=INK_2)
    ax1.set_title("Same model, different dataset", color=INK, fontsize=11, loc="left")

    # Right panel: why it failed. Median of each feature in both datasets, on a
    # log axis, so the overlap between "UNSW benign" and "CIC attack" is visible.
    shift = r.get("feature_shift") or []
    if shift:
        names = [s["feature"] for s in shift]
        y = np.arange(len(names))
        series = [
            ("cic_benign", "CIC benign", "#2a78d6", "o"),
            ("cic_attack", "CIC attack", "#1b4f8a", "s"),
            ("unsw_benign", "UNSW benign", "#f2a65a", "o"),
            ("unsw_attack", "UNSW attack", "#c2410c", "s"),
        ]
        for key, label, color, marker in series:
            vals = [max(float(s[key]), 1e-3) for s in shift]
            ax2.scatter(vals, y, s=46, color=color, marker=marker, label=label,
                        zorder=3, edgecolor="white", linewidth=0.6)
        for yi in y:
            ax2.axhline(yi, color=GRID, linewidth=0.7, zorder=1)
        ax2.set_xscale("log")
        ax2.set_yticks(y, names, color=INK_2, fontsize=9)
        ax2.invert_yaxis()
        ax2.set_xlabel("Median value (log scale)", color=INK_2)
        ax2.legend(frameon=False, fontsize=8, labelcolor=INK_2, ncol=2, loc="lower right")
        ax2.set_title("Why: the same feature means different things",
                      color=INK, fontsize=11, loc="left")
    else:
        cats = sorted(((c, v) for c, v in r["per_category"].items() if c != "normal"),
                      key=lambda kv: kv[1]["flagged_share"])
        names = [c for c, _ in cats]
        shares = [v["flagged_share"] for _, v in cats]
        ax2.barh(names, shares, height=0.6, color="#eb6834")
        ax2.set_xlim(0, 1.15)
        ax2.set_xlabel("Share of flows flagged as an attack", color=INK_2)
        ax2.set_title("UNSW-NB15 attack categories", color=INK, fontsize=11, loc="left")
    ax2.set_axisbelow(True)

    fig.text(0.01, 0.01, "Trained on CIC-IDS2017 only. No retraining, refitting or threshold "
                         "tuning was done for this evaluation.", color=MUTED, fontsize=8)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def print_summary(r: dict) -> None:
    b, dom = r["binary"], r.get("in_domain_cicids2017") or {}
    print(f"\nScored {r['scored_flows']:,} UNSW-NB15 flows with {r['model']} in {r['seconds']} s")
    print(f"  (trained on CIC-IDS2017 only, nothing retrained)\n")
    if dom:
        print(f"  {'':22s} {'CIC-IDS2017':>14s} {'UNSW-NB15':>14s}")
        print(f"  {'detection rate':22s} {dom['detection_rate']:>14.4f} {b['detection_rate']:>14.4f}")
        print(f"  {'false-positive rate':22s} {dom['false_positive_rate']:>14.5f} "
              f"{b['false_positive_rate']:>14.5f}")
    else:
        print(f"  detection rate       {b['detection_rate']:.4f}")
        print(f"  false-positive rate  {b['false_positive_rate']:.5f}")
    print(f"\n  {b['attacks_flagged']:,}/{b['attacks']:,} attacks flagged, "
          f"{b['benign_flagged']:,}/{b['benign']:,} benign wrongly flagged")
    print("\nBy category:")
    for name, c in sorted(r["per_category"].items(), key=lambda kv: -kv[1]["flows"]):
        target = c["netra_class"] or "-"
        print(f"  {name:16s} {c['flows']:>9,}  flagged {c['flagged_share']:>6.1%}   {target}")
    print(f"\nWritten to {REPORT_MD.name}, {REPORT_JSON.name} and {PLOT_PATH.name} in reports/")
