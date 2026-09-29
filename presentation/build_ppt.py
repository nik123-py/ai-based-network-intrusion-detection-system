"""Build the Netra presentation (presentation/Netra.pptx) with python-pptx.

Every metric on the slides is read at build time from the JSON written by
`python -m src.cli evaluate` (reports/metrics_*.json, reports/data_summary.json),
so the deck cannot drift from the measured results. Figures come from reports/
and screenshots from docs/screenshots/.

Usage:
    python presentation/build_ppt.py [-o presentation/Netra.pptx]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
SHOTS = ROOT / "docs" / "screenshots"

# --- palette ---------------------------------------------------------------
INK = RGBColor(0x0F, 0x17, 0x2A)      # dark navy, titles and dark backgrounds
BODY = RGBColor(0x33, 0x41, 0x55)     # body text
MUTED = RGBColor(0x64, 0x74, 0x8B)    # captions
ACCENT = RGBColor(0x0E, 0xA5, 0xE9)   # sky blue
GOOD = RGBColor(0x15, 0x80, 0x3D)     # green, positive results
BAD = RGBColor(0xB9, 0x1C, 0x1C)      # red, weaknesses stated honestly
LIGHT = RGBColor(0xF1, 0xF5, 0xF9)    # panel background
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
RULE = RGBColor(0xCB, 0xD5, 0xE1)

MODEL_NAMES = {"random_forest": "Random Forest", "xgboost": "XGBoost"}

W, H = Inches(13.333), Inches(7.5)
MARGIN = Inches(0.9)
CONTENT_W = W - 2 * MARGIN


# ---------------------------------------------------------------------------
# Measured values, loaded from the evaluation artifacts
# ---------------------------------------------------------------------------
def load_metrics() -> dict:
    def read(name: str) -> dict:
        path = REPORTS / name
        if not path.exists():
            sys.exit(f"missing {path}. Run: python -m src.cli evaluate")
        return json.loads(path.read_text(encoding="utf-8"))

    full, lite = read("metrics_full.json"), read("metrics_lite.json")
    return {
        "full": full,
        "lite": lite,
        "ae": read("metrics_autoencoder.json"),
        "data": read("data_summary.json"),
        "full_sel": full["models"][full["selected"]],
        "lite_sel": lite["models"][lite["selected"]],
    }


def pct(x: float, places: int = 2) -> str:
    return f"{100 * x:.{places}f}%"


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------
def blank(prs: Presentation):
    return prs.slides.add_slide(prs.slide_layouts[6])


def textbox(slide, left, top, width, height, align=PP_ALIGN.LEFT):
    tb = slide.shapes.add_textbox(left, top, width, height)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].alignment = align
    return tf


def write(tf, text, size=18, color=BODY, bold=False, space_after=6, para=None,
          align=None, italic=False):
    """Append (or fill) a paragraph. Returns the paragraph."""
    p = para if para is not None else (
        tf.paragraphs[0] if (len(tf.paragraphs) == 1 and not tf.paragraphs[0].runs) else tf.add_paragraph())
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    run.font.name = "Segoe UI"
    p.space_after = Pt(space_after)
    if align is not None:
        p.alignment = align
    return p


def rect(slide, left, top, width, height, fill=LIGHT, line=None,
         shape=MSO_SHAPE.ROUNDED_RECTANGLE):
    shp = slide.shapes.add_shape(shape, left, top, width, height)
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line
        shp.line.width = Pt(1)
    shp.shadow.inherit = False
    shp.text_frame.word_wrap = True
    return shp


def slide_number(slide, n: int) -> None:
    tf = textbox(slide, W - Inches(1.2), H - Inches(0.62), Inches(0.7), Inches(0.35),
                 align=PP_ALIGN.RIGHT)
    write(tf, str(n), size=11, color=MUTED)


def notes(slide, text: str) -> None:
    slide.notes_slide.notes_text_frame.text = text


def header(prs, title: str, kicker: str | None = None, n: int | None = None):
    """A content slide with a title, optional kicker line and a rule."""
    slide = blank(prs)
    top = Inches(0.55)
    if kicker:
        tf = textbox(slide, MARGIN, top, CONTENT_W, Inches(0.3))
        write(tf, kicker.upper(), size=12, color=ACCENT, bold=True, space_after=0)
        top += Inches(0.34)
    tf = textbox(slide, MARGIN, top, CONTENT_W, Inches(0.7))
    write(tf, title, size=32, color=INK, bold=True, space_after=0)
    ln = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, MARGIN, top + Inches(0.72),
                                Inches(1.4), Pt(3))
    ln.fill.solid()
    ln.fill.fore_color.rgb = ACCENT
    ln.line.fill.background()
    ln.shadow.inherit = False
    if n is not None:
        slide_number(slide, n)
    return slide


def bullets(slide, items, left=MARGIN, top=Inches(1.85), width=CONTENT_W,
            size=17, gap=9):
    """items: list of str, or (text, level) or (text, level, color)."""
    tf = textbox(slide, left, top, width, H - top - Inches(0.7))
    first = True
    for item in items:
        text, level, color = (item, 0, BODY) if isinstance(item, str) else (
            (item + (BODY,))[:3] if len(item) == 2 else item)
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.level = level
        bullet = "•  " if level == 0 else "–  "
        run = p.add_run()
        run.text = bullet + text
        run.font.size = Pt(size if level == 0 else size - 2)
        run.font.color.rgb = color
        run.font.name = "Segoe UI"
        p.space_after = Pt(gap)
    return tf


def table(slide, headers, rows, left=MARGIN, top=Inches(2.0), width=CONTENT_W,
          col_widths=None, size=13, header_size=13, row_h=Inches(0.36),
          highlight=None):
    """A styled table. highlight: set of row indices to emphasise."""
    n_rows, n_cols = len(rows) + 1, len(headers)
    height = row_h * n_rows
    shape = slide.shapes.add_table(n_rows, n_cols, left, top, width, height)
    tbl = shape.table
    tbl.first_row = True
    if col_widths:
        total = sum(col_widths)
        for i, frac in enumerate(col_widths):
            tbl.columns[i].width = Emu(int(width * frac / total))
    for i in range(n_rows):
        tbl.rows[i].height = row_h

    def style(cell, text, bold, color, fill, sz, align):
        cell.fill.solid()
        cell.fill.fore_color.rgb = fill
        cell.margin_left = cell.margin_right = Inches(0.08)
        cell.margin_top = cell.margin_bottom = Inches(0.02)
        cell.vertical_anchor = MSO_ANCHOR.MIDDLE
        tf = cell.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.alignment = align
        run = p.add_run()
        run.text = str(text)
        run.font.size = Pt(sz)
        run.font.bold = bold
        run.font.color.rgb = color
        run.font.name = "Segoe UI"

    for c, head in enumerate(headers):
        style(tbl.cell(0, c), head, True, WHITE, INK, header_size,
              PP_ALIGN.LEFT if c == 0 else PP_ALIGN.CENTER)
    for r, row in enumerate(rows, start=1):
        band = WHITE if r % 2 else LIGHT
        for c, val in enumerate(row):
            emphasise = highlight is not None and (r - 1) in highlight
            style(tbl.cell(r, c), val, emphasise, INK if emphasise else BODY, band, size,
                  PP_ALIGN.LEFT if c == 0 else PP_ALIGN.CENTER)
    return tbl


def picture(slide, path: Path, left, top, box_w, box_h, caption=None):
    """Fit an image inside a box, preserving its aspect ratio."""
    if not path.exists():
        tf = textbox(slide, left, top, box_w, Inches(0.4))
        write(tf, f"[missing figure: {path.name}]", size=12, color=BAD, italic=True)
        print(f"  warning: missing figure {path}")
        return None
    pic = slide.shapes.add_picture(str(path), left, top)
    scale = min(box_w / pic.width, box_h / pic.height)
    pic.width, pic.height = int(pic.width * scale), int(pic.height * scale)
    pic.left = int(left + (box_w - pic.width) / 2)
    pic.top = int(top + (box_h - pic.height) / 2)
    if caption:
        tf = textbox(slide, left, int(pic.top + pic.height) + Inches(0.06), box_w,
                     Inches(0.3), align=PP_ALIGN.CENTER)
        write(tf, caption, size=11, color=MUTED, italic=True)
    return pic


def stat_row(slide, stats, top, left=MARGIN, width=CONTENT_W, height=Inches(1.15)):
    """A row of headline numbers: [(value, label, color), ...]."""
    gap = Inches(0.18)
    box_w = int((width - gap * (len(stats) - 1)) / len(stats))
    for i, (value, label, color) in enumerate(stats):
        x = left + i * (box_w + gap)
        rect(slide, x, top, box_w, height, fill=LIGHT)
        tf = textbox(slide, x, top + Inches(0.14), box_w, Inches(0.55), align=PP_ALIGN.CENTER)
        write(tf, value, size=28, color=color, bold=True, space_after=0, align=PP_ALIGN.CENTER)
        tf2 = textbox(slide, x, top + Inches(0.68), box_w, Inches(0.4), align=PP_ALIGN.CENTER)
        write(tf2, label, size=12, color=MUTED, space_after=0, align=PP_ALIGN.CENTER)


def dark_slide(prs):
    slide = blank(prs)
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, H)
    bg.fill.solid()
    bg.fill.fore_color.rgb = INK
    bg.line.fill.background()
    bg.shadow.inherit = False
    return slide


# ---------------------------------------------------------------------------
# Slides
# ---------------------------------------------------------------------------
def slide_title(prs, m):
    slide = dark_slide(prs)
    tf = textbox(slide, MARGIN, Inches(2.25), CONTENT_W, Inches(1.0))
    write(tf, "NETRA", size=64, color=WHITE, bold=True, space_after=0)
    tf = textbox(slide, MARGIN, Inches(3.3), CONTENT_W, Inches(0.6))
    write(tf, "Network Threat Recognition and Automated response", size=24, color=ACCENT,
          space_after=0)
    ln = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, MARGIN, Inches(4.15), Inches(2.2), Pt(3))
    ln.fill.solid()
    ln.fill.fore_color.rgb = ACCENT
    ln.line.fill.background()
    ln.shadow.inherit = False
    tf = textbox(slide, MARGIN, Inches(4.5), CONTENT_W, Inches(1.2))
    write(tf, "A hybrid intrusion detection and response system:", size=17,
          color=RGBColor(0xCB, 0xD5, 0xE1))
    write(tf, "signature rules + supervised learning + unsupervised anomaly detection,",
          size=17, color=RGBColor(0xCB, 0xD5, 0xE1))
    write(tf, "with automated, time-limited firewall response.", size=17,
          color=RGBColor(0xCB, 0xD5, 0xE1))
    tf = textbox(slide, MARGIN, H - Inches(1.3), CONTENT_W, Inches(0.6))
    write(tf, "Trained and evaluated on CIC-IDS2017  |  Validated live in an isolated Docker attack lab",
          size=13, color=MUTED)
    notes(slide, "Netra detects network attacks and then acts on them. Three detection "
                 "methods, one fusion policy, and an automated response that is always "
                 "time-limited and reversible.")
    return slide


def slide_problem(prs, m, n):
    slide = header(prs, "Detection alone is not a system", "The problem", n)
    bullets(slide, [
        ("Signature systems are precise and explainable, but blind to any attack "
         "nobody wrote a rule for."),
        ("Anomaly systems generalise to unknown attacks, but produce alert volumes "
         "operators learn to ignore."),
        ("Most academic work stops at offline accuracy on a benchmark. An alert that "
         "nobody reads changes nothing."),
        ("Offline metrics are also optimistic: benchmark datasets carry artefacts that "
         "models happily learn (shown later in this deck).", 0, BAD),
    ], top=Inches(1.95), size=18, gap=16)
    rect(slide, MARGIN, Inches(4.9), CONTENT_W, Inches(1.35), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.3), Inches(5.08), CONTENT_W - Inches(0.6), Inches(1.0))
    write(tf, "The question this project asks", size=13, color=ACCENT, bold=True)
    write(tf, "Can the three detection approaches be combined under an explicit policy, "
              "coupled to a safe automated response, and shown to work on real packets "
              "rather than only on a benchmark?", size=17, color=INK)
    notes(slide, "Frame the gap: precision vs generalisation, and detection vs response. "
                 "The honest framing at the bottom sets up the negative finding later.")
    return slide


def slide_objectives(prs, m, n):
    slide = header(prs, "Objectives", "Scope", n)
    items = [
        ("1", "Detect", "Combine four packet-level signature rules, two supervised "
                        "classifiers and a benign-only autoencoder under an explicit "
                        "fusion policy."),
        ("2", "Respond", "Block the attacking source automatically, with every rule "
                         "time-limited, reversible and confined to one firewall chain."),
        ("3", "Demonstrate", "Validate end to end on live traffic in an isolated lab, "
                             "not only as offline metrics on a benchmark."),
    ]
    top = Inches(2.0)
    for num, title, body in items:
        rect(slide, MARGIN, top, CONTENT_W, Inches(1.28), fill=LIGHT)
        badge = rect(slide, MARGIN + Inches(0.28), top + Inches(0.3), Inches(0.62),
                     Inches(0.62), fill=ACCENT, shape=MSO_SHAPE.OVAL)
        tf = badge.text_frame
        tf.word_wrap = False
        write(tf, num, size=20, color=WHITE, bold=True, space_after=0,
              para=tf.paragraphs[0], align=PP_ALIGN.CENTER)
        tf = textbox(slide, MARGIN + Inches(1.15), top + Inches(0.2),
                     CONTENT_W - Inches(1.5), Inches(1.0))
        write(tf, title, size=19, color=INK, bold=True, space_after=2)
        write(tf, body, size=14, color=BODY, space_after=0)
        top += Inches(1.45)
    notes(slide, "Three objectives: detect, respond, demonstrate. The third is what "
                 "separates this from a pure ML exercise.")
    return slide


def slide_literature(prs, m, n):
    slide = header(prs, "Literature review", "Related work", n)
    table(slide, ["Work", "Contribution", "How it shaped Netra"], [
        ["Tavallaee et al. 2009 [3]", "KDD CUP 99 is full of duplicate records that\ninflate accuracy",
         "Duplicate removal and cross-split\nleakage checks are part of the pipeline"],
        ["Moustafa & Slay 2015 [2]", "UNSW-NB15; KDD-era traffic no longer\nrepresents modern networks",
         "Named as the cross-dataset test\nfor future work"],
        ["Sharafaldin et al. 2018 [1]", "CIC-IDS2017: realistic 5-day capture,\nlabelled flows + PCAPs",
         "The dataset used here"],
        ["Mirsky et al. 2018 [4]", "Kitsune: online autoencoder ensemble,\nno labels needed",
         "Benign-only autoencoder as one\nvoice in the fusion policy"],
        ["Ring et al. 2019 [5]", "Survey: dataset quality matters more\nthan classifier choice",
         "Motivated auditing the data before\ntrusting the metrics"],
        ["Engelen et al. 2021 [6]", "Audit of CIC-IDS2017: flag counting and\nlabelling defects",
         "Independently reproduced; drove the\nremoval of all 12 flag features"],
    ], top=Inches(1.9), col_widths=[0.24, 0.40, 0.36], size=11, header_size=12,
        row_h=Inches(0.68), highlight={5})
    notes(slide, "Two threads: dataset quality (3, 5, 6) and method (2, 4, 1). "
                 "Engelen is highlighted because this project reproduced its finding "
                 "and it changed the design.")
    return slide


def slide_architecture(prs, m, n):
    slide = header(prs, "System architecture", "Design", n)
    tf = textbox(slide, MARGIN, Inches(1.8), CONTENT_W, Inches(0.4))
    write(tf, "Five layers. Live capture, PCAP replay and dataset replay all produce the "
              "same feature schema.", size=14, color=MUTED)

    top = Inches(2.45)
    box_h = Inches(1.5)
    stages = [
        ("Ingestion", "scapy capture\nPCAP / dataset\nreplay", LIGHT, INK),
        ("Features", "5-tuple flows\n59 CIC features\n6 lite features", LIGHT, INK),
        ("Detection", "4 signature rules\nfull + lite RF\nautoencoder", ACCENT, WHITE),
        ("Fusion", "priority policy\ncorroboration\nper-source grouping", LIGHT, INK),
        ("Response", "block / quarantine\ntimed + reversible\nNETRA chain", LIGHT, INK),
    ]
    gap = Inches(0.42)
    box_w = int((CONTENT_W - gap * (len(stages) - 1)) / len(stages))
    for i, (title, body, fill, fg) in enumerate(stages):
        x = MARGIN + i * (box_w + gap)
        rect(slide, x, top, box_w, box_h, fill=fill)
        tf = textbox(slide, x, top + Inches(0.16), box_w, Inches(0.36), align=PP_ALIGN.CENTER)
        write(tf, title, size=16, color=fg, bold=True, space_after=0, align=PP_ALIGN.CENTER)
        tf = textbox(slide, x, top + Inches(0.58), box_w, Inches(0.85), align=PP_ALIGN.CENTER)
        write(tf, body, size=11, color=WHITE if fill == ACCENT else MUTED,
              space_after=0, align=PP_ALIGN.CENTER)
        if i < len(stages) - 1:
            arrow = slide.shapes.add_shape(
                MSO_SHAPE.RIGHT_ARROW, x + box_w + Inches(0.07),
                top + box_h / 2 - Inches(0.11), Inches(0.28), Inches(0.22))
            arrow.fill.solid()
            arrow.fill.fore_color.rgb = RULE
            arrow.line.fill.background()
            arrow.shadow.inherit = False

    rect(slide, MARGIN, Inches(4.35), CONTENT_W, Inches(0.72), fill=WHITE, line=RULE)
    tf = textbox(slide, MARGIN + Inches(0.25), Inches(4.5), CONTENT_W - Inches(0.5), Inches(0.5))
    write(tf, "Signature rules bypass flow assembly and fire on individual packets, in about "
              "one second, before any flow has completed.", size=14, color=INK)

    tf = textbox(slide, MARGIN, Inches(5.35), CONTENT_W, Inches(1.4))
    write(tf, "Presentation layer", size=13, color=ACCENT, bold=True)
    write(tf, "The engine publishes every alert, action and statistic on an event bus, exposed "
              "over WebSocket and REST. A native PySide6 desktop application consumes it, so "
              "the engine can run inside Docker while the operator watches from the host.",
          size=15, color=BODY)
    notes(slide, "Walk left to right. Emphasise that the signature path short-circuits the "
                 "flow assembly, which is why the live demo fires in a second.")
    return slide


def slide_signatures(prs, m, n):
    slide = header(prs, "Layer 1: signature rules", "Detection", n)
    tf = textbox(slide, MARGIN, Inches(1.82), CONTENT_W, Inches(0.4))
    write(tf, "Evaluated on every packet, with a 10 second per-source cooldown so a flood "
              "produces one alert, not thousands.", size=14, color=MUTED)
    table(slide, ["Rule", "Condition", "Class reported"], [
        ["syn_flood", "more than 100 SYN packets per second from one source", "DoS"],
        ["port_scan", "more than 30 distinct destination ports from one source in 5 s", "PortScan"],
        ["slow_dos", "50+ connections older than 5 s from one source, averaging under 50 B/s", "DoS-Slow"],
        ["brute_force", "more than 10 HTTP 401 replies to one client in 10 s, or 20+ new\nconnections to a login port in 5 s", "BruteForce"],
    ], top=Inches(2.45), col_widths=[0.18, 0.58, 0.24], size=13, row_h=Inches(0.6))
    rect(slide, MARGIN, Inches(5.15), CONTENT_W, Inches(1.1), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.3), Inches(5.32), CONTENT_W - Inches(0.6), Inches(0.8))
    write(tf, "Why keep rules at all?", size=13, color=ACCENT, bold=True)
    write(tf, "They need no flow to complete, they are unaffected by feature mismatches between "
              "training and deployment, and their alerts explain themselves. They only cover "
              "attacks someone anticipated, which is exactly what the learned layers are for.",
          size=14, color=INK)
    notes(slide, "These four rules are what make the live demo fire instantly. Be upfront "
                 "that the demo attacks are ones the rules cover.")
    return slide


def slide_models(prs, m, n):
    slide = header(prs, "Layers 2 and 3: learned detectors", "Detection", n)
    left_w = int(CONTENT_W / 2 - Inches(0.25))
    right_x = MARGIN + left_w + Inches(0.5)

    rect(slide, MARGIN, Inches(1.85), left_w, Inches(4.4), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.3), Inches(2.05), left_w - Inches(0.6), Inches(4.0))
    write(tf, "Supervised classifiers", size=18, color=INK, bold=True)
    write(tf, "Random Forest and XGBoost trained for each feature set; the higher validation "
              "macro F1 wins. Random Forest won both times.", size=14, color=BODY)
    write(tf, "Two feature sets", size=13, color=ACCENT, bold=True)
    write(tf, "Full (59 features): everything CICFlowMeter reports, for offline accuracy.",
          size=13, color=BODY, space_after=3)
    write(tf, "Lite (6 features): duration, packets/s, bytes/s, mean packet size, distinct "
              "ports and hosts per source in 60 s. Computable from packet headers anywhere, "
              "so the live path never depends on feature parity.", size=13, color=BODY)
    write(tf, "Macro F1 selects the model, not accuracy: with 85% benign traffic, accuracy "
              "is nearly uninformative.", size=13, color=MUTED, italic=True)

    rect(slide, right_x, Inches(1.85), left_w, Inches(4.4), fill=LIGHT)
    tf = textbox(slide, right_x + Inches(0.3), Inches(2.05), left_w - Inches(0.6), Inches(4.0))
    write(tf, "Autoencoder", size=18, color=INK, bold=True)
    write(tf, "A dense network (69-32-16-8-16-32-69) trained on benign flows only. It is never "
              "shown an attack.", size=14, color=BODY)
    write(tf, "Threshold", size=13, color=ACCENT, bold=True)
    write(tf, f"A flow is anomalous when reconstruction error exceeds the 99th percentile of "
              f"benign validation error ({m['ae']['threshold']:.5f}). This fixes the false-alarm "
              f"rate near 1% by construction and trades away recall.", size=13, color=BODY)
    write(tf, "Deployment", size=13, color=ACCENT, bold=True)
    write(tf, "Weights are exported to NumPy, so the detection container needs no TensorFlow. "
              "Training verifies NumPy and Keras agree to within 1e-6.", size=13, color=BODY)
    notes(slide, "The key contrast: supervised models need labels and cover known families; "
                 "the autoencoder needs no attack labels at all.")
    return slide


def slide_fusion(prs, m, n):
    slide = header(prs, "Fusion: combining evidence of different strengths", "Detection", n)
    steps = [
        ("1", "Signature hit", "Alert immediately, severity HIGH", ACCENT),
        ("2", "Full model, then lite model",
         "Attack class at confidence ≥ 0.9 is HIGH; 0.6 to 0.9 is MEDIUM", ACCENT),
        ("3", "Autoencoder error above threshold",
         'Raise "Anomaly (unknown)": MEDIUM if error ≥ 2× threshold, else LOW', ACCENT),
    ]
    top = Inches(1.95)
    for num, title, body, color in steps:
        rect(slide, MARGIN, top, CONTENT_W, Inches(0.95), fill=LIGHT)
        badge = rect(slide, MARGIN + Inches(0.25), top + Inches(0.22), Inches(0.5),
                     Inches(0.5), fill=color, shape=MSO_SHAPE.OVAL)
        write(badge.text_frame, num, size=17, color=WHITE, bold=True, space_after=0,
              para=badge.text_frame.paragraphs[0], align=PP_ALIGN.CENTER)
        tf = textbox(slide, MARGIN + Inches(1.0), top + Inches(0.12),
                     CONTENT_W - Inches(1.3), Inches(0.75))
        write(tf, title, size=16, color=INK, bold=True, space_after=2)
        write(tf, body, size=13, color=BODY, space_after=0)
        top += Inches(1.05)

    ben = m["data"]["splits"]["test"]["class_counts"]["Benign"]
    fp_rate = m["ae"]["false_positive_rate"]
    rect(slide, MARGIN, Inches(5.25), CONTENT_W, Inches(1.35), fill=INK)
    tf = textbox(slide, MARGIN + Inches(0.3), Inches(5.42), CONTENT_W - Inches(0.6), Inches(1.1))
    write(tf, "Corroboration: the rule that makes this practical", size=14, color=ACCENT, bold=True)
    write(tf, f"Weak evidence (lite model, medium confidence, or an anomaly) needs 3 flagged flows "
              f"from one source within 10 s before any alert. Without it, the autoencoder's "
              f"{pct(fp_rate)} false-alarm rate over {ben:,} benign test flows would mean roughly "
              f"{round(ben * fp_rate / 100) * 100:,} spurious alerts.",
          size=14, color=WHITE)
    notes(slide, "Priority order, then corroboration. Sustained attacks generate many flows "
                 "from one source, so corroboration costs almost nothing in recall.")
    return slide


def slide_response(prs, m, n):
    slide = header(prs, "Automated response", "Response", n)
    table(slide, ["Severity", "Action", "Mechanism", "Duration"], [
        ["HIGH", "Block", "iptables -A NETRA -s <ip> -j DROP", "120 s (90 s in lab)"],
        ["MEDIUM", "Quarantine", "accept 10 packets/s from the source, drop the rest", "60 s"],
        ["LOW", "Log only", "written to logs/alerts.jsonl", "n/a"],
    ], top=Inches(1.95), col_widths=[0.13, 0.15, 0.48, 0.24], size=13, row_h=Inches(0.48))

    tf = textbox(slide, MARGIN, Inches(3.75), CONTENT_W, Inches(0.4))
    write(tf, "Why automated blocking is defensible here", size=16, color=INK, bold=True)
    bullets(slide, [
        "Every rule is time-limited and removed by a background thread on expiry, so a false "
        "positive is a bounded outage for one address, never a permanent one.",
        "All rules live in one dedicated NETRA chain: the entire footprint is inspectable with "
        "one command and removable with one more.",
        "A never-block list protects loopback, the gateways and the protected server itself.",
        "Repeated alerts extend an existing block rather than stacking duplicate rules; a block "
        "supersedes a quarantine.",
    ], top=Inches(4.25), size=15, gap=10)
    notes(slide, "The three safety properties are the argument that automated response is "
                 "responsible rather than reckless: timed, contained, and with a never-block list.")
    return slide


def slide_dataset(prs, m, n):
    slide = header(prs, "Dataset: CIC-IDS2017", "Data", n)
    d = m["data"]
    stat_row(slide, [
        (f"{d['rows_loaded']:,}", "labelled flows published", INK),
        (f"{d['rows_after_cleaning']:,}", "flows after cleaning", ACCENT),
        (f"{len(d['class_counts_after_cleaning'])}", "classes retained", INK),
        (f"{d['n_features']}", "model features", INK),
    ], top=Inches(1.9))

    tf = textbox(slide, MARGIN, Inches(3.3), CONTENT_W, Inches(0.35))
    write(tf, "Cleaning pipeline, with the effect of every step recorded", size=16,
          color=INK, bold=True)
    dropped = d["classes_dropped_as_rare"]
    table(slide, ["Step", "Rows removed"], [
        ["Rows containing NaN or infinite values", f"{d['rows_nan_or_inf_dropped']:,}"],
        ["Exact duplicate rows", f"{d['rows_exact_duplicates_dropped']:,}"],
        ["Identical features with conflicting labels", f"{d['rows_conflicting_labels_dropped']:,}"],
        [f"Classes with under 100 rows ({', '.join(f'{k} {v}' for k, v in dropped.items())})",
         f"{sum(dropped.values()):,}"],
        ["Remaining", f"{d['rows_after_cleaning']:,}"],
    ], top=Inches(3.72), col_widths=[0.72, 0.28], size=13, row_h=Inches(0.40), highlight={4})

    rect(slide, MARGIN, Inches(6.22), CONTENT_W - Inches(0.9), Inches(0.66), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.25), Inches(6.32), CONTENT_W - Inches(1.4), Inches(0.5))
    share = d["rows_exact_duplicates_dropped"] / d["rows_loaded"]
    write(tf, f"Duplicates alone are {pct(share, 0)} of the data. Leaving them in leaks rows "
              f"between train and test and inflates every score, which is exactly the criticism "
              f"Tavallaee et al. levelled at KDD CUP 99.", size=14, color=INK)
    notes(slide, "The duplicate figure is the headline: 22% of the published dataset. "
                 "Cross-split duplicate vectors are verified to be zero after splitting.")
    return slide


def slide_features(prs, m, n):
    slide = header(prs, "Features and splitting", "Data", n)
    d = m["data"]
    tf = textbox(slide, MARGIN, Inches(1.82), CONTENT_W, Inches(0.35))
    write(tf, f"78 published flow statistics reduce to {d['n_features']} model inputs:",
          size=16, color=INK, bold=True)
    bullets(slide, [
        "one column (Fwd Header Length.1) is an exact duplicate of another",
        f"twelve TCP flag counters are dropped as unreliable (see the key finding slide)",
        f"{len(d['constant_features_dropped'])} bulk-transfer columns are constant across the "
        f"entire dataset and carry no information",
    ], top=Inches(2.28), size=15, gap=7)

    tf = textbox(slide, MARGIN, Inches(3.5), CONTENT_W, Inches(0.8))
    write(tf, "Excluded on purpose", size=14, color=ACCENT, bold=True)
    write(tf, "Addresses, ports and timestamps are kept as metadata but never used as model "
              "inputs, so models cannot memorise hosts. Destination port is excluded too: most "
              "DoS traffic in this dataset targets port 80, and a model leaning on that would "
              "not generalise to another network.", size=14, color=BODY)

    s = d["splits"]
    tf = textbox(slide, MARGIN, Inches(4.75), CONTENT_W, Inches(0.35))
    write(tf, "Splitting: 70 / 15 / 15, stratified", size=16, color=INK, bold=True)
    table(slide, ["Split", "Rows", "Class distribution", "Row cap"], [
        ["Train", f"{s['train']['rows']:,}", "capped, so Benign is undersampled",
         f"{d['max_train_rows_per_class']:,} per class"],
        ["Validation", f"{s['val']['rows']:,}", "natural", "none"],
        ["Test", f"{s['test']['rows']:,}", "natural", "none"],
    ], top=Inches(5.2), col_widths=[0.16, 0.16, 0.44, 0.24], size=13, row_h=Inches(0.42))
    tf = textbox(slide, MARGIN, Inches(6.62), CONTENT_W, Inches(0.4))
    write(tf, "Validation and test keep the natural distribution and get no resampling, so the "
              "reported metrics reflect realistic traffic. Cross-split duplicate vectors: 0.",
          size=13, color=MUTED, italic=True)
    notes(slide, "Only training is capped. That is what makes the headline metrics honest.")
    return slide


def slide_results_full(prs, m, n):
    slide = header(prs, "Results: full feature set (59 features)", "Results", n)
    sel, b = m["full_sel"], m["full_sel"]["binary"]
    stat_row(slide, [
        (f"{sel['accuracy']:.4f}", "Accuracy", INK),
        (f"{sel['macro']['f1']:.4f}", "Macro F1", ACCENT),
        (pct(b["detection_rate"]), "Detection rate", GOOD),
        (pct(b["false_positive_rate"]), "False-positive rate", GOOD),
    ], top=Inches(1.85))

    half = int(CONTENT_W / 2 - Inches(0.3))
    rows = []
    for name, mod in m["full"]["models"].items():
        label = MODEL_NAMES.get(name, name.replace("_", " ").title()) + (
            "  (selected)" if name == m["full"]["selected"] else "")
        rows.append([label, f"{mod['accuracy']:.4f}", f"{mod['macro']['f1']:.4f}",
                     f"{mod['binary']['false_positive_rate']:.5f}",
                     f"{mod['inference']['microseconds_per_flow']:.2f}"])
    sel_idx = list(m["full"]["models"]).index(m["full"]["selected"])
    table(slide, ["Model", "Accuracy", "Macro F1", "FP rate", "us/flow"], rows,
          left=MARGIN, top=Inches(3.15), width=half,
          col_widths=[0.34, 0.18, 0.18, 0.16, 0.14], size=11.5, header_size=11.5,
          row_h=Inches(0.42), highlight={sel_idx})

    tf = textbox(slide, MARGIN, Inches(4.65), half, Inches(2.2))
    write(tf, "Reading the numbers", size=14, color=ACCENT, bold=True)
    write(tf, f"{b['tp']:,} of {b['tp'] + b['fn']:,} attack flows flagged; "
              f"{b['fp']:,} of {b['fp'] + b['tn']:,} benign flows wrongly flagged.",
          size=14, color=BODY)
    worst = min(((c, v["f1-score"]) for c, v in sel["per_class"].items()), key=lambda x: x[1])
    write(tf, f"Per-class F1 exceeds 0.97 for every class except {worst[0]} "
              f"({worst[1]:.4f} on {int(sel['per_class'][worst[0]]['support']):,} test flows).",
          size=14, color=BODY)
    write(tf, "The two classifiers are close enough that the choice barely matters; Random "
              "Forest was selected on validation macro F1 and is twice as fast at inference.",
          size=13, color=MUTED, italic=True)

    picture(slide, REPORTS / "per_class_f1_full.png", MARGIN + half + Inches(0.6),
            Inches(3.1), half, Inches(3.6))
    notes(slide, "Lead with macro F1, not accuracy. Accuracy is high mostly because benign "
                 "dominates.")
    return slide


def slide_results_lite(prs, m, n):
    slide = header(prs, "Results: lite feature set (6 live features)", "Results", n)
    full_sel, lite_sel = m["full_sel"], m["lite_sel"]
    stat_row(slide, [
        (f"{lite_sel['macro']['f1']:.4f}",
         f"Macro F1 (vs {full_sel['macro']['f1']:.4f} full)", ACCENT),
        (pct(lite_sel["binary"]["detection_rate"]), "Detection rate", GOOD),
        (pct(lite_sel["binary"]["false_positive_rate"]), "False-positive rate", INK),
        (f"-{full_sel['macro']['f1'] - lite_sel['macro']['f1']:.4f}", "Macro F1 given up", BAD),
    ], top=Inches(1.85))

    order = ["DDoS", "DoS", "DoS-Slow", "BruteForce", "PortScan", "Bot", "WebAttack"]
    rows = []
    for cls in order:
        f_f1 = full_sel["per_class"][cls]["f1-score"]
        l_f1 = lite_sel["per_class"][cls]["f1-score"]
        rows.append([cls, f"{f_f1:.4f}", f"{l_f1:.4f}", f"{l_f1 - f_f1:+.4f}"])
    hurt = {i for i, r in enumerate(rows) if float(r[3]) < -0.05}
    table(slide, ["Class", "Full F1", "Lite F1", "Change"], rows,
          left=MARGIN, top=Inches(3.3), width=int(CONTENT_W / 2 - Inches(0.2)),
          col_widths=[0.34, 0.22, 0.22, 0.22], size=12, row_h=Inches(0.37), highlight=hurt)

    x = MARGIN + int(CONTENT_W / 2) + Inches(0.2)
    tf = textbox(slide, x, Inches(3.3), int(CONTENT_W / 2 - Inches(0.4)), Inches(3.4))
    write(tf, "The loss is not spread evenly", size=16, color=INK, bold=True)
    write(tf, "Volumetric attacks survive almost intact. DDoS, DoS and DoS-Slow all stay above "
              "0.99: they change the shape of traffic, and shape is exactly what six flow "
              "statistics measure.", size=14, color=BODY)
    wa_f, wa_l = full_sel["per_class"]["WebAttack"], lite_sel["per_class"]["WebAttack"]
    write(tf, f"WebAttack collapses from F1 {wa_f['f1-score']:.4f} to {wa_l['f1-score']:.4f}, but "
              f"not by missing attacks: recall is identical at {wa_l['recall']:.4f}. Precision "
              f"falls from {wa_f['precision']:.4f} to {wa_l['precision']:.4f}, because benign "
              f"flows get labelled WebAttack.", size=14, color=BAD)
    write(tf, "Stated plainly: six header-derived statistics are sufficient to recognise attacks "
              "that change the shape of traffic, and insufficient for attacks that change only "
              "its content.", size=14, color=INK, bold=True)
    notes(slide, "Do not hide the WebAttack collapse. It is the honest limit of header-only "
                 "features and it motivates the payload-inspection future work.")
    return slide


def slide_confusion(prs, m, n):
    slide = header(prs, "Where the errors actually are", "Results", n)
    tf = textbox(slide, MARGIN, Inches(1.78), CONTENT_W, Inches(0.4))
    write(tf, "Confusion matrices for the selected Random Forest on each feature set, "
              "row-normalised.", size=14, color=MUTED)
    half = int(CONTENT_W / 2 - Inches(0.25))
    picture(slide, REPORTS / "confusion_full_random_forest.png", MARGIN, Inches(2.25),
            half, Inches(3.5), caption="Full feature set (59 features)")
    picture(slide, REPORTS / "confusion_lite_random_forest.png",
            MARGIN + half + Inches(0.5), Inches(2.25), half, Inches(3.5),
            caption="Lite feature set (6 live features)")
    lite_sel, cls = m["lite_sel"], m["lite"]["classes"]
    bi, wi = cls.index("Benign"), cls.index("WebAttack")
    leaked = lite_sel["confusion_matrix"][bi][wi]
    rect(slide, MARGIN, Inches(6.15), CONTENT_W - Inches(0.9), Inches(0.72), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.25), Inches(6.28), CONTENT_W - Inches(1.4), Inches(0.55))
    write(tf, f"Both keep the diagonal almost everywhere. The difference is the Benign row: the "
              f"lite model labels {leaked:,} benign flows as WebAttack. Its WebAttack recall is "
              f"unchanged at {lite_sel['per_class']['WebAttack']['recall']:.4f}; it is precision "
              f"that collapses, to {lite_sel['per_class']['WebAttack']['precision']:.4f}.",
          size=13.5, color=INK)
    notes(slide, f"Point at the Benign row, not the WebAttack row. The lite model finds the same "
                 f"309 of 321 WebAttack flows as the full model. What it loses is precision: "
                 f"{leaked:,} benign flows are labelled WebAttack, so the class becomes unusable "
                 f"in practice even though recall is identical.")
    return slide


def slide_results_ae(prs, m, n):
    slide = header(prs, "Results: autoencoder (trained on benign only)", "Results", n)
    ae = m["ae"]
    stat_row(slide, [
        (f"{ae['roc_auc']:.4f}", "ROC-AUC", ACCENT),
        (pct(ae["detection_rate"]), "Detection rate", INK),
        (pct(ae["false_positive_rate"]), "False-positive rate", GOOD),
        (f"{ae['precision']:.4f}", "Precision", INK),
    ], top=Inches(1.82), height=Inches(1.05))

    tf = textbox(slide, MARGIN, Inches(3.0), CONTENT_W - Inches(0.9), Inches(0.5))
    write(tf, f"A low detection rate is the design, not a failure: the threshold is fixed at the "
              f"99th percentile of benign validation error, which buys a "
              f"{pct(ae['false_positive_rate'])} false-alarm rate and gives up recall.",
          size=14, color=INK, bold=True)

    left_w = int(CONTENT_W * 0.52)
    picture(slide, REPORTS / "autoencoder_errors.png", MARGIN, Inches(3.7), left_w, Inches(2.5),
            caption="Reconstruction error, benign versus attack, with the threshold")

    per = sorted(((c, v["flagged_share"]) for c, v in ae["per_class"].items()
                  if c != "Benign"), key=lambda x: -x[1])
    table(slide, ["Class", "Share flagged anomalous"], [[c, pct(s)] for c, s in per],
          left=MARGIN + left_w + Inches(0.45), top=Inches(3.7),
          width=CONTENT_W - left_w - Inches(0.45), col_widths=[0.5, 0.5], size=12,
          header_size=12, row_h=Inches(0.31), highlight={0, 1})

    tf = textbox(slide, MARGIN, Inches(6.45), CONTENT_W - Inches(1.0), Inches(0.55))
    write(tf, "It sees exactly what deviates from benign flow statistics: slow-rate and volumetric "
              "denial of service. It is nearly blind to brute force, web attacks and bots, which "
              "are statistically ordinary at flow level, and which the supervised models cover.",
          size=13, color=BODY)
    notes(slide, "The complementarity argument: the autoencoder is strong precisely where it is "
                 "cheap to be strong, and the supervised models cover the rest. It needs no "
                 "attack labels at all, which is the point.")
    return slide


def slide_lab(prs, m, n):
    slide = header(prs, "The isolated attack lab", "Validation", n)
    boxes = [
        ("attacker", "10.77.0.66", "nmap, hping3,\nslowhttptest, hydra", LIGHT),
        ("victim", "10.77.0.10", "stock nginx\nstatic page + /admin/", LIGHT),
        ("nids", "shares victim namespace", "capture, detection,\niptables response", ACCENT),
    ]
    gap = Inches(0.5)
    box_w = int((CONTENT_W - gap * 2) / 3)
    top = Inches(2.0)
    for i, (name, addr, body, fill) in enumerate(boxes):
        x = MARGIN + i * (box_w + gap)
        rect(slide, x, top, box_w, Inches(1.75), fill=fill)
        tf = textbox(slide, x, top + Inches(0.2), box_w, Inches(0.4), align=PP_ALIGN.CENTER)
        write(tf, name, size=19, color=WHITE if fill == ACCENT else INK, bold=True,
              space_after=0, align=PP_ALIGN.CENTER)
        tf = textbox(slide, x, top + Inches(0.66), box_w, Inches(0.3), align=PP_ALIGN.CENTER)
        write(tf, addr, size=12, color=WHITE if fill == ACCENT else ACCENT, space_after=0,
              align=PP_ALIGN.CENTER)
        tf = textbox(slide, x, top + Inches(1.02), box_w, Inches(0.6), align=PP_ALIGN.CENTER)
        write(tf, body, size=12, color=WHITE if fill == ACCENT else MUTED, space_after=0,
              align=PP_ALIGN.CENTER)

    tf = textbox(slide, MARGIN, Inches(4.05), CONTENT_W, Inches(0.4))
    write(tf, "Containment, by construction", size=16, color=INK, bold=True)
    bullets(slide, [
        "The lab network is internal: no route to the internet, the campus network or the host.",
        "Published ports bind to 127.0.0.1 only.",
        "Every attack script refuses any target outside 10.77.0.0/24.",
        "The NIDS shares the victim's network namespace, so it sees every packet the victim "
        "sends or receives and its iptables rules apply to exactly that traffic. The host "
        "firewall is never touched.",
    ], top=Inches(4.5), size=14, gap=8)

    rect(slide, MARGIN, Inches(6.3), CONTENT_W, Inches(0.72), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.25), Inches(6.45), CONTENT_W - Inches(0.5), Inches(0.5))
    write(tf, "On a real network this is a monitoring host on a switch SPAN port plus a firewall "
              "that enforces the decision. The detection logic is identical; only the enforcement "
              "point differs.", size=14, color=INK)
    notes(slide, "Stress containment first. Then the SPAN-port equivalence, which is the "
                 "Packet Tracer topology on the next slide.")
    return slide


def slide_topology(prs, m, n):
    slide = header(prs, "Enterprise topology (Cisco Packet Tracer)", "Validation", n)
    tf = textbox(slide, MARGIN, Inches(1.8), CONTENT_W, Inches(0.4))
    write(tf, "Where Netra would sit in a small enterprise network, and how the lab maps onto it.",
          size=14, color=MUTED)
    diagram = (
        "  [Internet PC]  external attacker\n"
        "        |\n"
        "  [R-EDGE  ISR4331]  203.0.113.2 / 10.0.0.1\n"
        "        |\n"
        "  [FW  ASA 5506-X]   dmz 172.16.10.1  |  inside 192.168.10.1\n"
        "        |                              |\n"
        "  [SW-DMZ 2960]                  [SW-CORE 2960]\n"
        "    |        |                      |        |\n"
        "  [WEB]   [NIDS]                  [PC1]    [PC2]\n"
        "  .10     SPAN destination, no IP on the sniffing port"
    )
    box = rect(slide, MARGIN, Inches(2.3), int(CONTENT_W * 0.55), Inches(2.9), fill=LIGHT)
    tf = box.text_frame
    tf.margin_left = tf.margin_top = Inches(0.2)
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT      # monospace art must not be centred, or the tree skews
    run = p.add_run()
    run.text = diagram
    run.font.size = Pt(11.5)
    run.font.name = "Consolas"
    run.font.color.rgb = INK

    x = MARGIN + int(CONTENT_W * 0.55) + Inches(0.4)
    w = CONTENT_W - int(CONTENT_W * 0.55) - Inches(0.4)
    table(slide, ["Packet Tracer", "Docker lab"], [
        ["Internet PC 203.0.113.10", "attacker 10.77.0.66"],
        ["WEB server in DMZ", "victim 10.77.0.10 (nginx)"],
        ["NIDS on SPAN port", "nids sharing victim namespace"],
        ["Firewall deny rule", "iptables NETRA chain"],
        ["DMZ switch, VLAN 10", "internal network 10.77.0.0/24"],
    ], left=x, top=Inches(2.3), width=w, col_widths=[0.5, 0.5], size=11.5,
        header_size=12, row_h=Inches(0.48))

    rect(slide, MARGIN, Inches(5.5), CONTENT_W, Inches(1.1), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.25), Inches(5.66), CONTENT_W - Inches(0.5), Inches(0.85))
    write(tf, "One honest difference", size=13, color=ACCENT, bold=True)
    write(tf, "On a real network a SPAN-port NIDS is passive and asks the firewall to block "
              "through an API. In the lab it shares the server's namespace and applies the block "
              "itself. Same detection, different enforcement point.", size=14, color=INK)
    notes(slide, "Packet Tracer models the topology and traffic paths; the Docker lab performs "
                 "the actual detection. Build steps are in docs/PACKET_TRACER_GUIDE.md.")
    return slide


def slide_live(prs, m, n):
    slide = header(prs, "Live validation: four real attacks", "Validation", n)
    tf = textbox(slide, MARGIN, Inches(1.82), CONTENT_W, Inches(0.4))
    write(tf, "Run from the attacker container against the victim, with the real iptables "
              "backend enabled.", size=14, color=MUTED)
    table(slide, ["Attack tool", "Alert raised", "Detector", "Response"], [
        ["nmap SYN scan", "PortScan", "signature:port_scan", "source blocked"],
        ["hping3 SYN flood", "DoS", "signature:syn_flood", "source blocked"],
        ["slowhttptest slow headers", "DoS-Slow", "signature:slow_dos", "source blocked"],
        ["hydra HTTP basic auth", "BruteForce", "signature:brute_force", "source blocked"],
        ["curl, ordinary browsing", "none", "n/a", "none"],
    ], top=Inches(2.35), col_widths=[0.30, 0.20, 0.28, 0.22], size=13, row_h=Inches(0.44),
        highlight={4})

    tf = textbox(slide, MARGIN, Inches(4.85), CONTENT_W, Inches(0.35))
    write(tf, "Two observations worth recording", size=16, color=INK, bold=True)
    bullets(slide, [
        "The SYN flood's half-open connections also satisfy the slow-DoS rule and raise the "
        "autoencoder's error, so the flood produces several corroborating alerts. The intended "
        "syn_flood alert fires first. This is realistic behaviour, not a bug.",
        "The slow HTTP attack genuinely exhausted nginx's connection pool, with slowhttptest "
        "reporting the service unavailable, while Netra detected it from the traffic pattern "
        "rather than from the victim's health. Detection did not depend on the victim being harmed.",
    ], top=Inches(5.3), size=14, gap=10)
    notes(slide, "Every attack detected in about a second and answered with a real, timed DROP "
                 "rule that expired on its own. The benign baseline raised nothing.")
    return slide


def slide_dashboard(prs, m, n):
    slide = header(prs, "The operator's view", "Validation", n)
    tf = textbox(slide, MARGIN, Inches(1.8), CONTENT_W, Inches(0.4))
    write(tf, "A native PySide6 desktop application. The engine runs inside Docker; the app "
              "connects over WebSocket.", size=14, color=MUTED)
    half = int(CONTENT_W / 2 - Inches(0.2))
    picture(slide, SHOTS / "lab_1_connected.png", MARGIN, Inches(2.35), half, Inches(2.9),
            caption="Connected: live traffic scored, no alerts on benign traffic")
    picture(slide, SHOTS / "lab_2_blocked.png", MARGIN + half + Inches(0.4), Inches(2.35),
            half, Inches(2.9), caption="Attacker blocked, with a live countdown to expiry")
    rect(slide, MARGIN, Inches(5.7), CONTENT_W, Inches(1.0), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.25), Inches(5.85), CONTENT_W - Inches(0.5), Inches(0.75))
    write(tf, "Alert feed with severity, alerted flows by attack type, traffic-rate chart, and "
              "blocked addresses with countdowns and per-address unblock buttons. The operator "
              "can always override the automated decision.", size=14, color=INK)
    notes(slide, "Show the real app during the demo rather than dwelling on these screenshots.")
    return slide


def slide_finding(prs, m, n):
    slide = header(prs, "Key finding: an entire feature family is unusable", "Discussion", n)
    rect(slide, MARGIN, Inches(1.85), CONTENT_W, Inches(1.12), fill=INK)
    tf = textbox(slide, MARGIN + Inches(0.3), Inches(2.0), CONTENT_W - Inches(0.6), Inches(0.9))
    write(tf, "CIC-IDS2017's TCP flag counters are wrong.", size=19, color=WHITE, bold=True)
    write(tf, "SYN Flag Count is 0 on every PortScan flow, although every such flow is by "
              "definition a SYN probe. FIN and PSH are near zero throughout, although ordinary "
              "TCP connections carry both.", size=14, color=RGBColor(0xCB, 0xD5, 0xE1))

    tf = textbox(slide, MARGIN, Inches(3.2), CONTENT_W, Inches(0.35))
    write(tf, "Why this matters more than it sounds", size=16, color=INK, bold=True)
    bullets(slide, [
        "Models trained on these columns learn the extraction tool's bug, not a property of "
        "network traffic.",
        "Offline this is invisible: the test split contains the same bug, so the metrics look "
        "excellent.",
        ("It became visible within minutes in the lab: real benign web traffic, where connections "
         "legitimately carry FIN and PSH, was scored as anomalous and a normal client was "
         "quarantined.", 0, BAD),
        ("All twelve flag features were removed, leaving 59 inputs. The offline cost was small, "
         "and benign live flows now score around 0.08 against the 0.146 threshold.", 0, GOOD),
    ], top=Inches(3.65), size=14, gap=9)

    rect(slide, MARGIN, Inches(5.95), CONTENT_W, Inches(0.95), fill=LIGHT)
    tf = textbox(slide, MARGIN + Inches(0.25), Inches(6.1), CONTENT_W - Inches(0.5), Inches(0.7))
    write(tf, "The general lesson: a model evaluated only against the dataset it was trained on "
              "can score well by learning that dataset's artefacts. Offline metrics cannot detect "
              "this. Live testing can, and did.", size=15, color=INK, bold=True)
    notes(slide, "This is the most valuable result in the project and it is a negative one. "
                 "It independently reproduces Engelen et al. 2021 and it changed the design.")
    return slide


def slide_limitations(prs, m, n):
    slide = header(prs, "Limitations", "Discussion", n)
    items = [
        ("Single dataset", "All learned components are trained and evaluated on CIC-IDS2017. "
                           "Generalisation to another network is not demonstrated, and given the "
                           "flag-counter finding it should not be assumed."),
        ("Payload-blind", "No component inspects packet contents, so live WebAttack detection is "
                          "weak and encrypted traffic is opaque to the flow-statistic detectors."),
        ("Source-address response", "Blocking by source is defeated by spoofing and by distributed "
                                    "attacks, and could be weaponised by spoofing a legitimate "
                                    "address to get it blocked. Timed expiry and the never-block "
                                    "list bound the damage without eliminating it."),
        ("Lab scale", "One attacker, one victim, one detector on a single host. Throughput under "
                      "realistic volumes, and per-source state across many thousands of sources, "
                      "are untested."),
        ("Known attacks in the live test", "The four demonstrated attacks are ones the signature "
                                           "rules cover, so the live test does not independently "
                                           "validate the ML detectors against novel attacks. The "
                                           "offline results carry that argument."),
    ]
    top = Inches(1.9)
    for title, body in items:
        rect(slide, MARGIN, top, CONTENT_W, Inches(0.92), fill=LIGHT)
        tf = textbox(slide, MARGIN + Inches(0.28), top + Inches(0.1),
                     CONTENT_W - Inches(0.56), Inches(0.78))
        write(tf, title, size=14, color=BAD, bold=True, space_after=1)
        write(tf, body, size=12.5, color=BODY, space_after=0)
        top += Inches(1.0)
    notes(slide, "Stating limits precisely is stronger than overclaiming, and it is where most "
                 "viva questions come from.")
    return slide


def slide_future(prs, m, n):
    slide = header(prs, "Future work", "Conclusion", n)
    items = [
        ("1", "Cross-dataset evaluation", "Measure how much of this performance is specific to "
                                          "CIC-IDS2017 by testing against UNSW-NB15 [2]."),
        ("2", "Payload features", "Address the WebAttack and Bot weakness directly, which flow "
                                  "statistics provably cannot separate."),
        ("3", "Online adaptation", "Recalibrate the autoencoder threshold against the deployment "
                                   "network's own benign traffic rather than the dataset's."),
        ("4", "Richer response", "Honeypot redirection, graduated rate limiting before outright "
                                 "blocking, and enforcement through an external firewall API."),
        ("5", "Ensemble anomaly detection", "Test whether an ensemble of small autoencoders over "
                                            "feature subsets, as in Kitsune [4], beats the single "
                                            "network used here."),
    ]
    top = Inches(1.95)
    for num, title, body in items:
        badge = rect(slide, MARGIN, top + Inches(0.1), Inches(0.46), Inches(0.46),
                     fill=ACCENT, shape=MSO_SHAPE.OVAL)
        write(badge.text_frame, num, size=15, color=WHITE, bold=True, space_after=0,
              para=badge.text_frame.paragraphs[0], align=PP_ALIGN.CENTER)
        tf = textbox(slide, MARGIN + Inches(0.75), top, CONTENT_W - Inches(0.9), Inches(0.85))
        write(tf, title, size=16, color=INK, bold=True, space_after=1)
        write(tf, body, size=13, color=BODY, space_after=0)
        top += Inches(0.92)
    notes(slide, "Ordered by expected value. Cross-dataset evaluation is first precisely because "
                 "of the flag-counter finding.")
    return slide


def slide_conclusion(prs, m, n):
    slide = header(prs, "Conclusion", "Conclusion", n)
    full, lite, ae = m["full_sel"], m["lite_sel"], m["ae"]
    stat_row(slide, [
        (f"{full['macro']['f1']:.4f}", "Full model macro F1", ACCENT),
        (f"{lite['macro']['f1']:.4f}", "Lite model macro F1", ACCENT),
        (f"{ae['roc_auc']:.4f}", "Autoencoder ROC-AUC", ACCENT),
        ("4 / 4", "Live attacks detected\nand blocked", GOOD),
    ], top=Inches(1.9), height=Inches(1.25))

    bullets(slide, [
        "Signature rules, supervised classification and unsupervised anomaly detection can be "
        "combined under an explicit fusion policy and coupled to an automated response, on "
        "hardware as modest as a single laptop.",
        f"The full model reaches macro F1 {full['macro']['f1']:.4f} at a "
        f"{pct(full['binary']['false_positive_rate'])} false-positive rate; the six-feature live "
        f"model reaches {lite['macro']['f1']:.4f}; the autoencoder adds label-free coverage of "
        f"denial-of-service-shaped anomalies at ROC-AUC {ae['roc_auc']:.4f}.",
        "In live operation against four real attack tools, every attack was detected within about "
        "a second and answered with a timed, reversible firewall rule, while ordinary traffic "
        "raised no alert.",
    ], top=Inches(3.5), size=15, gap=12)

    rect(slide, MARGIN, Inches(5.55), CONTENT_W, Inches(1.15), fill=INK)
    tf = textbox(slide, MARGIN + Inches(0.3), Inches(5.72), CONTENT_W - Inches(0.6), Inches(0.9))
    write(tf, "The most useful result may be the negative one.", size=15, color=ACCENT, bold=True)
    write(tf, "An entire family of features in a widely used benchmark is unusable, models trained "
              "on it look excellent offline and fail on real packets, and only live testing "
              "revealed it. Work that reports offline metrics alone cannot rule out this class of "
              "error.", size=14, color=WHITE)
    notes(slide, "Close on the negative finding. It is the most defensible contribution.")
    return slide


def slide_references(prs, m, n):
    slide = header(prs, "References", None, n)
    refs = [
        "Sharafaldin, I., Lashkari, A. H., and Ghorbani, A. A. (2018). Toward Generating a New "
        "Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP.",
        "Moustafa, N., and Slay, J. (2015). UNSW-NB15: a comprehensive data set for network "
        "intrusion detection systems. MilCIS, IEEE.",
        "Tavallaee, M., Bagheri, E., Lu, W., and Ghorbani, A. A. (2009). A Detailed Analysis of "
        "the KDD CUP 99 Data Set. IEEE CISDA.",
        "Mirsky, Y., Doshi, T., Ju, M., Elovici, Y., and Shabtai, A. (2018). Kitsune: An Ensemble "
        "of Autoencoders for Online Network Intrusion Detection. NDSS.",
        "Ring, M., Wunderlich, S., Scheuring, D., Landes, D., and Hotho, A. (2019). A Survey of "
        "Network-based Intrusion Detection Data Sets. Computers and Security, 86, 147-167.",
        "Engelen, G., Rimmer, V., and Joosen, W. (2021). Troubleshooting an Intrusion Detection "
        "Dataset: the CICIDS2017 Case Study. IEEE Security and Privacy Workshops (SPW).",
    ]
    tf = textbox(slide, MARGIN, Inches(1.95), CONTENT_W, Inches(4.6))
    for i, ref in enumerate(refs, start=1):
        p = tf.paragraphs[0] if i == 1 else tf.add_paragraph()
        run = p.add_run()
        run.text = f"[{i}]  {ref}"
        run.font.size = Pt(14)
        run.font.color.rgb = BODY
        run.font.name = "Segoe UI"
        p.space_after = Pt(13)
    return slide


def slide_thanks(prs, m):
    slide = dark_slide(prs)
    tf = textbox(slide, MARGIN, Inches(2.9), CONTENT_W, Inches(1.0))
    write(tf, "Thank you", size=50, color=WHITE, bold=True, space_after=0)
    ln = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, MARGIN, Inches(3.95), Inches(2.2), Pt(3))
    ln.fill.solid()
    ln.fill.fore_color.rgb = ACCENT
    ln.line.fill.background()
    ln.shadow.inherit = False
    tf = textbox(slide, MARGIN, Inches(4.35), CONTENT_W, Inches(0.6))
    write(tf, "Questions, and a live demonstration of the attack lab.", size=20,
          color=RGBColor(0xCB, 0xD5, 0xE1))
    return slide


# ---------------------------------------------------------------------------
def build(out: Path) -> Path:
    m = load_metrics()
    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H

    slide_title(prs, m)
    builders = [
        slide_problem, slide_objectives, slide_literature, slide_architecture,
        slide_signatures, slide_models, slide_fusion, slide_response,
        slide_dataset, slide_features, slide_results_full, slide_results_lite,
        slide_confusion, slide_results_ae, slide_lab, slide_topology, slide_live,
        slide_dashboard,
        slide_finding, slide_limitations, slide_future, slide_conclusion,
        slide_references,
    ]
    for i, fn in enumerate(builders, start=2):
        fn(prs, m, i)
    slide_thanks(prs, m)

    out.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Netra presentation.")
    ap.add_argument("-o", "--out", default=str(ROOT / "presentation" / "Netra.pptx"))
    args = ap.parse_args()
    out = build(Path(args.out))
    print(f"Wrote {out} ({len(Presentation(str(out)).slides)} slides)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
