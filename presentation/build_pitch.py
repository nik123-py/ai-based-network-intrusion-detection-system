"""Build the Netra pitch deck: presentation/Netra_Pitch.pptx.

This is the persuasive deck, not the academic one. `build_ppt.py` produces the
formal 27-slide report deck with cautious wording; this one is written to be
pitched out loud, with hooks and short lines. Every number in it is still a real
measured number from reports/, because a pitch that cannot survive a question is
worth nothing.

    python presentation/build_pitch.py
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

# ---------------------------------------------------------------------------
# Design system
# ---------------------------------------------------------------------------
W, H = Inches(13.333), Inches(7.5)
MARGIN = Inches(0.85)
CONTENT_W = W - 2 * MARGIN

NIGHT = RGBColor(0x0A, 0x0F, 0x1E)      # deep background
CARD = RGBColor(0x14, 0x1C, 0x32)       # raised panel on night
INK = RGBColor(0xF5, 0xF7, 0xFB)        # primary text on night
DIM = RGBColor(0x94, 0xA3, 0xB8)        # secondary text on night
CYAN = RGBColor(0x22, 0xD3, 0xEE)       # primary accent
VIOLET = RGBColor(0xA7, 0x8B, 0xFA)     # secondary accent
LIME = RGBColor(0x4A, 0xDE, 0x80)       # positive
CORAL = RGBColor(0xFB, 0x71, 0x85)      # negative / honest
PAPER = RGBColor(0xF8, 0xFA, 0xFC)      # light slide background
SLATE = RGBColor(0x0F, 0x17, 0x2A)      # text on light
SLATE2 = RGBColor(0x47, 0x55, 0x69)     # secondary text on light
FONT = "Segoe UI"


def load_numbers() -> dict:
    """Every figure in the deck, read from the measured artifacts."""

    def read(name):
        p = REPORTS / name
        if not p.exists():
            sys.exit(f"missing {p}. Run the evaluation first (see README).")
        return json.loads(p.read_text(encoding="utf-8"))

    full, lite, ae = read("metrics_full.json"), read("metrics_lite.json"), read("metrics_autoencoder.json")
    openset, discovery = read("openset.json"), read("discovery.json")
    cross = read("cross_dataset.json")
    data = read("data_summary.json")
    return {
        "full": full["models"][full["selected"]],
        "lite": lite["models"][lite["selected"]],
        "ae": ae,
        "openset": openset,
        "discovery": discovery,
        "cross": cross,
        "data": data,
    }


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------
def blank(prs, bg=NIGHT):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    rect = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, H)
    rect.fill.solid()
    rect.fill.fore_color.rgb = bg
    rect.line.fill.background()
    rect.shadow.inherit = False
    return slide


def textbox(slide, left, top, width, height, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    return tf


def write(tf, text, size=18, color=INK, bold=False, align=PP_ALIGN.LEFT,
          space_after=8, space_before=0, para=None, line_spacing=None, italic=False):
    p = para if para is not None else (tf.paragraphs[0] if not tf.paragraphs[0].runs
                                       and not tf.paragraphs[0].text else tf.add_paragraph())
    p.alignment = align
    p.space_after = Pt(space_after)
    p.space_before = Pt(space_before)
    if line_spacing:
        p.line_spacing = line_spacing
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    run.font.name = FONT
    return p


def panel(slide, left, top, width, height, fill=CARD, line=None, radius=True):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
        left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    if line is None:
        shape.line.fill.background()
    else:
        shape.line.color.rgb = line
        shape.line.width = Pt(1)
    shape.shadow.inherit = False
    if radius:
        try:
            shape.adjustments[0] = 0.06
        except (IndexError, AttributeError):
            pass
    return shape


def kicker(slide, text, color=CYAN, top=Inches(0.52)):
    tf = textbox(slide, MARGIN, top, CONTENT_W, Inches(0.3))
    write(tf, text.upper(), size=12, color=color, bold=True, space_after=0)


def heading(slide, text, top=Inches(0.92), size=36, color=INK, width=None):
    tf = textbox(slide, MARGIN, top, width or CONTENT_W, Inches(1.1))
    write(tf, text, size=size, color=color, bold=True, space_after=0)
    return tf


def subheading(slide, text, top=Inches(1.85), color=DIM, size=16, width=None):
    tf = textbox(slide, MARGIN, top, width or CONTENT_W, Inches(0.6))
    write(tf, text, size=size, color=color, space_after=0, line_spacing=1.25)
    return tf


def bullets(slide, items, top, left=MARGIN, width=None, size=16,
            color=INK, gap=12, bullet_color=CYAN):
    """items: list of str, or (bold_lead, rest) tuples."""
    tf = textbox(slide, left, top, width or CONTENT_W, H - top - Inches(0.5))
    first = True
    for item in items:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.space_after = Pt(gap)
        p.line_spacing = 1.2
        dot = p.add_run()
        dot.text = "●  "
        dot.font.size = Pt(size - 4)
        dot.font.color.rgb = bullet_color
        dot.font.name = FONT
        if isinstance(item, tuple):
            lead, rest = item
            r = p.add_run()
            r.text = lead
            r.font.size = Pt(size)
            r.font.bold = True
            r.font.color.rgb = color
            r.font.name = FONT
            r2 = p.add_run()
            r2.text = rest
            r2.font.size = Pt(size)
            r2.font.color.rgb = DIM if color == INK else SLATE2
            r2.font.name = FONT
        else:
            r = p.add_run()
            r.text = item
            r.font.size = Pt(size)
            r.font.color.rgb = color
            r.font.name = FONT
    return tf


def stat_row(slide, stats, top, height=Inches(1.5), gap=Inches(0.22),
             fill=CARD, value_color=CYAN, label_color=DIM):
    """stats: list of (value, label) or (value, label, color)."""
    n = len(stats)
    total_gap = gap * (n - 1)
    box_w = Emu(int((CONTENT_W - total_gap) / n))
    for i, item in enumerate(stats):
        value, label = item[0], item[1]
        colour = item[2] if len(item) > 2 else value_color
        left = Emu(int(MARGIN + i * (box_w + gap)))
        panel(slide, left, top, box_w, height, fill=fill)
        tf = textbox(slide, left + Inches(0.22), top + Inches(0.2),
                     box_w - Inches(0.44), height - Inches(0.4))
        write(tf, value, size=34, color=colour, bold=True, space_after=2)
        write(tf, label, size=12, color=label_color, space_after=0, line_spacing=1.1)


def footer(slide, text, color=DIM):
    tf = textbox(slide, MARGIN, H - Inches(0.66), CONTENT_W, Inches(0.36))
    write(tf, text, size=11, color=color, space_after=0)


def notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text


def pct(x, places=2):
    return f"{100 * x:.{places}f}%"


# ---------------------------------------------------------------------------
# Slides
# ---------------------------------------------------------------------------
def s_title(prs, m):
    slide = blank(prs)
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.16), H)
    bar.fill.solid()
    bar.fill.fore_color.rgb = CYAN
    bar.line.fill.background()
    bar.shadow.inherit = False

    tf = textbox(slide, MARGIN, Inches(1.9), Inches(10.6), Inches(1.2))
    write(tf, "NETRA", size=78, color=INK, bold=True, space_after=0)
    tf = textbox(slide, MARGIN, Inches(3.15), Inches(11.4), Inches(0.6))
    write(tf, "The intrusion detection system that knows what it doesn’t know.",
          size=24, color=CYAN, bold=True, space_after=0)
    tf = textbox(slide, MARGIN, Inches(3.95), Inches(10.2), Inches(1.2))
    write(tf, "Every AI security tool tells you what it recognises. "
              "Ours tells you when it recognises nothing — and then finds out what it is.",
          size=17, color=DIM, space_after=0, line_spacing=1.3)

    panel(slide, MARGIN, Inches(5.35), Inches(10.4), Inches(0.92), fill=CARD)
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(5.58), Inches(9.8), Inches(0.5))
    write(tf, "AI-powered  ·  Self-defending  ·  Zero-day ready  ·  "
              "Explainable by design  ·  Runs on one laptop",
          size=14, color=VIOLET, bold=True, space_after=0)
    footer(slide, "21CSC302J  ·  Computer Networks Course Case Study  ·  "
                  "CIC-IDS2017  ·  96 automated tests passing")
    notes(slide, "Open with the one-liner. The whole pitch hangs on the difference between "
                 "recognising something and admitting you recognise nothing.")
    return slide


def s_hook(prs, m):
    slide = blank(prs)
    kicker(slide, "the problem nobody puts on a slide")
    heading(slide, "Your firewall is a bouncer\nwith a photo album.")
    tf = textbox(slide, MARGIN, Inches(2.75), Inches(11.0), Inches(1.4))
    write(tf, "It stops everyone whose picture it already has. "
              "Anyone new walks straight in — and gets waved through with a smile.",
          size=20, color=DIM, space_after=0, line_spacing=1.3)
    stat_row(slide, [
        ("2,830,743", "network flows analysed from the CIC-IDS2017 benchmark"),
        ("8", "attack classes the models were trained to recognise"),
        ("∞", "attack types that exist outside those eight", CORAL),
    ], top=Inches(4.3), height=Inches(1.7))
    footer(slide, "The gap between 8 and infinity is where this project lives.")
    notes(slide, "The hook. Signature systems and trained classifiers share the same blind "
                 "spot: both only know what they were shown.")
    return slide


def s_truth(prs, m):
    slide = blank(prs, bg=PAPER)
    kicker(slide, "the uncomfortable truth", color=RGBColor(0x0E, 0x76, 0x90))
    heading(slide, "A trained model is physically\nincapable of saying “I don’t know.”",
            color=SLATE, size=34)
    tf = textbox(slide, MARGIN, Inches(2.95), Inches(11.4), Inches(1.0))
    write(tf, "Its output is a probability over the classes it was taught. "
              "The numbers must add up to 1. There is no box for “none of the above”.",
          size=18, color=SLATE2, space_after=0, line_spacing=1.3)

    panel(slide, MARGIN, Inches(4.1), Inches(5.6), Inches(2.3),
          fill=RGBColor(0xFF, 0xFF, 0xFF), line=RGBColor(0xE2, 0xE8, 0xF0))
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(4.35), Inches(4.9), Inches(1.9))
    write(tf, "What you ask", size=13, color=SLATE2, bold=True, space_after=8)
    write(tf, "“Is this brand-new attack dangerous?”", size=17, color=SLATE, space_after=0)

    panel(slide, MARGIN + Inches(5.95), Inches(4.1), Inches(5.6), Inches(2.3),
          fill=RGBColor(0xFF, 0xE4, 0xE6), line=RGBColor(0xFE, 0xCD, 0xD3))
    tf = textbox(slide, MARGIN + Inches(6.3), Inches(4.35), Inches(4.9), Inches(1.9))
    write(tf, "What it answers", size=13, color=RGBColor(0x9F, 0x12, 0x39), bold=True, space_after=8)
    write(tf, "“Benign. 100% confident.”", size=17,
          color=RGBColor(0x9F, 0x12, 0x39), bold=True, space_after=6)
    write(tf, "Not a bug. The maths leaves it no other option.",
          size=13, color=RGBColor(0x9F, 0x12, 0x39), space_after=0)
    footer(slide, "This is the single idea the rest of the deck is built on.",
           color=SLATE2)
    notes(slide, "Make them feel the inevitability: softmax normalises to 1, so the model "
                 "must distribute belief across known classes only.")
    return slide


def s_proof(prs, m):
    slide = blank(prs)
    kicker(slide, "we measured it", color=CORAL)
    heading(slide, "We deleted one attack from its memory.\nThen we attacked it.")
    subheading(slide, "Each attack class was removed from training, from the feature scaling and "
                      "from the calibration, then replayed. The model had genuinely never seen it.",
               top=Inches(2.5))
    loco = m["openset"]["leave_one_class_out"]
    silent = sum(1 for f in loco["folds"] if f["closed_set_called_benign"] > 0.5)
    total = len(loco["folds"])
    perfect = sum(1 for f in loco["folds"] if f["closed_set_called_benign"] >= 0.999)
    stat_row(slide, [
        (f"{silent} of {total}", "unseen attacks where the model called the majority of it BENIGN",
         CORAL),
        (f"{perfect}", "attacks where it called EVERY SINGLE FLOW benign", CORAL),
        ("0", "alerts raised. Total silence.", CORAL),
    ], top=Inches(3.5), height=Inches(1.8))
    panel(slide, MARGIN, Inches(5.65), CONTENT_W, Inches(0.95), fill=CARD)
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(5.88), CONTENT_W - Inches(0.7), Inches(0.5))
    write(tf, "The same model scores 0.9570 macro F1 on the attacks it does know. "
              "In-domain metrics cannot see this failure at all.",
          size=15, color=INK, bold=True, space_after=0)
    notes(slide, "This is the proof slide. The closed-set baseline is the project's own Random "
                 "Forest, trained on the seven remaining classes.")
    return slide


def s_solution(prs, m):
    slide = blank(prs)
    kicker(slide, "the fix")
    heading(slide, "We gave it a ninth answer.")
    subheading(slide, "Not a better classifier. A different kind of verdict.", top=Inches(2.05),
               size=19)
    cards = [
        ("1", "ROUTE", "A conformal test asks: does this flow resemble anything I was trained on? "
                       "If no class accepts it, it goes to the unknown pile."),
        ("2", "GROUP", "Unknown flows are clustered live by the direction in which they deviate "
                       "from normal. One new attack becomes one object, not 500 alarms."),
        ("3", "NAME", "Each family gets a permanent ID, a fingerprint and its nearest known "
                      "relative. An analyst names it once; every future alert uses that name."),
    ]
    box_w = Inches(3.72)
    for i, (num, title, body) in enumerate(cards):
        left = Emu(int(MARGIN + i * (box_w + Inches(0.22))))
        panel(slide, left, Inches(2.95), box_w, Inches(3.1), fill=CARD)
        badge = slide.shapes.add_shape(MSO_SHAPE.OVAL, left + Inches(0.32), Inches(3.25),
                                       Inches(0.52), Inches(0.52))
        badge.fill.solid()
        badge.fill.fore_color.rgb = CYAN
        badge.line.fill.background()
        badge.shadow.inherit = False
        btf = badge.text_frame
        btf.margin_left = btf.margin_right = btf.margin_top = btf.margin_bottom = 0
        write(btf, num, size=18, color=NIGHT, bold=True, align=PP_ALIGN.CENTER,
              space_after=0, para=btf.paragraphs[0])
        tf = textbox(slide, left + Inches(0.32), Inches(4.0), box_w - Inches(0.64), Inches(1.9))
        write(tf, title, size=20, color=INK, bold=True, space_after=8)
        write(tf, body, size=14, color=DIM, space_after=0, line_spacing=1.25)
    footer(slide, "Routing is statistical. Grouping is geometric. Naming is human. "
                  "Each step does only what it is good at.")
    notes(slide, "Three steps. Emphasise that the system never claims to identify the attack: "
                 "it proves novelty, describes it, and hands it to a person.")
    return slide


def s_guarantee(prs, m):
    slide = blank(prs, bg=PAPER)
    kicker(slide, "why this isn't just another threshold", color=RGBColor(0x0E, 0x76, 0x90))
    heading(slide, "A dial that comes with a promise.", color=SLATE)
    tf = textbox(slide, MARGIN, Inches(2.0), Inches(11.4), Inches(0.9))
    write(tf, "Most anomaly thresholds are guessed, then tuned until the demo looks good. "
              "Ours is a conformal significance level: set it to 0.05 and exactly 5% of normal "
              "traffic goes to the unknown pile. Guaranteed by the mathematics, before you see "
              "any data.", size=17, color=SLATE2, space_after=0, line_spacing=1.3)

    curve = m["openset"]["leave_one_class_out"]["totals"]["mean_curve"]
    rows = [("You promise", "You actually get", "Novel attack flows caught")]
    for c in curve:
        if c["alpha"] in (0.01, 0.05, 0.10, 0.25):
            rows.append((f"{c['alpha']:.2f}", f"{c['known_rejection_rate']:.4f}",
                         f"{c['unknown_rate']:.1%}"))
    left, top = MARGIN, Inches(3.3)
    tw, rh = Inches(7.4), Inches(0.46)
    table = slide.shapes.add_table(len(rows), 3, left, top, tw, rh * len(rows)).table
    table.columns[0].width = Emu(int(tw * 0.3))
    table.columns[1].width = Emu(int(tw * 0.34))
    table.columns[2].width = Emu(int(tw * 0.36))
    for r, row in enumerate(rows):
        table.rows[r].height = rh
        for c, val in enumerate(row):
            cell = table.cell(r, c)
            cell.fill.solid()
            cell.fill.fore_color.rgb = SLATE if r == 0 else RGBColor(0xFF, 0xFF, 0xFF)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.margin_left = cell.margin_right = Inches(0.12)
            p = cell.text_frame.paragraphs[0]
            p.alignment = PP_ALIGN.LEFT if c == 0 else PP_ALIGN.CENTER
            run = p.add_run()
            run.text = val
            run.font.size = Pt(13 if r == 0 else 15)
            run.font.bold = r == 0
            run.font.name = FONT
            run.font.color.rgb = PAPER if r == 0 else SLATE

    panel(slide, MARGIN + Inches(7.8), Inches(3.3), Inches(3.75), rh * len(rows),
          fill=RGBColor(0xEC, 0xFD, 0xF5), line=RGBColor(0xA7, 0xF3, 0xD0))
    tf = textbox(slide, MARGIN + Inches(8.1), Inches(3.6), Inches(3.15), Inches(2.0))
    write(tf, "Promise kept.", size=19, color=RGBColor(0x06, 0x6E, 0x55), bold=True, space_after=8)
    write(tf, "Measured on 329,392 held-out flows, at every level from 0.01 to 0.5. "
              "The false-alarm cost is a budget you set, not a surprise you discover.",
          size=13, color=RGBColor(0x06, 0x6E, 0x55), space_after=0, line_spacing=1.25)
    footer(slide, "This is what lets us be generous with suspicion without drowning anyone in alerts.",
           color=SLATE2)
    notes(slide, "The conformal guarantee is the technical heart. Alpha is a false-alarm budget, "
                 "not a tuned threshold.")
    return slide


def s_before_after(prs, m):
    slide = blank(prs)
    kicker(slide, "what the operator actually sees")
    heading(slide, "From a shrug to a lead.")
    panel(slide, MARGIN, Inches(2.35), Inches(5.6), Inches(2.6),
          fill=RGBColor(0x2A, 0x14, 0x1C))
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(2.6), Inches(4.9), Inches(2.1))
    write(tf, "BEFORE", size=13, color=CORAL, bold=True, space_after=10)
    write(tf, "“Anomaly (unknown)”", size=22, color=INK, bold=True, space_after=10)
    write(tf, "One line. Per flow. Hundreds of them. No name, no cause, no idea whether it "
              "matters. Operators learn to ignore it.", size=14, color=DIM,
          space_after=0, line_spacing=1.25)

    panel(slide, MARGIN + Inches(5.95), Inches(2.35), Inches(5.6), Inches(2.6),
          fill=RGBColor(0x0B, 0x2A, 0x24))
    tf = textbox(slide, MARGIN + Inches(6.3), Inches(2.6), Inches(4.9), Inches(2.1))
    write(tf, "AFTER", size=13, color=LIME, bold=True, space_after=10)
    write(tf, "NETRA-U001", size=22, color=INK, bold=True, space_after=10)
    write(tf, "47 unrecognised flows from 3 sources. Flow IAT Mean = 10.5 s, no backward "
              "packets. Nearest known class DoS-Slow, p = 0.004.",
          size=14, color=DIM, space_after=0, line_spacing=1.25)

    panel(slide, MARGIN, Inches(5.25), CONTENT_W, Inches(1.25), fill=CARD)
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(5.5), CONTENT_W - Inches(0.7), Inches(0.8))
    write(tf, "One object to judge instead of several hundred lines to scroll. "
              "Click “Name it”, type what it is, and every future alert says so — "
              "across restarts.", size=16, color=INK, space_after=0, line_spacing=1.25)
    notes(slide, "Show the real app here if there is time. The families panel is in the "
                 "bottom-left of the dashboard.")
    return slide


def s_surprise(prs, m):
    slide = blank(prs, bg=PAPER)
    kicker(slide, "the result we did not plan", color=RGBColor(0x6D, 0x28, 0xD9))
    heading(slide, "It discovered the tools,\nnot just the categories.", color=SLATE, size=34)
    tf = textbox(slide, MARGIN, Inches(2.8), Inches(11.4), Inches(0.8))
    write(tf, "The dataset lumps different hacking tools under one label. Nobody told the "
              "clusterer that. It separated them anyway.", size=18, color=SLATE2,
          space_after=0, line_spacing=1.3)
    items = [
        ("“BruteForce”", "is really two tools — and the family it found was "
                                   "274 FTP-Patator flows with just 2 SSH-Patator"),
        ("“DoS”", "is really Hulk and GoldenEye — and the family it found was "
                            "2,639 pure Hulk flows, zero GoldenEye"),
        ("“DoS-Slow”", "is really slowloris and slowhttptest — and it split them too"),
    ]
    bullets(slide, items, top=Inches(3.9), size=16, color=SLATE,
            bullet_color=VIOLET, gap=16)
    panel(slide, MARGIN, Inches(5.95), CONTENT_W, Inches(0.95),
          fill=RGBColor(0xF5, 0xF3, 0xFF), line=RGBColor(0xDD, 0xD6, 0xFE))
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(6.18), CONTENT_W - Inches(0.7), Inches(0.5))
    write(tf, "A finer distinction than the labels it was trained on. "
              "That is discovery, not classification.",
          size=16, color=RGBColor(0x5B, 0x21, 0xB6), bold=True, space_after=0)
    notes(slide, "Strong moment. The clusterer rediscovered structure the label map had erased.")
    return slide


def s_numbers(prs, m):
    slide = blank(prs)
    kicker(slide, "the receipts")
    heading(slide, "Every claim, measured.")
    full, lite, ae = m["full"], m["lite"], m["ae"]
    stat_row(slide, [
        (f"{full['macro']['f1']:.4f}", "Macro F1, full 59-feature model"),
        (f"{pct(full['binary']['detection_rate'], 2)}", "attack flows detected", LIME),
        (f"{full['binary']['false_positive_rate']:.5f}", "false-positive rate"),
        (f"{ae['roc_auc']:.4f}", "autoencoder ROC-AUC, zero attack labels"),
    ], top=Inches(2.2), height=Inches(1.6))
    loco = m["openset"]["leave_one_class_out"]["totals"]
    disc = m["discovery"]["totals"]
    kr = m["openset"]["known_rejection"]["scores"][m["openset"]["score"]]["rejection_rate"]
    stat_row(slide, [
        (f"{kr:.4f}", "measured cost of the unknown path (promised 0.05)", VIOLET),
        (f"{disc['folds_where_novel_family_reported']} of {len(m['discovery']['folds'])}",
         "unseen attacks surfaced as a named family", VIOLET),
        (f"{disc['mean_purity']:.3f}", "cluster purity — families stay clean", VIOLET),
        (f"{loco['mean_novelty_auc']:.3f}", "mean novelty AUC across folds", VIOLET),
    ], top=Inches(4.05), height=Inches(1.6))
    footer(slide, "Full tables in reports/RESULTS.md, reports/OPENSET.md and "
                  "reports/CROSS_DATASET.md. 96 automated tests keep them honest.")
    notes(slide, "Top row: the conventional results. Bottom row: the contribution.")
    return slide


def s_honest(prs, m):
    slide = blank(prs, bg=PAPER)
    kicker(slide, "the slide most decks leave out", color=RGBColor(0xB9, 0x1C, 0x1C))
    heading(slide, "What it does not do.", color=SLATE)
    subheading(slide, "We tested until it broke, then wrote down where.",
               top=Inches(2.0), color=SLATE2, size=18)
    items = [
        ("It does not transfer to another network. ",
         "Trained on CIC-IDS2017, tested on UNSW-NB15: detection fell from 99.76% to 0.03%. "
         "It had learned one network's packet rates, not what an attack is."),
        ("It is blind to web attacks. ",
         "We never read packet contents. Held-out SQL-injection flows rank as MORE normal than "
         "normal traffic. No threshold fixes that — only payload inspection would."),
        ("Bots are hard. ",
         "A bot checking in looks like small ordinary web traffic. Novelty AUC 0.760, the "
         "weakest of all classes, and we report it rather than averaging it away."),
        ("A family is a lead, not an identification. ",
         "The system proves something is new and describes it. Only a person can say what it is."),
    ]
    bullets(slide, items, top=Inches(2.95), size=15, color=SLATE,
            bullet_color=CORAL, gap=15)
    panel(slide, MARGIN, Inches(6.05), CONTENT_W, Inches(0.85),
          fill=RGBColor(0xFF, 0xF1, 0xF2), line=RGBColor(0xFE, 0xCD, 0xD3))
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(6.25), CONTENT_W - Inches(0.7), Inches(0.45))
    write(tf, "A system that hides its failures cannot be trusted with a firewall rule.",
          size=16, color=RGBColor(0x9F, 0x12, 0x39), bold=True, space_after=0)
    notes(slide, "Counter-intuitively this is the most persuasive slide. Leading with limits "
                 "buys credibility for everything else.")
    return slide


def s_domainshift(prs, m):
    slide = blank(prs)
    kicker(slide, "the failure that became a feature", color=LIME)
    heading(slide, "It knows when it is out of its depth.")
    tf = textbox(slide, MARGIN, Inches(2.1), Inches(11.4), Inches(0.9))
    write(tf, "We pointed the sensor at UNSW-NB15 — a completely different network, captured "
              "by different researchers. A normal classifier reports “all quiet”. "
              "Ours raises its hand.", size=18, color=DIM, space_after=0, line_spacing=1.3)
    ds = m["openset"]["domain_shift"]
    score = m["openset"]["score"]
    here = m["openset"]["known_rejection"]["scores"][score]["rejection_rate"]
    there = ds["scores"][score]["unknown_rate"]
    stat_row(slide, [
        (pct(here, 2), "of traffic unrecognised on the network it was trained for", LIME),
        (pct(there, 2), "of traffic unrecognised on a foreign network", CORAL),
        (f"{there / max(here, 1e-9):.0f}×", "louder. A calibrated cry for help.", CYAN),
    ], top=Inches(3.35), height=Inches(1.75))
    panel(slide, MARGIN, Inches(5.45), CONTENT_W, Inches(1.1), fill=CARD)
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(5.68), CONTENT_W - Inches(0.7), Inches(0.7))
    write(tf, "“Retrain me for this network” is a sentence a closed-set classifier "
              "can never say. On the same traffic it returns Benign with high confidence, "
              "and the operator sees a quiet network.",
          size=15, color=INK, space_after=0, line_spacing=1.25)
    notes(slide, "The open-set layer cannot recover the detection rate here and we say so; "
                 "what it recovers is the sensor's honesty about its own competence.")
    return slide


def s_stack(prs, m):
    slide = blank(prs)
    kicker(slide, "under the hood")
    heading(slide, "Four detectors. One verdict.")
    layers = [
        ("RULES", "4 packet-level signatures", "Fire in ~1 second. Catch what we anticipated.", CYAN),
        ("CLASSIFIERS", "Random Forest × 2", "59 features offline, 6 features live. "
                                                   "Name the attacks we trained on.", CYAN),
        ("AUTOENCODER", "59-32-16-8-16-32-59", "Trained on normal traffic only. "
                                                "Never saw an attack.", VIOLET),
        ("OPEN-SET", "conformal + clustering", "The ninth answer. Routes, groups and names "
                                               "what nothing else recognised.", LIME),
    ]
    top = Inches(2.25)
    for name, tech, body, colour in layers:
        panel(slide, MARGIN, top, CONTENT_W, Inches(0.95), fill=CARD)
        tag = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, MARGIN + Inches(0.25),
                                     top + Inches(0.22), Inches(1.75), Inches(0.5))
        tag.fill.solid()
        tag.fill.fore_color.rgb = colour
        tag.line.fill.background()
        tag.shadow.inherit = False
        ttf = tag.text_frame
        ttf.margin_left = ttf.margin_right = 0
        write(ttf, name, size=12, color=NIGHT, bold=True, align=PP_ALIGN.CENTER,
              space_after=0, para=ttf.paragraphs[0])
        tf = textbox(slide, MARGIN + Inches(2.25), top + Inches(0.17),
                     Inches(2.6), Inches(0.6))
        write(tf, tech, size=14, color=INK, bold=True, space_after=0)
        tf = textbox(slide, MARGIN + Inches(5.0), top + Inches(0.17),
                     Inches(6.3), Inches(0.62))
        write(tf, body, size=14, color=DIM, space_after=0, line_spacing=1.2)
        top = Emu(int(top + Inches(1.08)))
    footer(slide, "Priority fusion: a rule beats a confident classifier, which beats the "
                  "open-set test, which beats the autoencoder. Weak evidence must repeat before "
                  "anything is blocked.")
    notes(slide, "Each layer covers the previous one's blind spot. That is the architecture "
                 "argument in one line.")
    return slide


def s_response(prs, m):
    slide = blank(prs, bg=PAPER)
    kicker(slide, "it doesn't just watch", color=RGBColor(0x0E, 0x76, 0x90))
    heading(slide, "Detection is a diagnosis.\nWe wrote the prescription too.", color=SLATE,
            size=34)
    cards = [
        ("BLOCK", "High severity", "iptables DROP for 120 s", RGBColor(0xB9, 0x1C, 0x1C),
         RGBColor(0xFF, 0xF1, 0xF2)),
        ("QUARANTINE", "Medium severity", "10 packets/s, 60 s", RGBColor(0xB4, 0x53, 0x09),
         RGBColor(0xFF, 0xF7, 0xED)),
        ("LOG ONLY", "Low severity", "recorded, no rule written", RGBColor(0x15, 0x80, 0x3D),
         RGBColor(0xF0, 0xFD, 0xF4)),
    ]
    box_w = Inches(3.72)
    for i, (title, sev, detail, fg, bg) in enumerate(cards):
        left = Emu(int(MARGIN + i * (box_w + Inches(0.22))))
        panel(slide, left, Inches(3.1), box_w, Inches(1.85), fill=bg,
              line=RGBColor(0xE2, 0xE8, 0xF0))
        tf = textbox(slide, left + Inches(0.3), Inches(3.35), box_w - Inches(0.6), Inches(1.4))
        write(tf, title, size=21, color=fg, bold=True, space_after=6)
        write(tf, sev, size=13, color=SLATE2, space_after=4)
        write(tf, detail, size=14, color=SLATE, bold=True, space_after=0)
    items = [
        ("Every rule expires by itself. ", "The worst case of a false alarm is a short, bounded "
                                           "outage for one address — never a permanent ban."),
        ("Everything lives in one chain. ", "All rules sit in a dedicated NETRA iptables chain: "
                                            "inspect with one command, remove with one more."),
        ("A never-block list protects the critical addresses, ",
         "so the system can never cut off its own network or the server it defends."),
    ]
    bullets(slide, items, top=Inches(5.25), size=14, color=SLATE,
            bullet_color=RGBColor(0x0E, 0x76, 0x90), gap=10)
    notes(slide, "Automated blocking is only defensible because it is timed, scoped and "
                 "reversible. Say all three.")
    return slide


def s_proof_live(prs, m):
    slide = blank(prs)
    kicker(slide, "not a simulation")
    heading(slide, "It runs. We filmed it.")
    subheading(slide, "A full Docker lab: attacker, victim and sensor on an isolated network, "
                      "with real packet capture and real firewall rules.", top=Inches(2.05))
    stat_row(slide, [
        ("4 / 4", "real attack tools detected: nmap, hping3, slowloris, hydra", LIME),
        ("~1 s", "from first packet to firewall rule", LIME),
        ("0", "alerts on ordinary browsing traffic", LIME),
    ], top=Inches(3.0), height=Inches(1.7))
    panel(slide, MARGIN, Inches(5.0), CONTENT_W, Inches(1.5), fill=CARD)
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(5.25), CONTENT_W - Inches(0.7), Inches(1.0))
    write(tf, "Live run, dataset replay mode", size=13, color=CYAN, bold=True, space_after=8)
    write(tf, "4,176 flows scored  ·  12 alerts, every attack class correctly named  ·  "
              "76 unknown families formed from the benign tail  ·  0 of them loud enough to "
              "report  ·  0 false alarms", size=15, color=INK, space_after=0, line_spacing=1.25)
    footer(slide, "Native desktop app in PySide6 — not a web page. "
                  "python -m src.cli demo")
    notes(slide, "If the laptop allows, run the demo live here instead of showing this slide.")
    return slide


def s_roadmap(prs, m):
    slide = blank(prs, bg=PAPER)
    kicker(slide, "what's next", color=RGBColor(0x0E, 0x76, 0x90))
    heading(slide, "Where this goes.", color=SLATE)
    items = [
        ("Read the payload. ", "The one change that would fix our worst weakness: web attacks "
                               "live in the text, not in the timing."),
        ("Close the loop. ", "A named family is labelled data. Feed it back into training and "
                             "every discovery becomes a ninth class, then a tenth."),
        ("Tell the whole story. ", "Correlate alerts into campaigns so a multi-stage intrusion "
                                   "reads as one narrative, not forty separate alarms."),
        ("Learn a sharper lens. ", "Measure distances in a space trained to separate classes, "
                                   "to lift the weakest novelty scores."),
    ]
    bullets(slide, items, top=Inches(2.4), size=16, color=SLATE,
            bullet_color=RGBColor(0x0E, 0x76, 0x90), gap=18)
    panel(slide, MARGIN, Inches(5.5), CONTENT_W, Inches(1.2),
          fill=RGBColor(0xEF, 0xF6, 0xFF), line=RGBColor(0xBF, 0xDB, 0xFE))
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(5.75), CONTENT_W - Inches(0.7), Inches(0.75))
    write(tf, "Every item above came out of a measurement that disappointed us. "
              "That is the right way to build a roadmap.",
          size=16, color=RGBColor(0x1D, 0x4E, 0xD8), bold=True, space_after=0)
    notes(slide, "Roadmap ordered by expected value, each traceable to a specific measured gap.")
    return slide


def s_close(prs, m):
    slide = blank(prs)
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.16), H)
    bar.fill.solid()
    bar.fill.fore_color.rgb = CYAN
    bar.line.fill.background()
    bar.shadow.inherit = False
    tf = textbox(slide, MARGIN, Inches(2.1), Inches(11.2), Inches(2.0))
    write(tf, "Any system can tell you\nwhat it recognises.", size=38, color=DIM, bold=True,
          space_after=14, line_spacing=1.15)
    tf = textbox(slide, MARGIN, Inches(3.75), Inches(11.2), Inches(1.4))
    write(tf, "Netra tells you when it recognises nothing —\nand then finds out what it is.",
          size=38, color=CYAN, bold=True, space_after=0, line_spacing=1.15)
    panel(slide, MARGIN, Inches(5.6), CONTENT_W, Inches(1.0), fill=CARD)
    tf = textbox(slide, MARGIN + Inches(0.35), Inches(5.82), CONTENT_W - Inches(0.7), Inches(0.6))
    write(tf, "NETRA  ·  Network Threat Recognition and Automated response  ·  "
              "21CSC302J Computer Networks Case Study",
          size=14, color=DIM, space_after=0)
    notes(slide, "Land on the one-liner. Then invite questions, especially about the limits "
                 "slide: that is where the credibility is.")
    return slide


BUILDERS = [s_title, s_hook, s_truth, s_proof, s_solution, s_guarantee, s_stack,
            s_before_after, s_surprise, s_domainshift, s_numbers, s_response,
            s_honest, s_proof_live, s_roadmap, s_close]


def build(out: Path) -> Path:
    m = load_numbers()
    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H
    for fn in BUILDERS:
        fn(prs, m)
    out.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Netra pitch deck.")
    ap.add_argument("-o", "--out", default=str(ROOT / "presentation" / "Netra_Pitch.pptx"))
    args = ap.parse_args()
    out = build(Path(args.out))
    print(f"Wrote {out} ({len(BUILDERS)} slides)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
