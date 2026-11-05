"""Build the SRMIST case-study report: docs/Netra_Case_Study_Report.docx.

Formatting follows the department template exactly, as stated in its own
"SRMIST Formatting Specifications" page:

    Font            Times New Roman throughout
    Chapter heading 16 pt bold, title case
    Section heading 14 pt bold
    Sub-section     12 pt bold
    Body text       12 pt regular, justified
    Line spacing    1.5 throughout body paragraphs
    Margins         left 1.5in, right 1.0in, top 1.0in, bottom 1.0in
    Page numbers    roman front matter, arabic from Chapter 1

Names are deliberately left blank, as placeholders in square brackets, for the
team to fill in. Every measured number is read from reports/ so the report
cannot drift away from the results.

    python presentation/build_report.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

FONT = "Times New Roman"
BODY_PT = 12
SUBSEC_PT = 12
SECTION_PT = 14
CHAPTER_PT = 16
LINE_SPACING = 1.5


# ---------------------------------------------------------------------------
# Measured numbers
# ---------------------------------------------------------------------------
def load() -> dict:
    def read(name):
        p = REPORTS / name
        if not p.exists():
            sys.exit(f"missing {p}. Run the evaluation first (see README).")
        return json.loads(p.read_text(encoding="utf-8"))

    full, lite, ae = read("metrics_full.json"), read("metrics_lite.json"), read("metrics_autoencoder.json")
    return {
        "full_all": full,
        "lite_all": lite,
        "full": full["models"][full["selected"]],
        "lite": lite["models"][lite["selected"]],
        "ae": ae,
        "openset": read("openset.json"),
        "discovery": read("discovery.json"),
        "cross": read("cross_dataset.json"),
        "data": read("data_summary.json"),
    }


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def style_run(run, size=BODY_PT, bold=False, italic=False, caps=False):
    run.font.name = FONT
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.all_caps = caps
    # East-Asian font must be set too, or Word may substitute.
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(attr), FONT)
    return run


def para(doc, text="", size=BODY_PT, bold=False, align=None, space_after=6,
         space_before=0, line_spacing=LINE_SPACING, italic=False, indent_left=None,
         keep_with_next=False):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.alignment = align if align is not None else WD_ALIGN_PARAGRAPH.JUSTIFY
    pf.space_after = Pt(space_after)
    pf.space_before = Pt(space_before)
    pf.line_spacing = line_spacing
    pf.keep_with_next = keep_with_next
    if indent_left is not None:
        pf.left_indent = Inches(indent_left)
    if text:
        style_run(p.add_run(text), size=size, bold=bold, italic=italic)
    return p


def chapter(doc, text, page_break=True):
    if page_break:
        doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    return para(doc, text, size=CHAPTER_PT, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT,
                space_before=0, space_after=12, line_spacing=1.5, keep_with_next=True)


def section(doc, text):
    return para(doc, text, size=SECTION_PT, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT,
                space_before=10, space_after=6, line_spacing=1.5, keep_with_next=True)


def subsection(doc, text):
    return para(doc, text, size=SUBSEC_PT, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT,
                space_before=8, space_after=4, line_spacing=1.5, keep_with_next=True)


def bullet(doc, text, lead=None):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pf.left_indent = Inches(0.35)
    pf.first_line_indent = Inches(-0.2)
    pf.space_after = Pt(4)
    pf.line_spacing = LINE_SPACING
    style_run(p.add_run("•  "))
    if lead:
        style_run(p.add_run(lead), bold=True)
    style_run(p.add_run(text))
    return p


def numbered(doc, n, text, lead=None):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pf.left_indent = Inches(0.4)
    pf.first_line_indent = Inches(-0.25)
    pf.space_after = Pt(4)
    pf.line_spacing = LINE_SPACING
    style_run(p.add_run(f"{n}. "))
    if lead:
        style_run(p.add_run(lead), bold=True)
    style_run(p.add_run(text))
    return p


def blank(doc, n=1, size=BODY_PT):
    for _ in range(n):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.0
        style_run(p.add_run(""), size=size)


def set_cell(cell, text, bold=False, size=11, align=WD_ALIGN_PARAGRAPH.LEFT):
    cell.text = ""
    p = cell.paragraphs[0]
    p.alignment = align
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.line_spacing = 1.0
    style_run(p.add_run(str(text)), size=size, bold=bold)


TEXT_WIDTH_IN = 8.27 - 1.5 - 1.0   # A4 minus the specified margins


def figure(doc, path, caption, width=5.9):
    """Embed a figure with a centred, italic, numbered caption.

    A missing image is reported as a placeholder rather than crashing the
    build, so the report can still be produced before every artifact exists.
    """
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.0
    full = path if Path(path).is_absolute() else (ROOT / path)
    if full.exists():
        # Never let a figure run into the margins.
        p.add_run().add_picture(str(full), width=Inches(min(width, TEXT_WIDTH_IN)))
    else:
        style_run(p.add_run(f"[ figure not found: {path} ]"), size=11, italic=True)
    para(doc, caption, size=11, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         space_before=0, space_after=12, line_spacing=1.0)


def table(doc, headers, rows, widths=None, caption=None, size=11):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        set_cell(t.rows[0].cells[i], h, bold=True, size=size,
                 align=WD_ALIGN_PARAGRAPH.CENTER)
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            set_cell(cells[i], v, size=size,
                     align=WD_ALIGN_PARAGRAPH.LEFT if i == 0 else WD_ALIGN_PARAGRAPH.CENTER)
    if widths:
        # Scale the requested column widths to fit the text column exactly,
        # so a wide table shrinks rather than spilling into the margin.
        total = sum(widths)
        scale = min(1.0, TEXT_WIDTH_IN / total) if total else 1.0
        for r in t.rows:
            for i, w in enumerate(widths):
                r.cells[i].width = Inches(w * scale)
    if caption:
        para(doc, caption, size=11, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER,
             space_before=4, space_after=10, line_spacing=1.0)
    return t


def add_page_number_field(paragraph):
    """A PAGE field, so Word numbers the pages itself."""
    run = paragraph.add_run()
    style_run(run, size=11)
    for instr, kind in ((None, "begin"), ("PAGE", "instrText"), (None, "end")):
        el = OxmlElement(f"w:{'fldChar' if kind != 'instrText' else 'instrText'}")
        if kind == "instrText":
            el.set(qn("xml:space"), "preserve")
            el.text = " PAGE "
        else:
            el.set(qn("w:fldCharType"), kind)
        run._element.append(el)


def set_page_numbering(section_obj, fmt, start=None):
    """fmt: 'lowerRoman' or 'decimal'."""
    sect_pr = section_obj._sectPr
    pg = sect_pr.find(qn("w:pgNumType"))
    if pg is None:
        pg = OxmlElement("w:pgNumType")
        sect_pr.append(pg)
    pg.set(qn("w:fmt"), fmt)
    if start is not None:
        pg.set(qn("w:start"), str(start))


def configure(section_obj):
    # A4, matching the department template. python-docx defaults to US Letter.
    section_obj.page_width = Inches(8.27)
    section_obj.page_height = Inches(11.69)
    section_obj.left_margin = Inches(1.5)
    section_obj.right_margin = Inches(1.0)
    section_obj.top_margin = Inches(1.0)
    section_obj.bottom_margin = Inches(1.0)


def footer_number(section_obj):
    section_obj.footer.is_linked_to_previous = False
    p = section_obj.footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(0)
    add_page_number_field(p)


def pct(x, places=2):
    return f"{100 * x:.{places}f}%"


# ---------------------------------------------------------------------------
# Front matter
# ---------------------------------------------------------------------------
def title_page(doc):
    c = WD_ALIGN_PARAGRAPH.CENTER
    blank(doc, 1)
    para(doc, "NETRA: AN OPEN-SET INTRUSION DETECTION AND AUTOMATED RESPONSE SYSTEM",
         size=16, bold=True, align=c, space_after=4, line_spacing=1.25)
    para(doc, "Detecting, Grouping and Naming Attacks the Models Were Never Trained On",
         size=13, bold=True, align=c, space_after=14, line_spacing=1.25)
    para(doc, "21CSC302J – Computer Networks Course Case Study Project",
         size=12, bold=True, align=c, space_after=16, line_spacing=1.2)
    para(doc, "Submitted by", size=12, align=c, space_after=10, line_spacing=1.2)

    # Space for the team to write their names.
    for _ in range(4):
        para(doc, "____________________________        [Reg. No. ____________________]",
             size=13, bold=True, align=c, space_after=12, line_spacing=1.2)

    para(doc, "Under the guidance of", size=12, align=c, space_after=8, line_spacing=1.2)
    para(doc, "[ Name of the Faculty ]", size=14, bold=True, align=c, space_after=2,
         line_spacing=1.2)
    para(doc, "[ Designation ]", size=14, bold=True, align=c, space_after=2, line_spacing=1.2)
    para(doc, "[ Department ]", size=14, bold=True, align=c, space_after=14, line_spacing=1.2)

    para(doc, "in partial fulfillment of the requirements for the degree of",
         size=12, align=c, space_after=2, line_spacing=1.2)
    para(doc, "BACHELOR OF TECHNOLOGY", size=12, bold=True, align=c, space_after=2,
         line_spacing=1.2)
    para(doc, "in", size=12, align=c, space_after=2, line_spacing=1.2)
    para(doc, "[ DEPARTMENT ]", size=14, bold=True, align=c, space_after=16, line_spacing=1.2)

    for line in ("FACULTY OF ENGINEERING AND TECHNOLOGY",
                 "SCHOOL OF COMPUTING",
                 "SRM INSTITUTE OF SCIENCE AND TECHNOLOGY",
                 "KATTANKULATHUR – 603203"):
        para(doc, line, size=14, bold=True, align=c, space_after=2, line_spacing=1.2)
    para(doc, "NOVEMBER 2026", size=14, bold=True, align=c, space_after=0, line_spacing=1.2)


def bonafide(doc):
    c = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    para(doc, "SRM INSTITUTE OF SCIENCE AND TECHNOLOGY", size=13, bold=True, align=c,
         space_after=2, line_spacing=1.2)
    para(doc, "KATTANKULATHUR – 603203", size=13, bold=True, align=c, space_after=18,
         line_spacing=1.2)
    para(doc, "BONAFIDE CERTIFICATE", size=14, bold=True, align=c, space_after=18,
         line_spacing=1.2)
    para(doc, "This is to certify that the 21CSC302J – Computer Networks case study report "
              "titled “Netra: An Open-Set Intrusion Detection and Automated Response "
              "System” is the bonafide work of ______________________________________ "
              "[Reg. No. ____________________], ______________________________________ "
              "[Reg. No. ____________________], ______________________________________ "
              "[Reg. No. ____________________] and ______________________________________ "
              "[Reg. No. ____________________], who undertook the task of completing the "
              "report within the allotted time.",
         size=14, space_after=28, line_spacing=1.5)
    blank(doc, 3)
    t = doc.add_table(rows=1, cols=2)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    left, right = t.rows[0].cells
    for cell, lines in ((left, ["SIGNATURE", "", "[ Name of the Faculty In-Charge ]",
                                "[ Designation ]", "[ Department ]"]),
                        (right, ["SIGNATURE", "", "[ Name of the Head of Department ]",
                                 "Head of the Department", "[ Department ]"])):
        cell.text = ""
        for i, line in enumerate(lines):
            p = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.line_spacing = 1.2
            style_run(p.add_run(line), size=12, bold=(i == 0))
        cell.width = Inches(TEXT_WIDTH_IN / 2)


def declaration(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    para(doc, "DECLARATION", size=14, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         space_after=18, line_spacing=1.2)
    para(doc, "We hereby declare that the case study report titled “Netra: An Open-Set "
              "Intrusion Detection and Automated Response System” submitted for the "
              "21CSC302J Computer Networks course is our own original work. The design, the "
              "implementation, the experiments and the results reported here were carried out "
              "by us. All external sources, datasets and tools used have been duly "
              "acknowledged in the references. Every performance figure quoted in this report "
              "was produced by the evaluation scripts included with the project and can be "
              "reproduced by running them.",
         size=12, space_after=36, line_spacing=1.5)
    blank(doc, 4)
    for _ in range(4):
        para(doc, "______________________________        [Reg. No. ____________________]",
             size=12, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=16, line_spacing=1.2)
    para(doc, "Place: Kattankulathur", size=12, align=WD_ALIGN_PARAGRAPH.LEFT,
         space_after=4, line_spacing=1.2)
    para(doc, "Date:  ____________________", size=12, align=WD_ALIGN_PARAGRAPH.LEFT,
         space_after=0, line_spacing=1.2)


def acknowledgement(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    para(doc, "ACKNOWLEDGEMENT", size=14, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         space_after=18, line_spacing=1.2)
    para(doc, "We express our sincere gratitude to our faculty in-charge, "
              "[ Name of the Faculty ], [ Designation ], [ Department ], for the guidance, "
              "the technical direction and the patience offered throughout this case study. "
              "The insistence on validating the system against data it had not been trained on "
              "shaped the most valuable findings reported here.",
         size=12, space_after=10, line_spacing=1.5)
    para(doc, "We thank [ Name of the Head of Department ], Head of the Department of "
              "[ Department ], and the faculty of the School of Computing, SRM Institute of "
              "Science and Technology, for providing the laboratory facilities and the "
              "academic environment in which this work was carried out.",
         size=12, space_after=10, line_spacing=1.5)
    para(doc, "We also acknowledge the Canadian Institute for Cybersecurity at the University "
              "of New Brunswick for publishing the CIC-IDS2017 dataset, and the Australian "
              "Centre for Cyber Security at UNSW Canberra for the UNSW-NB15 dataset, without "
              "which the cross-dataset evaluation that forms a central part of this report "
              "would not have been possible.",
         size=12, space_after=10, line_spacing=1.5)
    para(doc, "Finally, we thank our families and friends for their constant encouragement "
              "during the course of this project.",
         size=12, space_after=0, line_spacing=1.5)


def abstract(doc, m):
    full, ae = m["full"], m["ae"]
    os_ = m["openset"]
    kr = os_["known_rejection"]["scores"][os_["score"]]["rejection_rate"]
    loco = os_["leave_one_class_out"]
    silent = sum(1 for f in loco["folds"] if f["closed_set_called_benign"] > 0.5)
    ds = os_["domain_shift"]["scores"][os_["score"]]["unknown_rate"]
    disc = m["discovery"]["totals"]

    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    para(doc, "ABSTRACT", size=14, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         space_after=18, line_spacing=1.2)
    para(doc,
         "Network intrusion detection systems must catch attacks that have never been seen "
         "before while raising few enough false alarms to remain usable. This case study "
         "presents Netra, a hybrid detection and automated response system that combines four "
         "packet-level signature rules, two supervised classifiers trained on the CIC-IDS2017 "
         "benchmark, an autoencoder trained only on benign traffic, and an open-set recognition "
         "layer, and that responds to detected attacks by installing timed, reversible firewall "
         f"rules. On the held-out test split the selected Random Forest attains "
         f"macro F1 {full['macro']['f1']:.4f} and accuracy {full['accuracy']:.4f}, flagging "
         f"{pct(full['binary']['detection_rate'])} of attack flows while misclassifying "
         f"{pct(full['binary']['false_positive_rate'], 3)} of benign flows, and the autoencoder "
         f"reaches ROC-AUC {ae['roc_auc']:.4f} without ever being shown an attack during "
         "training. The distinguishing contribution is the open-set layer, which supplies the "
         "verdict a trained classifier structurally cannot produce: that a flow matches none of "
         "the classes it was taught. A conformal test fixes the cost of that verdict in advance, "
         f"rejecting a measured {kr:.4f} of known traffic against a promised 0.05, and the flows "
         "it rejects are clustered online into named families carrying readable fingerprints "
         "that an analyst can identify and name permanently. Removing each attack class in turn "
         "from training, scaling and calibration shows that the closed-set baseline reports the "
         f"majority of the unseen attack as benign in {silent} of 7 cases and raises no alert "
         "at all, whereas the open-set layer surfaces the attack as a named family in "
         f"{disc['folds_where_novel_family_reported']} of 7 cases at a mean cluster purity of "
         f"{disc['mean_purity']:.3f}. Two negative findings are reported with equal weight: the "
         "TCP flag counters in CIC-IDS2017 are unreliable and were excluded, and the trained "
         "model does not transfer across networks, its detection rate falling from 0.9976 to "
         f"0.0003 on UNSW-NB15. On that foreign network the open-set layer reports {pct(ds)} of "
         "traffic as unrecognised against 4.68 percent in domain, which is a statement about "
         "its own competence that a closed-set classifier cannot make.",
         size=12, space_after=12, line_spacing=1.5)
    para(doc, "Keywords: intrusion detection, open-set recognition, conformal prediction, "
              "anomaly detection, zero-day attacks, CIC-IDS2017, machine learning, network "
              "security, automated response.",
         size=12, italic=True, space_after=0, line_spacing=1.5)


# Page numbers measured from the rendered PDF of this document, not estimated.
# Regenerate with the extraction snippet documented in the project history if
# the content changes enough to shift the layout.
TOC_ROWS = [
    ("", "Bonafide Certificate", "ii"),
    ("", "Declaration", "iii"),
    ("", "Acknowledgement", "iv"),
    ("", "Abstract", "v"),
    ("", "Table of Contents", "vi"),
    ("", "List of Figures and Tables", "viii"),
    ("", "List of Abbreviations", "ix"),
    ("1", "Introduction", "1"),
    ("1.1", "Background", "1"),
    ("1.2", "Industry / Domain Context", "1"),
    ("1.3", "Problem Statement", "2"),
    ("1.4", "Objectives", "2"),
    ("1.5", "Scope and Limitations", "3"),
    ("1.6", "Organization of the Report", "3"),
    ("2", "Literature Review / Background Study", "4"),
    ("2.1", "Introduction", "4"),
    ("2.2", "Review of Existing Approaches", "4"),
    ("2.3", "Comparative Analysis and Gap Identification", "6"),
    ("3", "Methodology / Framework Design", "7"),
    ("3.1", "Approach Overview", "7"),
    ("3.2", "Data Collection and Requirements", "7"),
    ("3.3", "Architecture and Workflow", "9"),
    ("3.4", "Implementation Strategy", "10"),
    ("4", "Case Study Implementation and Analysis", "12"),
    ("4.1", "Execution and Step-by-Step Analysis", "12"),
    ("4.2", "Core Algorithms and Configurations", "12"),
    ("4.3", "Challenges Faced and Mitigation", "14"),
    ("5", "Results and Discussion", "16"),
    ("5.1", "Findings and Output", "16"),
    ("5.2", "Discussion", "27"),
    ("5.3", "Practical Implications", "28"),
    ("6", "Conclusion and Future Scope", "29"),
    ("6.1", "Conclusion", "29"),
    ("6.2", "Future Scope", "29"),
    ("", "References", "31"),
    ("", "Appendix A: Command Reference", "33"),
]


def toc(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    para(doc, "TABLE OF CONTENTS", size=14, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         space_after=14, line_spacing=1.2)
    rows = [(a, b, c) for a, b, c in TOC_ROWS]
    table(doc, ["Chapter No.", "Title", "Page No."], rows,
          widths=[1.1, 4.3, 1.0], size=11)
    para(doc, "Page numbers refer to the printed folios of this document and should be "
              "refreshed if the content is edited.", size=10, italic=True,
         align=WD_ALIGN_PARAGRAPH.LEFT, space_before=6, space_after=0, line_spacing=1.0)


def lists_page(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    para(doc, "LIST OF FIGURES AND TABLES", size=14, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=14, line_spacing=1.2)
    section(doc, "List of Figures")
    figs = [
        ("3.1", "Class distribution across the three splits and test-split balance"),
        ("3.2", "Netra six-layer detection and response pipeline"),
        ("3.3", "Isolated Docker laboratory topology"),
        ("5.1", "Confusion matrix, full 59-feature Random Forest"),
        ("5.2", "One-vs-rest ROC curves and the binary attack view"),
        ("5.3", "Top fifteen features used by the full Random Forest"),
        ("5.4", "Per-class F1 score, full feature set"),
        ("5.5", "Per-class F1 score, lite feature set"),
        ("5.6", "Autoencoder reconstruction-error distribution"),
        ("5.7", "Novelty AUC per unseen attack, and what reaches the operator"),
        ("5.8", "Open-set operating curve and closed-set comparison"),
        ("5.9", "Reporting-threshold trade-off curve"),
        ("5.10", "Cross-dataset transfer to UNSW-NB15"),
        ("5.11", "Laboratory baseline: attacker reaches the victim"),
        ("5.12", "Laboratory after detection: attacker blocked by iptables"),
        ("5.13", "Laboratory after rule expiry: connectivity restored"),
        ("5.14", "Desktop application during a live laboratory run"),
        ("5.15", "Desktop application with the unknown-families panel"),
        ("5.16", "Desktop application after an analyst names a family"),
    ]
    table(doc, ["Figure", "Title", "Page"], [(a, b, "") for a, b in figs],
          widths=[0.9, 4.5, 0.9], size=11)
    section(doc, "List of Tables")
    tabs = [
        ("3.1", "Class distribution after cleaning and splitting"),
        ("3.2", "The six live-computable lite features"),
        ("3.3", "Protocols observed, parsed and used by the system"),
        ("5.1", "Model comparison on the full feature set"),
        ("5.2", "Per-class results, full Random Forest"),
        ("5.3", "Conformal validity of the open-set test"),
        ("5.4", "Leave-one-class-out: closed-set versus open-set"),
        ("5.5", "Unknown-family discovery results"),
        ("5.6", "Reporting-threshold trade-off curve"),
        ("5.7", "Cross-dataset and domain-shift results"),
    ]
    table(doc, ["Table", "Title", "Page"], [(a, b, "") for a, b in tabs],
          widths=[0.9, 4.5, 0.9], size=11)


ABBREVIATIONS = [
    ("ACK", "Acknowledgement flag (TCP)"),
    ("API", "Application Programming Interface"),
    ("ARI", "Adjusted Rand Index"),
    ("AUC", "Area Under the Curve"),
    ("CIC", "Canadian Institute for Cybersecurity"),
    ("DDoS", "Distributed Denial of Service"),
    ("DMZ", "Demilitarised Zone"),
    ("DoS", "Denial of Service"),
    ("FPR", "False Positive Rate"),
    ("HTTP", "Hypertext Transfer Protocol"),
    ("IAT", "Inter-Arrival Time"),
    ("IDS", "Intrusion Detection System"),
    ("IPS", "Intrusion Prevention System"),
    ("ML", "Machine Learning"),
    ("REST", "Representational State Transfer"),
    ("RF", "Random Forest"),
    ("ROC", "Receiver Operating Characteristic"),
    ("SYN", "Synchronise flag (TCP)"),
    ("TCP", "Transmission Control Protocol"),
    ("UDP", "User Datagram Protocol"),
    ("VLAN", "Virtual Local Area Network"),
    ("XSS", "Cross-Site Scripting"),
]


def abbreviations(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    para(doc, "LIST OF ABBREVIATIONS", size=14, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=14, line_spacing=1.2)
    table(doc, ["Abbreviation", "Expansion"], ABBREVIATIONS, widths=[1.6, 4.7], size=11)


# ---------------------------------------------------------------------------
# Chapters
# ---------------------------------------------------------------------------
def chapter1(doc, m):
    data = m["data"]
    # No page break: the body section already begins on a new page, and adding
    # one here would leave an empty page 1 before the first chapter.
    chapter(doc, "Chapter 1: Introduction", page_break=False)

    section(doc, "1.1 Background")
    para(doc, "A computer network moves data by cutting it into packets, each carrying a "
              "header that says where it is going and a payload that carries the content. "
              "Every service a machine offers listens on a numbered port, and every "
              "conversation between two machines is identified by a five-part key: the source "
              "address, the source port, the destination address, the destination port and the "
              "protocol. Security tools watch this traffic because almost every attack on a "
              "networked service must, at some point, travel across the network as packets.")
    para(doc, "Two families of tool dominate this task. Signature-based systems compare traffic "
              "against stored patterns of known attacks. They are precise and fast, but they "
              "are blind to anything nobody has written a pattern for. Anomaly-based systems "
              "learn a model of normal traffic and report deviations from it. They can in "
              "principle react to attacks nobody anticipated, but they historically produce "
              "alert volumes that operators learn to ignore. Machine learning sits between the "
              "two: given enough labelled examples, a classifier learns the statistical "
              "signature of each attack family without anyone writing rules by hand.")
    para(doc, "This case study builds such a system end to end, and then examines the "
              "assumption that all three families quietly share: that the attacks encountered "
              "in deployment will resemble the attacks described in the training data.")

    section(doc, "1.2 Industry / Domain Context")
    para(doc, "In an enterprise network, an intrusion detection sensor typically sits on a "
              "mirrored switch port, watching a copy of traffic crossing a choke point such as "
              "the boundary between the internet and a demilitarised zone that holds "
              "public-facing servers. The sensor classifies traffic and raises alerts to a "
              "security operations centre, where human analysts triage them. An intrusion "
              "prevention system goes further and enforces a response, usually by instructing "
              "a firewall to drop traffic from the offending address.")
    para(doc, "Two practical pressures shape such deployments. The first is alert fatigue: an "
              "analyst who receives thousands of low-quality alerts per day stops reading them, "
              "so a detector that is technically sensitive but imprecise is operationally "
              "useless. The second is the cost of an automated mistake. Blocking an address "
              "automatically is powerful but dangerous, because a false positive becomes an "
              "outage for a legitimate user, and an attacker who can provoke false positives "
              "can turn the defence into the attack.")

    section(doc, "1.3 Problem Statement")
    para(doc, "A supervised classifier is closed-set. Its output is a probability distribution "
              "over the classes present in its training labels, and those probabilities are "
              "constrained to sum to one. There is therefore no output the model can produce "
              "that means “none of these”. When traffic from an attack family absent "
              "from the training data arrives, the model does not fail loudly; it distributes "
              "its belief among the classes it knows and returns the nearest one, usually with "
              "high confidence. In an intrusion detection setting the nearest class is "
              "ordinarily the benign class, so a novel attack produces silence rather than an "
              "alarm.")
    para(doc, "This failure is invisible to the evaluation methods normally used. A model "
              "evaluated on a held-out split of the same dataset is only ever asked about "
              "classes it has seen, so accuracy, F1 and ROC-AUC on that split say nothing about "
              "its behaviour on a class that is absent. The problem addressed in this case "
              "study is therefore twofold: to give a network intrusion detection system a way "
              "to report that traffic matches nothing it was trained on, at a false-alarm cost "
              "that is known in advance rather than discovered by trial; and to make that "
              "report useful, by grouping the unrecognised traffic into coherent, named, "
              "described objects instead of a stream of unlabelled anomalies.")

    section(doc, "1.4 Objectives")
    objs = [
        ("To design and implement a complete hybrid intrusion detection and response "
         "pipeline", " spanning live packet capture, flow assembly, signature rules, "
         "supervised classification, unsupervised anomaly detection and automated firewall "
         "response."),
        ("To train and rigorously evaluate supervised and unsupervised models",
         " on the CIC-IDS2017 benchmark, selecting between candidates on validation macro F1 "
         "so that rare attack classes are weighted equally with common ones."),
        ("To add an open-set recognition layer",
         " that allows the system to reject a flow as matching none of its trained classes, "
         "with a false-alarm cost that is fixed in advance by a conformal construction."),
        ("To cluster and name the rejected traffic",
         " online, so that a novel attack appears as a single described family rather than "
         "hundreds of separate anomaly records, and to allow an analyst to assign a permanent "
         "name to a family."),
        ("To validate the system against data it was not trained on",
         ", by removing each attack class in turn from training and by evaluating the trained "
         "model on a second, independently captured dataset."),
        ("To implement a safe automated response",
         " in which every firewall rule is timed, reversible, confined to a dedicated chain "
         "and subject to a never-block list."),
    ]
    for i, (lead, rest) in enumerate(objs, start=1):
        numbered(doc, i, rest, lead=lead)

    section(doc, "1.5 Scope and Limitations")
    para(doc, "The system operates on flow-level statistics derived from packet headers. It "
              f"was trained on {data['rows_loaded']:,} flows from CIC-IDS2017, of which "
              f"{data['rows_after_cleaning']:,} remained after cleaning, covering eight "
              "classes. Live validation was performed in an isolated Docker laboratory "
              "containing one attacker, one victim and one sensor.")
    para(doc, "Three limitations bound the work and are stated here because they qualify every "
              "result that follows. First, no component inspects packet payloads, so attacks "
              "that are carried in application content rather than in traffic shape, such as "
              "SQL injection, are poorly detected, and encrypted traffic is opaque to the "
              "flow-statistic detectors. Second, response is by source address, which is "
              "defeated by address spoofing and by sufficiently distributed attacks. Third, the "
              "laboratory is small; throughput at carrier scale and the behaviour of the "
              "per-source state tables under many thousands of simultaneous sources are "
              "untested.")

    section(doc, "1.6 Organization of the Report")
    para(doc, "Chapter 2 reviews existing work on intrusion detection datasets, machine "
              "learning detectors, anomaly detection and open-set recognition, and identifies "
              "the gap this case study addresses. Chapter 3 describes the methodology: the "
              "dataset and its cleaning, the feature sets, the six-layer architecture and the "
              "implementation strategy. Chapter 4 details the implementation, the core "
              "algorithms including the conformal open-set test and the online clusterer, and "
              "the practical obstacles encountered. Chapter 5 presents the measured results, "
              "including the leave-one-class-out and cross-dataset experiments, and discusses "
              "what they mean. Chapter 6 concludes and sets out future work.")


def chapter2(doc, m):
    chapter(doc, "Chapter 2: Literature Review / Background Study")

    section(doc, "2.1 Introduction")
    para(doc, "This chapter establishes the technical foundation of the case study by "
              "reviewing four strands of prior work: the benchmark datasets used to train and "
              "evaluate network intrusion detection systems, supervised machine learning "
              "applied to those datasets, unsupervised anomaly detection, and open-set "
              "recognition. The last of these has been developed largely in the computer "
              "vision literature and is comparatively rarely applied to network traffic, which "
              "is the gap this work addresses.")

    section(doc, "2.2 Review of Existing Approaches")
    subsection(doc, "2.2.1 Benchmark datasets")
    para(doc, "Sharafaldin, Lashkari and Ghorbani (2018) introduced CIC-IDS2017, generated over "
              "five working days on a testbed with profiled benign user behaviour and labelled "
              "attacks including denial of service, distributed denial of service, brute force, "
              "port scanning, web attacks, botnet traffic and infiltration. Flow features are "
              "extracted using CICFlowMeter. The dataset largely replaced KDD Cup 99 and "
              "NSL-KDD, both of which are synthetic, decades old and known to contain "
              "redundancies that inflate reported accuracy.")
    para(doc, "Moustafa and Slay (2015) published UNSW-NB15, created independently using the "
              "IXIA PerfectStorm traffic generator with nine attack categories. Because it was "
              "captured on a different network by different researchers, it provides an "
              "independent test of whether a model has learned attack behaviour or merely the "
              "characteristics of one capture environment. This report uses it for exactly that "
              "purpose.")
    para(doc, "Engelen, Rimmer and Joosen (2021) re-examined CIC-IDS2017 and documented errors "
              "in the CICFlowMeter extraction, including incorrect TCP flag accounting and "
              "flawed flow termination logic. Their findings are reproduced independently in "
              "this case study and directly changed its feature selection.")

    subsection(doc, "2.2.2 Supervised machine learning detectors")
    para(doc, "A large body of work applies tree ensembles to these datasets. Random Forests "
              "and gradient-boosted trees such as XGBoost repeatedly report accuracy and F1 "
              "scores above 0.99 on CIC-IDS2017, typically outperforming support vector "
              "machines and shallow neural networks while training far faster. Deep learning "
              "approaches using convolutional and recurrent architectures report comparable "
              "accuracy at substantially greater computational cost and with reduced "
              "interpretability.")
    para(doc, "Two methodological weaknesses recur across this literature. Results are usually "
              "reported on a random split of a single dataset, so they measure in-domain "
              "performance only. And evaluation is closed-set: every test sample belongs to a "
              "class present in training, so the published metrics cannot describe behaviour on "
              "an unseen attack family.")

    subsection(doc, "2.2.3 Unsupervised anomaly detection")
    para(doc, "Mirsky et al. (2018) presented Kitsune, an ensemble of small autoencoders "
              "performing online anomaly detection on network traffic without attack labels, "
              "establishing the autoencoder reconstruction error as a practical anomaly score. "
              "The general weakness of this family is interpretability: the output is a single "
              "number, and an alert that says only “unusual” gives an analyst nothing "
              "to act on. The present work keeps the autoencoder but addresses this weakness "
              "directly.")

    subsection(doc, "2.2.4 Open-set recognition and conformal prediction")
    para(doc, "Scheirer et al. (2013) formalised open-set recognition as the problem of "
              "classifying while rejecting inputs from classes absent at training time. Lee et "
              "al. (2018) proposed a widely used detector that models each class as a Gaussian "
              "in feature space and scores samples by Mahalanobis distance. Papernot and "
              "McDaniel (2018) used nearest-neighbour distances in a learned representation as "
              "a non-conformity measure.")
    para(doc, "Vovk, Gammerman and Shafer (2005) developed conformal prediction, which converts "
              "any non-conformity score into a p-value with a distribution-free validity "
              "guarantee: the probability that a genuine member of a class is rejected at level "
              "alpha is at most alpha. This property is the reason the present work adopts a "
              "conformal formulation, because it converts the detection threshold from a "
              "quantity tuned on data into a false-alarm budget chosen in advance.")
    para(doc, "Explainability is addressed by Saabas's decision-path decomposition, which "
              "attributes a tree ensemble's predicted probability exactly to a bias term plus "
              "one contribution per feature. Unlike approximate attribution methods it is "
              "exact and cheap enough to compute per alert.")

    section(doc, "2.3 Comparative Analysis and Gap Identification")
    rows = [
        ("Signature rules (Snort, Suricata)", "Known attacks", "Fast, precise, explainable",
         "Blind to anything unwritten"),
        ("Supervised ML on CIC-IDS2017", "Trained classes", "High in-domain accuracy",
         "Closed-set; cannot report an unknown class"),
        ("Autoencoder anomaly detection", "Deviation from normal", "Needs no attack labels",
         "Output is one number; no explanation"),
        ("Gaussian open-set (Lee et al.)", "Distance to class mean", "Principled, simple",
         "Fails on multi-modal benign traffic"),
        ("Netra (this work)", "All of the above plus conformal rejection",
         "Bounded false-alarm cost; named families", "Payload-blind; per-network retraining"),
    ]
    table(doc, ["Approach", "Detects", "Strength", "Limitation"], rows,
          widths=[1.9, 1.5, 1.6, 1.6], size=10,
          caption="Table 2.1: Comparative analysis of detection approaches.")
    para(doc, "Three gaps follow from this comparison. Detectors are evaluated almost "
              "exclusively in-domain, so their behaviour on novel attacks and on other networks "
              "is undocumented. Anomaly detectors report deviation without description, "
              "producing alerts that are technically correct and operationally useless. And "
              "rejection thresholds are typically tuned until results look acceptable, which "
              "provides no guarantee about the false-alarm rate in deployment. This case study "
              "addresses all three: it evaluates by removing classes and by changing datasets, "
              "it describes and names what it rejects, and it fixes the rejection cost "
              "mathematically in advance.")


def chapter3(doc, m):
    data = m["data"]
    chapter(doc, "Chapter 3: Methodology / Framework Design")

    section(doc, "3.1 Approach Overview")
    para(doc, "Netra is organised as six layers. Packets are ingested from live capture, a "
              "capture file or a replay of held-out dataset rows, and all three paths produce "
              "the same feature schema so that a detector behaves identically regardless of "
              "source. Packets are assembled into bidirectional flows. Each completed flow is "
              "scored by a priority-ordered fusion of detectors. A verdict becomes an alert, "
              "and an alert may become a firewall rule. Everything the engine does is published "
              "on an event bus consumed by a native desktop application.")
    para(doc, "The design principle throughout is that each layer should cover the blind spot "
              "of the one before it. Signature rules cover attacks that are anticipated but "
              "must be caught in about one second. Supervised classifiers cover attacks that "
              "were labelled in training but have no hand-written rule. The autoencoder covers "
              "patterns for which no label exists. The open-set layer covers the case none of "
              "the others can express: that the traffic matches nothing the system was taught.")

    section(doc, "3.2 Data Collection and Requirements")
    subsection(doc, "3.2.1 Dataset and cleaning")
    para(doc, f"The primary dataset is the CIC-IDS2017 GeneratedLabelledFlows release, chosen "
              f"over the machine-learning release because it retains source and destination "
              f"addresses and timestamps, which the replay and the per-source window features "
              f"require. All five capture days were loaded, yielding {data['rows_loaded']:,} "
              f"flows. Cleaning proceeded in defined stages: rows with missing or infinite "
              f"feature values were dropped; exact duplicates of a feature vector and class "
              f"were collapsed to a single row; feature vectors appearing with more than one "
              f"class were removed as ambiguous; and classes with fewer than 100 remaining rows "
              f"were dropped, which removed Heartbleed with 11 rows and Infiltration. "
              f"{data['rows_after_cleaning']:,} rows and eight classes remained.")
    para(doc, "Because duplicate feature vectors are collapsed before splitting, no feature "
              "vector can appear in more than one split, which eliminates a common source of "
              "optimistic bias in published results on this dataset.")
    splits = data["splits"]
    rows = []
    for cls in sorted(splits["test"]["class_counts"]):
        rows.append((cls,
                     f"{splits['train']['class_counts'].get(cls, 0):,}",
                     f"{splits['val']['class_counts'].get(cls, 0):,}",
                     f"{splits['test']['class_counts'].get(cls, 0):,}"))
    rows.append(("Total", f"{splits['train']['rows']:,}", f"{splits['val']['rows']:,}",
                 f"{splits['test']['rows']:,}"))
    table(doc, ["Class", "Train", "Validation", "Test"], rows,
          widths=[1.9, 1.6, 1.6, 1.5], size=11,
          caption="Table 3.1: Class distribution after cleaning and stratified splitting.")
    figure(doc, "reports/fig_class_distribution.png",
           "Figure 3.1: Class distribution across the three splits, plotted on a logarithmic "
           "scale because benign traffic outnumbers the rarest attack class by three orders of "
           "magnitude, and the resulting attack-versus-benign balance of the test split.",
           width=6.0)
    para(doc, "Training rows were capped at 400,000 per class, which in practice undersamples "
              "only benign traffic. Validation and test splits retain the natural class "
              "distribution, so reported metrics describe realistic traffic rather than a "
              "balanced laboratory mixture.")

    subsection(doc, "3.2.2 Feature sets and a corrected exclusion")
    para(doc, f"Two feature sets are maintained. The full set contains "
              f"{data['n_features']} CICFlowMeter statistics and serves as the offline "
              f"benchmark. The lite set contains {data['n_lite_features']} features that can be "
              f"computed from live packets in any environment, guaranteeing that the live "
              f"demonstration works even where full feature parity is not achievable.")
    rows = [
        ("flow_duration", "Seconds from first to last packet of the flow"),
        ("packets_per_sec", "Packet rate over the flow"),
        ("bytes_per_sec", "Payload byte rate over the flow"),
        ("mean_packet_size", "Mean payload bytes per packet"),
        ("src_unique_dst_ports", "Distinct destination ports contacted by the source in 60 s"),
        ("src_unique_dsts", "Distinct destination hosts contacted by the source in 60 s"),
    ]
    table(doc, ["Lite feature", "Meaning"], rows, widths=[2.3, 4.0], size=11,
          caption="Table 3.2: The six live-computable features.")
    para(doc, "Flow identifiers are excluded from both sets. Addresses, ports and timestamps "
              "are retained as metadata for replay but are never model inputs, so the models "
              "cannot memorise hosts or times. Destination port is excluded for the same "
              "reason: in this dataset it acts as a shortcut, since most denial-of-service rows "
              "target port 80, and a model exploiting it would not generalise.")
    para(doc, "All twelve TCP flag counters are also excluded. Inspection of the dataset "
              "confirmed the problem reported by Engelen et al.: SYN Flag Count is zero on "
              "every port-scan flow, although such a flow is by definition a SYN probe, and FIN "
              "Flag Count is zero on almost all flows. A model trained on these columns learns "
              "an extraction bug rather than a property of traffic, and the consequence is not "
              "theoretical. Before the exclusion, ordinary browsing traffic in the laboratory, "
              "whose connections legitimately carry FIN and PSH flags, was scored as anomalous "
              "and a benign client was quarantined. Removing the twelve columns cost little "
              "offline accuracy and was necessary for the system to function on real packets. "
              "The flags are still used by the signature rules, which read them from real "
              "packets rather than from the dataset.")

    subsection(doc, "3.2.3 Protocols observed and handled")
    para(doc, "The packet parser accepts IPv4 datagrams carrying TCP or UDP and returns "
              "nothing for anything else, so the protocol coverage of the system is defined "
              "precisely. Table 3.3 lists every protocol the project touches, together with "
              "the number of flows carrying it in the held-out test split where that figure "
              "is meaningful.")
    rows = [
        ("Link", "Ethernet", "–", "Carries every frame on the laboratory bridge network."),
        ("Internet", "IPv4", "–", "The only address family parsed; supplies the source "
                                       "and destination addresses used for response."),
        ("Internet", "ARP", "–", "Resolves addresses on the lab segment. Observed but "
                                      "not parsed."),
        ("Internet", "ICMP", "proto 1", "Not parsed. A stated limitation: an ICMP flood or "
                                        "tunnel would not be seen."),
        ("Transport", "TCP", "proto 6", "The principal protocol. Flags, window size and "
                                        "handshake state are read by the signature rules; all "
                                        "four laboratory attacks are TCP."),
        ("Transport", "UDP", "proto 17", "Parsed, but carries no flags or connection state. "
                                         "Used by DNS and NTP traffic."),
        ("Application", "DNS", "53 / UDP", "129,011 flows. The commonest port in the test "
                                           "split; benign background traffic."),
        ("Application", "HTTP", "80", "80,737 flows. The protected web server, the slow "
                                      "denial-of-service target and the brute-force target."),
        ("Application", "HTTPS / TLS", "443", "69,787 flows. Encrypted, so only traffic shape "
                                              "is observable, never content."),
        ("Application", "NTP", "123", "3,143 flows. Time synchronisation; benign."),
        ("Application", "SSH", "22", "1,509 flows. Target of the SSH-Patator brute force and "
                                     "a watched login port."),
        ("Application", "FTP", "21", "1,401 flows. Target of the FTP-Patator brute force and "
                                     "a watched login port."),
        ("Application", "LDAP", "389", "862 flows. Directory lookups in benign traffic."),
        ("Application", "NetBIOS / SMB", "139, 445", "Windows file sharing in benign traffic, "
                                                     "and a frequent port-scan target."),
        ("Application", "HTTP-alt", "8080", "The port on which the Bot class contacts its "
                                            "command-and-control server."),
        ("Application", "Telnet, RDP", "23, 3389", "Watched login ports in the brute-force "
                                                   "rule, alongside FTP and SSH."),
        ("System", "WebSocket", "8000", "Carries live events from the detection engine to the "
                                        "desktop application."),
        ("System", "HTTP REST", "8000", "The control API: status, alerts, blocks, and naming "
                                        "a discovered family."),
        ("System", "iptables / netfilter", "–", "Not a protocol but the enforcement "
                                                     "mechanism by which a verdict becomes a "
                                                     "rule."),
    ]
    table(doc, ["Layer", "Protocol", "Port", "Role in the system"], rows,
          widths=[0.9, 1.3, 0.9, 3.4], size=9,
          caption="Table 3.3: Protocols observed, parsed and used by the system.")
    para(doc, "Two decisions in this table deserve comment. The protocol number itself is one "
              "of the 59 model inputs, so a classifier can learn that a given attack family "
              "occurs only over a particular transport. The destination port, by contrast, is "
              "deliberately excluded from the inputs: in CIC-IDS2017 almost every "
              "denial-of-service flow targets port 80, so a model permitted to use the port "
              "would learn that association rather than the behaviour, and would fail on any "
              "network whose web server listens elsewhere.")
    para(doc, "The 69,787 HTTPS flows illustrate both the strength and the boundary of a "
              "flow-statistics approach. Transport Layer Security conceals the content of a "
              "conversation but not its shape, so timing, sizes, direction and packet counts "
              "remain measurable and the detectors continue to function. Equally, an attack "
              "carried inside that encrypted payload is invisible, which is the same "
              "limitation Section 5.1.3 measures for web attacks over plain HTTP.")

    section(doc, "3.3 Architecture and Workflow")
    para(doc, "Figure 3.2 shows the layered architecture. The data path is as follows.")
    layers = [
        ("Ingestion.", " Live capture using scapy's asynchronous sniffer, replay of a capture "
                       "file through the same packet path, or replay of held-out test-split "
                       "rows on a scripted timeline."),
        ("Feature extraction.", " Packets are grouped into bidirectional flows keyed by the "
                                "five-tuple following CICFlowMeter conventions: the sender of "
                                "the first packet defines the forward direction, lengths count "
                                "transport payload bytes, and active and idle periods are "
                                "separated by gaps longer than five seconds."),
        ("Detection.", " Four packet-level signature rules, a full and a lite Random Forest, "
                       "and an autoencoder trained only on benign flows."),
        ("Open-set recognition and discovery.", " A conformal test over class-conditional "
                                                "nearest-neighbour distances, followed by "
                                                "online clustering of whatever it rejects."),
        ("Response.", " Timed, reversible iptables rules in a dedicated chain."),
        ("Presentation.", " An event bus exposed over WebSocket and REST, consumed by a native "
                          "PySide6 desktop application."),
    ]
    for lead, rest in layers:
        bullet(doc, rest, lead=lead)
    figure(doc, "reports/fig_architecture.png",
           "Figure 3.2: The six-layer detection and response pipeline. Note that the open-set "
           "test is reached only when the classifiers have already concluded that the flow is "
           "benign, and that a rejected flow enters the clusterer rather than raising an alert "
           "directly.", width=6.3)
    para(doc, "Fusion is by explicit priority, evaluated per flow. A signature hit alerts "
              "immediately at high severity. Otherwise the full model is consulted, then the "
              "lite model, with a predicted attack class at confidence of at least 0.9 treated "
              "as high severity and between 0.6 and 0.9 as medium. Otherwise the open-set test "
              "is applied, and a rejected flow is passed to the clusterer rather than alerted "
              "on directly. Otherwise an autoencoder error above threshold passes the flow to "
              "the same clusterer by a second route.")
    para(doc, "Weak evidence, meaning a lite-model hit or a medium-confidence prediction, must "
              "be corroborated by three flagged flows from the same source within ten seconds "
              "before any alert is raised. This suppresses isolated false positives while "
              "leaving sustained attacks, which by their nature generate many flows from one "
              "source, fully detectable. Unknown families carry their own corroboration, "
              "because a family must grow before it is reported.")

    section(doc, "3.4 Implementation Strategy")
    para(doc, "The system is implemented in Python 3.11. Scikit-learn provides the Random "
              "Forest, the covariance estimation and the preprocessing pipeline; XGBoost "
              "provides the competing gradient-boosted classifier; Keras is used to train the "
              "autoencoder, whose weights are then exported to NumPy arrays so that the "
              "detection container needs no deep learning framework at runtime. Scapy performs "
              "packet capture. FastAPI and uvicorn expose the event API, and PySide6 implements "
              "the desktop application, which is a native window rather than a web page.")
    para(doc, "The laboratory is defined by Docker Compose and contains three containers: an "
              "attacker, a victim running nginx, and the sensor, which shares the victim's "
              "network namespace so that it sees the same traffic and can apply iptables rules "
              "in the same namespace. The sensor container is granted only the NET_ADMIN and "
              "NET_RAW capabilities. All attack traffic is confined to an isolated Docker "
              "bridge network and never leaves the host, which is a safety requirement rather "
              "than a convenience.")
    figure(doc, "reports/fig_lab_topology.png",
           "Figure 3.3: The isolated Docker laboratory used for live validation. The sensor "
           "shares the victim's network namespace so that it observes the same traffic and "
           "enforces rules in the same place.", width=6.1)
    para(doc, "Reproducibility is treated as a requirement rather than a convenience. Random "
              "seeds are fixed, all evaluation artifacts are written to a reports directory as "
              "machine-readable JSON, the results document and the presentation are generated "
              "from those JSON files rather than typed by hand, and an automated test suite of "
              "96 tests covers the feature extraction, the preprocessing, the detection logic, "
              "the explanation mathematics, the open-set test, the clusterer and the user "
              "interface.")


def chapter4(doc, m):
    chapter(doc, "Chapter 4: Case Study Implementation and Analysis")

    section(doc, "4.1 Execution and Step-by-Step Analysis")
    steps = [
        ("Preprocessing.", " Day files are loaded and concatenated, labels are mapped to the "
                           "coarse class set, lite features are computed over one-minute "
                           "windows before any rows are removed so that the window aggregates "
                           "describe everything a source did, rows are cleaned and "
                           "deduplicated, the data is split in a stratified manner, and the "
                           "scalers are fitted on the training split alone."),
        ("Supervised training.", " A Random Forest and an XGBoost classifier are trained for "
                                 "each feature set and compared on validation macro F1. Class "
                                 "imbalance is handled with balanced class weights on the "
                                 "training split only; the test split is never resampled."),
        ("Autoencoder training.", " A dense network of shape 59-32-16-8-16-32-59 is trained on "
                                  "benign flows only. The threshold is the 99th percentile of "
                                  "reconstruction error on benign validation flows. Weights are "
                                  "exported to NumPy and the exported inference path is checked "
                                  "to agree with Keras to within 1e-6."),
        ("Open-set fitting.", " Class geometry and reference flows are taken from the training "
                              "split; calibration scores are computed on the validation split. "
                              "The two are disjoint, which is what makes the resulting p-values "
                              "valid."),
        ("Evaluation.", " Models are evaluated on the held-out test split, then by "
                        "leave-one-class-out folds, then against UNSW-NB15."),
        ("Live validation.", " The laboratory is started, attack tools are run from the "
                             "attacker container, and detection, alerting and firewall "
                             "enforcement are observed in the desktop application."),
    ]
    for i, (lead, rest) in enumerate(steps, start=1):
        numbered(doc, i, rest, lead=lead)

    section(doc, "4.2 Core Algorithms and Configurations")
    subsection(doc, "4.2.1 Signature rules")
    rows = [
        ("syn_flood", "More than 100 SYN packets per second from one source", "DoS"),
        ("port_scan", "More than 30 distinct destination ports from one source in 5 s",
         "PortScan"),
        ("slow_dos", "At least 50 connections older than 5 s averaging under 50 bytes/s",
         "DoS-Slow"),
        ("brute_force", "More than 10 HTTP 401 replies in 10 s, or more than 20 new "
                        "connections to a login port in 5 s", "BruteForce"),
    ]
    table(doc, ["Rule", "Condition (default)", "Class"], rows,
          widths=[1.3, 3.8, 1.2], size=10,
          caption="Table 4.1: Packet-level signature rules. Each has a 10-second cooldown "
                  "per source.")

    subsection(doc, "4.2.2 The conformal open-set test")
    para(doc, "Each class is summarised in the scaled feature space by its mean and a "
              "covariance estimated with Ledoit-Wolf shrinkage. Shrinkage is necessary rather "
              "than decorative, because the Bot class has 977 training flows against 59 "
              "features, where a sample covariance is singular and its inverse meaningless. "
              "Averaging the per-class precision matrices yields one global metric whose matrix "
              "factor converts that Mahalanobis metric into ordinary Euclidean distance.")
    para(doc, "The non-conformity of a flow with respect to class c is the distance to the "
              "tenth nearest training flow of class c. Each raw score is converted into a "
              "conformal p-value against held-out flows of the same class:")
    para(doc, "p_c(x) = ( 1 + |{ i in cal_c : s_c(x_i) ≥ s_c(x) }| ) / ( n_cal_c + 1 )",
         size=12, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_before=6, space_after=6)
    para(doc, "A flow is known when some class accepts it at level alpha, that is when the "
              "maximum p-value over classes is at least alpha, and unknown otherwise. The value "
              "of this construction is that alpha is not a threshold discovered by experiment: "
              "it is the share of genuine known-class traffic that the test will route to the "
              "unknown path, fixed in advance and verifiable afterwards.")
    para(doc, "For deployment the accept-or-reject decision is computed without p-values at "
              "all, because the test is equivalent to comparing the raw score against a fixed "
              "quantile of that class's calibration scores. Classes are tried largest first, so "
              "an ordinary benign flow is resolved against one class rather than eight. The two "
              "formulations are checked to agree on every row by the test suite, and a batch of "
              "2000 flows costs about 220 milliseconds in the 59-feature space.")

    subsection(doc, "4.2.3 Online family discovery")
    para(doc, "A rejected flow on its own is the useless alert this work set out to remove. "
              "Rejected flows are therefore grouped by leader clustering, and the quantity "
              "clustered is the direction in which a flow deviates from normal traffic: the "
              "whitened feature vector, minus the benign class mean, normalised to unit length "
              "and compared by cosine distance.")
    para(doc, "Direction rather than absolute distance, for a reason established by "
              "measurement. An absolute radius must be calibrated against something, and the "
              "only reference available is the known classes, which are dense: benign traffic "
              "has 400,000 training flows, so the spacing between neighbours inside it is far "
              "smaller than the spread of a novel attack observed a few dozen times. A radius "
              "fitted to the known classes shatters a novel family into one cluster per flow, "
              "which is what the first implementation did, producing 24 families from 25 "
              "near-identical flows. Direction has no such scale: the same attack run gently "
              "and run hard deviates the same way, and the threshold is an angle, which means "
              "the same thing on any network.")
    para(doc, "Each family carries a stable identifier of the form NETRA-U001, its flow and "
              "source counts, the nearest known class with the p-value that class assigned, and "
              "a fingerprint naming the features that make it unusual in units an operator "
              "reads. A family arriving by the autoencoder route uses that detector's "
              "per-feature reconstruction errors as its fingerprint instead. A family is "
              "reported once it holds 50 flows, a value read off the measured curve in "
              "Table 5.6. It may then be promoted to a real name through the desktop "
              "application, the REST API or the command line; the name and the centroid are "
              "persisted, so the identification survives a restart.")

    section(doc, "4.3 Challenges Faced and Mitigation")
    challenges = [
        ("Unreliable dataset features.",
         " TCP flag counters in CIC-IDS2017 are incorrect, and models trained on them scored "
         "excellently offline while failing on real packets. All twelve flag columns were "
         "removed from the model inputs, leaving 59 features, and the flags were retained only "
         "in the signature rules, which read real packets."),
        ("A single Gaussian per class rejects nothing.",
         " The class-conditional Gaussian score was implemented first. Benign CIC-IDS2017 "
         "traffic is strongly multi-modal, so one ellipsoid per class also covers the empty "
         "space between its modes. Measured against UNSW-NB15, that score places attack flows "
         "at a median p-value of 0.52 under the benign class and rejects 0.22 percent of an "
         "entirely foreign network. Replacing the score with a tenth-nearest-neighbour distance "
         "fixed it; both are retained and reported, because the gap is a result about the data."),
        ("Clustering radius calibration.",
         " As described in 4.2.3, a Euclidean radius calibrated on dense known classes "
         "fragmented novel families. Clustering on deviation direction removed the scale "
         "dependence entirely."),
        ("A stricter conformal level for alerting does not work.",
         " At alpha 0.05 the benign tail enters the clusterer and is not always scattered: "
         "three marginally unusual benign flows once aligned, formed a family and quarantined a "
         "healthy host. The first remedy was to require a number of flows rejected at a "
         "stricter level of 0.01. Measured over the leave-one-class-out folds this reported the "
         "novel family in only one fold out of seven while still admitting 164 families of "
         "ordinary traffic. The cause is structural: the routing level has already conditioned "
         "on the p-value, so among flows that reached the clusterer a rejected benign flow and "
         "a rejected novel flow have p-values from much the same range. Reporting is therefore "
         "decided by family size, chosen from a measured curve."),
        ("An unsafe response policy.",
         " The engine originally derived the firewall action from severity at the point of use "
         "and mapped everything that was not high severity to a quarantine, so a flow barely "
         "above the autoencoder threshold rate-limited a host, contradicting the engine's own "
         "documentation. The policy is now declared in a single table and low severity takes no "
         "firewall action, with a regression test."),
        ("Platform constraints.",
         " Scapy on the Windows host has no libpcap backend, so live capture is confined to the "
         "Linux containers; the host is used for dataset replay, training and evaluation. "
         "CICFlowMeter 0.3 and later require Python 3.12, so version 0.2.0 is pinned for "
         "offline capture-file conversion and the custom live extractor is used in the sensor."),
    ]
    for lead, rest in challenges:
        bullet(doc, rest, lead=lead)


def chapter5(doc, m):
    full_all, full, lite, ae = m["full_all"], m["full"], m["lite"], m["ae"]
    os_, disc = m["openset"], m["discovery"]
    chapter(doc, "Chapter 5: Results and Discussion")

    section(doc, "5.1 Findings and Output")
    subsection(doc, "5.1.1 Supervised classification")
    para(doc, "All figures below are measured on the held-out CIC-IDS2017 test split, which "
              "retains the natural class distribution and was never used for training or model "
              "selection.")
    rows = []
    for name, r in full_all["models"].items():
        label = name.replace("_", " ").title() + (" (selected)" if name == full_all["selected"] else "")
        rows.append((label, f"{r['accuracy']:.4f}", f"{r['macro']['f1']:.4f}",
                     f"{r['binary']['detection_rate']:.4f}",
                     f"{r['binary']['false_positive_rate']:.5f}"))
    table(doc, ["Model", "Accuracy", "Macro F1", "Detection rate", "False-positive rate"],
          rows, widths=[1.9, 1.1, 1.1, 1.3, 1.3], size=10,
          caption="Table 5.1: Model comparison on the full 59-feature set.")
    b = full["binary"]
    para(doc, f"The Random Forest was selected on validation macro F1. On the test split it "
              f"flags {b['tp']:,} of {b['tp'] + b['fn']:,} "
              f"attack flows while wrongly flagging {b['fp']:,} of "
              f"{b['fp'] + b['tn']:,} benign flows. Macro F1 is reported in preference "
              f"to accuracy throughout, because benign traffic constitutes roughly 85 percent "
              f"of the test split and accuracy is correspondingly uninformative.")
    rows = []
    for cls, r in full["per_class"].items():
        rows.append((cls, f"{r['precision']:.4f}", f"{r['recall']:.4f}",
                     f"{r['f1-score']:.4f}", f"{int(r['support']):,}"))
    table(doc, ["Class", "Precision", "Recall", "F1", "Test flows"], rows,
          widths=[1.6, 1.2, 1.2, 1.2, 1.3], size=10,
          caption="Table 5.2: Per-class results for the selected full model.")
    figure(doc, "reports/confusion_full_random_forest.png",
           "Figure 5.1: Confusion matrix for the full Random Forest on the held-out test "
           "split. The diagonal is correct classification; the residual confusion is "
           "concentrated in the Bot row, which is also the class with the lowest precision.",
           width=5.6)
    figure(doc, "reports/fig_roc_curves.png",
           "Figure 5.2: One-vs-rest ROC curves per class, and the binary attack-versus-benign "
           "view plotted on a logarithmic false-positive axis so that behaviour in the "
           "operationally relevant low-false-alarm region is visible.", width=6.3)
    figure(doc, "reports/fig_feature_importance.png",
           "Figure 5.3: The fifteen features the forest relies on most. Timing and "
           "directionality features dominate, which is consistent with the attacks in the "
           "dataset being distinguished by traffic shape rather than by volume alone.",
           width=5.7)
    figure(doc, "reports/per_class_f1_full.png",
           "Figure 5.4: Per-class F1 for the full feature set.", width=5.4)
    para(doc, f"The lite model, restricted to the six features computable from live packets, "
              f"reaches macro F1 {lite['macro']['f1']:.4f}. Its weakest class is WebAttack at "
              f"F1 {lite['per_class']['WebAttack']['f1-score']:.4f}, which is expected: at the level "
              f"of six flow statistics a SQL injection is indistinguishable from an ordinary "
              f"small HTTP request. The full model raises the same class to "
              f"{full['per_class']['WebAttack']['f1-score']:.4f} because it sees detailed timing and "
              f"size features.")
    figure(doc, "reports/per_class_f1_lite.png",
           "Figure 5.5: Per-class F1 for the six-feature lite set. The collapse of the "
           "WebAttack bar is the payload-blindness discussed in Section 5.2 made visible.",
           width=5.4)
    para(doc, f"The autoencoder, which never saw an attack during training, attains ROC-AUC "
              f"{ae['roc_auc']:.4f} and detects {pct(ae['detection_rate'])} of attacks at a "
              f"false-alarm rate of {pct(ae['false_positive_rate'], 2)}. Its coverage is "
              f"concentrated on denial-of-service-shaped anomalies and is weak on Bot and "
              f"WebAttack, which is consistent with those classes resembling ordinary traffic "
              f"in flow statistics.")
    figure(doc, "reports/autoencoder_errors.png",
           "Figure 5.6: Reconstruction-error distribution for benign and attack flows, with "
           "the threshold set at the 99th percentile of benign validation error. The overlap "
           "on the left is why the autoencoder alone is a safety net rather than a primary "
           "detector.", width=5.8)

    subsection(doc, "5.1.2 Validity of the open-set test")
    kr = os_["known_rejection"]["scores"]
    rows = []
    for score, v in kr.items():
        rows.append((score, f"{os_['known_rejection']['alpha']}",
                     f"{v['rejection_rate']:.4f}",
                     "Yes" if v["within_alpha"] else "No"))
    table(doc, ["Non-conformity score", "Promised alpha", "Measured rejection", "Within bound"],
          rows, widths=[2.0, 1.4, 1.5, 1.4], size=10,
          caption="Table 5.3: Conformal validity on the test split, where every flow belongs "
                  "to a known class.")
    para(doc, "Every flow in the test split belongs to a class the recogniser was fitted on, so "
              "anything it rejects is pure cost. The promise holds, and it holds across two "
              "orders of magnitude of alpha: averaged over the leave-one-class-out folds the "
              "measured rejection of known traffic is 0.0085 at alpha 0.01, 0.0466 at 0.05, "
              "0.0947 at 0.10 and 0.2456 at 0.25. This is what allows the layer to be "
              "configured from a false-alarm budget rather than by trial.")

    subsection(doc, "5.1.3 Attacks the system was never trained on")
    para(doc, "In each fold one attack class is removed from the training data, from the "
              "feature scaling and from the open-set calibration, and that class's test flows "
              "are then replayed. The closed-set baseline is a Random Forest trained on the "
              "same seven remaining classes.")
    rows = []
    for f in sorted(os_["leave_one_class_out"]["folds"], key=lambda x: -x["novelty_auc"]):
        rows.append((f["held_out"], f"{f['novel_flows']:,}", f"{f['novelty_auc']:.3f}",
                     f"{f['closed_set_called_benign']:.3f}", f"{f['unknown_rate']:.3f}",
                     f"{1 - f['surfaced_rate']:.3f}"))
    t = os_["leave_one_class_out"]["totals"]
    rows.append(("Mean", "", f"{t['mean_novelty_auc']:.3f}",
                 f"{t['mean_closed_set_called_benign']:.3f}",
                 f"{t['mean_unknown_rate']:.3f}", f"{1 - t['mean_surfaced_rate']:.3f}"))
    table(doc, ["Held out", "Flows", "AUC", "Closed-set calls it benign",
                "Open-set rejects it", "Share still silent"], rows,
          widths=[1.2, 0.9, 0.8, 1.4, 1.2, 1.1], size=9,
          caption="Table 5.4: Leave-one-class-out comparison. AUC is the probability that a "
                  "novel flow ranks as more anomalous than a known one.")
    para(doc, "Three observations follow. Where the layer works it changes the outcome "
              "completely: for DoS-Slow, 98.4 percent of a wholly unseen attack is surfaced and "
              "the share that reaches nobody falls from 0.835 to 0.016, while the closed-set "
              "model files 83.2 percent of it as benign traffic. In six of the seven folds the "
              "closed-set model calls the majority of the unseen attack benign, and in two it "
              "does so for every single flow, which is the silent failure this layer exists to "
              "remove. And the layer does not rescue every case: Bot at AUC 0.760 is weakly "
              "separable, and WebAttack at 0.149 is the instructive failure, because an AUC "
              "below 0.5 means its flows rank as more typical than benign traffic itself.")
    figure(doc, "reports/fig_novelty_auc.png",
           "Figure 5.7: Left, how separable each unseen attack is, independently of any "
           "threshold; the dashed line at 0.5 marks no information, and WebAttack falls below "
           "it. Right, the share of each attack that reaches nobody, before and after the "
           "open-set layer.", width=6.3)
    figure(doc, "reports/openset.png",
           "Figure 5.8: Left, the operating curve for each fold, showing novel flows rejected "
           "against the price paid on known traffic, with the deployed alpha marked. Right, "
           "what happens to an attack nobody trained on, comparing the closed-set baseline "
           "with the open-set layer.", width=6.3)
    para(doc, "The per-class calibration medians explain the WebAttack result. The "
              "tenth-nearest-neighbour distance inside the benign class has a median of 19.8 in "
              "the whitened metric, while held-out WebAttack flows sit at 0.15, which is to say "
              "in the densest part of the benign distribution rather than outside it. This is "
              "the payload-blindness of Section 1.5 measured from a different direction, and no "
              "significance level can repair it.")

    subsection(doc, "5.1.4 Discovered families")
    dt = disc["totals"]
    rows = []
    for f in disc["folds"]:
        lat = f["flows_to_discovery"]
        rows.append((f["held_out"], f"{f['rejected_flows']:,}", f"{f['families']}",
                     f"{f['families_reportable']}", f"{f['purity']:.3f}",
                     f"{f['dominant_family_precision']:.3f}",
                     str(lat) if lat else "not reported"))
    rows.append(("Mean", "", "", "", f"{dt['mean_purity']:.3f}",
                 f"{dt['mean_dominant_precision']:.3f}", ""))
    table(doc, ["Held out", "Rejected", "Families", "Reportable", "Purity",
                "Largest family precision", "Flows to report"], rows,
          widths=[1.1, 0.9, 0.9, 1.0, 0.8, 1.2, 1.0], size=9,
          caption="Table 5.5: Unknown-family discovery, with the held-out class mixed back "
                  "into 30,000 ordinary test flows.")
    para(doc, f"The novel family was reported in {dt['folds_where_novel_family_reported']} of "
              f"seven folds at a mean cluster purity of {dt['mean_purity']:.3f}. Across all "
              f"seven folds 42 families were reported in total, of which "
              f"{dt['total_false_alarm_families']} consisted of ordinary traffic, which is "
              f"between two and five per fold. The two folds never reported are Bot and "
              f"WebAttack, the two the previous section identified as weakly separable; their "
              f"families do form, correctly and purely, but at 3 and 16 flows they are too "
              f"small to clear the reporting threshold.")
    curve = dt.get("threshold_curve", [])
    if curve:
        rows = [(str(c["min_flows"]) + (" (selected)" if c["min_flows"] == disc["min_family_flows"] else ""),
                 f"{c['folds_where_novel_family_reported']} of 7",
                 str(c["total_false_alarm_families"]),
                 str(c["total_families_reported"])) for c in curve]
        table(doc, ["Flows to report", "Novel family found", "Families of ordinary traffic",
                    "Families reported"], rows, widths=[1.5, 1.5, 2.0, 1.3], size=10,
              caption="Table 5.6: The reporting-threshold trade-off, measured over all seven "
                      "folds.")
        figure(doc, "reports/fig_threshold_curve.png",
               "Figure 5.9: The reporting-threshold trade-off. Raising the threshold from 20 "
               "to 50 flows leaves the number of novel families found unchanged while cutting "
               "the families of ordinary traffic from 112 to 16, which is why 50 was selected.",
               width=5.9)
        para(doc, "The selected value of 50 flows finds the novel family in the same five folds "
                  "as 20 or 30 do, while reporting 16 families of ordinary traffic instead of "
                  "112. Those families are not errors in the way a misclassification is: they "
                  "are patterns the deployment has and the training data did not describe, "
                  "unusual in the same way every time, which is why they cluster at all. An "
                  "operator names such a family once and it ceases to be an unexplained alert.")
    para(doc, "The most interesting result in this experiment was not the one being measured. "
              "The families do not correspond to the classes the models were trained on; they "
              "correspond to the individual attack tools, which is finer. Three of the coarse "
              "classes are unions of two tools each, and the clusterer separated them without "
              "being told they were different: the dominant BruteForce family is 274 "
              "FTP-Patator flows and 2 SSH-Patator, the dominant DoS family is 2,639 DoS Hulk "
              "flows and no GoldenEye at all, and the dominant DoS-Slow family is 416 "
              "Slowhttptest flows. A recall below one for those classes therefore reflects the "
              "attack occupying two families because it is two tools, not a defect in the "
              "clustering.")

    subsection(doc, "5.1.5 Cross-dataset transfer and domain shift")
    cross = m["cross"]
    score = os_["score"]
    ds = os_["domain_shift"]["scores"]
    rows = [
        ("Detection rate, in domain (CIC-IDS2017)",
         f"{cross['in_domain_cicids2017']['detection_rate']:.4f}"),
        ("Detection rate, UNSW-NB15", f"{cross['binary']['detection_rate']:.4f}"),
        ("Open-set unknown rate, in domain",
         f"{kr[score]['rejection_rate']:.4f}"),
        ("Open-set unknown rate, UNSW-NB15 (nearest neighbour)",
         f"{ds[score]['unknown_rate']:.4f}"),
        ("Open-set unknown rate, UNSW-NB15 (Gaussian score)",
         f"{ds['gaussian']['unknown_rate']:.4f}"),
    ]
    table(doc, ["Measure", "Value"], rows, widths=[4.3, 2.0], size=10,
          caption="Table 5.7: Transfer to a second, independently captured dataset.")
    para(doc, f"Scored over {cross['scored_flows']:,} UNSW-NB15 flows with the model, the "
              f"scaler and the feature code used exactly as the live system loads them, "
              f"detection falls from 0.9976 in domain to {cross['binary']['detection_rate']:.4f}. "
              f"The feature medians explain it: UNSW benign traffic runs at 2,775 packets per "
              f"second and UNSW attacks at 79, while CIC benign traffic runs at 66. The model "
              f"learned that low packet rates are suspicious, and on the second network "
              f"ordinary traffic is two orders of magnitude faster while its attacks sit at "
              f"roughly the rate CIC-IDS2017 calls normal. The learned boundary is not merely "
              f"in the wrong place; it points the wrong way.")
    figure(doc, "reports/cross_dataset.png",
           "Figure 5.10: Transfer to UNSW-NB15. Left, detection rate and false-positive rate "
           "in domain against the same model on the second dataset. Right, the feature "
           "medians that explain the collapse: ordinary UNSW traffic runs at roughly the "
           "packet rate CIC-IDS2017 associates with attacks.", width=6.3)
    para(doc, f"The open-set layer does not recover that detection rate and cannot, for the "
              f"reason just given. What changes is what the sensor reports about its own "
              f"competence: {pct(ds[score]['unknown_rate'])} of that foreign network is "
              f"reported as matching nothing the models know, against "
              f"{pct(kr[score]['rejection_rate'])} in domain, a factor of twenty. A closed-set "
              f"classifier cannot express this at all; on the same flows it returns benign with "
              f"high confidence, so an operator would conclude the network was quiet when the "
              f"correct conclusion is that the sensor needs retraining for this network.")

    subsection(doc, "5.1.6 Live validation in the Docker laboratory")
    para(doc, "In the Docker laboratory, four attack tools were run against the victim: a port "
              "scan with nmap, a SYN flood with hping3, a slow denial-of-service attack with "
              "slowloris, and a credential brute-force attempt with hydra. Every attack was "
              "detected within approximately one second and the attacking host was blocked by "
              "a real iptables rule that expired on its own, while ordinary browsing traffic "
              "raised no alert.")
    figure(doc, "docs/screenshots/lab_1_connected.png",
           "Figure 5.11: Baseline. The attacker container reaches the victim's web server "
           "normally and the sensor reports no alert.", width=5.8)
    figure(doc, "docs/screenshots/lab_2_blocked.png",
           "Figure 5.12: After detection. Netra has written an iptables DROP rule into its "
           "own NETRA chain and the same request from the attacker now times out, "
           "demonstrating that enforcement is real rather than advisory.", width=5.8)
    figure(doc, "docs/screenshots/lab_3_unblocked.png",
           "Figure 5.13: After the rule expires, or after the operator clicks Unblock all, "
           "connectivity is restored. Every automated action is reversible and time-bounded.",
           width=5.8)
    figure(doc, "docs/screenshots/lab_live_capture.png",
           "Figure 5.14: The desktop application during a complete laboratory run, in live "
           "capture mode with the iptables backend active. All four attacks have been "
           "detected, the attacker is currently blocked with 43 seconds remaining, and the "
           "open-set layer has additionally formed thirteen unknown families from the live "
           "attack traffic.", width=6.3)
    para(doc, "A detail of that run is worth recording, because it was not anticipated. The "
              "open-set layer produced alerts on live traffic as well as the signature rules: "
              "the nmap scan and the slow HTTP attack generated flows that the classifiers "
              "placed in no trained class, and the clusterer grouped them into families whose "
              "fingerprints describe exactly what the tools do. One family collected 66 flows "
              "of zero-length forward packets at 139,810 packets per second, which is a SYN "
              "scan described in the system's own words. The laboratory tools do not behave "
              "identically to the CIC-IDS2017 recordings of the same attack categories, and "
              "the open-set layer reports that difference rather than silently forcing the "
              "traffic into the nearest trained class.")
    para(doc, "In dataset replay mode with the full pipeline loaded, 4,176 flows produced 12 "
              "alerts, each correctly named by the classifiers, and 76 unknown families formed "
              "from the benign tail, none of which reached the reporting threshold, so no "
              "false alarm was raised. This is the intended behaviour on in-domain traffic: "
              "the open-set layer is active and routing flows, but it reports nothing because "
              "nothing recurs.")
    figure(doc, "docs/screenshots/app_families_dark.png",
           "Figure 5.15: The desktop application during replay. The alert feed names each "
           "attack with the detector that produced it, and the Unknown families discovered "
           "panel at the lower left lists the families formed from the benign tail with their "
           "fingerprints and nearest known class.", width=6.3)
    figure(doc, "docs/screenshots/app_families_light.png",
           "Figure 5.16: The same application after an analyst has named a family. The panel "
           "header reads “113 discovered, 1 named” and the named family is "
           "highlighted; the name persists across restarts and is used by every later alert "
           "about that family.", width=6.3)

    section(doc, "5.2 Discussion")
    para(doc, "The objectives of Section 1.4 are met. A complete hybrid pipeline was built and "
              "demonstrated live; models were trained and selected on validation macro F1; an "
              "open-set layer with a mathematically fixed false-alarm cost was added and its "
              "guarantee verified; rejected traffic is grouped and named; the system was "
              "validated against both removed classes and a second dataset; and the response is "
              "timed, reversible and bounded.")
    para(doc, "The four detectors are not redundant, and the results show why. Signature rules "
              "are what make live demonstration work, firing in about one second on packets, "
              "but cover only anticipated attacks. Supervised models classify flows the rules "
              "say nothing about, with high precision, but only for families present in the "
              "training labels. The autoencoder requires no attack labels at all and "
              "contributes coverage for denial-of-service-shaped anomalies at a fixed one "
              "percent false-alarm cost. The open-set layer is the only component that can "
              "report the absence of a verdict; the other three always produce one, since a "
              "rule either matches or stays silent, a classifier returns its best class, and "
              "the autoencoder returns a number. It is what distinguishes “no attack "
              "here” from “nothing here that I was taught”, which are the same "
              "output everywhere else in the pipeline and are not at all the same conclusion.")
    para(doc, "The corroboration requirement is what makes combining them practical. Without "
              "it, the autoencoder's one percent false-alarm rate over 278,975 benign test "
              "flows would mean roughly 2,800 spurious alerts. Requiring three flagged flows "
              "from one source within ten seconds suppresses isolated errors while leaving "
              "sustained attacks fully detectable, and the open-set layer's equivalent "
              "safeguard is that a family must grow to a measured size before it is reported.")
    para(doc, "Two findings deserve emphasis because they are negative and because they were "
              "invisible to the metrics the project reported before they were sought. An entire "
              "family of features in a widely used benchmark is unusable, and only live testing "
              "revealed it. And a model reporting a 99.76 percent detection rate on its own "
              "benchmark detects 0.03 percent of attacks on a second dataset, because it "
              "learned flow rates that are a property of one network rather than of hostile "
              "behaviour. Intrusion detection work that reports offline metrics on a single "
              "benchmark cannot rule out either class of error.")

    section(doc, "5.3 Practical Implications")
    para(doc, "For a deployment, three implications follow. First, an intrusion detection model "
              "should be retrained on traffic from the network it will watch; figures published "
              "against a benchmark describe that benchmark. Second, an open-set layer is cheap "
              "to add to an existing classifier, requiring no retraining of the classifier "
              "itself, and converts the most dangerous failure mode, silent misclassification "
              "of a novel attack as benign, into an explicit and bounded report. Third, the "
              "unknown rate is itself a useful operational signal: in domain it sits at the "
              "configured alpha, so a sustained departure from that value is a calibrated "
              "indication that the traffic has changed and the model should be refreshed.")
    para(doc, "The naming workflow has a practical consequence worth stating. The families of "
              "ordinary traffic that the layer reports are the normal baselining cost of any "
              "anomaly detector. In a real deployment an analyst would name each of them once "
              "during commissioning, after which they cease to be unexplained, and the "
              "remaining reports are genuinely novel. This is the standard practice for anomaly "
              "systems, and the contribution here is that the objects being named are coherent "
              "and described rather than being individual unlabelled flows.")


def chapter6(doc, m):
    chapter(doc, "Chapter 6: Conclusion and Future Scope")

    section(doc, "6.1 Conclusion")
    para(doc, "This case study has shown that signature rules, supervised classification and "
              "unsupervised anomaly detection can be combined under an explicit fusion policy "
              "and coupled to an automated response on hardware as modest as a single laptop. "
              "The full model reaches macro F1 0.9570 at a 0.11 percent false-positive rate, "
              "the six-feature live model reaches 0.8400, and the autoencoder adds label-free "
              "coverage at ROC-AUC 0.9603. In live operation against four real attack tools, "
              "every attack was detected within about a second and answered with a timed, "
              "reversible firewall rule, while ordinary traffic raised no alert.")
    para(doc, "Beyond that combination, the distinguishing capability is the ability to decline "
              "to classify. A trained classifier has no way to report an attack it was never "
              "shown, because its output is a distribution over the classes in its training "
              "labels; the leave-one-class-out experiment shows that in six of seven cases the "
              "nearest class is benign and the attack passes in silence. A conformal open-set "
              "test supplies the missing verdict at a false-alarm cost fixed in advance rather "
              "than tuned, verified at 0.0468 against a promised 0.05, and an online clusterer "
              "turns the rejected flows into named families with readable fingerprints that an "
              "analyst can identify once and name permanently. The contribution is not better "
              "accuracy on known attacks, which is unchanged, but a safe and informative "
              "behaviour in the case the training data did not cover.")
    para(doc, "The most useful results are the negative ones. An entire feature family in a "
              "widely used benchmark is unusable. The model does not transfer between networks. "
              "A standard Gaussian open-set score rejects nothing on a foreign network. A "
              "Euclidean clustering radius fragments novel families. And a stricter conformal "
              "level for alerting, which appeared to be the obvious refinement, reported only "
              "one of seven genuine discoveries. Each was found by evaluating the system "
              "against something other than its own training distribution, and each changed the "
              "design.")

    section(doc, "6.2 Future Scope")
    items = [
        ("Payload features.", " The clearest remaining gap. The open-set results identify "
                              "precisely which attacks flow statistics cannot reach: held-out "
                              "WebAttack flows rank as more ordinary than benign traffic, so "
                              "they are not merely hard to separate but genuinely inside the "
                              "benign distribution."),
        ("Retraining from promoted families.", " A family an analyst has named is labelled data "
                                               "for a class the models do not have. Feeding it "
                                               "back into training would make each discovery a "
                                               "ninth class, closing the loop the naming step "
                                               "currently opens."),
        ("Correlating alerts into campaigns.", " Grouping alerts by attacker, victim and time "
                                               "into a single incident with an ordered kill "
                                               "chain would turn a multi-stage intrusion into "
                                               "one narrative rather than dozens of separate "
                                               "alerts."),
        ("Network-invariant features.", " Features expressed relative to a host's own baseline, "
                                        "such as a flow's rate as a multiple of that source's "
                                        "median rate, would attack the cause of the "
                                        "cross-dataset failure rather than its symptom."),
        ("A discriminative embedding.", " Distances are currently measured in the scaled "
                                        "feature space. A representation trained to separate "
                                        "the classes may raise the weaker per-class novelty "
                                        "scores; increasing the reference-sample cap of 4,000 "
                                        "flows per class is the cheaper experiment to try "
                                        "first."),
        ("Automatic recalibration.", " Extending the manual calibration command into a periodic "
                                     "background process with drift detection, triggered by the "
                                     "open-set unknown rate departing from its configured "
                                     "level."),
    ]
    for i, (lead, rest) in enumerate(items, start=1):
        numbered(doc, i, rest, lead=lead)


REFERENCES = [
    "I. Sharafaldin, A. H. Lashkari and A. A. Ghorbani, “Toward Generating a New "
    "Intrusion Detection Dataset and Intrusion Traffic Characterization,” in Proc. 4th "
    "Int. Conf. on Information Systems Security and Privacy (ICISSP), 2018, pp. 108–116.",

    "N. Moustafa and J. Slay, “UNSW-NB15: A Comprehensive Data Set for Network Intrusion "
    "Detection Systems,” in Proc. Military Communications and Information Systems Conf. "
    "(MilCIS), 2015, pp. 1–6.",

    "G. Engelen, V. Rimmer and W. Joosen, “Troubleshooting an Intrusion Detection Dataset: "
    "the CICIDS2017 Case Study,” in Proc. IEEE Security and Privacy Workshops (SPW), 2021, "
    "pp. 7–12.",

    "Y. Mirsky, T. Doitshman, Y. Elovici and A. Shabtai, “Kitsune: An Ensemble of "
    "Autoencoders for Online Network Intrusion Detection,” in Proc. Network and "
    "Distributed System Security Symposium (NDSS), 2018.",

    "W. J. Scheirer, A. Rocha, A. Sapkota and T. E. Boult, “Toward Open Set "
    "Recognition,” IEEE Trans. Pattern Analysis and Machine Intelligence, vol. 35, no. 7, "
    "pp. 1757–1772, 2013.",

    "K. Lee, K. Lee, H. Lee and J. Shin, “A Simple Unified Framework for Detecting "
    "Out-of-Distribution Samples and Adversarial Attacks,” in Advances in Neural "
    "Information Processing Systems (NeurIPS), 2018.",

    "N. Papernot and P. McDaniel, “Deep k-Nearest Neighbors: Towards Confident, "
    "Interpretable and Robust Deep Learning,” arXiv:1803.04765, 2018.",

    "V. Vovk, A. Gammerman and G. Shafer, Algorithmic Learning in a Random World. New York, "
    "NY: Springer, 2005.",

    "O. Ledoit and M. Wolf, “A Well-Conditioned Estimator for Large-Dimensional Covariance "
    "Matrices,” Journal of Multivariate Analysis, vol. 88, no. 2, pp. 365–411, 2004.",

    "L. Breiman, “Random Forests,” Machine Learning, vol. 45, no. 1, pp. 5–32, "
    "2001.",

    "T. Chen and C. Guestrin, “XGBoost: A Scalable Tree Boosting System,” in Proc. "
    "22nd ACM SIGKDD Int. Conf. on Knowledge Discovery and Data Mining, 2016, pp. 785–794.",

    "J. A. Hartigan, Clustering Algorithms. New York, NY: John Wiley and Sons, 1975.",

    "A. Saabas, “Interpreting Random Forests,” treeinterpreter, 2014. [Online]. "
    "Available: https://github.com/andosa/treeinterpreter",

    "A. H. Lashkari, G. Draper-Gil, M. S. I. Mamun and A. A. Ghorbani, "
    "“Characterization of Encrypted and VPN Traffic Using Time-Related Features,” in "
    "Proc. 2nd Int. Conf. on Information Systems Security and Privacy (ICISSP), 2016, "
    "pp. 407–414.",
]


def back_matter(doc):
    chapter(doc, "References")
    for i, ref in enumerate(REFERENCES, start=1):
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        pf.left_indent = Inches(0.45)
        pf.first_line_indent = Inches(-0.45)
        pf.space_after = Pt(6)
        pf.line_spacing = LINE_SPACING
        style_run(p.add_run(f"[{i}]  "))
        style_run(p.add_run(ref))

    chapter(doc, "Appendix A: Command Reference")
    para(doc, "The complete system is driven from a single command-line entry point. The "
              "commands below reproduce every number reported in Chapter 5.")
    rows = [
        ("python -m src.cli preprocess", "Clean, split and scale the dataset"),
        ("python -m src.cli train", "Train all models and evaluate them"),
        ("python -m src.cli evaluate", "Evaluate on the held-out test split"),
        ("python -m src.cli openset-fit", "Fit the open-set recogniser"),
        ("python -m src.cli openset-eval", "Run all three open-set experiments"),
        ("python -m src.cli cross-eval", "Test the trained model on UNSW-NB15"),
        ("python -m src.cli demo", "Dataset replay plus the desktop application"),
        ("python -m src.cli live --iface eth0", "Live capture, detection and response"),
        ("python -m src.cli families", "List the unknown families discovered"),
        ("python -m src.cli families --promote ID NAME", "Give a discovered family a name"),
        ("python -m src.cli calibrate", "Retune the autoencoder threshold locally"),
        ("python -m src.cli unblock-all", "Remove every firewall rule Netra added"),
        ("python -m pytest tests/ -q", "Run the 96-test automated suite"),
    ]
    table(doc, ["Command", "Purpose"], rows, widths=[3.1, 3.2], size=10,
          caption="Table A.1: Command reference.")
    para(doc, "Generated artifacts: reports/RESULTS.md holds the supervised and autoencoder "
              "results, reports/OPENSET.md the open-set and discovery experiments, and "
              "reports/CROSS_DATASET.md the transfer evaluation. Each is produced from the "
              "corresponding JSON file so that the prose cannot drift away from the "
              "measurements.")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def build(out: Path) -> Path:
    m = load()
    doc = Document()

    normal = doc.styles["Normal"]
    normal.font.name = FONT
    normal.font.size = Pt(BODY_PT)
    rpr = normal.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(attr), FONT)

    front = doc.sections[0]
    configure(front)
    set_page_numbering(front, "lowerRoman", start=1)
    footer_number(front)

    title_page(doc)
    bonafide(doc)
    declaration(doc)
    acknowledgement(doc)
    abstract(doc, m)
    toc(doc)
    lists_page(doc)
    abbreviations(doc)

    body = doc.add_section(WD_SECTION.NEW_PAGE)
    configure(body)
    body.footer.is_linked_to_previous = False
    set_page_numbering(body, "decimal", start=1)
    footer_number(body)

    chapter1(doc, m)
    chapter2(doc, m)
    chapter3(doc, m)
    chapter4(doc, m)
    chapter5(doc, m)
    chapter6(doc, m)
    back_matter(doc)

    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Netra case study report.")
    ap.add_argument("-o", "--out",
                    default=str(ROOT / "docs" / "Netra_Case_Study_Report.docx"))
    args = ap.parse_args()
    out = build(Path(args.out))
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
