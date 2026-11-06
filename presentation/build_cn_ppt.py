"""Build the Computer Networks presentation: presentation/Netra_CN_Presentation.pptx.

This deck is written for the Computer Networks course. It explains the Packet
Tracer topology device by device, names the networking concepts the design uses,
and then explains the machine learning that runs on top of it. The language is
plain and the claims are the measured ones from reports/.

    python presentation/build_cn_ppt.py
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

# ---------------------------------------------------------------------------
# Layout and palette: light, plain, readable from the back of a room.
# ---------------------------------------------------------------------------
W, H = Inches(13.333), Inches(7.5)
MARGIN = Inches(0.75)
CONTENT_W = W - 2 * MARGIN

PAPER = RGBColor(0xFF, 0xFF, 0xFF)
BAND = RGBColor(0x1F, 0x3A, 0x5F)        # title band, dark navy
INK = RGBColor(0x1A, 0x1A, 0x1A)
INK2 = RGBColor(0x44, 0x4A, 0x55)
RULE = RGBColor(0xD5, 0xDA, 0xE1)
PANEL = RGBColor(0xF2, 0xF5, 0xF9)
BLUE = RGBColor(0x1F, 0x5E, 0xA8)
GREEN = RGBColor(0x1B, 0x6E, 0x3C)
RED = RGBColor(0xA3, 0x1D, 0x1D)
AMBER = RGBColor(0x8A, 0x5A, 0x00)
FONT = "Calibri"


def numbers() -> dict:
    def read(name):
        p = REPORTS / name
        if not p.exists():
            sys.exit(f"missing {p}. Run the evaluation first.")
        return json.loads(p.read_text(encoding="utf-8"))

    full, lite, ae = read("metrics_full.json"), read("metrics_lite.json"), read("metrics_autoencoder.json")
    return {
        "full": full["models"][full["selected"]],
        "lite": lite["models"][lite["selected"]],
        "ae": ae,
        "openset": read("openset.json"),
        "discovery": read("discovery.json"),
        "data": read("data_summary.json"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def slide_base(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, H)
    bg.fill.solid()
    bg.fill.fore_color.rgb = PAPER
    bg.line.fill.background()
    bg.shadow.inherit = False
    return s


def tb(slide, left, top, width, height, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(left, top, width, height)
    f = box.text_frame
    f.word_wrap = True
    f.vertical_anchor = anchor
    f.margin_left = f.margin_right = f.margin_top = f.margin_bottom = 0
    return f


def put(f, text, size=18, color=INK, bold=False, align=PP_ALIGN.LEFT,
        after=6, before=0, para=None, spacing=None, italic=False, font=FONT):
    p = para if para is not None else (
        f.paragraphs[0] if not f.paragraphs[0].runs and not f.paragraphs[0].text
        else f.add_paragraph())
    p.alignment = align
    p.space_after = Pt(after)
    p.space_before = Pt(before)
    if spacing:
        p.line_spacing = spacing
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = color
    r.font.name = font
    return p


def header(slide, number, title, subtitle=None):
    """Numbered title band at the top of a content slide."""
    band = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Inches(1.0))
    band.fill.solid()
    band.fill.fore_color.rgb = BAND
    band.line.fill.background()
    band.shadow.inherit = False
    f = tb(slide, MARGIN, Inches(0.2), CONTENT_W, Inches(0.6))
    put(f, f"{number}.  {title}", size=26, color=PAPER, bold=True, after=0)
    if subtitle:
        f2 = tb(slide, MARGIN, Inches(1.18), CONTENT_W, Inches(0.4))
        put(f2, subtitle, size=14, color=INK2, after=0)
    return Inches(1.75) if subtitle else Inches(1.4)


def bullets(slide, items, top, left=MARGIN, width=None, size=17, gap=11,
            colour=INK, marker_colour=BLUE):
    f = tb(slide, left, top, width or CONTENT_W, H - top - Inches(0.4))
    first = True
    for item in items:
        p = f.paragraphs[0] if first else f.add_paragraph()
        first = False
        p.space_after = Pt(gap)
        p.line_spacing = 1.15
        m = p.add_run()
        m.text = "–  "
        m.font.size = Pt(size)
        m.font.color.rgb = marker_colour
        m.font.name = FONT
        if isinstance(item, tuple):
            lead, rest = item
            a = p.add_run()
            a.text = lead
            a.font.size = Pt(size)
            a.font.bold = True
            a.font.color.rgb = colour
            a.font.name = FONT
            b = p.add_run()
            b.text = rest
            b.font.size = Pt(size)
            b.font.color.rgb = INK2
            b.font.name = FONT
        else:
            a = p.add_run()
            a.text = item
            a.font.size = Pt(size)
            a.font.color.rgb = colour
            a.font.name = FONT
    return f


def table(slide, headers, rows, left, top, width, col_fracs=None,
          size=12, head_size=12, row_h=Inches(0.34)):
    t = slide.shapes.add_table(len(rows) + 1, len(headers), left, top, width,
                               row_h * (len(rows) + 1)).table
    if col_fracs:
        total = sum(col_fracs)
        for i, fr in enumerate(col_fracs):
            t.columns[i].width = Emu(int(width * fr / total))
    for i, h in enumerate(headers):
        c = t.cell(0, i)
        c.fill.solid()
        c.fill.fore_color.rgb = BAND
        c.vertical_anchor = MSO_ANCHOR.MIDDLE
        c.margin_left = c.margin_right = Inches(0.08)
        p = c.text_frame.paragraphs[0]
        p.alignment = PP_ALIGN.LEFT
        r = p.add_run()
        r.text = h
        r.font.size = Pt(head_size)
        r.font.bold = True
        r.font.color.rgb = PAPER
        r.font.name = FONT
    for ri, row in enumerate(rows, start=1):
        for ci, val in enumerate(row):
            c = t.cell(ri, ci)
            c.fill.solid()
            c.fill.fore_color.rgb = PAPER if ri % 2 else PANEL
            c.vertical_anchor = MSO_ANCHOR.MIDDLE
            c.margin_left = c.margin_right = Inches(0.08)
            c.margin_top = c.margin_bottom = Inches(0.02)
            p = c.text_frame.paragraphs[0]
            p.alignment = PP_ALIGN.LEFT
            r = p.add_run()
            r.text = str(val)
            r.font.size = Pt(size)
            r.font.color.rgb = INK
            r.font.name = FONT
    for ri in range(len(rows) + 1):
        t.rows[ri].height = row_h
    return t


def note_panel(slide, text, top, colour=PANEL, text_colour=INK, height=Inches(0.8)):
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, MARGIN, top,
                                 CONTENT_W, height)
    box.fill.solid()
    box.fill.fore_color.rgb = colour
    box.line.color.rgb = RULE
    box.line.width = Pt(0.75)
    box.shadow.inherit = False
    f = tb(slide, MARGIN + Inches(0.25), top + Inches(0.16),
           CONTENT_W - Inches(0.5), height - Inches(0.32))
    put(f, text, size=14, color=text_colour, after=0, spacing=1.15)


def picture(slide, path, left, top, width):
    p = ROOT / path if not Path(path).is_absolute() else Path(path)
    if p.exists():
        return slide.shapes.add_picture(str(p), left, top, width=width)
    f = tb(slide, left, top, width, Inches(0.4))
    put(f, f"[missing image: {path}]", size=12, color=RED, italic=True, after=0)
    return None


def notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text


def footer(slide, text):
    f = tb(slide, MARGIN, H - Inches(0.45), CONTENT_W, Inches(0.3))
    put(f, text, size=10, color=INK2, after=0)


# ---------------------------------------------------------------------------
# Slides
# ---------------------------------------------------------------------------
def s01_title(prs, m):
    s = slide_base(prs)
    band = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Inches(2.5))
    band.fill.solid()
    band.fill.fore_color.rgb = BAND
    band.line.fill.background()
    band.shadow.inherit = False

    f = tb(s, MARGIN, Inches(0.72), CONTENT_W, Inches(1.5))
    put(f, "NETRA", size=40, color=PAPER, bold=True, after=4)
    put(f, "An AI-based Network Intrusion Detection and Response System",
        size=20, color=RGBColor(0xC9, 0xD8, 0xEC), after=0)

    f = tb(s, MARGIN, Inches(2.95), CONTENT_W, Inches(0.5))
    put(f, "21CSC302J  –  Computer Networks Course Case Study", size=16,
        color=INK2, after=0)

    f = tb(s, MARGIN, Inches(3.75), Inches(6.0), Inches(2.2))
    put(f, "Submitted by", size=14, color=INK2, after=10)
    for _ in range(4):
        put(f, "___________________________     [ Reg. No. ______________ ]",
            size=13, color=INK, after=9)

    f = tb(s, Inches(7.6), Inches(3.75), Inches(5.0), Inches(2.2))
    put(f, "Guided by", size=14, color=INK2, after=10)
    put(f, "[ Name of the Faculty ]", size=14, color=INK, bold=True, after=4)
    put(f, "[ Designation ]", size=13, color=INK2, after=4)
    put(f, "[ Department ]", size=13, color=INK2, after=14)
    put(f, "School of Computing", size=13, color=INK, after=2)
    put(f, "SRM Institute of Science and Technology", size=13, color=INK, after=0)

    footer(s, "November 2026")
    notes(s, "Introduce the team and the title. One line: this is a network intrusion "
             "detection system designed for an enterprise network and tested on a real "
             "dataset and a live lab.")
    return s


def s02_what(prs, m):
    s = slide_base(prs)
    top = header(s, 1, "What the project does")
    bullets(s, [
        ("It watches network traffic. ", "Packets are captured at a monitoring point, "
                                         "grouped into flows, and measured."),
        ("It decides what each flow is. ", "Four detectors run in order: signature rules, "
                                           "two trained classifiers, an autoencoder, and an "
                                           "open-set test."),
        ("It blocks the attacker automatically. ", "A detected attack produces a firewall "
                                                   "rule that expires on its own."),
        ("It reports what it does not recognise. ", "Traffic matching none of the trained "
                                                    "attack types is grouped, described and "
                                                    "given a name for an analyst to review."),
    ], top=top + Inches(0.2), size=18, gap=18)
    note_panel(s, "Scope for this course: the network design is built in Cisco Packet Tracer; "
                  "the detection engine is implemented in Python and tested on the CIC-IDS2017 "
                  "dataset and in an isolated Docker laboratory.",
               top=Inches(5.5), height=Inches(1.0))
    notes(s, "Four sentences. Do not go into the models yet; that is slide 10 onward.")
    return s


def s03_topology(prs, m):
    s = slide_base(prs)
    top = header(s, 2, "The network: Cisco Packet Tracer topology",
                 "Enterprise design with an internet edge, a firewall, a DMZ, a campus core, "
                 "access switches and a branch site over a WAN link.")
    picture(s, "docs/screenshots/packet_tracer_topology.png",
            MARGIN + Inches(0.3), top - Inches(0.1), Inches(11.2))
    footer(s, "Each green triangle is an active link. Dashed lines are the core-to-access "
              "uplinks.")
    notes(s, "Walk the diagram left to right and top to bottom: outside, edge router, "
             "firewall, DMZ, core, access, server farm, branch. Say that the two NIDS "
             "servers are the Netra sensors.")
    return s


def s04_segments(prs, m):
    s = slide_base(prs)
    top = header(s, 3, "The topology, segment by segment")
    rows = [
        ("Outside", "ATTACKER, EXT-CLIENT, SW-INET", "Simulated internet. The attacker and a "
                                                     "normal external user sit here."),
        ("Edge", "R-EDGE (ISR 1331)", "Routes between the outside world and the enterprise."),
        ("Security", "FW (ASA 5506-X)", "Firewall. Separates outside, DMZ and inside; "
                                        "enforces the block."),
        ("DMZ", "SW-DMZ, WEB, NIDS-DMZ", "Public web server, kept away from the internal "
                                         "network. Sensor 1 watches it."),
        ("Core", "CORE (3560-24PS), NIDS-CORE", "Multilayer switch doing inter-VLAN routing. "
                                                "Sensor 2 watches internal traffic."),
        ("Access", "ACC1, ACC2 + staff / eng / admin PCs", "User ports, assigned to VLANs."),
        ("Servers", "SW-SRV, NETRA-CONSOLE", "Server VLAN. Both sensors report to this "
                                             "console."),
        ("Branch", "R-BR1, BR-SW1, BR-PC1/2", "Remote site reached over the WAN link."),
    ]
    table(s, ["Segment", "Devices in the diagram", "Purpose"], rows,
          MARGIN, top, CONTENT_W, col_fracs=[1.0, 2.5, 4.2], size=12.5, row_h=Inches(0.42))
    notes(s, "This table is the map for the rest of the deck. Every later slide refers back "
             "to one of these segments.")
    return s


def s05_cn_hierarchy(prs, m):
    s = slide_base(prs)
    top = header(s, 4, "Networking concept: hierarchical design")
    bullets(s, [
        ("Access layer. ", "Where user devices plug in (ACC1, ACC2, BR-SW1). Ports are "
                           "assigned to VLANs; no routing happens here."),
        ("Core layer. ", "One multilayer switch (CORE) that routes between VLANs and "
                         "connects everything. This is a collapsed core: the distribution "
                         "and core layers are combined, which suits a single site."),
        ("Edge. ", "R-EDGE and the firewall connect the enterprise to the outside."),
        ("Why it is built this way. ", "Adding users means adding an access switch with the "
                                       "same configuration and two uplinks. Nothing else in "
                                       "the network changes."),
    ], top=top + Inches(0.15), size=17, gap=14)
    note_panel(s, "Addressing follows the same idea: 10.10.V.0/24 at headquarters where V is "
                  "the VLAN ID, and 10.21.0.0/16 for branch 1. Each site summarises to one "
                  "route, so the routing table stays small as sites are added.",
               top=Inches(5.3), height=Inches(1.0))
    notes(s, "Hierarchy is the examinable concept here: access, distribution, core. Explain "
             "that we collapsed distribution into the core because there is one building.")
    return s


def s06_vlans(prs, m):
    s = slide_base(prs)
    top = header(s, 5, "Networking concept: VLANs and inter-VLAN routing")
    rows = [
        ("10", "MGMT", "10.10.10.0/24", "Device management, kept separate from user traffic"),
        ("20", "STAFF", "10.10.20.0/24", "PC-STAFF1, PC-STAFF2"),
        ("30", "ENG", "10.10.30.0/24", "PC-ENG1, PC-ENG2"),
        ("50", "SERVERS", "10.10.50.0/24", "NETRA-CONSOLE and other servers"),
        ("99", "NATIVE", "no addresses", "Trunk native VLAN, carries no user traffic"),
        ("999", "PARKING", "no addresses", "Unused ports, shut down"),
    ]
    table(s, ["VLAN", "Name", "Subnet", "Used by"], rows, MARGIN, top, CONTENT_W,
          col_fracs=[0.7, 1.2, 1.8, 4.0], size=13, row_h=Inches(0.40))
    bullets(s, [
        ("A VLAN splits one physical switch into separate logical networks. ",
         "Staff and engineering traffic cannot see each other even on the same switch."),
        ("Access ports carry one VLAN; trunk ports carry many. ",
         "The core-to-access links are trunks, so one cable serves every VLAN."),
        ("Traffic between VLANs must be routed. ",
         "The 3560 core does this, which is why a multilayer switch is used there."),
    ], top=Inches(5.0), size=15, gap=10)
    notes(s, "Expect a question on access versus trunk ports and on why a layer 2 switch "
             "cannot route between VLANs.")
    return s


def s07_dmz(prs, m):
    s = slide_base(prs)
    top = header(s, 6, "Networking concept: firewall and DMZ")
    bullets(s, [
        ("The DMZ is a separate segment for public-facing servers. ",
         "The WEB server must be reachable from the internet, so it is placed where a "
         "compromise does not put the attacker inside the internal network."),
        ("The firewall has three zones. ",
         "Outside (the internet), DMZ (the web server) and inside (the campus). Traffic from "
         "outside may reach the DMZ on port 80 only; it may not reach the inside at all."),
        ("Security levels decide the default. ",
         "On an ASA, traffic from a higher security level to a lower one is allowed by "
         "default, and the reverse direction needs an explicit rule."),
    ], top=top + Inches(0.15), size=17, gap=15)
    note_panel(s, "In Packet Tracer, Netra's response is shown by adding a deny rule for the "
                  "attacker on the firewall and replaying the request, which is then dropped. "
                  "This is how a passive sensor works in production: it detects on mirrored "
                  "traffic and asks the firewall to enforce the block.",
               top=Inches(5.3), height=Inches(1.1))
    notes(s, "Say explicitly that in the Docker lab the sensor enforces the block itself "
             "because it shares the server's network namespace, while in this topology it "
             "would ask the firewall.")
    return s


def s08_sensors(prs, m):
    s = slide_base(prs)
    top = header(s, 7, "Networking concept: where the sensors sit (SPAN)")
    bullets(s, [
        ("A sensor must see traffic without being in its path. ",
         "If it were inline and failed, the network would fail with it."),
        ("Port mirroring (SPAN) solves this. ",
         "The switch copies every frame crossing a chosen port to a monitoring port. The "
         "sensor reads the copy."),
        ("Two sensors cover two different choke points. ",
         "NIDS-DMZ sees traffic to and from the public web server. NIDS-CORE sees internal "
         "traffic between VLANs and traffic leaving for the internet."),
        ("Each sensor has two interfaces. ",
         "One passive capture port with no IP address, and one management port in the MGMT "
         "VLAN that reports to NETRA-CONSOLE."),
    ], top=top + Inches(0.15), size=16.5, gap=13)
    note_panel(s, "The capture port is in promiscuous mode, which makes the network card "
                  "accept every frame it sees rather than only those addressed to it.",
               top=Inches(5.6), height=Inches(0.75))
    notes(s, "Common viva question: why not put the IDS inline? Answer: availability, and "
             "because a passive sensor cannot be the cause of an outage.")
    return s


def s09_protocols(prs, m):
    s = slide_base(prs)
    top = header(s, 8, "Protocols the system works with")
    rows = [
        ("Internet", "IPv4", "–", "The only address family parsed"),
        ("Internet", "ICMP", "proto 1", "Not parsed. A stated limitation of the project"),
        ("Transport", "TCP", "proto 6", "Main protocol: flags, window, handshake"),
        ("Transport", "UDP", "proto 17", "Parsed; carries DNS and NTP"),
        ("Application", "DNS", "53", "129,011 flows in the test data"),
        ("Application", "HTTP", "80", "80,737 flows. The web server and attack target"),
        ("Application", "HTTPS / TLS", "443", "69,787 flows. Only traffic shape is visible"),
        ("Application", "SSH / FTP", "22 / 21", "Brute-force targets, watched login ports"),
        ("Application", "Telnet / RDP", "23 / 3389", "Also watched as login ports"),
        ("System", "WebSocket, REST", "8000", "Engine to console; alerts and control"),
    ]
    table(s, ["Layer", "Protocol", "Port", "Role in the project"], rows,
          MARGIN, top, CONTENT_W, col_fracs=[1.0, 1.5, 1.0, 4.3], size=12.5,
          row_h=Inches(0.345))
    note_panel(s, "The protocol number is one of the model inputs. The destination port is "
                  "deliberately not an input: in this dataset most denial-of-service traffic "
                  "targets port 80, so a model allowed to use the port would learn the port "
                  "rather than the behaviour.",
               top=Inches(5.75), height=Inches(0.95))
    notes(s, "If asked which protocols: IPv4 with TCP and UDP, and above them HTTP, HTTPS, "
             "DNS, FTP, SSH, Telnet, RDP, NTP and SMB.")
    return s


def s10_flows(prs, m):
    s = slide_base(prs)
    top = header(s, 9, "From packets to flows: the bridge to machine learning")
    steps = [
        ("1", "Capture", "Packets arrive on the mirrored port."),
        ("2", "Group", "Packets with the same 5-tuple (source IP, source port, destination "
                       "IP, destination port, protocol) form one flow."),
        ("3", "Measure", "Each completed flow is reduced to numbers: duration, packets per "
                         "second, bytes per second, mean packet size, inter-arrival times, "
                         "forward and backward counts."),
        ("4", "Classify", "Those numbers are what the models see. The models never see "
                          "addresses or payload."),
    ]
    y = top + Inches(0.1)
    for num, title, body in steps:
        badge = s.shapes.add_shape(MSO_SHAPE.OVAL, MARGIN, y + Inches(0.06),
                                   Inches(0.42), Inches(0.42))
        badge.fill.solid()
        badge.fill.fore_color.rgb = BLUE
        badge.line.fill.background()
        badge.shadow.inherit = False
        bf = badge.text_frame
        bf.margin_left = bf.margin_right = 0
        put(bf, num, size=15, color=PAPER, bold=True, align=PP_ALIGN.CENTER, after=0,
            para=bf.paragraphs[0])
        f = tb(s, MARGIN + Inches(0.65), y, CONTENT_W - Inches(0.65), Inches(1.0))
        put(f, title, size=17, color=INK, bold=True, after=3)
        put(f, body, size=14.5, color=INK2, after=0, spacing=1.12)
        y = Emu(int(y + Inches(1.12)))
    note_panel(s, "Two feature sets are used: 59 features from the full CICFlowMeter schema "
                  "for offline work, and 6 features that can be computed live from packets "
                  "in any environment.",
               top=Inches(5.9), height=Inches(0.8))
    notes(s, "This is the slide that connects the networking half to the ML half. The 5-tuple "
             "is the key networking idea; the feature vector is the key ML idea.")
    return s


def s11_ml_supervised(prs, m):
    s = slide_base(prs)
    full, lite = m["full"], m["lite"]
    top = header(s, 10, "Machine learning concept: supervised classification")
    bullets(s, [
        ("Supervised learning means learning from labelled examples. ",
         "We used CIC-IDS2017: 2.8 million recorded flows, each labelled benign or with an "
         "attack name."),
        ("The model is a Random Forest. ",
         "Many decision trees, each trained on a random part of the data, voting on the "
         "answer. It was compared against XGBoost and selected on validation macro F1."),
        ("Eight classes. ",
         "Benign, Bot, BruteForce, DDoS, DoS, DoS-Slow, PortScan, WebAttack."),
    ], top=top + Inches(0.1), size=16, gap=11)
    rows = [
        ("Accuracy", f"{full['accuracy']:.4f}", "Share of all flows classified correctly"),
        ("Macro F1", f"{full['macro']['f1']:.4f}", "Every class counts equally, so rare "
                                                   "attacks are not ignored"),
        ("Detection rate", f"{full['binary']['detection_rate']:.4f}", "Share of attack flows "
                                                                     "caught"),
        ("False-positive rate", f"{full['binary']['false_positive_rate']:.5f}",
         "Share of normal flows wrongly flagged"),
        ("Lite model macro F1", f"{lite['macro']['f1']:.4f}", "Using only the 6 live features"),
    ]
    table(s, ["Measure", "Value", "What it means"], rows, MARGIN, Inches(4.25), CONTENT_W,
          col_fracs=[1.6, 1.0, 4.2], size=12.5, row_h=Inches(0.37))
    footer(s, "Measured on the held-out test split, which was never used for training.")
    notes(s, "Lead with macro F1 rather than accuracy, and explain why: benign traffic is "
             "about 85 percent of the data, so accuracy alone is misleading.")
    return s


def s12_ml_unsupervised(prs, m):
    s = slide_base(prs)
    ae = m["ae"]
    top = header(s, 11, "Machine learning concept: unsupervised anomaly detection")
    bullets(s, [
        ("Unsupervised means no labels are used. ",
         "The autoencoder was trained only on normal traffic and never saw an attack."),
        ("How an autoencoder works. ",
         "A neural network shaped like an hourglass, 59-32-16-8-16-32-59. It compresses a "
         "flow into 8 numbers and rebuilds it. Trained on normal traffic, it rebuilds normal "
         "traffic well and unusual traffic badly."),
        ("The rebuilding error is the anomaly score. ",
         f"Above the threshold, the flow is unusual. ROC-AUC {ae['roc_auc']:.4f}, detecting "
         f"{100 * ae['detection_rate']:.1f}% of attacks at a "
         f"{100 * ae['false_positive_rate']:.2f}% false-alarm rate."),
        ("Why it is included. ",
         "It needs no attack labels, so it can react to a pattern nobody wrote a rule for "
         "and nobody labelled."),
    ], top=top + Inches(0.15), size=16, gap=13)
    note_panel(s, "Limitation: the output is a single number. On its own it says a flow is "
                  "unusual but not why or what it is. The next slide addresses that.",
               top=Inches(5.75), height=Inches(0.8))
    notes(s, "Keep the explanation concrete: compress and rebuild. The error is the score.")
    return s


def s13_openset(prs, m):
    s = slide_base(prs)
    os_ = m["openset"]
    loco = os_["leave_one_class_out"]
    silent = sum(1 for f in loco["folds"] if f["closed_set_called_benign"] > 0.5)
    kr = os_["known_rejection"]["scores"][os_["score"]]["rejection_rate"]
    top = header(s, 12, "Machine learning concept: open-set recognition",
                 "The part of the project that is not a standard pipeline.")
    bullets(s, [
        ("A trained classifier can only answer with classes it has seen. ",
         "Its output is a probability over the eight trained classes, and those add up to 1. "
         "There is no option for “none of these”."),
        ("So a new attack is forced into an existing class. ",
         f"We tested this by deleting one attack class from training and then showing it to "
         f"the model. In {silent} of 7 cases it called most of that attack Benign and raised "
         f"no alert."),
        ("Our addition: a conformal test. ",
         "Before accepting “Benign”, the system checks whether the flow actually "
         "resembles anything it was trained on, using the distance to the 10 nearest "
         "training examples of each class."),
        ("The cost is fixed in advance. ",
         f"Set the level to 0.05 and exactly 5% of known traffic is sent to the unknown path. "
         f"Measured: {kr:.4f}. It is a false-alarm budget, not a tuned threshold."),
    ], top=top + Inches(0.1), size=15.5, gap=11)
    notes(s, "This is the novel contribution. If asked how the threshold was chosen without "
             "seeing new attacks: it is a significance level, chosen from the false-alarm "
             "budget, and the guarantee is mathematical.")
    return s


def s14_families(prs, m):
    s = slide_base(prs)
    d = m["discovery"]["totals"]
    top = header(s, 13, "What happens to traffic the system does not recognise")
    bullets(s, [
        ("Rejected flows are grouped, not alerted individually. ",
         "They are clustered by the direction in which they differ from normal traffic, so "
         "one new attack becomes one object instead of hundreds of separate alarms."),
        ("Each group gets an identifier and a description. ",
         "For example: 213 unrecognised flows from 1 source, 1.008 seconds between packets "
         "on port 80, nearest known class Benign."),
        ("An analyst names it once. ",
         "The name is stored and used by every later alert about that group, and it survives "
         "a restart."),
        ("Measured on held-out attacks. ",
         f"The new attack was reported as a named group in "
         f"{d['folds_where_novel_family_reported']} of 7 tests, with cluster purity "
         f"{d['mean_purity']:.3f}."),
    ], top=top + Inches(0.15), size=16, gap=13)
    note_panel(s, "In the live laboratory the system grouped the attack traffic without being "
                  "told what it was. One group was 1.008 seconds between packets on port 80, "
                  "which is a slow HTTP attack holding connections open; another was 139,810 "
                  "packets per second of empty probes, which is a port scan.",
               top=Inches(5.65), height=Inches(0.95))
    notes(s, "Give the two live examples. They show the fingerprints map onto real tool "
             "behaviour.")
    return s


def s15_response(prs, m):
    s = slide_base(prs)
    top = header(s, 14, "Detection to response")
    rows = [
        ("High", "Signature hit, or a classifier above 0.9 confidence",
         "Block the source for 120 seconds (iptables DROP)"),
        ("Medium", "Classifier between 0.6 and 0.9, or a reported unknown group",
         "Rate-limit the source to 10 packets per second for 60 seconds"),
        ("Low", "Weak evidence", "Record it only; no firewall rule"),
    ]
    table(s, ["Severity", "What triggers it", "Action taken"], rows, MARGIN, top, CONTENT_W,
          col_fracs=[1.0, 3.0, 3.0], size=13, row_h=Inches(0.48))
    bullets(s, [
        ("Every rule expires by itself. ",
         "The worst case of a wrong decision is a short outage for one address, not a "
         "permanent ban."),
        ("All rules live in one chain. ",
         "A dedicated NETRA iptables chain, so the whole footprint can be listed with one "
         "command and removed with another."),
        ("Critical addresses are never blocked. ",
         "Gateways, the loopback and the protected server are on a never-block list."),
        ("In the Packet Tracer design the firewall enforces it. ",
         "The sensor is passive, so it asks the ASA to add the deny rule."),
    ], top=Inches(4.35), size=15, gap=10)
    notes(s, "Automated blocking is only defensible because it is timed, scoped and "
             "reversible. Say all three.")
    return s


def s16_testing(prs, m):
    s = slide_base(prs)
    top = header(s, 15, "How the system was tested")
    rows = [
        ("Offline", "Held-out CIC-IDS2017 test split, 329,392 flows",
         "Macro F1 0.9570, detection 99.80%"),
        ("Unseen attacks", "Each attack class removed from training, then replayed",
         "Closed-set model silent in 6 of 7; open-set reports them"),
        ("Second dataset", "The trained model run on UNSW-NB15",
         "Detection falls to 0.03%: the model does not transfer"),
        ("Live laboratory", "Docker lab: nmap, hping3, slowhttptest, hydra",
         "All four detected and blocked with real iptables rules"),
        ("Automated tests", "Unit and integration tests in the repository", "96 passing"),
    ]
    table(s, ["Test", "What was done", "Result"], rows, MARGIN, top, CONTENT_W,
          col_fracs=[1.3, 3.3, 3.0], size=13, row_h=Inches(0.52))
    note_panel(s, "The cross-dataset result is reported as a finding, not hidden. The model "
                  "learned the packet rates of one network rather than what an attack is, "
                  "which is why an intrusion detection model has to be retrained for the "
                  "network it will watch.",
               top=Inches(5.5), height=Inches(0.95))
    notes(s, "The negative results are the most defensible part of the project. Present them "
             "confidently.")
    return s


def s17_limits(prs, m):
    s = slide_base(prs)
    top = header(s, 16, "Limitations")
    bullets(s, [
        ("No payload inspection. ",
         "Only packet headers and flow statistics are used, so attacks carried in the "
         "content of a request, such as SQL injection, are poorly detected."),
        ("Encrypted traffic. ",
         "For HTTPS the shape of the traffic is visible but the content is not."),
        ("ICMP is not parsed. ",
         "A ping flood or an ICMP tunnel would not be seen."),
        ("Response is by source address. ",
         "Address spoofing and widely distributed attacks defeat it."),
        ("The model is network-specific. ",
         "It must be retrained on traffic from the network it will protect."),
    ], top=top + Inches(0.15), size=16.5, gap=13)
    notes(s, "Stating limits plainly is better than being caught out by a question. Each one "
             "here is measured, not guessed.")
    return s


def s18_conclusion(prs, m):
    s = slide_base(prs)
    top = header(s, 17, "Conclusion")
    bullets(s, [
        ("A complete enterprise network was designed in Packet Tracer. ",
         "Hierarchical addressing, VLANs, inter-VLAN routing, a firewall with a DMZ, a WAN "
         "link to a branch, and two monitoring points fed by SPAN."),
        ("A working detection and response system was built for it. ",
         "Signature rules, two classifiers, an autoencoder and an open-set test, with "
         "automatic and reversible firewall response."),
        ("It was tested beyond its own training data. ",
         "By removing attack classes, by using a second dataset, and in a live laboratory "
         "against four real attack tools."),
        ("It reports what it does not know. ",
         "Unrecognised traffic is grouped, described and named rather than being silently "
         "classified as benign."),
    ], top=top + Inches(0.15), size=16.5, gap=14)
    note_panel(s, "Future work: inspect payloads for web attacks, feed named groups back into "
                  "training, and correlate alerts into multi-stage incidents.",
               top=Inches(5.85), height=Inches(0.75))
    notes(s, "Close on the four points, then invite questions.")
    return s


def s19_thanks(prs, m):
    s = slide_base(prs)
    band = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, Inches(2.6), W, Inches(2.0))
    band.fill.solid()
    band.fill.fore_color.rgb = BAND
    band.line.fill.background()
    band.shadow.inherit = False
    f = tb(s, MARGIN, Inches(3.15), CONTENT_W, Inches(1.0))
    put(f, "Thank you", size=34, color=PAPER, bold=True, align=PP_ALIGN.CENTER, after=6)
    put(f, "Questions", size=18, color=RGBColor(0xC9, 0xD8, 0xEC), align=PP_ALIGN.CENTER,
        after=0)
    f = tb(s, MARGIN, Inches(5.1), CONTENT_W, Inches(0.5))
    put(f, "NETRA  ·  21CSC302J Computer Networks Course Case Study", size=13,
        color=INK2, align=PP_ALIGN.CENTER, after=0)
    notes(s, "Likely questions: why not inline, access versus trunk ports, why macro F1, how "
             "the open-set threshold is chosen, and what happens on encrypted traffic.")
    return s


BUILDERS = [s01_title, s02_what, s03_topology, s04_segments, s05_cn_hierarchy, s06_vlans,
            s07_dmz, s08_sensors, s09_protocols, s10_flows, s11_ml_supervised,
            s12_ml_unsupervised, s13_openset, s14_families, s15_response, s16_testing,
            s17_limits, s18_conclusion, s19_thanks]


def build(out: Path) -> Path:
    m = numbers()
    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H
    for fn in BUILDERS:
        fn(prs, m)
    out.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Computer Networks presentation.")
    ap.add_argument("-o", "--out",
                    default=str(ROOT / "presentation" / "Netra_CN_Presentation.pptx"))
    args = ap.parse_args()
    out = build(Path(args.out))
    print(f"Wrote {out} ({len(BUILDERS)} slides)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
