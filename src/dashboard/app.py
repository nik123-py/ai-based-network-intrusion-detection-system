"""Netra desktop app (PySide6 / Qt).

A native window that shows what the detection engine is doing in real time:
alert feed, traffic rate, attack-type distribution, blocked addresses with
countdowns, and model/health status. It connects to the engine's event API
(``src/dashboard/api.py``) over a WebSocket, so the same app works with the
engine running on the host (``netra demo``) or inside the Docker lab.

    python -m src.cli app                       # connect to ws://127.0.0.1:8000/ws
    python -m src.cli app --url ws://HOST:8000/ws
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter, deque
from datetime import datetime

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSet,
    QChart,
    QChartView,
    QHorizontalBarSeries,
    QLineSeries,
    QValueAxis,
)
from PySide6.QtCore import QByteArray, QMargins, QObject, QPointF, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QActionGroup, QColor, QFont, QGuiApplication, QPainter, QPen
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest
from PySide6.QtWebSockets import QWebSocket
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

APP_TITLE = "Netra: Network Threat Recognition and Automated response"
HISTORY_S = 120  # seconds shown on the traffic chart

# Tokens from the project's reference palette. Status colours are reserved for
# severity and connection state and always appear with an icon and a word.
THEMES = {
    "light": {"page": "#f9f9f7", "card": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
              "grid": "#e1e0d9", "axis": "#c3c2b7", "border": "#e6e5df", "series": "#2a78d6",
              "select": "#cde2fb", "button": "#ffffff"},
    "dark": {"page": "#0d0d0d", "card": "#1a1a19", "ink": "#ffffff", "ink2": "#c3c2b7", "muted": "#898781",
             "grid": "#2c2c2a", "axis": "#383835", "border": "#2c2c2a", "series": "#3987e5",
             "select": "#184f95", "button": "#242423"},
}
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
SEVERITY = {"high": ("▲ High", STATUS["critical"]),
            "medium": ("● Medium", STATUS["serious"]),
            "low": ("○ Low", None)}
ACTION_TEXT = {"block": "Blocked", "block-extended": "Extended", "quarantine": "Quarantined",
               "quarantine-extended": "Extended", "logged": "Logged only",
               "log-only": "Logged (response off)", "skipped-allowlist": "Allow-listed", "pending": "..."}
METRICS = {"Packets per second": "packets_per_s", "Flows scored per second": "flows_per_s",
           "Bytes per second": "bytes_per_s"}


MODEL_SHORT = {"random_forest": "RF", "xgboost": "XGB"}


def detector_label(a: dict) -> str:
    """Short, human-readable name of the detector that produced an alert."""
    det, model = a.get("detector", ""), a.get("model") or ""
    if det.startswith("signature:"):
        return f"Rule · {det.split(':', 1)[1]}"
    if det == "anomaly":
        return "Autoencoder"
    if "/" in model:
        kind, name = model.split("/", 1)
        return f"ML {kind} · {MODEL_SHORT.get(name, name)}"
    return det


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def fmt_num(v: float) -> str:
    v = float(v)
    for unit, size in (("G", 1e9), ("M", 1e6), ("k", 1e3)):
        if abs(v) >= size:
            return f"{v / size:.1f}{unit}"
    return f"{v:.0f}"


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
class EngineClient(QObject):
    """WebSocket client with automatic reconnect, plus REST calls for unblock actions."""

    event = Signal(dict)
    connection = Signal(bool)

    def __init__(self, ws_url: str):
        super().__init__()
        self.ws_url = ws_url
        self.http_base = ws_url.replace("ws://", "http://").replace("wss://", "https://").rsplit("/ws", 1)[0]
        self.socket = QWebSocket()
        self.socket.textMessageReceived.connect(self._on_text)
        self.socket.connected.connect(lambda: self.connection.emit(True))
        self.socket.disconnected.connect(self._on_disconnected)
        self.http = QNetworkAccessManager(self)
        self.retry = QTimer(self, interval=2000, singleShot=True)
        self.retry.timeout.connect(self.connect_now)

    def connect_now(self) -> None:
        self.socket.open(QUrl(self.ws_url))

    def _on_disconnected(self) -> None:
        self.connection.emit(False)
        self.retry.start()

    def _on_text(self, text: str) -> None:
        try:
            self.event.emit(json.loads(text))
        except json.JSONDecodeError:
            pass

    def post(self, path: str) -> None:
        req = QNetworkRequest(QUrl(self.http_base + path))
        req.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "application/json")
        self.http.post(req, QByteArray(b"{}"))


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------
class Card(QFrame):
    def __init__(self, title: str | None = None):
        super().__init__()
        self.setObjectName("card")
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(14, 12, 14, 12)
        self.layout_.setSpacing(8)
        if title:
            label = QLabel(title)
            label.setObjectName("cardTitle")
            self.header = QHBoxLayout()
            self.header.addWidget(label)
            self.header.addStretch()
            self.layout_.addLayout(self.header)


class StatTile(Card):
    def __init__(self, label: str):
        super().__init__()
        self.value = QLabel("0")
        self.value.setObjectName("statValue")
        caption = QLabel(label)
        caption.setObjectName("statLabel")
        self.layout_.addWidget(self.value)
        self.layout_.addWidget(caption)

    def set(self, text: str) -> None:
        self.value.setText(text)


def _chart(theme: dict) -> QChart:
    chart = QChart()
    chart.setBackgroundBrush(QColor(theme["card"]))
    chart.setBackgroundRoundness(0)
    chart.setMargins(QMargins(0, 4, 4, 0))
    chart.legend().hide()
    chart.setAnimationOptions(QChart.AnimationOption.NoAnimation)
    return chart


def _style_axis(axis, theme: dict) -> None:
    axis.setLabelsColor(QColor(theme["muted"]))
    axis.setGridLineColor(QColor(theme["grid"]))
    axis.setLinePenColor(QColor(theme["axis"]))
    font = QFont()
    font.setPointSize(8)
    axis.setLabelsFont(font)


class TrafficChart(QChartView):
    """Rolling traffic rate. One metric at a time, so there is always a single y-axis."""

    def __init__(self, theme: dict):
        super().__init__()
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.points: deque = deque(maxlen=HISTORY_S)
        self.metric_key = "packets_per_s"
        self.apply_theme(theme)

    def apply_theme(self, theme: dict) -> None:
        self.theme = theme
        chart = _chart(theme)
        self.series = QLineSeries()
        pen = QPen(QColor(theme["series"]))
        pen.setWidthF(2.0)
        self.series.setPen(pen)
        chart.addSeries(self.series)
        self.x = QValueAxis()
        self.x.setRange(-HISTORY_S, 0)
        self.x.setTickCount(7)
        self.x.setLabelFormat("%d s")
        self.y = QValueAxis()
        self.y.setLabelFormat("%.0f")
        self.y.setTickCount(5)
        for axis, align in ((self.x, Qt.AlignmentFlag.AlignBottom), (self.y, Qt.AlignmentFlag.AlignLeft)):
            _style_axis(axis, theme)
            chart.addAxis(axis, align)
            self.series.attachAxis(axis)
        self.x.setGridLineVisible(False)
        self.setChart(chart)
        self.redraw()

    def add(self, stats: dict) -> None:
        self.points.append((stats.get("time", time.time()), stats))
        self.redraw()

    def redraw(self) -> None:
        now = time.time()
        pts = [QPointF(t - now, float(s.get(self.metric_key, 0))) for t, s in self.points]
        self.series.replace(pts)
        peak = max((p.y() for p in pts), default=0.0)
        self.y.setRange(0, max(10.0, peak * 1.15))
        self.y.applyNiceNumbers()


class AttackChart(QChartView):
    """Alerted flows per attack type (single series, so no legend)."""

    def __init__(self, theme: dict):
        super().__init__()
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.counts: Counter = Counter()
        self.apply_theme(theme)

    def apply_theme(self, theme: dict) -> None:
        self.theme = theme
        self.redraw()

    def redraw(self) -> None:
        theme = self.theme
        chart = _chart(theme)
        items = sorted(self.counts.items(), key=lambda kv: kv[1]) or [("No alerts yet", 0)]
        bar = QBarSet("Alerted flows")
        bar.setColor(QColor(theme["series"]))
        bar.setBorderColor(QColor(theme["series"]))
        bar.setLabelColor(QColor(theme["ink2"]))
        for _, v in items:
            bar.append(v)
        series = QHorizontalBarSeries()
        series.append(bar)
        series.setBarWidth(0.6)
        series.setLabelsVisible(True)
        series.setLabelsPosition(QHorizontalBarSeries.LabelsPosition.LabelsOutsideEnd)
        chart.addSeries(series)
        cats = QBarCategoryAxis()
        cats.append([k for k, _ in items])
        vals = QValueAxis()
        vals.setRange(0, max(1, max(v for _, v in items)) * 1.2)
        vals.setLabelFormat("%d")
        vals.setTickCount(4)
        for axis, align in ((cats, Qt.AlignmentFlag.AlignLeft), (vals, Qt.AlignmentFlag.AlignBottom)):
            _style_axis(axis, theme)
            chart.addAxis(axis, align)
            series.attachAxis(axis)
        cats.setGridLineVisible(False)
        cats.setTruncateLabels(False)
        vals.applyNiceNumbers()
        self.setChart(chart)


def _item(text: str, color: str | None = None, align_right: bool = False) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if color:
        item.setForeground(QColor(color))
    if align_right:
        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    return item


class AlertTable(QTableWidget):
    COLUMNS = ["Time", "Severity", "Source", "Destination", "Attack", "Conf.", "Detector", "Flows", "Action"]

    def __init__(self):
        super().__init__(0, len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.verticalHeader().hide()
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.rows: dict[int, int] = {}  # alert id -> row (counted from the bottom)

    def add(self, a: dict) -> None:
        self.insertRow(0)
        label, color = SEVERITY.get(a.get("severity"), (a.get("severity", ""), None))
        values = [
            _item(fmt_time(a["time"])),
            _item(label, color),
            _item(a["src"]),
            _item(f"{a['dst']}:{a['dport']}"),
            _item(a["attack"]),
            _item(f"{a['confidence']:.2f}", align_right=True),
            _item(detector_label(a)),
            _item(str(a.get("count", 1)), align_right=True),
            _item(ACTION_TEXT.get(a.get("action"), a.get("action", ""))),
        ]
        values[4].setToolTip(a.get("description", ""))
        for col, item in enumerate(values):
            self.setItem(0, col, item)
        self.rows[a["id"]] = self.rowCount()
        if self.rowCount() > 500:
            self.removeRow(self.rowCount() - 1)

    def update_count(self, u: dict) -> None:
        pos = self.rows.get(u["id"])
        if pos is None:
            return
        row = self.rowCount() - pos
        if 0 <= row < self.rowCount():
            self.item(row, 7).setText(str(u["count"]))
            self.item(row, 5).setText(f"{u['confidence']:.2f}")


class BlockTable(QTableWidget):
    COLUMNS = ["Address", "Action", "Reason", "Remaining", ""]
    unblock = Signal(str)

    def __init__(self):
        super().__init__(0, len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.verticalHeader().hide()
        self.setShowGrid(False)
        self.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.verticalHeader().setDefaultSectionSize(36)
        self.blocks: list[dict] = []

    def set_blocks(self, blocks: list[dict]) -> None:
        now = time.time()
        self.blocks = [{**b, "_until": now + float(b.get("remaining", 0))} for b in blocks]
        self.setRowCount(len(self.blocks))
        for row, b in enumerate(self.blocks):
            kind = "■ Blocked" if b["kind"] == "block" else "◒ Quarantined"
            color = STATUS["critical"] if b["kind"] == "block" else STATUS["serious"]
            self.setItem(row, 0, _item(b["ip"]))
            self.setItem(row, 1, _item(kind, color))
            self.setItem(row, 2, _item(b.get("reason", "")))
            self.setItem(row, 3, _item("", align_right=True))
            button = QPushButton("Unblock")
            button.setObjectName("smallButton")
            button.setMinimumWidth(76)
            button.clicked.connect(lambda _=False, ip=b["ip"]: self.unblock.emit(ip))
            self.setCellWidget(row, 4, button)
        self.tick()

    def tick(self) -> None:
        now = time.time()
        for row, b in enumerate(self.blocks):
            item = self.item(row, 3)
            if item is not None:
                left = max(0, int(round(b["_until"] - now)))
                item.setText(f"{left // 60}:{left % 60:02d}")


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self, ws_url: str, theme: str = "auto"):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1440, 900)
        self.client = EngineClient(ws_url)
        self.theme_name = self._resolve_theme(theme)
        self.theme = THEMES[self.theme_name]
        self.total_alerts = 0
        self._status: dict = {}
        self._health: dict = {}
        self._alert_attack: dict[int, str] = {}   # alert id -> attack class
        self._alert_counts: dict[int, int] = {}   # alert id -> flows already counted
        self._build()
        self.client.event.connect(self.on_event)
        self.client.connection.connect(self.on_connection)
        self.on_connection(False)
        self.client.connect_now()
        self.timer = QTimer(self, interval=1000)
        self.timer.timeout.connect(self.blocks.tick)
        self.timer.start()

    @staticmethod
    def _resolve_theme(theme: str) -> str:
        if theme in THEMES:
            return theme
        scheme = QGuiApplication.styleHints().colorScheme()
        return "dark" if scheme == Qt.ColorScheme.Dark else "light"

    # -- layout -------------------------------------------------------------
    def _build(self) -> None:
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(16, 12, 16, 16)
        outer.setSpacing(12)

        # Header row
        header = QHBoxLayout()
        title = QLabel("Netra")
        title.setObjectName("appTitle")
        subtitle = QLabel("Network Threat Recognition and Automated response")
        subtitle.setObjectName("appSubtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        header.addStretch()
        self.segment = QLabel("")
        self.segment.setObjectName("muted")
        header.addWidget(self.segment)
        self.conn = QLabel()
        self.conn.setObjectName("connLabel")
        header.addWidget(self.conn)
        outer.addLayout(header)

        # Stat tiles
        tiles = QHBoxLayout()
        tiles.setSpacing(12)
        self.tile_alerts = StatTile("Alerts raised")
        self.tile_blocked = StatTile("Addresses blocked or quarantined")
        self.tile_pps = StatTile("Packets per second")
        self.tile_fps = StatTile("Flows scored per second")
        self.tile_flows = StatTile("Flows scored in total")
        for t in (self.tile_alerts, self.tile_blocked, self.tile_pps, self.tile_fps, self.tile_flows):
            tiles.addWidget(t)
        outer.addLayout(tiles)

        # Charts row
        charts = QHBoxLayout()
        charts.setSpacing(12)
        traffic_card = Card("Traffic rate, last two minutes")
        self.metric_box = QComboBox()
        self.metric_box.addItems(list(METRICS))
        self.metric_box.currentTextChanged.connect(self._metric_changed)
        traffic_card.header.addWidget(self.metric_box)
        self.traffic = TrafficChart(self.theme)
        traffic_card.layout_.addWidget(self.traffic)
        attack_card = Card("Alerted flows by attack type")
        self.attacks = AttackChart(self.theme)
        attack_card.layout_.addWidget(self.attacks)
        charts.addWidget(traffic_card, 3)
        charts.addWidget(attack_card, 2)
        chart_row = QWidget()
        chart_row.setLayout(charts)
        chart_row.setMinimumHeight(260)

        # Lower row: alerts | blocks + status
        alerts_card = Card("Alert feed (newest first)")
        self.alert_table = AlertTable()
        alerts_card.layout_.addWidget(self.alert_table)

        blocks_card = Card("Blocked and quarantined addresses")
        unblock_all = QPushButton("Unblock all")
        unblock_all.setObjectName("unblockAllButton")
        unblock_all.clicked.connect(lambda: self.client.post("/api/unblock-all"))
        blocks_card.header.addWidget(unblock_all)
        self.blocks = BlockTable()
        self.blocks.unblock.connect(lambda ip: self.client.post(f"/api/unblock/{ip}"))
        blocks_card.layout_.addWidget(self.blocks)

        status_card = Card("Models and health")
        self.status_grid = QGridLayout()
        self.status_grid.setHorizontalSpacing(16)
        self.status_grid.setVerticalSpacing(2)
        status_card.layout_.addLayout(self.status_grid)
        status_card.layout_.addStretch()

        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(blocks_card)
        right.addWidget(status_card)
        right.setSizes([380, 240])
        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.addWidget(alerts_card)
        lower.addWidget(right)
        lower.setSizes([900, 500])

        main_split = QSplitter(Qt.Orientation.Vertical)
        main_split.addWidget(chart_row)
        main_split.addWidget(lower)
        main_split.setSizes([300, 500])
        outer.addWidget(main_split, 1)
        self.setCentralWidget(root)
        self._build_menu()
        self._apply_stylesheet()

    def _build_menu(self) -> None:
        view = self.menuBar().addMenu("View")
        group = QActionGroup(self)
        for name in ("light", "dark"):
            act = QAction(f"{name.capitalize()} theme", self, checkable=True)
            act.setChecked(name == self.theme_name)
            act.triggered.connect(lambda _=False, n=name: self.set_theme(n))
            group.addAction(act)
            view.addAction(act)
        actions = self.menuBar().addMenu("Actions")
        act = QAction("Block an address...", self)
        act.triggered.connect(self._block_dialog)
        actions.addAction(act)
        act = QAction("Unblock all addresses", self)
        act.triggered.connect(lambda: self.client.post("/api/unblock-all"))
        actions.addAction(act)
        act = QAction("Clear alert feed", self)
        act.triggered.connect(self._clear_alerts)
        actions.addAction(act)

    def _block_dialog(self) -> None:
        from PySide6.QtWidgets import QInputDialog

        ip, ok = QInputDialog.getText(self, "Block an address", "IPv4 address to block:")
        if ok and ip.strip():
            self.client.post(f"/api/block/{ip.strip()}")

    def _clear_alerts(self) -> None:
        self.alert_table.setRowCount(0)
        self.alert_table.rows.clear()
        self.attacks.counts.clear()
        self.attacks.redraw()

    def set_theme(self, name: str) -> None:
        self.theme_name, self.theme = name, THEMES[name]
        self._apply_stylesheet()
        self.traffic.apply_theme(self.theme)
        self.attacks.apply_theme(self.theme)

    def _apply_stylesheet(self) -> None:
        t = self.theme
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background: {t['page']}; color: {t['ink']};
                font-family: "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif; font-size: 13px; }}
            QMenuBar, QMenu {{ background: {t['card']}; color: {t['ink']}; }}
            QMenu::item:selected, QMenuBar::item:selected {{ background: {t['select']}; }}
            #card {{ background: {t['card']}; border: 1px solid {t['border']}; border-radius: 10px; }}
            #card QWidget {{ background: {t['card']}; }}
            #cardTitle {{ color: {t['ink']}; font-size: 13px; font-weight: 600; }}
            #statValue {{ color: {t['ink']}; font-size: 26px; font-weight: 600; }}
            #statLabel, #muted {{ color: {t['ink2']}; font-size: 12px; }}
            #appTitle {{ font-size: 22px; font-weight: 700; }}
            #appSubtitle {{ color: {t['ink2']}; font-size: 13px; padding-left: 8px; padding-top: 6px; }}
            QTableWidget {{ border: none; gridline-color: {t['grid']}; selection-background-color: {t['select']};
                selection-color: {t['ink']}; }}
            QTableWidget::item {{ padding: 4px 8px; border-bottom: 1px solid {t['grid']}; }}
            QHeaderView::section {{ background: {t['card']}; color: {t['muted']}; border: none;
                border-bottom: 1px solid {t['axis']}; padding: 6px 8px; font-weight: 600; font-size: 12px; }}
            QPushButton {{ background: {t['button']}; color: {t['ink']}; border: 1px solid {t['axis']};
                border-radius: 6px; padding: 5px 12px; }}
            QPushButton:hover {{ border-color: {t['series']}; }}
            #smallButton {{ padding: 2px 8px; font-size: 12px; }}
            QComboBox {{ background: {t['button']}; border: 1px solid {t['axis']}; border-radius: 6px;
                padding: 3px 8px; }}
            QSplitter::handle {{ background: {t['page']}; }}
            QScrollBar:vertical {{ background: {t['card']}; width: 10px; margin: 0; }}
            QScrollBar:horizontal {{ background: {t['card']}; height: 10px; margin: 0; }}
            QScrollBar::handle {{ background: {t['axis']}; border-radius: 4px; min-height: 24px; min-width: 24px; }}
            QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
            QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
        """)

    # -- events -------------------------------------------------------------
    def _metric_changed(self, label: str) -> None:
        self.traffic.metric_key = METRICS[label]
        self.traffic.redraw()

    def on_connection(self, ok: bool) -> None:
        if ok:
            self.conn.setText("● Connected to engine")
            self.conn.setStyleSheet(f"color: {STATUS['good']}; font-weight: 600;")
        else:
            self.conn.setText(f"○ Waiting for engine at {self.client.ws_url}")
            self.conn.setStyleSheet(f"color: {STATUS['critical']}; font-weight: 600;")

    def on_event(self, e: dict) -> None:
        kind = e.get("type")
        if kind == "alert":
            self._add_alert(e)
        elif kind == "alert_update":
            self.alert_table.update_count(e)
            self._bump_attack(e.get("id"), e.get("count"))
        elif kind == "history":
            for ev in e.get("events", []):
                if ev.get("type") == "alert":
                    self._add_alert(ev)
        elif kind == "stats":
            self.traffic.add(e)
            self.tile_pps.set(fmt_num(e.get("packets_per_s", 0)))
            self.tile_fps.set(fmt_num(e.get("flows_per_s", 0)))
            self.tile_flows.set(fmt_num(e.get("totals", {}).get("flows", 0)))
            self._health["Scoring queue"] = f"{e.get('queue', 0)} flows waiting"
            self._health["Flows dropped"] = str(e.get("flows_dropped", 0))
            self._render_status()
        elif kind == "blocks":
            self.blocks.set_blocks(e.get("blocks", []))
            self.tile_blocked.set(str(len(e.get("blocks", []))))
        elif kind == "status":
            self._status = e
            self._render_status()
            if "live" not in e.get("mode", "") and self.metric_box.currentIndex() == 0:
                self.metric_box.setCurrentText("Flows scored per second")  # replay has no packets
        elif kind == "replay":
            seg = e.get("segment")
            self.segment.setText("" if seg in (None, "finished") else f"Replay: {seg}   ")

    def _add_alert(self, a: dict) -> None:
        if a["id"] in self._alert_attack:
            return
        self.alert_table.add(a)
        self.total_alerts += 1
        self.tile_alerts.set(str(self.total_alerts))
        self._alert_attack[a["id"]] = a["attack"]
        self._alert_counts[a["id"]] = 0
        self._bump_attack(a["id"], a.get("count", 1))

    def _bump_attack(self, alert_id, count) -> None:
        attack = self._alert_attack.get(alert_id)
        if attack is None or count is None:
            return
        delta = count - self._alert_counts.get(alert_id, 0)
        self._alert_counts[alert_id] = count
        self.attacks.counts[attack] += delta
        self.attacks.redraw()

    def _render_status(self) -> None:
        while self.status_grid.count():
            w = self.status_grid.takeAt(0).widget()
            if w:
                w.deleteLater()
        s = self._status
        rows = []
        if s:
            rows += [("Mode", s.get("mode", "")),
                     ("Firewall", f"{s.get('firewall_backend')} ({'on' if s.get('response_enabled') else 'off'})")]
            for name, text in s.get("models", {}).items():
                rows.append((f"Model: {name}", text))
            th = s.get("thresholds", {})
            rows.append(("Block threshold", f"confidence ≥ {th.get('supervised_high')}, "
                                            f"block {th.get('block_seconds')} s"))
        rows += list(self._health.items())
        for r, (k, v) in enumerate(rows):
            key = QLabel(k)
            key.setObjectName("muted")
            val = QLabel(v)
            val.setWordWrap(True)
            self.status_grid.addWidget(key, r, 0, Qt.AlignmentFlag.AlignTop)
            self.status_grid.addWidget(val, r, 1)


def run(ws_url: str = "ws://127.0.0.1:8000/ws", theme: str = "auto", screenshot: str | None = None,
        screenshot_after: float = 5.0, quit_after_screenshot: bool = False) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Netra")
    window = MainWindow(ws_url, theme)
    window.show()
    if screenshot:
        def grab():
            window.grab().save(screenshot)
            print(f"screenshot saved to {screenshot}", flush=True)
            if quit_after_screenshot:
                app.quit()
        QTimer.singleShot(int(screenshot_after * 1000), grab)
    return app.exec()


if __name__ == "__main__":
    sys.exit(run(*(sys.argv[1:2] or [])))
