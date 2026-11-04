"""The desktop app's unknown-families panel, driven offscreen.

``scripts/gui_selftest.py`` exercises the whole app against the Docker lab and
needs the lab running. This covers only the parts the open-set layer added, with
no engine and no network: that family events reach the table, that a named
family shows its name, that an alert from the open-set detector is labelled as
one, and that the empty state says so. Qt runs on the offscreen platform, so
this needs no display.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="the desktop app is optional for the detection engine")

from PySide6.QtWidgets import QApplication  # noqa: E402

from src.dashboard.app import MainWindow  # noqa: E402

FAMILIES = [
    {"id": "NETRA-U001", "label": "NETRA-U001", "promoted_name": None, "flows": 47,
     "alertable": True, "best_p": 0.004, "n_sources": 3,
     "nearest_class": "DoS-Slow", "nearest_p": 0.004,
     "fingerprint": [{"feature": "Flow IAT Mean", "value": 10500000, "deviation": 12.4,
                      "basis": "distance from benign mean"}],
     "description": "NETRA-U001: 47 unrecognised flows from 3 sources."},
    {"id": "NETRA-U002", "label": "Slowloris variant", "promoted_name": "Slowloris variant",
     "flows": 31, "alertable": True, "best_p": 0.0, "n_sources": 1,
     "nearest_class": None, "nearest_p": 0.0, "fingerprint": [],
     "description": "Slowloris variant: 31 unrecognised flows from 1 source."},
]


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    # A port nothing listens on: the client retries in the background and the
    # window stays in its disconnected state, which is all this test needs.
    win = MainWindow("ws://127.0.0.1:59999/ws", theme="light")
    yield win
    win.close()


def test_families_reach_the_table(window):
    window.on_event({"type": "families", "families": FAMILIES})
    assert window.families.rowCount() == 2
    assert window.families.item(0, 0).text() == "NETRA-U001"
    assert window.families.item(0, 3).text().startswith("DoS-Slow")
    assert "Flow IAT Mean" in window.families.item(0, 4).text()
    assert "2 discovered, 1 named" in window.families_hint.text()


def test_named_family_shows_its_name(window):
    window.on_event({"type": "families", "families": FAMILIES})
    assert window.families.item(1, 0).text() == "Slowloris variant"
    assert window.families.item(1, 3).text() == "nothing close"


def test_status_event_carries_families(window):
    window.on_event({"type": "status", "mode": "test", "models": {}, "classes": ["Benign"],
                     "firewall_backend": "dry-run", "response_enabled": True,
                     "feature_importance": [], "families": FAMILIES, "thresholds": {}})
    assert window.families.rowCount() == 2


def test_open_set_alert_is_labelled_as_one(window):
    window.on_event({"type": "alert", "id": 1, "time": 0.0, "src": "10.0.0.5", "dst": "10.0.0.1",
                     "dport": 80, "attack": "NETRA-U001", "confidence": 0.996,
                     "detector": "openset", "model": "openset/full", "severity": "medium",
                     "description": "unrecognised", "evidence": {}, "explain": [], "count": 1,
                     "action": "quarantine", "family": "NETRA-U001"})
    assert window.alert_table.rowCount() == 1
    assert window.alert_table.item(0, 4).text() == "NETRA-U001"
    assert window.alert_table.item(0, 6).text() == "Open-set"


def test_empty_state_says_so(window):
    window.on_event({"type": "families", "families": []})
    assert "nothing unrecognised yet" in window.families_hint.text()
    assert window.families.rowCount() == 0
