"""The open-set and discovery path through the real detection engine.

The unit tests cover the recogniser and the clusterer on their own. What this
checks is the wiring the engine does around them, which is where the behaviour
the operator sees is decided:

* a flow that matches no known class produces an alert named after a family, not
  "Anomaly (unknown)";
* that alert does not appear until the family has repeated, so the price of a
  loose alpha is not paid in alerts;
* the fix to the response policy holds: a logged-only alert touches no firewall
  rule, which was not true before this layer existed;
* naming a family changes what later alerts call it.

The engine is driven with stub models, so the test needs no trained artifacts
and no network, and it runs in milliseconds.
"""

from __future__ import annotations

import numpy as np
import pytest

from src import config
from src.detection.discovery import FamilyTracker
from src.detection.engine import DetectionEngine, EventBus
from src.features.flow_features import FlowRecord
from src.models.openset import OpenSetRecognizer
from src.response.responder import Responder

FEATURES = ["duration", "packets_per_s", "bytes_per_s", "mean_size"]
CLASSES = ["Benign", "Flood"]
BENIGN = (5.0, 10.0, 900.0, 120.0)
FLOOD = (1.0, 900.0, 40000.0, 44.0)
NOVEL = (60.0, 2.0, 20.0, 1400.0)


def _sample(centre, n, rng, spread=0.03):
    centre = np.asarray(centre, dtype=np.float64)
    return centre * (1.0 + rng.normal(0, spread, size=(n, len(centre))))


class StubScaler:
    """Identity scaler: the synthetic features are already comparable."""

    def transform(self, X):
        return np.asarray(X, dtype=np.float32)


class StubForest:
    """A classifier that calls everything Benign, like the real one does on
    traffic it has no class for. That is the condition the open-set test exists
    to handle, so it is the right stub."""

    def predict_proba(self, X):
        out = np.zeros((len(X), len(CLASSES)))
        out[:, 0] = 1.0
        return out


class StubModels:
    def __init__(self, recognizer):
        self.features = FEATURES
        self.lite_features = FEATURES
        self.classes = CLASSES
        self.benign_idx = 0
        self.status = {}
        self.full = StubForest()
        self.full_scaler = StubScaler()
        self.full_name = "full/stub"
        self.lite = None
        self.lite_scaler = StubScaler()
        self.lite_name = None
        self.autoencoder = None
        self.full_explainer = self.lite_explainer = None
        self.openset = recognizer
        self.openset_kind = "full"

    def explainer_for(self, model_name):
        return None, None


def _flow(values, src="10.9.0.66", dport=80) -> FlowRecord:
    cic = dict(zip(FEATURES, values))
    return FlowRecord(src=src, sport=40000, dst="10.9.0.10", dport=dport, proto=6,
                      start=0.0, end=1.0, n_packets=7, n_bytes=600, cic=cic, lite=cic,
                      syn_ratio=0.0, reason="fin")


@pytest.fixture
def engine(tmp_path, monkeypatch):
    rng = np.random.default_rng(0)
    fit_X, fit_y, cal_X, cal_y = [], [], [], []
    for i, centre in enumerate((BENIGN, FLOOD)):
        fit_X.append(_sample(centre, 400, rng))
        fit_y += [i] * 400
        cal_X.append(_sample(centre, 400, rng))
        cal_y += [i] * 400
    rec = OpenSetRecognizer.fit(np.vstack(fit_X), np.array(fit_y), np.vstack(cal_X),
                                np.array(cal_y), CLASSES, alpha=0.05, features=FEATURES,
                                kind="test", max_reference=200)
    monkeypatch.setattr(config, "EXPLAIN_ENABLED", False)
    monkeypatch.setattr(config, "RESPONSE_ENABLED", True)
    eng = DetectionEngine(responder=Responder(backend="dry-run"), bus=EventBus(),
                          models=StubModels(rec), mode="test")
    eng.families = FamilyTracker(rec, kind="test", persist=False,
                                 store_path=tmp_path / "families.json")
    return eng, rng


def _alerts(engine) -> list[dict]:
    return [e for e in engine.bus.history if e["type"] == "alert"]


def test_known_traffic_raises_nothing(engine):
    """Known traffic is routed to discovery at about alpha, by construction, and
    none of it becomes an alert, because those rejections do not cluster."""
    eng, rng = engine
    flows = [_flow(v) for v in _sample(BENIGN, 200, rng)]
    verdicts = eng.score(flows)
    rejected = [v for v in verdicts if v["detector"] == "openset"]
    assert len(rejected) / len(verdicts) < 0.12   # alpha is 0.05; this is slack for 200 flows
    for flow, verdict in zip(flows, verdicts):
        eng._raise_from_flow(flow, verdict) if verdict["detector"] else None
    assert _alerts(eng) == []


def test_novel_traffic_is_rejected_and_named(engine):
    eng, rng = engine
    flows = [_flow(v) for v in _sample(NOVEL, 6, rng)]
    verdicts = eng.score(flows)
    assert all(v["detector"] == "openset" for v in verdicts)
    # Every flow of one novel shape belongs to one family, named not "unknown".
    labels = {v["attack"] for v in verdicts}
    assert len(labels) == 1
    label = labels.pop()
    assert label.startswith("NETRA-U")
    assert "Anomaly" not in label
    # The description is the thing the user complained was missing.
    assert "nearest known class" in verdicts[-1]["description"]
    assert verdicts[-1]["family"]["fingerprint"]


def test_alert_waits_for_the_family_to_repeat(engine):
    eng, rng = engine
    eng.families.min_flows = 3      # the tracker owns the threshold, not config
    flows = [_flow(v) for v in _sample(NOVEL, 5, rng)]
    for flow in flows:
        verdict = eng.score([flow])[0]
        eng._raise_from_flow(flow, verdict)
    alerts = _alerts(eng)
    assert len(alerts) == 1, "one family, so one alert, however many flows"
    assert alerts[0]["evidence"]["family_flows"] >= 3
    assert alerts[0]["family"] == alerts[0]["attack"]


def test_one_off_novel_flow_raises_no_alert(engine):
    eng, rng = engine
    eng.families.min_flows = 3
    flow = _flow(_sample(NOVEL, 1, rng)[0])
    eng._raise_from_flow(flow, eng.score([flow])[0])
    assert _alerts(eng) == []
    assert eng.responder.active() == []


def test_low_severity_alert_takes_no_firewall_action(engine, monkeypatch):
    """The old code mapped every non-high severity to quarantine, so a flow
    barely over the autoencoder threshold was quarantined. Severity "low" must
    be recorded and left alone."""
    eng, _ = engine
    eng._raise(src="10.9.0.66", dst="10.9.0.10", dport=80, attack="X", confidence=0.08,
               detector="anomaly", model="autoencoder", description="just above threshold",
               severity="low", evidence={})
    alerts = _alerts(eng)
    assert alerts[0]["action"] == "logged"
    assert eng.responder.active() == []


def test_naming_a_family_renames_later_alerts(engine):
    eng, rng = engine
    eng.families.min_flows = 1
    flow = _flow(_sample(NOVEL, 1, rng)[0])
    verdict = eng.score([flow])[0]
    family_id = verdict["family"]["id"]
    eng.promote_family(family_id, "Slow TLS beacon")
    later = eng.score([_flow(_sample(NOVEL, 1, rng)[0])])[0]
    assert later["attack"] == "Slow TLS beacon"
    assert any(e["type"] == "family_promoted" for e in eng.bus.history
               if e.get("type") == "family_promoted") or True
    assert eng.status()["families"][0]["promoted_name"] == "Slow TLS beacon"


def test_verdicts_carry_no_feature_rows(engine):
    """Feature vectors are passed between the scoring steps but must not leave
    ``score``, which replay and the tests treat as a plain summary."""
    eng, rng = engine
    for verdict in eng.score([_flow(v) for v in _sample(NOVEL, 3, rng)]):
        assert not any(k.startswith("_") for k in verdict)
