"""Replay CIC-IDS2017 flows through the detection engine on a scripted timeline.

Only rows from the held-out test split are used, so the models have never seen
them. Each row keeps its original source and destination addresses from the
dataset. Replay exercises the ML detectors, alert aggregation and the
responder; signature rules need packets, so they are demonstrated in the live
Docker lab (or with ``--pcap``).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import numpy as np
import pandas as pd

from src import config
from src.data.preprocess import CLASS_COLUMN, load_feature_spec, load_split
from src.features.flow_features import FlowRecord

log = logging.getLogger(__name__)


@dataclass
class Segment:
    attack: str | None   # class to inject, or None for benign-only background
    seconds: float
    attack_rate: float = 0.0  # attack flows per second during this segment


DEFAULT_SCRIPT = [
    Segment(None, 8),
    Segment("PortScan", 8, 25),
    Segment(None, 6),
    Segment("DoS", 10, 40),
    Segment(None, 6),
    Segment("DoS-Slow", 8, 15),
    Segment(None, 6),
    Segment("BruteForce", 8, 15),
    Segment(None, 6),
    Segment("DDoS", 8, 40),
    Segment(None, 6),
    Segment("WebAttack", 8, 10),
    Segment("Bot", 8, 8),
    Segment(None, 8),
]


def row_to_flow(row: pd.Series, features: list[str], lite: list[str], now: float) -> FlowRecord:
    cic = {f: float(row[f]) for f in features}
    duration = cic.get("Flow Duration", 0.0) / 1e6
    return FlowRecord(
        src=str(row["Source IP"]), sport=int(row["Source Port"]) if pd.notna(row["Source Port"]) else 0,
        dst=str(row["Destination IP"]), dport=int(row["Destination Port"]) if pd.notna(row["Destination Port"]) else 0,
        proto=int(cic.get("Protocol", 6)), start=now - duration, end=now,
        n_packets=int(cic.get("Total Fwd Packets", 0) + cic.get("Total Backward Packets", 0)),
        n_bytes=int(cic.get("Total Length of Fwd Packets", 0) + cic.get("Total Length of Bwd Packets", 0)),
        cic=cic, lite={f: float(row[f]) for f in lite}, syn_ratio=0.0, reason="replay")


class DatasetReplay:
    def __init__(self, engine, script: list[Segment] | None = None, speed: float = 1.0,
                 background_rate: float = 30.0, seed: int = config.RANDOM_STATE):
        self.engine = engine
        self.script = script or DEFAULT_SCRIPT
        self.speed = max(speed, 0.01)
        self.background_rate = background_rate
        self.rng = np.random.default_rng(seed)
        spec = load_feature_spec()
        self.features, self.lite = spec["features"], spec["lite_features"]
        df = load_split("test")
        self.pools = {c: g.reset_index(drop=True) for c, g in df.groupby(CLASS_COLUMN)}
        self.sent = {"benign": 0, "attack": 0}

    def _emit(self, cls: str, n: int) -> None:
        pool = self.pools.get(cls)
        if pool is None or n <= 0:
            return
        now = time.time()
        for i in self.rng.integers(0, len(pool), n):
            self.engine.on_flow(row_to_flow(pool.iloc[int(i)], self.features, self.lite, now))
        self.sent["benign" if cls == config.BENIGN_LABEL else "attack"] += n

    def run(self, loops: int = 1, on_segment=None) -> None:
        tick = 0.25
        for _ in range(loops):
            for seg in self.script:
                label = seg.attack or "background"
                log.info("replay segment: %s for %.0f s", label, seg.seconds / self.speed)
                if on_segment:
                    on_segment(seg)
                self.engine.bus.publish({"type": "replay", "segment": label, "time": time.time()})
                end = time.time() + seg.seconds / self.speed
                carry_b = carry_a = 0.0
                while time.time() < end:
                    carry_b += self.background_rate * tick * self.speed
                    carry_a += seg.attack_rate * tick * self.speed
                    nb, na = int(carry_b), int(carry_a)
                    carry_b -= nb
                    carry_a -= na
                    self._emit(config.BENIGN_LABEL, nb)
                    if seg.attack:
                        self._emit(seg.attack, na)
                    time.sleep(tick)
        self.engine.bus.publish({"type": "replay", "segment": "finished", "time": time.time()})
