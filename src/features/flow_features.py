"""Turn packets into bidirectional flows and CICFlowMeter-compatible feature vectors.

Why a custom extractor: the ``cicflowmeter`` release usable on Python 3.11
(0.2.0) only emits a flow after 240 seconds of inactivity and ignores FIN/RST
termination, which is far too slow for live detection. This module follows the
CICFlowMeter definitions (bidirectional flows keyed by the 5-tuple, the first
packet's sender is the forward direction, lengths are transport payload bytes,
durations and inter-arrival times are in microseconds) but closes flows on
FIN/RST or after a short idle timeout. ``cicflowmeter`` is still used for
offline PCAP conversion (see ``cicflowmeter_pcap_to_frame``).

Every flow yields:
  * ``cic``:  the CIC-IDS2017 feature names used by the full model,
  * ``lite``: the lite features (per-flow values plus per-source 60 s aggregates),
  * ``syn_ratio``: SYN packets / all packets (used by signatures, not by models).

``align_to_schema`` reorders any feature mapping to the exact training order,
filling missing features with a safe default.
"""

from __future__ import annotations

import math
import subprocess
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

import numpy as np
import pandas as pd

from src import config
from src.data.preprocess import lite_flow_features

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

ACTIVITY_TIMEOUT_S = 5.0     # CICFlowMeter default gap that separates active periods
MAX_FLOW_LIFETIME_S = 120.0  # CICFlowMeter flow timeout; long flows are emitted and restarted
MAX_FLOWS = 100_000          # bound on tracked flows (floods create one flow per packet)
CLOSED_GRACE_S = 2.0         # after FIN/RST, ignore trailing non-SYN packets of the same 5-tuple


@dataclass(slots=True)
class PacketInfo:
    """The fields of one IPv4 TCP/UDP packet that feature extraction needs."""
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: int                # 6 = TCP, 17 = UDP
    flags: int = 0            # TCP flag bitmask, 0 for UDP
    payload_len: int = 0      # transport payload bytes
    header_len: int = 0       # transport header bytes
    window: int = 0           # TCP window
    payload_head: bytes = b""  # first bytes of payload (used by signature rules)
    wire_len: int = 0         # full IP packet length, for traffic-rate statistics


def parse_packet(pkt) -> PacketInfo | None:
    """Extract a ``PacketInfo`` from a scapy packet, or None if not IPv4 TCP/UDP."""
    from scapy.layers.inet import IP, TCP, UDP

    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        t = pkt[TCP]
        header = int(t.dataofs or 5) * 4
        payload = bytes(t.payload)
        return PacketInfo(float(pkt.time), ip.src, ip.dst, int(t.sport), int(t.dport), 6, int(t.flags),
                          len(payload), header, int(t.window), payload[:64], int(ip.len or len(ip)))
    if UDP in pkt:
        u = pkt[UDP]
        payload = bytes(u.payload)
        return PacketInfo(float(pkt.time), ip.src, ip.dst, int(u.sport), int(u.dport), 17, 0,
                          len(payload), 8, 0, payload[:64], int(ip.len or len(ip)))
    return None


def flow_key(p: PacketInfo) -> tuple:
    """Direction-independent key: both directions of a conversation map to the same flow."""
    a, b = (p.src, p.sport), (p.dst, p.dport)
    return (p.proto, *min(a, b), *max(a, b))


def _stats(values) -> tuple[float, float, float, float]:
    """mean, population std, max, min (zeros for an empty list), as CICFlowMeter reports them."""
    if len(values) == 0:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.asarray(values, dtype=np.float64)
    return float(arr.mean()), float(arr.std()), float(arr.max()), float(arr.min())


@dataclass
class Flow:
    src: str
    sport: int
    dst: str
    dport: int
    proto: int
    start: float
    last: float = 0.0
    times: list = field(default_factory=list)
    fwd_times: list = field(default_factory=list)
    bwd_times: list = field(default_factory=list)
    fwd_lens: list = field(default_factory=list)
    bwd_lens: list = field(default_factory=list)
    fwd_header: int = 0
    bwd_header: int = 0
    flag_counts: dict = field(default_factory=lambda: defaultdict(int))
    fwd_psh: int = 0
    fwd_urg: int = 0
    syn_packets: int = 0
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    act_data_fwd: int = 0
    min_seg_fwd: int = 0
    fin_fwd: bool = False
    fin_bwd: bool = False
    rst: bool = False

    def add(self, p: PacketInfo) -> None:
        forward = (p.src, p.sport) == (self.src, self.sport)
        self.last = p.ts
        self.times.append(p.ts)
        if forward:
            self.fwd_times.append(p.ts)
            self.fwd_lens.append(p.payload_len)
            self.fwd_header += p.header_len
            self.min_seg_fwd = p.header_len if len(self.fwd_lens) == 1 else min(self.min_seg_fwd, p.header_len)
            if p.payload_len > 0:
                self.act_data_fwd += 1
            if p.proto == 6 and self.init_win_fwd < 0:
                self.init_win_fwd = p.window
            if p.flags & PSH:
                self.fwd_psh += 1
            if p.flags & URG:
                self.fwd_urg += 1
        else:
            self.bwd_times.append(p.ts)
            self.bwd_lens.append(p.payload_len)
            self.bwd_header += p.header_len
            if p.proto == 6 and self.init_win_bwd < 0:
                self.init_win_bwd = p.window
        for bit, name in ((FIN, "FIN"), (SYN, "SYN"), (RST, "RST"), (PSH, "PSH"), (ACK, "ACK"),
                          (URG, "URG"), (CWR, "CWE"), (ECE, "ECE")):
            if p.flags & bit:
                self.flag_counts[name] += 1
        if p.flags & SYN:
            self.syn_packets += 1
        if p.flags & FIN:
            if forward:
                self.fin_fwd = True
            else:
                self.fin_bwd = True
        if p.flags & RST:
            self.rst = True

    @property
    def finished(self) -> bool:
        return self.rst or (self.fin_fwd and self.fin_bwd)

    @property
    def n_packets(self) -> int:
        return len(self.times)

    # -- features -----------------------------------------------------------
    def cic_features(self) -> dict[str, float]:
        us = 1e6
        duration_us = (self.last - self.start) * us
        duration_s = max(self.last - self.start, 0.0)
        n_fwd, n_bwd = len(self.fwd_lens), len(self.bwd_lens)
        tot_fwd, tot_bwd = float(sum(self.fwd_lens)), float(sum(self.bwd_lens))
        all_lens = self.fwd_lens + self.bwd_lens
        f_mean, f_std, f_max, f_min = _stats(self.fwd_lens)
        b_mean, b_std, b_max, b_min = _stats(self.bwd_lens)
        p_mean, p_std, p_max, p_min = _stats(all_lens)
        iat = np.diff(self.times) * us
        fwd_iat = np.diff(self.fwd_times) * us
        bwd_iat = np.diff(self.bwd_times) * us
        i_mean, i_std, i_max, i_min = _stats(iat)
        fi_mean, fi_std, fi_max, fi_min = _stats(fwd_iat)
        bi_mean, bi_std, bi_max, bi_min = _stats(bwd_iat)
        active, idle = self._active_idle()
        a_mean, a_std, a_max, a_min = _stats(active)
        d_mean, d_std, d_max, d_min = _stats(idle)
        rate = (lambda x: x / duration_s) if duration_s > 0 else (lambda x: 0.0)
        # CIC-IDS2017 flag columns behave as presence indicators (0 or 1); mirror that.
        flag = lambda name: float(self.flag_counts.get(name, 0) > 0)  # noqa: E731
        n = self.n_packets

        return {
            "Protocol": float(self.proto),
            "Flow Duration": duration_us,
            "Total Fwd Packets": float(n_fwd),
            "Total Backward Packets": float(n_bwd),
            "Total Length of Fwd Packets": tot_fwd,
            "Total Length of Bwd Packets": tot_bwd,
            "Fwd Packet Length Max": f_max, "Fwd Packet Length Min": f_min,
            "Fwd Packet Length Mean": f_mean, "Fwd Packet Length Std": f_std,
            "Bwd Packet Length Max": b_max, "Bwd Packet Length Min": b_min,
            "Bwd Packet Length Mean": b_mean, "Bwd Packet Length Std": b_std,
            "Flow Bytes/s": rate(tot_fwd + tot_bwd),
            "Flow Packets/s": rate(n),
            "Flow IAT Mean": i_mean, "Flow IAT Std": i_std, "Flow IAT Max": i_max, "Flow IAT Min": i_min,
            "Fwd IAT Total": float(fwd_iat.sum()) if len(fwd_iat) else 0.0,
            "Fwd IAT Mean": fi_mean, "Fwd IAT Std": fi_std, "Fwd IAT Max": fi_max, "Fwd IAT Min": fi_min,
            "Bwd IAT Total": float(bwd_iat.sum()) if len(bwd_iat) else 0.0,
            "Bwd IAT Mean": bi_mean, "Bwd IAT Std": bi_std, "Bwd IAT Max": bi_max, "Bwd IAT Min": bi_min,
            "Fwd PSH Flags": float(self.fwd_psh > 0),
            "Bwd PSH Flags": 0.0,
            "Fwd URG Flags": float(self.fwd_urg > 0),
            "Bwd URG Flags": 0.0,
            "Fwd Header Length": float(self.fwd_header),
            "Bwd Header Length": float(self.bwd_header),
            "Fwd Packets/s": rate(n_fwd),
            "Bwd Packets/s": rate(n_bwd),
            "Min Packet Length": p_min, "Max Packet Length": p_max,
            "Packet Length Mean": p_mean, "Packet Length Std": p_std, "Packet Length Variance": p_std ** 2,
            "FIN Flag Count": flag("FIN"), "SYN Flag Count": flag("SYN"), "RST Flag Count": flag("RST"),
            "PSH Flag Count": flag("PSH"), "ACK Flag Count": flag("ACK"), "URG Flag Count": flag("URG"),
            "CWE Flag Count": flag("CWE"), "ECE Flag Count": flag("ECE"),
            "Down/Up Ratio": float(math.floor(n_bwd / n_fwd)) if n_fwd else 0.0,
            "Average Packet Size": (tot_fwd + tot_bwd) / n if n else 0.0,
            "Avg Fwd Segment Size": f_mean,
            "Avg Bwd Segment Size": b_mean,
            "Subflow Fwd Packets": float(n_fwd), "Subflow Fwd Bytes": tot_fwd,
            "Subflow Bwd Packets": float(n_bwd), "Subflow Bwd Bytes": tot_bwd,
            "Init_Win_bytes_forward": float(self.init_win_fwd),
            "Init_Win_bytes_backward": float(self.init_win_bwd),
            "act_data_pkt_fwd": float(self.act_data_fwd),
            "min_seg_size_forward": float(self.min_seg_fwd),
            "Active Mean": a_mean, "Active Std": a_std, "Active Max": a_max, "Active Min": a_min,
            "Idle Mean": d_mean, "Idle Std": d_std, "Idle Max": d_max, "Idle Min": d_min,
        }

    def _active_idle(self) -> tuple[list[float], list[float]]:
        """Split the flow into active periods separated by gaps longer than ACTIVITY_TIMEOUT_S."""
        if len(self.times) < 2:
            return [], []
        active, idle = [], []
        period_start = prev = self.times[0]
        for t in self.times[1:]:
            if t - prev > ACTIVITY_TIMEOUT_S:
                if prev > period_start:
                    active.append((prev - period_start) * 1e6)
                idle.append((t - prev) * 1e6)
                period_start = t
            prev = t
        if prev > period_start and idle:
            active.append((prev - period_start) * 1e6)
        return active, idle

    def lite_flow(self) -> dict[str, float]:
        values = lite_flow_features(max(self.last - self.start, 0.0), self.n_packets,
                                    sum(self.fwd_lens) + sum(self.bwd_lens))
        return {k: float(v) for k, v in values.items()}


@dataclass
class FlowRecord:
    """A completed flow with everything the detection engine needs."""
    src: str
    sport: int
    dst: str
    dport: int
    proto: int
    start: float
    end: float
    n_packets: int
    n_bytes: int
    cic: dict
    lite: dict
    syn_ratio: float
    reason: str  # "fin", "rst", "idle", "lifetime", "flush"


class SourceWindow:
    """Distinct destination ports and hosts contacted by each source over a sliding window."""

    def __init__(self, window_s: float = config.LITE_WINDOW_S):
        self.window_s = window_s
        self.events: dict[str, deque] = defaultdict(deque)

    def record(self, ts: float, src: str, dst: str, dport: int) -> None:
        self.events[src].append((ts, dst, dport))

    def counts(self, src: str, now: float) -> tuple[int, int]:
        q = self.events.get(src)
        if not q:
            return 0, 0
        while q and q[0][0] < now - self.window_s:
            q.popleft()
        return len({e[2] for e in q}), len({e[1] for e in q})

    def prune(self, now: float) -> None:
        for src in list(self.events):
            q = self.events[src]
            while q and q[0][0] < now - self.window_s:
                q.popleft()
            if not q:
                del self.events[src]


class FlowTable:
    """Assemble packets into flows and emit ``FlowRecord`` objects when flows end."""

    def __init__(self, idle_timeout_s: float = config.FLOW_TIMEOUT_S,
                 max_lifetime_s: float = MAX_FLOW_LIFETIME_S, max_flows: int = MAX_FLOWS):
        self.idle_timeout_s = idle_timeout_s
        self.max_lifetime_s = max_lifetime_s
        self.max_flows = max_flows
        self.flows: dict[tuple, Flow] = {}
        self.closed: dict[tuple, float] = {}  # recently finished flow keys -> close time
        self.sources = SourceWindow()

    def add(self, p: PacketInfo) -> list[FlowRecord]:
        key = flow_key(p)
        flow = self.flows.get(key)
        if flow is None and key in self.closed:
            # The last ACK after a FIN exchange, or a repeated RST, belongs to the flow that
            # just ended. Only a new SYN may reopen the 5-tuple during the grace period.
            if p.ts - self.closed[key] < CLOSED_GRACE_S and not (p.flags & SYN):
                return []
            del self.closed[key]
        if flow is None:
            flow = Flow(p.src, p.sport, p.dst, p.dport, p.proto, start=p.ts)
            self.flows[key] = flow
            self.sources.record(p.ts, p.src, p.dst, p.dport)
        flow.add(p)
        done = []
        if flow.finished:
            done.append(self._emit(key, "rst" if flow.rst else "fin"))
            self.closed[key] = p.ts
        if len(self.flows) > self.max_flows:
            done.extend(self._evict_oldest(len(self.flows) - self.max_flows))
        return done

    def expire(self, now: float) -> list[FlowRecord]:
        done = []
        for key, flow in list(self.flows.items()):
            if now - flow.last > self.idle_timeout_s:
                done.append(self._emit(key, "idle"))
            elif now - flow.start > self.max_lifetime_s:
                done.append(self._emit(key, "lifetime"))
        self.sources.prune(now)
        for key, t in list(self.closed.items()):
            if now - t > CLOSED_GRACE_S:
                del self.closed[key]
        return done

    def flush(self) -> list[FlowRecord]:
        return [self._emit(key, "flush") for key in list(self.flows)]

    def _evict_oldest(self, n: int) -> list[FlowRecord]:
        oldest = sorted(self.flows.items(), key=lambda kv: kv[1].last)[:n]
        return [self._emit(key, "idle") for key, _ in oldest]

    def _emit(self, key: tuple, reason: str) -> FlowRecord:
        flow = self.flows.pop(key)
        lite = flow.lite_flow()
        ports, hosts = self.sources.counts(flow.src, flow.last)
        lite["src_unique_dst_ports"] = float(max(ports, 1))
        lite["src_unique_dsts"] = float(max(hosts, 1))
        n = flow.n_packets
        return FlowRecord(
            src=flow.src, sport=flow.sport, dst=flow.dst, dport=flow.dport, proto=flow.proto,
            start=flow.start, end=flow.last, n_packets=n,
            n_bytes=int(sum(flow.fwd_lens) + sum(flow.bwd_lens)),
            cic=flow.cic_features(), lite=lite,
            syn_ratio=flow.syn_packets / n if n else 0.0, reason=reason)


def flows_from_packets(packets: Iterable[PacketInfo], **table_kwargs) -> list[FlowRecord]:
    """Offline helper: run a packet sequence through a FlowTable and return every flow."""
    table = FlowTable(**table_kwargs)
    out: list[FlowRecord] = []
    last = 0.0
    for p in packets:
        out.extend(table.add(p))
        if p.ts - last >= 1.0:
            out.extend(table.expire(p.ts))
            last = p.ts
    out.extend(table.flush())
    return out


# ---------------------------------------------------------------------------
# Schema alignment
# ---------------------------------------------------------------------------
def align_to_schema(features: Mapping[str, float], schema: list[str], default: float = 0.0) -> np.ndarray:
    """Vector in exactly the training column order. Missing or non-finite values become ``default``."""
    out = np.empty(len(schema), dtype=np.float64)
    for i, name in enumerate(schema):
        v = features.get(name, default)
        try:
            v = float(v)
        except (TypeError, ValueError):
            v = default
        out[i] = v if math.isfinite(v) else default
    return out


def align_frame(df: pd.DataFrame, schema: list[str], default: float = 0.0) -> pd.DataFrame:
    """DataFrame version of ``align_to_schema``: reindex columns, fill gaps, drop extras."""
    out = df.reindex(columns=schema).apply(pd.to_numeric, errors="coerce")
    return out.replace([np.inf, -np.inf], np.nan).fillna(default)


# ---------------------------------------------------------------------------
# cicflowmeter (offline PCAP conversion)
# ---------------------------------------------------------------------------
CICFLOWMETER_TO_CIC = {
    "protocol": "Protocol", "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets", "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets", "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max", "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean", "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max", "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean", "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s", "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean", "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max", "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total", "fwd_iat_mean": "Fwd IAT Mean", "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max", "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total", "bwd_iat_mean": "Bwd IAT Mean", "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max", "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags", "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags", "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length", "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s", "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length", "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean", "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count", "syn_flag_cnt": "SYN Flag Count", "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count", "ack_flag_cnt": "ACK Flag Count", "urg_flag_cnt": "URG Flag Count",
    "ece_flag_cnt": "ECE Flag Count", "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "init_fwd_win_byts": "Init_Win_bytes_forward", "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd", "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean", "active_std": "Active Std", "active_max": "Active Max",
    "active_min": "Active Min", "idle_mean": "Idle Mean", "idle_std": "Idle Std",
    "idle_max": "Idle Max", "idle_min": "Idle Min",
    "src_ip": "Source IP", "dst_ip": "Destination IP", "src_port": "Source Port",
    "dst_port": "Destination Port", "timestamp": "Timestamp",
}


def cicflowmeter_pcap_to_frame(pcap: Path, csv_out: Path | None = None) -> pd.DataFrame:
    """Convert a PCAP with the ``cicflowmeter`` CLI and rename its columns to CIC-IDS2017 names."""
    csv_out = csv_out or Path(pcap).with_suffix(".flows.csv")
    subprocess.run(["cicflowmeter", "-f", str(pcap), "-c", str(csv_out)], check=True)
    df = pd.read_csv(csv_out).rename(columns=CICFLOWMETER_TO_CIC)
    return df
