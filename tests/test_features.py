"""Flow feature extraction and schema alignment tests."""

import numpy as np
import pandas as pd
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from src.features.flow_features import (
    FlowTable,
    align_frame,
    align_to_schema,
    flows_from_packets,
    parse_packet,
)

C, S = "10.0.0.2", "10.0.0.3"


def pkt(src, dst, sport, dport, flags, payload=b"", t=0.0, window=64240):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, window=window)
    if payload:
        p = p / Raw(payload)
    p = IP(bytes(p))  # build so lengths and offsets are filled in
    p.time = t
    return parse_packet(p)


def tcp_session():
    return [
        pkt(C, S, 40000, 80, "S", t=0.000),
        pkt(S, C, 80, 40000, "SA", t=0.001, window=65160),
        pkt(C, S, 40000, 80, "A", t=0.002),
        pkt(C, S, 40000, 80, "PA", b"GET / HTTP/1.1\r\n\r\n", t=0.003),
        pkt(S, C, 80, 40000, "PA", b"x" * 100, t=0.010),
        pkt(C, S, 40000, 80, "FA", t=0.020),
        pkt(S, C, 80, 40000, "FA", t=0.021),
    ]


def test_parse_packet_payload_and_header():
    p = pkt(C, S, 40000, 80, "PA", b"hello")
    assert (p.src, p.dst, p.sport, p.dport, p.proto) == (C, S, 40000, 80, 6)
    assert p.payload_len == 5 and p.header_len == 20
    assert parse_packet(IP() / UDP(sport=1, dport=53)).proto == 17


def test_bidirectional_flow_closes_on_fin():
    flows = flows_from_packets(tcp_session())
    assert len(flows) == 1
    f = flows[0]
    assert f.reason == "fin"
    assert (f.src, f.dst, f.dport) == (C, S, 80)  # initiator is the forward direction
    cic = f.cic
    assert cic["Total Fwd Packets"] == 4 and cic["Total Backward Packets"] == 3
    assert cic["Total Length of Fwd Packets"] == 18
    assert cic["Total Length of Bwd Packets"] == 100
    assert cic["Flow Duration"] == pytest.approx(21_000, rel=1e-6)  # microseconds
    assert cic["Init_Win_bytes_forward"] == 64240
    assert cic["Init_Win_bytes_backward"] == 65160
    assert cic["act_data_pkt_fwd"] == 1
    assert cic["SYN Flag Count"] == 1.0 and cic["FIN Flag Count"] == 1.0
    assert f.syn_ratio == pytest.approx(2 / 7)
    assert f.lite["mean_packet_size"] == pytest.approx(118 / 7)
    assert f.lite["packets_per_sec"] == pytest.approx(7 / 0.021)


def test_idle_flows_expire():
    table = FlowTable(idle_timeout_s=5.0)
    table.add(pkt(C, S, 40001, 22, "S", t=100.0))
    assert table.expire(103.0) == []
    done = table.expire(106.0)
    assert len(done) == 1 and done[0].reason == "idle"


def test_port_scan_raises_source_window_counts():
    packets = []
    for i, port in enumerate(range(1, 101)):
        packets.append(pkt(C, S, 50000, port, "S", t=i * 0.001))
        packets.append(pkt(S, C, port, 50000, "RA", t=i * 0.001 + 0.0005))
    flows = flows_from_packets(packets)
    assert len(flows) == 100
    assert max(f.lite["src_unique_dst_ports"] for f in flows) == 100
    assert all(f.lite["src_unique_dsts"] == 1 for f in flows)


def test_align_to_schema_orders_and_fills():
    schema = ["b", "a", "missing", "bad"]
    vec = align_to_schema({"a": 1.0, "b": 2.0, "extra": 9.0, "bad": float("inf")}, schema)
    assert vec.tolist() == [2.0, 1.0, 0.0, 0.0]


def test_live_vector_matches_training_schema():
    from src.data.preprocess import load_feature_spec

    spec = load_feature_spec()
    flow = flows_from_packets(tcp_session())[0]
    full = align_to_schema(flow.cic, spec["features"])
    lite = align_to_schema(flow.lite, spec["lite_features"])
    assert full.shape == (len(spec["features"]),) and np.isfinite(full).all()
    assert lite.shape == (len(spec["lite_features"]),)
    # Every training feature is produced by the live extractor (no silent zero-fill).
    assert set(spec["features"]) <= set(flow.cic)
    assert set(spec["lite_features"]) <= set(flow.lite)


def test_trailing_ack_after_fin_does_not_open_ghost_flow():
    packets = tcp_session() + [pkt(C, S, 40000, 80, "A", t=0.022)]  # final ACK after both FINs
    flows = flows_from_packets(packets)
    assert len(flows) == 1 and flows[0].reason == "fin"


def test_new_syn_reopens_same_tuple():
    packets = tcp_session() + [pkt(C, S, 40000, 80, "S", t=0.5), pkt(S, C, 80, 40000, "RA", t=0.501)]
    flows = flows_from_packets(packets)
    assert [f.reason for f in flows] == ["fin", "rst"]


def test_align_frame_reindexes():
    df = pd.DataFrame({"x": [1, 2], "y": ["3", "bad"], "z": [np.inf, 5]})
    out = align_frame(df, ["z", "y", "w"])
    assert list(out.columns) == ["z", "y", "w"]
    assert out.to_numpy().tolist() == [[0.0, 3.0, 0.0], [5.0, 0.0, 0.0]]
