"""Signature rule and responder tests on synthetic inputs (no network, no root)."""

from src.detection.signatures import SignatureEngine
from src.features.flow_features import ACK, FIN, PSH, RST, SYN, PacketInfo
from src.response.responder import CHAIN, Responder

A, V = "10.9.0.66", "10.9.0.10"


def syn(ts, dport=80, sport=40000, src=A):
    return PacketInfo(ts, src, V, sport, dport, 6, SYN, 0, 20, 64240)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
def test_syn_rate_rule_fires_once_per_cooldown():
    sig = SignatureEngine(syn_rate=100)
    hits = []
    for i in range(500):  # 500 SYN in 1 s from one source, varying source ports
        hits += sig.observe(syn(i / 500, sport=1024 + i))
    rules = [h.rule for h in hits]
    assert rules.count("syn_flood") == 1
    assert hits[0].attack == "DoS" and hits[0].src == A


def test_normal_connection_rate_does_not_fire():
    sig = SignatureEngine(syn_rate=100, scan_ports=30)
    hits = []
    for i in range(50):  # 50 connections over 10 s to one port
        hits += sig.observe(syn(i * 0.2, sport=2000 + i))
    assert hits == []


def test_port_rule_fires_on_many_distinct_ports():
    sig = SignatureEngine(scan_ports=30)
    hits = []
    for port in range(1, 200):
        hits += sig.observe(syn(port * 0.001, dport=port))
    scan = [h for h in hits if h.rule == "port_scan"]
    assert len(scan) == 1
    assert scan[0].attack == "PortScan" and scan[0].evidence["distinct_ports"] == 31


def test_few_ports_do_not_fire():
    sig = SignatureEngine(scan_ports=30)
    hits = []
    for i, port in enumerate([80, 443, 22] * 10):
        hits += sig.observe(syn(i * 0.01, dport=port, sport=3000 + i))
    assert not [h for h in hits if h.rule == "port_scan"]


def test_http_401_rule():
    sig = SignatureEngine(brute_401=10)
    hits = []
    for i in range(15):
        reply = PacketInfo(i * 0.3, V, A, 80, 5000 + i, 6, PSH | ACK, 200, 20, 500,
                           b"HTTP/1.1 401 Unauthorized\r\n")
        hits += sig.observe(reply)
    brute = [h for h in hits if h.rule == "brute_force"]
    assert len(brute) == 1 and brute[0].src == A  # the client, not the server


def test_long_held_quiet_connections_rule():
    sig = SignatureEngine(slow_conns=50, slow_max_bps=50, window_s=5)
    for i in range(60):  # open 60 connections at t=0
        sig.observe(syn(0.0, sport=6000 + i))
    hits = []
    for i in range(60):  # a few bytes on each, 10 s later
        hits += sig.observe(PacketInfo(10.0 + i * 0.01, A, V, 6000 + i, 80, 6, PSH | ACK, 5, 20, 500))
    slow = [h for h in hits if h.rule == "slow_dos"]
    assert len(slow) == 1 and slow[0].attack == "DoS-Slow"


def test_closed_connections_are_forgotten():
    sig = SignatureEngine()
    sig.observe(syn(0.0, sport=7000))
    assert len(sig.conns) == 1
    sig.observe(PacketInfo(0.5, A, V, 7000, 80, 6, FIN | ACK, 0, 20, 500))
    assert sig.conns == {}
    sig.observe(syn(1.0, sport=7001))
    sig.observe(PacketInfo(1.5, V, A, 80, 7001, 6, RST, 0, 20, 0))
    assert sig.conns == {}


# ---------------------------------------------------------------------------
# Responder
# ---------------------------------------------------------------------------
class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make_responder(**kw):
    clock = Clock()
    issued = []
    r = Responder(backend="iptables", runner=issued.append, never_block={"10.9.0.1"}, clock=clock, **kw)
    return r, clock, issued


def test_block_adds_drop_rule():
    r, _, issued = make_responder()
    rec = r.block(A, "test", duration_s=60)
    assert rec["action"] == "block"
    assert ["iptables", "-w", "-A", CHAIN, "-s", A, "-m", "comment", "--comment", "netra-block",
            "-j", "DROP"] in issued
    assert [b["ip"] for b in r.active()] == [A]


def test_block_expires_and_rule_is_removed():
    r, clock, issued = make_responder()
    r.block(A, "test", duration_s=60)
    clock.t += 30
    assert r.expire() == [] and len(r.active()) == 1
    clock.t += 31
    removed = r.expire()
    assert removed[0]["action"] == "unblock" and r.active() == []
    assert ["iptables", "-w", "-D", CHAIN, "-s", A, "-m", "comment", "--comment", "netra-block",
            "-j", "DROP"] in issued


def test_quarantine_is_rate_limit_and_upgrades_to_block():
    r, _, issued = make_responder()
    r.quarantine(A, "low confidence")
    assert any("limit" in cmd for cmd in issued)
    assert r.active()[0]["kind"] == "quarantine"
    rec = r.block(A, "confirmed")
    assert rec["action"] == "block" and r.active()[0]["kind"] == "block"


def test_repeat_block_extends_instead_of_duplicating():
    r, clock, issued = make_responder()
    r.block(A, "first", duration_s=60)
    n_rules = sum(1 for c in issued if "-A" in c)
    clock.t += 50
    rec = r.block(A, "again", duration_s=60)
    assert rec["action"] == "block-extended"
    assert sum(1 for c in issued if "-A" in c) == n_rules
    assert r.active()[0]["remaining"] == 60


def test_allowlist_is_never_blocked():
    r, _, _ = make_responder()
    assert r.block("10.9.0.1", "gateway")["action"] == "skipped-allowlist"
    assert r.active() == []


def test_unblock_all_clears_state_and_flushes_chain():
    r, _, issued = make_responder()
    r.block(A, "x")
    r.quarantine("10.9.0.77", "y")
    rec = r.unblock_all()
    assert rec["action"] == "unblock-all" and r.active() == []
    assert issued[-1] == ["iptables", "-w", "-F", CHAIN]


def test_dry_run_records_but_does_not_execute():
    r = Responder(backend="dry-run", never_block=set())
    r.block(A, "x")
    assert any("-A" in c for c in r.commands)
    assert r.backend == "dry-run"
