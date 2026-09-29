"""Deterministic signature rules evaluated on every packet.

These fire within a second of an attack starting, before any flow has ended,
and do not depend on ML feature parity. Each rule keeps per-source sliding
windows and has a cooldown so a flood produces one alert per source per
cooldown period, not one per packet.

Rules
  syn_flood    SYN packets (without ACK) per second from one source
  port_scan    distinct destination ports probed by one source within a window
  slow_dos     many long-lived, nearly silent TCP connections from one source
               (Slowloris and slow HTTP attacks hold connections open)
  brute_force  repeated HTTP 401 responses to one client, or many new
               connections to a login port (SSH, FTP, Telnet, RDP)
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from src import config
from src.features.flow_features import ACK, FIN, RST, SYN, PacketInfo

COOLDOWN_S = 10.0


@dataclass
class SignatureHit:
    rule: str
    attack: str        # class name shown to the user, aligned with the ML class names
    src: str
    dst: str
    dport: int
    description: str
    evidence: dict = field(default_factory=dict)
    time: float = field(default_factory=time.time)


class _Window:
    """Timestamps (with an optional value) within the last ``span`` seconds."""

    def __init__(self, span: float):
        self.span = span
        self.items: deque = deque()

    def add(self, ts: float, value=None) -> None:
        self.items.append((ts, value))

    def trim(self, now: float) -> None:
        while self.items and self.items[0][0] < now - self.span:
            self.items.popleft()

    def count(self, now: float) -> int:
        self.trim(now)
        return len(self.items)

    def distinct(self, now: float) -> int:
        self.trim(now)
        return len({v for _, v in self.items})


class SignatureEngine:
    def __init__(self, window_s: float = config.WINDOW_S,
                 syn_rate: float = config.SYN_RATE_THRESHOLD,
                 scan_ports: int = config.PORTSCAN_PORT_THRESHOLD,
                 slow_conns: int = config.SLOWDOS_CONN_THRESHOLD,
                 slow_max_bps: float = config.SLOWDOS_MAX_BYTES_PER_S,
                 brute_conns: int = config.BRUTEFORCE_CONN_THRESHOLD,
                 brute_401: int = config.BRUTEFORCE_401_THRESHOLD,
                 auth_ports: set[int] = frozenset(config.AUTH_PORTS)):
        self.window_s = window_s
        self.syn_rate, self.scan_ports = syn_rate, scan_ports
        self.slow_conns, self.slow_max_bps = slow_conns, slow_max_bps
        self.brute_conns, self.brute_401, self.auth_ports = brute_conns, brute_401, set(auth_ports)
        self.syn: dict[str, _Window] = defaultdict(lambda: _Window(1.0))
        self.ports: dict[str, _Window] = defaultdict(lambda: _Window(window_s))
        self.auth_conns: dict[str, _Window] = defaultdict(lambda: _Window(window_s))
        self.http_401: dict[str, _Window] = defaultdict(lambda: _Window(2 * window_s))
        # Open TCP connections: (src, sport, dst, dport) -> [opened_ts, payload bytes from src]
        self.conns: dict[tuple, list] = {}
        self.last_fired: dict[tuple, float] = {}
        self._last_slow_check: dict[str, float] = {}

    # -- helpers ------------------------------------------------------------
    def _fire(self, rule: str, src: str, now: float) -> bool:
        key = (rule, src)
        if now - self.last_fired.get(key, -1e18) < COOLDOWN_S:
            return False
        self.last_fired[key] = now
        return True

    # -- main entry ---------------------------------------------------------
    def observe(self, p: PacketInfo, now: float | None = None) -> list[SignatureHit]:
        now = p.ts if now is None else now
        hits: list[SignatureHit] = []
        is_syn = p.proto == 6 and (p.flags & SYN) and not (p.flags & ACK)

        # SYN flood: pure SYNs per second from one source.
        if is_syn:
            w = self.syn[p.src]
            w.add(now)
            rate = w.count(now) / w.span
            if rate > self.syn_rate and self._fire("syn_flood", p.src, now):
                hits.append(SignatureHit("syn_flood", "DoS", p.src, p.dst, p.dport,
                                         f"SYN flood: {rate:.0f} SYN packets/s from {p.src}",
                                         {"syn_per_s": round(rate, 1)}, now))

        # Port scan: distinct destination ports probed (TCP SYN or UDP).
        if is_syn or p.proto == 17:
            w = self.ports[p.src]
            w.add(now, (p.dst, p.dport))
            n = w.distinct(now)
            if n > self.scan_ports and self._fire("port_scan", p.src, now):
                hits.append(SignatureHit("port_scan", "PortScan", p.src, p.dst, p.dport,
                                         f"Port scan: {n} ports probed in {self.window_s:.0f} s by {p.src}",
                                         {"distinct_ports": n}, now))

        # Brute force (a): many new connections to a login port.
        if is_syn and p.dport in self.auth_ports:
            w = self.auth_conns[p.src]
            w.add(now)
            n = w.count(now)
            if n > self.brute_conns and self._fire("brute_force", p.src, now):
                hits.append(SignatureHit("brute_force", "BruteForce", p.src, p.dst, p.dport,
                                         f"Brute force: {n} connections to port {p.dport} in "
                                         f"{self.window_s:.0f} s from {p.src}",
                                         {"connections": n}, now))

        # Brute force (b): repeated HTTP 401 responses sent back to one client.
        if p.proto == 6 and p.payload_head.startswith(b"HTTP/1.") and b" 401 " in p.payload_head[:16]:
            client = p.dst
            w = self.http_401[client]
            w.add(now)
            n = w.count(now)
            if n > self.brute_401 and self._fire("brute_force", client, now):
                hits.append(SignatureHit("brute_force", "BruteForce", client, p.src, p.sport,
                                         f"Brute force: {n} failed HTTP logins in {w.span:.0f} s by {client}",
                                         {"http_401": n}, now))

        # Slow DoS: track connection lifetimes and bytes.
        if p.proto == 6:
            hits.extend(self._track_connection(p, now))
        return hits

    def _track_connection(self, p: PacketInfo, now: float) -> list[SignatureHit]:
        fwd = (p.src, p.sport, p.dst, p.dport)
        rev = (p.dst, p.dport, p.src, p.sport)
        if p.flags & (FIN | RST):
            self.conns.pop(fwd, None)
            self.conns.pop(rev, None)
            return []
        if (p.flags & SYN) and not (p.flags & ACK):
            self.conns[fwd] = [now, 0]
        elif fwd in self.conns:
            self.conns[fwd][1] += p.payload_len

        # Evaluate at most once per second per source.
        src = p.src
        if fwd not in self.conns or now - self._last_slow_check.get(src, -1e18) < 1.0:
            return []
        self._last_slow_check[src] = now
        mature = [(opened, sent) for (s, _, _, _), (opened, sent) in self.conns.items()
                  if s == src and now - opened >= self.window_s]
        if len(mature) < self.slow_conns:
            return []
        bps = [sent / max(now - opened, 1e-6) for opened, sent in mature]
        avg_bps = sum(bps) / len(bps)
        if avg_bps < self.slow_max_bps and self._fire("slow_dos", src, now):
            return [SignatureHit("slow_dos", "DoS-Slow", src, p.dst, p.dport,
                                 f"Slow DoS: {len(mature)} long-held connections averaging "
                                 f"{avg_bps:.1f} B/s from {src}",
                                 {"open_connections": len(mature), "avg_bytes_per_s": round(avg_bps, 2)}, now)]
        return []

    def prune(self, now: float, max_conn_age_s: float = 600.0) -> None:
        """Drop state for idle sources and very old connections (call periodically)."""
        for store in (self.syn, self.ports, self.auth_conns, self.http_401):
            for src in list(store):
                if store[src].count(now) == 0:
                    del store[src]
        for key, (opened, _) in list(self.conns.items()):
            if now - opened > max_conn_age_s:
                del self.conns[key]
