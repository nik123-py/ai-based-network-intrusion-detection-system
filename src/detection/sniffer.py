"""Packet capture: live on an interface (scapy) or from a PCAP file.

Each packet is parsed once into a ``PacketInfo`` and handed to:
  * ``on_packet`` callbacks (signature rules and traffic statistics), and
  * a ``FlowTable``, whose completed flows go to ``on_flow`` callbacks (ML scoring).

A background sweep expires idle flows once per second.

Run directly to check feature extraction on real traffic:
    python -m src.detection.sniffer --iface eth0 --print
"""

from __future__ import annotations

import argparse
import logging
import threading
import time
from typing import Callable

import scapy.layers.inet  # noqa: F401  registers IP/TCP/UDP
import scapy.layers.l2  # noqa: F401  registers Ethernet; without it frames are captured as Raw

from src import config
from src.features.flow_features import FlowRecord, FlowTable, PacketInfo, parse_packet

log = logging.getLogger(__name__)

PacketCallback = Callable[[PacketInfo], None]
FlowCallback = Callable[[FlowRecord], None]


def resolve_interface(spec: str, subnet: str = config.LAB_SUBNET) -> str:
    """Return ``spec`` unchanged, or for "auto" the interface whose IPv4 address is in ``subnet``.

    The lab victim has two interfaces (lab and management); capturing on the lab
    one keeps the desktop app's own API traffic out of the analysis.
    """
    if spec != "auto":
        return spec
    import ipaddress

    from scapy.interfaces import get_if_list
    from scapy.arch import get_if_addr

    net = ipaddress.ip_network(subnet)
    for name in get_if_list():
        try:
            if ipaddress.ip_address(get_if_addr(name)) in net:
                return name
        except ValueError:
            continue
    raise RuntimeError(f"no interface with an address in {subnet}")


class Sniffer:
    def __init__(self, iface: str | None = None, pcap: str | None = None, bpf: str = "ip",
                 idle_timeout_s: float = config.FLOW_TIMEOUT_S):
        if not iface and not pcap:
            raise ValueError("either iface or pcap is required")
        self.iface, self.pcap, self.bpf = iface, pcap, bpf
        self.table = FlowTable(idle_timeout_s=idle_timeout_s)
        self.packet_callbacks: list[PacketCallback] = []
        self.flow_callbacks: list[FlowCallback] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sniffer = None
        self._sweeper: threading.Thread | None = None
        self.packets_seen = 0

    def on_packet(self, cb: PacketCallback) -> None:
        self.packet_callbacks.append(cb)

    def on_flow(self, cb: FlowCallback) -> None:
        self.flow_callbacks.append(cb)

    # -- packet path --------------------------------------------------------
    def _handle(self, pkt) -> None:
        info = parse_packet(pkt)
        if info is None:
            return
        self.packets_seen += 1
        for cb in self.packet_callbacks:
            try:
                cb(info)
            except Exception:  # a faulty consumer must not stop capture
                log.exception("packet callback failed")
        with self._lock:
            done = self.table.add(info)
        self._dispatch(done)

    def _dispatch(self, flows: list[FlowRecord]) -> None:
        for flow in flows:
            for cb in self.flow_callbacks:
                try:
                    cb(flow)
                except Exception:
                    log.exception("flow callback failed")

    def _sweep(self) -> None:
        while not self._stop.wait(1.0):
            with self._lock:
                done = self.table.expire(time.time())
            self._dispatch(done)

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        """Start live capture in the background (non-blocking)."""
        from scapy.sendrecv import AsyncSniffer

        self._sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=self._handle, store=False)
        self._sniffer.start()
        self._sweeper = threading.Thread(target=self._sweep, name="flow-sweeper", daemon=True)
        self._sweeper.start()
        log.info("capturing on %s (filter %r)", self.iface, self.bpf)

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        with self._lock:
            done = self.table.flush()
        self._dispatch(done)

    def replay_pcap(self, speed: float = 0.0) -> None:
        """Process a PCAP file (blocking). speed=0 runs as fast as possible, 1.0 is real time."""
        from scapy.utils import PcapReader

        first_pkt_ts = wall_start = None
        last_sweep = 0.0
        with PcapReader(self.pcap) as reader:
            for pkt in reader:
                ts = float(pkt.time)
                if speed > 0:
                    if first_pkt_ts is None:
                        first_pkt_ts, wall_start = ts, time.time()
                    delay = (ts - first_pkt_ts) / speed - (time.time() - wall_start)
                    if delay > 0:
                        time.sleep(delay)
                self._handle(pkt)
                if ts - last_sweep >= 1.0:
                    with self._lock:
                        done = self.table.expire(ts)
                    self._dispatch(done)
                    last_sweep = ts
        with self._lock:
            done = self.table.flush()
        self._dispatch(done)


def _print_flow(schema: list[str], lite_schema: list[str]):
    from src.features.flow_features import align_to_schema

    def show(f: FlowRecord) -> None:
        full = align_to_schema(f.cic, schema)
        lite = align_to_schema(f.lite, lite_schema)
        print(f"{f.src}:{f.sport} -> {f.dst}:{f.dport} proto={f.proto} pkts={f.n_packets} "
              f"end={f.reason} | full[{len(full)}] dur_us={full[schema.index('Flow Duration')]:.0f} "
              f"fwd_pkts={full[schema.index('Total Fwd Packets')]:.0f} "
              f"bwd_pkts={full[schema.index('Total Backward Packets')]:.0f} | lite="
              + ", ".join(f"{n}={v:.3g}" for n, v in zip(lite_schema, lite))
              + f" | syn_ratio={f.syn_ratio:.2f}", flush=True)
    return show


def main() -> None:
    from src.data.preprocess import load_feature_spec

    ap = argparse.ArgumentParser(description="Capture packets and print aligned flow feature vectors.")
    ap.add_argument("--iface", default=config.CAPTURE_INTERFACE)
    ap.add_argument("--pcap", default=None, help="read a PCAP instead of live capture")
    ap.add_argument("--print", action="store_true", help="print every completed flow")
    ap.add_argument("--seconds", type=float, default=0, help="stop after this many seconds (0 = forever)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    spec = load_feature_spec()
    sniffer = Sniffer(iface=None if args.pcap else resolve_interface(args.iface), pcap=args.pcap)
    if args.print:
        sniffer.on_flow(_print_flow(spec["features"], spec["lite_features"]))
    if args.pcap:
        sniffer.replay_pcap()
        return
    sniffer.start()
    try:
        deadline = time.time() + args.seconds if args.seconds else None
        while deadline is None or time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        print(f"packets seen: {sniffer.packets_seen}")


if __name__ == "__main__":
    main()
