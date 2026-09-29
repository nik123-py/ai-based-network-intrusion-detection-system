"""Netra command-line entry point.

Usage:
    python -m src.cli <command> [options]

Commands:
    preprocess   Clean CIC-IDS2017, split it and save scalers and feature lists.
    train        Preprocess (if needed), train all models and evaluate them.
    evaluate     Evaluate trained models on the held-out test split.
    replay       Run the engine on test-split flows or a PCAP (headless, with event API).
    live         Capture packets on an interface, detect and respond in real time.
    app          Open the Netra desktop app and connect to a running engine.
    demo         Scripted replay plus the desktop app in one command (no Docker needed).
    unblock-all  Remove every block and quarantine rule added by Netra.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

ALL_KINDS = ["full", "lite", "autoencoder"]


# ---------------------------------------------------------------------------
# Data and models
# ---------------------------------------------------------------------------
def cmd_preprocess(args: argparse.Namespace) -> int:
    from src.data import preprocess

    start = time.time()
    stats = preprocess.run(days=args.days)
    preprocess.print_summary(stats)
    print(f"\nArtifacts written to models/ and data/processed/ in {time.time() - start:.0f} s")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from src import config
    from src.models import train_supervised

    if args.days or not config.FEATURES_PATH.exists():
        cmd_preprocess(args)
    for kind in args.kinds:
        if kind == "autoencoder":
            from src.models import autoencoder

            meta = autoencoder.train()
            print(f"[autoencoder] {meta['epochs_run']} epochs, threshold {meta['threshold']:.5f}")
        else:
            meta = train_supervised.train(kind)
            print(f"[{kind}] selected {meta['best']} by validation macro F1")
    return cmd_evaluate(args)


def cmd_evaluate(args: argparse.Namespace) -> int:
    from src.models import evaluate

    for kind in args.kinds:
        if kind == "autoencoder":
            from src.models import autoencoder

            r = autoencoder.evaluate()
            print(f"[autoencoder] ROC-AUC {r['roc_auc']:.4f}, detection rate {r['detection_rate']:.4f}, "
                  f"false-positive rate {r['false_positive_rate']:.5f}")
            continue
        report = evaluate.evaluate(kind)
        best = report["models"][report["selected"]]
        print(f"[{kind}] {report['selected']}: accuracy {best['accuracy']:.4f}, "
              f"macro F1 {best['macro']['f1']:.4f}, detection rate {best['binary']['detection_rate']:.4f}, "
              f"false-positive rate {best['binary']['false_positive_rate']:.5f}")
    evaluate.write_results_markdown()
    print("Metrics, confusion matrices and RESULTS.md written to reports/")
    return 0


# ---------------------------------------------------------------------------
# Engine, app and response
# ---------------------------------------------------------------------------
def _engine(mode: str, backend: str | None):
    from src import config
    from src.detection.engine import DetectionEngine
    from src.response.responder import Responder

    return DetectionEngine(responder=Responder(backend=backend or config.FIREWALL_BACKEND), mode=mode)


def _serve(engine, host: str, port: int) -> None:
    from src.dashboard.api import serve_in_background

    serve_in_background(engine, host, port)
    engine.start()


def _wait_forever() -> None:
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def cmd_replay(args: argparse.Namespace) -> int:
    engine = _engine("pcap replay" if args.pcap else "dataset replay", args.backend)
    _serve(engine, args.host, args.port)
    if args.pcap:
        from src.detection.sniffer import Sniffer

        sniffer = Sniffer(pcap=args.pcap)
        sniffer.on_packet(engine.on_packet)
        sniffer.on_flow(engine.on_flow)
        sniffer.replay_pcap(speed=args.speed)
    else:
        from src.detection.replay import DatasetReplay

        DatasetReplay(engine, speed=args.speed).run(loops=args.loops)
    engine.drain()
    print(f"Replay finished: {engine.totals.get('alerts', 0)} alerts raised.")
    if args.keep_running:
        print("Event API still running; press Ctrl+C to exit.")
        _wait_forever()
    engine.stop()
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    from src import config
    from src.detection.sniffer import Sniffer, resolve_interface

    iface = resolve_interface(args.iface or config.CAPTURE_INTERFACE)
    engine = _engine("live capture", args.backend)
    _serve(engine, args.host, args.port)
    sniffer = Sniffer(iface=iface)
    sniffer.on_packet(engine.on_packet)
    sniffer.on_flow(engine.on_flow)
    sniffer.start()
    print(f"Netra live on {iface}; event API on {args.host}:{args.port}. Press Ctrl+C to stop.", flush=True)
    _wait_forever()
    sniffer.stop()
    engine.stop()
    return 0


def cmd_app(args: argparse.Namespace) -> int:
    from src.dashboard.app import run

    return run(args.url, args.theme, args.screenshot, args.screenshot_after, args.quit_after_screenshot)


def cmd_demo(args: argparse.Namespace) -> int:
    import threading

    from src.dashboard.app import run
    from src.detection.replay import DatasetReplay

    engine = _engine("demo (dataset replay)", "dry-run")
    _serve(engine, args.host, args.port)
    replay = DatasetReplay(engine, speed=args.speed)
    threading.Thread(target=replay.run, kwargs={"loops": args.loops}, name="replay", daemon=True).start()
    code = run(f"ws://127.0.0.1:{args.port}/ws", args.theme, args.screenshot, args.screenshot_after,
               args.quit_after_screenshot)
    engine.stop()
    return code


def cmd_unblock_all(args: argparse.Namespace) -> int:
    import urllib.request

    try:
        req = urllib.request.Request(args.url.rstrip("/") + "/api/unblock-all", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            print("Engine:", resp.read().decode())
            return 0
    except OSError as e:
        print(f"Engine not reachable at {args.url} ({e}); flushing the firewall chain directly.")
    from src.response.responder import flush_chain

    flush_chain()
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netra", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    days_help = 'capture days to use, "all" or e.g. "Wednesday,Friday" (default: config.DAYS)'
    p = sub.add_parser("preprocess", help="clean, split and scale the dataset")
    p.add_argument("--days", default=None, help=days_help)
    p.set_defaults(func=cmd_preprocess)

    kinds_help = "models to use: full, lite, autoencoder (default: all)"
    p = sub.add_parser("train", help="preprocess data (if needed), train and evaluate models")
    p.add_argument("--days", default=None, help=days_help)
    p.add_argument("--kinds", nargs="+", default=ALL_KINDS, choices=ALL_KINDS, help=kinds_help)
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("evaluate", help="evaluate trained models on the test split")
    p.add_argument("--kinds", nargs="+", default=ALL_KINDS, choices=ALL_KINDS, help=kinds_help)
    p.set_defaults(func=cmd_evaluate)

    def server_args(p, default_host="127.0.0.1"):
        p.add_argument("--host", default=default_host, help="event API bind address")
        p.add_argument("--port", type=int, default=8000, help="event API port")
        p.add_argument("--backend", choices=["iptables", "dry-run"], default=None,
                       help="firewall backend (default: NETRA_FIREWALL_BACKEND, else dry-run)")

    def app_args(p):
        p.add_argument("--theme", choices=["auto", "light", "dark"], default="auto")
        p.add_argument("--screenshot", default=None, help="save a PNG of the window after a delay")
        p.add_argument("--screenshot-after", type=float, default=8.0, help="seconds before the screenshot")
        p.add_argument("--quit-after-screenshot", action="store_true")

    p = sub.add_parser("replay", help="engine on test-split flows or a PCAP, with event API")
    server_args(p)
    p.add_argument("--pcap", default=None, help="replay this PCAP through capture, signatures and ML")
    p.add_argument("--speed", type=float, default=1.0, help="time scale (2 = twice as fast)")
    p.add_argument("--loops", type=int, default=1, help="dataset replay script repetitions")
    p.add_argument("--keep-running", action="store_true", help="keep the event API up after replay")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("live", help="live capture, detection and response")
    server_args(p, default_host="0.0.0.0")
    p.add_argument("--iface", default=None, help="capture interface (default: NETRA_IFACE or eth0)")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("app", help="open the desktop app")
    p.add_argument("--url", default="ws://127.0.0.1:8000/ws", help="engine event API WebSocket URL")
    app_args(p)
    p.set_defaults(func=cmd_app)

    p = sub.add_parser("demo", help="scripted replay plus the desktop app (no Docker)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--speed", type=float, default=1.0, help="time scale (2 = twice as fast)")
    p.add_argument("--loops", type=int, default=100, help="replay script repetitions")
    app_args(p)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("unblock-all", help="remove all Netra firewall rules")
    p.add_argument("--url", default="http://127.0.0.1:8000", help="engine event API base URL")
    p.set_defaults(func=cmd_unblock_all)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%H:%M:%S")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
