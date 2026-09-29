"""Automated response: timed, reversible firewall actions against attacking sources.

Actions
  block       DROP every packet from the source for ``BLOCK_DURATION_S``.
  quarantine  Rate-limit the source (accept up to ``QUARANTINE_RATE``, drop the rest)
              for ``QUARANTINE_DURATION_S``. Used for lower-confidence alerts.

All rules live in a dedicated ``NETRA`` iptables chain jumped to from INPUT and
FORWARD, so ``unblock_all`` only has to flush that chain and never touches any
other firewall rule. In the Docker lab this runs inside the NIDS container's
network namespace, so the host firewall is never modified.

Backends
  iptables  run the commands (requires root / CAP_NET_ADMIN, Linux only)
  dry-run   record the commands that would have run (host demo and tests)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from logging.handlers import RotatingFileHandler
from typing import Callable

from src import config

log = logging.getLogger(__name__)
CHAIN = "NETRA"


@dataclass
class Block:
    ip: str
    kind: str          # "block" or "quarantine"
    reason: str
    created: float
    expires: float

    def remaining(self, now: float | None = None) -> float:
        return max(0.0, self.expires - (now or time.time()))


def action_logger() -> logging.Logger:
    """JSON-lines logger for alerts and actions, rotated by size."""
    logger = logging.getLogger("netra.events")
    if not logger.handlers:
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(config.ALERT_LOG_PATH, maxBytes=config.LOG_MAX_BYTES,
                                      backupCount=config.LOG_BACKUP_COUNT, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


class Responder:
    def __init__(self, backend: str = config.FIREWALL_BACKEND, enabled: bool = config.RESPONSE_ENABLED,
                 never_block: set[str] | None = None, runner: Callable[[list[str]], None] | None = None,
                 clock: Callable[[], float] = time.time):
        if backend not in ("iptables", "dry-run"):
            raise ValueError("backend must be 'iptables' or 'dry-run'")
        if backend == "iptables" and runner is None and shutil.which("iptables") is None:
            log.warning("iptables not found, falling back to dry-run")
            backend = "dry-run"
        self.backend = backend
        self.enabled = enabled
        self.never_block = set(config.NEVER_BLOCK if never_block is None else never_block)
        self.clock = clock
        self.blocks: dict[str, Block] = {}
        self.commands: list[list[str]] = []  # every command issued (both backends)
        self.listeners: list[Callable[[dict], None]] = []
        self._runner = runner or self._run
        self._lock = threading.RLock()
        self._events = action_logger()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._setup_chain()

    # -- firewall primitives ------------------------------------------------
    def _run(self, cmd: list[str]) -> None:
        if self.backend == "dry-run":
            return
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log.debug("command %s failed: %s", " ".join(cmd), result.stderr.strip())

    def _cmd(self, *args: str) -> None:
        cmd = ["iptables", "-w", *args]
        self.commands.append(cmd)
        self._runner(cmd)

    def _setup_chain(self) -> None:
        self._cmd("-N", CHAIN)                       # fails harmlessly if it already exists
        self._cmd("-F", CHAIN)
        for parent in ("INPUT", "FORWARD"):
            self._cmd("-D", parent, "-j", CHAIN)     # avoid duplicate jumps on restart
            self._cmd("-I", parent, "1", "-j", CHAIN)

    def _rule_specs(self, b: Block) -> list[list[str]]:
        tag = ["-m", "comment", "--comment", f"netra-{b.kind}"]
        if b.kind == "block":
            return [["-s", b.ip, *tag, "-j", "DROP"]]
        return [["-s", b.ip, "-m", "limit", "--limit", config.QUARANTINE_RATE, "--limit-burst", "20",
                 *tag, "-j", "ACCEPT"],
                ["-s", b.ip, *tag, "-j", "DROP"]]

    def _apply(self, b: Block) -> None:
        for spec in self._rule_specs(b):
            self._cmd("-A", CHAIN, *spec)

    def _remove(self, b: Block) -> None:
        for spec in self._rule_specs(b):
            self._cmd("-D", CHAIN, *spec)

    # -- public API ---------------------------------------------------------
    def respond(self, ip: str, kind: str, reason: str, duration_s: float | None = None) -> dict:
        """Apply a block or quarantine. Returns an action record describing what happened."""
        now = self.clock()
        if duration_s is None:
            duration_s = config.BLOCK_DURATION_S if kind == "block" else config.QUARANTINE_DURATION_S
        with self._lock:
            if not self.enabled:
                return self._record("log-only", ip, reason, 0)
            if ip in self.never_block:
                return self._record("skipped-allowlist", ip, reason, 0)
            existing = self.blocks.get(ip)
            if existing and (existing.kind == "block" or kind == "quarantine"):
                existing.expires = max(existing.expires, now + duration_s)  # extend, never downgrade
                return self._record(f"{existing.kind}-extended", ip, reason, existing.remaining(now))
            if existing:  # quarantine -> block upgrade
                self._remove(existing)
            b = Block(ip, kind, reason, now, now + duration_s)
            self._apply(b)
            self.blocks[ip] = b
            return self._record(kind, ip, reason, duration_s)

    def block(self, ip: str, reason: str, duration_s: float | None = None) -> dict:
        return self.respond(ip, "block", reason, duration_s)

    def quarantine(self, ip: str, reason: str, duration_s: float | None = None) -> dict:
        return self.respond(ip, "quarantine", reason, duration_s)

    def unblock(self, ip: str, reason: str = "manual") -> dict | None:
        with self._lock:
            b = self.blocks.pop(ip, None)
            if b is None:
                return None
            self._remove(b)
            return self._record("unblock", ip, reason, 0)

    def expire(self) -> list[dict]:
        now = self.clock()
        with self._lock:
            due = [ip for ip, b in self.blocks.items() if b.expires <= now]
            return [self.unblock(ip, "expired") for ip in due]

    def unblock_all(self) -> dict:
        with self._lock:
            n = len(self.blocks)
            self.blocks.clear()
            self._cmd("-F", CHAIN)
            return self._record("unblock-all", "*", f"{n} rule(s) removed", 0)

    def active(self) -> list[dict]:
        now = self.clock()
        with self._lock:
            return [{**asdict(b), "remaining": round(b.remaining(now), 1)} for b in self.blocks.values()]

    # -- expiry thread ------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="responder-expiry", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(1.0):
            self.expire()

    def stop(self) -> None:
        self._stop.set()

    # -- logging ------------------------------------------------------------
    def _record(self, action: str, ip: str, reason: str, duration_s: float) -> dict:
        rec = {"type": "action", "time": self.clock(), "action": action, "ip": ip, "reason": reason,
               "duration_s": round(duration_s, 1), "backend": self.backend}
        self._events.info(json.dumps(rec))
        if action not in ("skipped-allowlist",):
            log.info("response: %s %s (%s)", action, ip, reason)
        for cb in self.listeners:
            try:
                cb(rec)
            except Exception:
                log.exception("action listener failed")
        return rec


def flush_chain() -> None:
    """Remove every Netra rule directly (used by ``cli unblock-all`` when no engine is running)."""
    if shutil.which("iptables") is None:
        print("iptables not available on this machine; nothing to flush.")
        return
    subprocess.run(["iptables", "-w", "-F", CHAIN], check=False)
    print(f"Flushed iptables chain {CHAIN}.")
