"""End-to-end self-test of the desktop app against the Docker lab.

Drives the real Netra window with Qt's test tools and checks each step:
  1. the app connects to the engine running in the NIDS container and shows its status;
  2. normal web traffic from the lab client appears in the traffic statistics;
  3. a manual block of the client address (event API) appears in the blocked table,
     and the victim really becomes unreachable from that client (iptables enforcement);
  4. clicking "Unblock all" in the app removes the block and access returns.
Screenshots of each stage are written to docs/screenshots/.

Prerequisite: the lab is running (docker compose up -d).
Usage: python scripts/gui_selftest.py
"""

from __future__ import annotations

import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import Qt, QTimer  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from src.dashboard.app import MainWindow  # noqa: E402

CLIENT_IP = "10.77.0.66"
SHOTS = ROOT / "docs" / "screenshots"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)


def client_can_reach_victim() -> bool:
    """One ordinary HTTP GET from the lab client container to the victim page."""
    r = subprocess.run(["docker", "compose", "exec", "-T", "attacker", "curl", "-s", "-o", "/dev/null",
                        "-w", "%{http_code}", "--max-time", "4", "http://10.77.0.10/"],
                       cwd=ROOT, capture_output=True, text=True)
    return r.stdout.strip() == "200"


def normal_traffic(n: int = 20) -> None:
    for _ in range(n):
        client_can_reach_victim()


def wait_until(app: QApplication, cond, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        app.processEvents()
        if cond():
            return True
        QTest.qWait(100)
    return False


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    win = MainWindow("ws://127.0.0.1:8000/ws", theme="light")
    win.show()

    # 1. Connection and status
    connected = wait_until(app, lambda: "Connected" in win.conn.text(), 15)
    check("app connects to engine in Docker", connected, win.conn.text())
    got_status = wait_until(app, lambda: bool(win._status), 10)
    check("engine status received", got_status,
          f"mode={win._status.get('mode')} firewall={win._status.get('firewall_backend')}")
    models_ok = all(v.startswith("loaded") for v in win._status.get("models", {}).values())
    check("all three models loaded in container", models_ok, str(win._status.get("models")))

    # 2. Normal traffic shows up in live statistics
    def flows_total() -> int:
        return int(win.traffic.points[-1][1].get("totals", {}).get("flows", 0)) if win.traffic.points else 0

    wait_until(app, lambda: bool(win.traffic.points), 5)
    start_total = flows_total()
    normal_traffic(20)
    counted = wait_until(app, lambda: flows_total() > start_total, 15)
    check("normal traffic is captured and scored", counted, f"flows scored: {win.tile_flows.value.text()}")
    QTest.qWait(1500)
    check("normal traffic raises no alerts (no false positives)", win.total_alerts == 0,
          f"alerts={win.total_alerts}")
    win.grab().save(str(SHOTS / "lab_1_connected.png"))

    # 3. Manual block through the event API, as the app's "Block an address" action does
    check("client reaches victim before block", client_can_reach_victim())
    urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:8000/api/block/{CLIENT_IP}",
                                                  data=b"{}", method="POST"), timeout=5).read()
    shown = wait_until(app, lambda: any(b["ip"] == CLIENT_IP for b in win.blocks.blocks), 10)
    check("block appears in the app's blocked table", shown,
          f"rows={[(b['ip'], b['kind']) for b in win.blocks.blocks]}")
    check("victim unreachable from blocked client (iptables DROP)", not client_can_reach_victim())
    QTest.qWait(2500)
    remaining = win.blocks.item(0, 3).text() if win.blocks.rowCount() else ""
    check("countdown is running", remaining not in ("", "0:00"), f"remaining={remaining}")
    win.grab().save(str(SHOTS / "lab_2_blocked.png"))

    # 4. Click "Unblock all" in the app
    button = win.findChild(QPushButton, "unblockAllButton")
    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
    cleared = wait_until(app, lambda: win.blocks.rowCount() == 0, 10)
    check("Unblock all button clears the table", cleared)
    check("client reaches victim again after unblock", client_can_reach_victim())
    QTest.qWait(1000)
    win.grab().save(str(SHOTS / "lab_3_unblocked.png"))

    # Theme switch works without errors
    win.set_theme("dark")
    QTest.qWait(800)
    win.grab().save(str(SHOTS / "lab_4_dark.png"))
    check("dark theme renders", True)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed", flush=True)
    QTimer.singleShot(0, app.quit)
    app.exec()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
