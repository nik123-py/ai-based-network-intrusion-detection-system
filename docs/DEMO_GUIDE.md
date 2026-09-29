# Netra demo guide

Exact steps for demonstrating Netra live. The whole demo runs on one laptop with
Docker Desktop. Allow 10 to 12 minutes for the full run, or 5 minutes for the
short version.

All commands are run from the `netra/` directory. On Windows use Git Bash for the
`bash` commands and either shell for the Python ones. `python` below means the
project interpreter: `.venv/Scripts/python.exe` on Windows, `.venv/bin/python` on
macOS or Linux.

## 1. Before the demo (do this the day before)

Run every step once on the machine you will present from. The first Docker build
downloads packages and takes a few minutes; afterwards it is cached.

```bash
docker compose up -d --build          # build images, start the lab
python -m src.cli app --url ws://127.0.0.1:8000/ws    # check the app connects
python -m pytest -q tests             # 31 tests should pass
python scripts/gui_selftest.py        # 12 checks should pass
docker compose down
```

Checklist:

- [ ] Docker Desktop starts and stays running
- [ ] `models/` contains the trained files (if not, run `python -m src.cli train --days all`, about 8 minutes)
- [ ] The desktop app opens and shows "Connected"
- [ ] All three models report "loaded" in the app's status panel
- [ ] `python -m pytest -q tests` passes
- [ ] Screen resolution set so the app window and a terminal are both visible
- [ ] Laptop on mains power, notifications and sleep disabled

## 2. Demo setup (5 minutes before you present)

Open two terminals side by side, both in `netra/`.

### Which shell you are using matters

The attack commands differ slightly between PowerShell and Git Bash. Pick one and
stick to it for the whole demo.

- **PowerShell** (the usual choice on this machine): run the commands exactly as
  written below. Nothing extra is needed.
- **Git Bash**: prefix every `docker compose exec` command with
  `MSYS_NO_PATHCONV=1`, otherwise MSYS rewrites `/attacks/...` into a Windows
  path and you get `sh: 0: cannot open C:/Program Files/Git/attacks/...`.

`MSYS_NO_PATHCONV=1` is bash syntax. Typing it in PowerShell fails with
"The term 'MSYS_NO_PATHCONV=1' is not recognized".

Terminal 1, start the lab and leave it running:

```bash
docker compose up -d
```

Terminal 2, open the dashboard and position the window so the audience can see
the alert feed and the blocked-addresses table:

```bash
python -m src.cli app --url ws://127.0.0.1:8000/ws
```

Confirm the app shows "Connected" and three loaded models before you start
talking. Leave Terminal 1 free for the attack commands.

## 3. The run sheet

### Step 1: show the lab (about 1 minute)

Explain the three containers while the app is on screen:

- `attacker` 10.77.0.66, standard tools (nmap, hping3, slowhttptest, hydra)
- `victim` 10.77.0.10, an ordinary nginx web server
- `nids`, Netra itself, sharing the victim's network namespace so it sees every
  packet the victim sends or receives, like a SPAN port on a real switch

The lab network is internal: it has no route to the internet, the campus network
or the host. Point out that the attack tools also refuse any target outside
10.77.0.0/24.

### Step 2: normal traffic, no alerts (about 1 minute)

```powershell
docker compose exec -T attacker sh /attacks/normal.sh 10.77.0.10 20 0.2
```

Point at the app: the flow counter and the traffic chart rise, and the alert feed
stays empty. This is the false-positive check. Say that the full model's measured
false-positive rate on the test split is 0.11 percent.

### Step 3: the four attacks (about 5 minutes)

Run them one at a time and talk while each one runs. After each attack, wait for
the alert to appear in the feed and the source to appear in the blocked table
with a live countdown.

Run them **one at a time**, not as a block. Click **Unblock all** in the app
between attacks, or the attacker is still blocked and its packets are dropped
before Netra can see them.

```powershell
# Port scan -> PortScan alert
docker compose exec -T attacker sh /attacks/portscan.sh 10.77.0.10

# SYN flood -> DoS alert
docker compose exec -T attacker sh /attacks/synflood.sh 10.77.0.10 80 15

# Slow HTTP (Slowloris) -> DoS-Slow alert
docker compose exec -T attacker sh /attacks/slowloris.sh 10.77.0.10 80 200 25

# Brute force -> BruteForce alert
docker compose exec -T attacker sh /attacks/bruteforce.sh 10.77.0.10
```

In Git Bash, prefix each of these with `MSYS_NO_PATHCONV=1`.

Things worth pointing out as they happen:

- The alert appears within about a second, because the signature rules work on
  packets and do not wait for the flow to finish.
- The blocked table shows the attacker's address with a countdown. The block is
  a real `iptables` DROP rule in the victim's namespace, and it expires by
  itself, so a false positive cannot lock anyone out permanently.
- After the port scan, the attacker is blocked, so a repeat of the same scan gets
  nothing back. That is the response working.
- The slow HTTP attack usually makes slowhttptest print `service available: NO`.
  The attack really does exhaust nginx's connection pool, and Netra catches it
  from the traffic pattern, not from the server's health.
- The brute force ends with hydra printing the recovered password. That is the
  attack succeeding against an unprotected server; Netra's job is that the
  source was flagged and blocked while it was guessing.

To prove enforcement rather than just display, show the rule itself:

```bash
docker compose exec -T nids iptables -L NETRA -n
```

### Step 4: operator control (about 1 minute)

Click **Unblock all** in the app. The blocked table empties and the attacker can
reach the victim again:

```bash
docker compose exec -T attacker curl -s -o /dev/null -w '%{http_code}\n' http://10.77.0.10/
```

This returns 200 after the unblock. Switch the theme to dark to show the app is a
real native desktop application, not a web page.

### Step 5: the numbers (about 2 minutes)

Move to the slides or `reports/RESULTS.md`. State the measured results:

- Full model (59 features): accuracy 0.9987, macro F1 0.9570, detection rate
  99.80 percent, false-positive rate 0.11 percent
- Lite model (6 live features): macro F1 0.8400, weak on WebAttack (F1 0.25)
  because that attack lives in the HTTP payload, not in flow statistics
- Autoencoder: ROC-AUC 0.9603, catches 38.9 percent of attacks at a 1 percent
  false-alarm rate, and it was never shown an attack during training

Be honest about the limits: the lite model is the one that runs live, the
autoencoder is a safety net for unknown attacks rather than a primary detector,
and the signature rules are what make the live demo fire instantly.

## 4. One-command version

If you would rather not type during the demo, the driver script runs the whole
sequence, pausing before each step so you can talk:

```bash
bash scripts/run_demo.sh
```

It starts the lab, waits for the victim, runs the benign baseline and then each
attack, and clears the blocks at the end. Useful flags:

```bash
bash scripts/run_demo.sh --yes --pause 12     # unattended, 12 s between steps
bash scripts/run_demo.sh --attacks "portscan bruteforce"   # short version
bash scripts/run_demo.sh --yes --down         # unattended, then tear the lab down
```

Open the app first so the audience can watch it while the script runs.

## 5. If Docker is not available

There is a fallback that needs no Docker. It replays real attack flows from the
held-out CIC-IDS2017 test split through the same engine, with the firewall in
dry-run mode, and opens the app:

```bash
python -m src.cli demo
```

This shows the ML detectors, the fusion logic and the responder's decisions, but
not the signature rules (it replays flow records, not packets) and it applies no
real firewall rules. Say so if you use it.

## 6. Reset and cleanup

```bash
python -m src.cli unblock-all --url http://127.0.0.1:8000   # clear blocks
docker compose down                                          # stop the lab
```

Blocks also expire on their own after 90 seconds in the lab, so a forgotten
block is not a problem. `unblock-all` flushes the `NETRA` iptables chain. Netra
never touches the host firewall: every rule lives inside the victim container's
network namespace and disappears with the container.

To reset between two rehearsals, `unblock-all` is enough; a full `docker compose
down && docker compose up -d` gives a completely clean state including counters.

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| App shows "Disconnected" | The lab is not up, or port 8000 is taken. `docker compose ps`, then `docker compose up -d`. |
| `cannot open C:/Program Files/Git/attacks/...` | Git Bash rewrote the path. Prefix the command with `MSYS_NO_PATHCONV=1`. |
| `The term 'MSYS_NO_PATHCONV=1' is not recognized` | That prefix is bash syntax and you are in PowerShell. Drop it and run the command on its own. |
| Attack runs but no alert | The attacker may still be blocked from the previous attack, so its packets are dropped. Click **Unblock all** and run it again. |
| Victim returns no HTTP 200 | Slow HTTP attack still holding connections. Wait for it to finish, or `docker compose restart victim`. |
| Models show "not loaded" | `models/` is empty or not mounted. Run `python -m src.cli train --days all`. |
| Port scan raises no alert | Check the scan covers more than 30 ports: the threshold is 30 distinct ports in 5 seconds. |
| Blocks never clear | Check the NIDS container is running; the expiry thread lives there. `docker compose logs nids`. |

## 8. Questions to expect

**Why block by source address, and is that not dangerous?**
It is, which is why every block is timed (90 seconds in the lab), reversible from
the app, and refused for addresses on the never-block list (loopback, the lab
gateways, the victim itself). Weak evidence also needs three flagged flows from
one source within 10 seconds before it can raise an alert at all.

**Why do you need machine learning if the rules catch everything in the demo?**
The rules only cover attacks someone anticipated. The supervised models classify
flows the rules say nothing about, and the autoencoder is trained only on benign
traffic, so it can flag a pattern that no one wrote a rule for and no label
existed for. The demo attacks are deliberately ones the rules cover, because that
is what makes them fire in one second in front of an audience.

**Is the detection real, or replayed?**
In the Docker lab it is real: scapy captures live packets, the models score real
flows and iptables applies real rules. `python -m src.cli demo` is the replay
mode, and it is clearly labelled as dataset replay in the app's status.

**Why is WebAttack detection so weak?**
The lite model sees only six flow statistics. A SQL injection looks like an
ordinary small HTTP request at that level, so its F1 is 0.25. The full model gets
it to 0.97 because it sees the detailed timing and size features. Detecting it
properly needs payload inspection, which is listed as future work.
