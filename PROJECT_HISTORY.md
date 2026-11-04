# Netra: project history and handoff

This file is a handoff for continuing Netra in a fresh session. It records what was built, what works, the decisions that are easy to get wrong, and what remains. Read it first, then `docs/ARCHITECTURE.md` and `reports/RESULTS.md`.

## What Netra is

An AI network intrusion detection and response system, built as graded academic coursework. It trains ML models on CIC-IDS2017, scores live network flows with a hybrid of signature rules, supervised classifiers and an unsupervised autoencoder, and responds by blocking attacking source addresses with timed, reversible iptables rules. The attack lab runs entirely in Docker on one laptop. The dashboard is a native PySide6 desktop app, not a web page (this was a specific requirement).

Everything lives in `computer network project/netra/`.

## Environment (important, non-obvious)

- **Host:** Windows 11, PowerShell plus a Git Bash tool. No system Python 3.11.
- **Python 3.11 comes from `uv`.** The venv is `netra/.venv`, created with `uv venv --python 3.11 --seed .venv`. Run Python as `.venv/Scripts/python.exe`.
- **Windows file encoding trap:** Python on this host defaults to cp1252. When a script reads or writes source files that contain non-ASCII characters, set `PYTHONUTF8=1` or pass `encoding="utf-8"`, or it raises `UnicodeDecodeError`. Use `PYTHONIOENCODING=utf-8` when running modules that print the class names.
- **Docker Desktop** is installed and was started during the build. `docker compose` v2 is available.
- **cicflowmeter is pinned to 0.2.0** because 0.3.0+ needs Python 3.12. 0.2.0 only emits a flow after 240 s idle, so it is used only for offline PCAP conversion. Live capture uses the custom extractor in `src/features/flow_features.py`.

## Current status by phase

| Phase | State |
|---|---|
| 0 Scaffold | Done. `requirements.txt` pinned; `pip install` clean. |
| 1 Data pipeline | Done. 2,195,946 clean flows (per `reports/data_summary.json`), 8 classes, no cross-split leakage. |
| 2 Supervised | Done. Random Forest selected (full and lite). Real metrics in `reports/`. |
| 3 Autoencoder | Done. NumPy inference matches Keras. |
| 4 Live capture | Done and verified inside Docker on real packets. |
| 5 Engine + response | Done. Fusion, corroboration, timed iptables blocks, all tested. |
| 6 Desktop app | Done. PySide6, light/dark, verified by `scripts/gui_selftest.py`. |
| 7 Docker lab | Done. `docker compose up` runs attacker+victim+nids; GUI self-test 12/12. |
| 8 Attack scripts + demo | Done. Four attack scripts + benign baseline + `run_demo.sh`; all four detectors fire and block in the live lab (verified). |
| 9 Presentation (Netra.pptx) | Done. `presentation/build_ppt.py` generates a 25-slide deck; verified by rendering every slide to PNG. |
| 10 Docs/report | Done. `ARCHITECTURE.md`, `PACKET_TRACER_GUIDE.md`, `DEMO_GUIDE.md`, `REPORT.md`; README updated for all phases. |

### Phase 8 (done)

Attack scripts live in `scripts/attacks/`, mounted read-only into the attacker container at `/attacks`:

- `portscan.sh` (nmap `-sS`) -> PortScan (`signature:port_scan`)
- `synflood.sh` (hping3 `--flood`) -> DoS (`signature:syn_flood`)
- `slowloris.sh` (slowhttptest `-H`) -> DoS-Slow (`signature:slow_dos`)
- `bruteforce.sh` (hydra `http-get /admin/`, wordlist `passwords.txt`) -> BruteForce (`signature:brute_force`)
- `normal.sh` (curl loop) -> benign baseline, raises no alert
- `_lib.sh` shared helpers with `require_lab_target`, which refuses any address outside `10.77.0.0/24` (the README safety rule, enforced in code)

`scripts/run_demo.sh` (host, bash) is the driver: `docker compose up -d --build`, waits for the victim, prints the app launch command, runs the benign baseline then each attack from the attacker container, and finishes with `unblock-all`. Flags: `--yes` (unattended, sleeps `--pause` seconds), `--attacks "a b"` (subset), `--down` (teardown at the end).

Verified end to end on 2026-09-29 with the lab up (`FIREWALL_BACKEND=iptables`): each of the four attacks raised its expected alert and produced a real timed `DROP` of the attacker (10.77.0.66) in the victim's `NETRA` iptables chain; `unblock-all` cleared it. hydra also recovers the lab password `Lab-Only-Passw0rd`, so the brute force shows a success as well as the 401 flood.

Gotchas found and handled:
- **Windows Git Bash path mangling.** `docker compose exec ... sh /attacks/foo.sh` gets its `/attacks/...` argument rewritten to a Windows path by MSYS. `run_demo.sh` exports `MSYS_NO_PATHCONV=1` (ignored on Linux/macOS) so the container path is passed literally. Do the same for any manual `exec` call on this host.
- Scripts are POSIX `sh` (the attacker is `debian:bookworm-slim`, `/bin/sh` is dash) and are invoked as `sh /attacks/foo.sh`, so the read-only mount needs no executable bit.
- `slowhttptest -g` writes report files to the cwd (`/attacks`, read-only), so it is omitted.
- The half-open SYN flood also trips `slow_dos` and the autoencoder as a side effect; the primary `syn_flood` alert still fires first. This is realistic, not a bug.


## How to run things

```
cd netra
# Data (already downloaded and verified; re-runs are idempotent)
bash data/download_data.sh

# Train + evaluate everything (~8 min). Writes models/ and reports/.
.venv/Scripts/python.exe -m src.cli train --days all

# No-Docker demo: app + scripted replay of real attack flows
.venv/Scripts/python.exe -m src.cli demo

# Docker lab
docker compose up -d              # attacker 10.77.0.66, victim 10.77.0.10, nids
.venv/Scripts/python.exe -m src.cli app --url ws://127.0.0.1:8000/ws   # app to the lab engine
docker compose down

# Tests and the GUI end-to-end self-test (needs the lab up)
.venv/Scripts/python.exe -m pytest -q tests                # 31 pass
.venv/Scripts/python.exe scripts/gui_selftest.py           # 12 checks, writes docs/screenshots/lab_*.png
```

CLI subcommands (`src/cli.py`): `preprocess, train, evaluate, replay, live, app, demo, unblock-all`.

## Key design decisions and gotchas

1. **Dataset source.** UNB now gates CIC-IDS2017 behind a form, so the data was fetched from the Hugging Face mirror `bencorn/CICIDS2017`. Both zips were SHA-256 verified and their contents match the published per-label counts exactly (2,830,743 flows). Two releases are used: `data/cicids2017_labelled/` (GeneratedLabelledFlows, has IPs+timestamps, the primary input) and `data/cicids2017/` (MachineLearningCSV, reference). Data is gitignored.

2. **The dataset's TCP flag counters are broken** (Engelen et al., 2021). `SYN Flag Count` is 0 on every PortScan flow; FIN/PSH are near-zero everywhere though real connections carry them. Two consequences:
   - The SYN ratio is computed only from live packets, used by the SYN-flood rule, never learned.
   - **All 12 flag features were removed from the models** (`config.UNRELIABLE_FLAG_COLUMNS`). This was found during live testing: normal web traffic was being flagged as anomalous and the client got quarantined, because live flows have FIN/PSH set and the models had learned they should be 0. Full model went 69 -> 59 features. After this fix, normal flows score ~0.08 against the 0.146 autoencoder threshold. **Do not re-add flag features.**

3. **Destination port is metadata, not a feature.** It is a shortcut in this dataset (most DoS targets port 80). Removing it also collapses most of nmap's 158,930 PortScan rows into duplicates, leaving ~1,956 unique; that is expected.

4. **Only the training split is capped** (400k rows/class, affects Benign only). Validation and test keep the natural distribution, so reported metrics are realistic. No resampling on test.

5. **Lite window is 60 s** because CIC-IDS2017 timestamps have minute resolution; live capture uses the same 60 s window for per-source aggregates.

6. **Autoencoder ships as NumPy weights** (`autoencoder_weights.npz`) so the NIDS container needs no TensorFlow. Training checks NumPy vs Keras agree to 1e-6.

7. **Fusion priority** (`src/detection/engine.py`): signature hit > full model high-confidence > lite/medium/anomaly. Weak evidence needs 3 flagged flows from one source in 10 s before it alerts (corroboration), which kills isolated false positives. Alerts are grouped per (source, class, detector).

8. **Response** (`src/response/responder.py`): high severity = block (DROP), medium = quarantine (rate-limit), low = logged only. Rules live in a dedicated `NETRA` iptables chain; `unblock_all` just flushes it. Backends: `iptables` (real, in-container) and `dry-run` (host/tests). Never-block list protects loopback, gateways, the victim.

9. **Docker capture gotcha (fixed):** scapy captured undecoded Raw frames until `scapy.layers.l2`/`inet` were imported in `sniffer.py`. Also the NIDS shares the victim's network namespace (`network_mode: service:victim`) so it sees the victim's traffic and its iptables rules apply there; the host firewall is never touched. `NETRA_IFACE=auto` picks the interface whose address is in `10.77.0.0/24`.

10. **Ghost-flow fix:** the trailing ACK after a FIN used to open a fake 1-packet flow with a nonsense rate. `FlowTable` now ignores non-SYN packets on a just-closed 5-tuple for 2 s (`CLOSED_GRACE_S`). Tests cover it.

11. **PySide6 gotcha:** an attribute named `metric` on a `QChartView` shadows Qt's `QPaintDevice.metric()` and breaks painting. The traffic chart's field is `metric_key`. Don't rename it back.

## Measured results (test split, natural distribution)

- Full Random Forest: accuracy 0.9987, macro F1 **0.9570**, detection 99.80%, false positives 0.11%.
- Lite Random Forest (6 live features): macro F1 0.8400; weak on WebAttack (F1 0.25) and Bot (0.73) because those live in packet payloads, not flow stats. State this honestly in the report.
- Autoencoder: ROC-AUC 0.960, catches 38.9% of attacks at ~1% false alarms. Lower than the earlier 77.8% because that number was partly the flag-counter bug; this version works on real traffic. Explain the trade-off.
- Full numbers and confusion matrices: `reports/RESULTS.md` and the PNGs beside it.

### Phases 9 and 10 (done)

`presentation/build_ppt.py` builds `presentation/Netra.pptx` (25 slides, 16:9). It reads every
metric at build time from `reports/metrics_*.json` and `reports/data_summary.json`, so the deck
cannot drift from the measured results; rerun it after any retrain. Figures come from `reports/`
and `docs/screenshots/`. Slides carry speaker notes. Rebuild with:

```
.venv/Scripts/python.exe presentation/build_ppt.py
```

Docs added: `docs/DEMO_GUIDE.md` (pre-flight checklist, run sheet with exact commands,
one-command version, no-Docker fallback, reset, troubleshooting table, expected questions) and
`docs/REPORT.md` (paper-style, 6 references). README now has the architecture section, a docs
index and the attack-lab section.

**Corrections made during this phase (both were stale or wrong in earlier docs):**
- The clean-flow count is **2,195,946**, not 2,198,337. Verified against `data_summary.json`
  (2,830,743 - 2,867 - 631,253 - 630 - 47). README and this file were fixed.
- The lite model's WebAttack problem is **precision, not recall**. Recall is identical to the full
  model at 0.9626 (same 309 of 321 flows found); precision falls from 0.9841 to 0.1439 because the
  lite model labels 1,821 benign flows as WebAttack versus 3 for the full model. Any description
  that says the lite model "misses" web attacks is wrong.

Verification: the deck was rendered slide by slide to PNG through PowerPoint COM
(`$pp.Presentations.Open(...)`, `SaveAs(dir, 18)`) and each slide inspected for overflow and
layout. That is the only way to check a generated deck on this host; LibreOffice is not installed.

## Post-phase-10 additions (tier 1 features)

Three features added after the phased build finished. All three exist to test or tune the system
against something other than its own training distribution.

**1. Cross-dataset evaluation** (`src/data/unsw.py`, `src/models/cross_eval.py`, CLI `cross-eval`).
Runs the CIC-trained lite model unchanged over all 2,059,415 UNSW-NB15 flows. Only the lite model
can transfer: the 59 full features are CICFlowMeter's own output with no UNSW counterpart. Feature
arithmetic is shared with training via `preprocess.lite_flow_features`, so conversion is identical
on both sides.

**The headline result is a failure, and it is the most important number in the project:**
detection drops from **0.9976 in domain to 0.0003** on UNSW-NB15 (29 of 99,643 attacks). Every
attack category is predicted Benign. Verified not to be an artifact: at min confidence 0 (pure
argmax) it is 0.0004, and with header-byte correction 0.0002. The cause is in the feature medians:
UNSW benign traffic runs at 2,775 packets/s and UNSW *attacks* at 79 packets/s, while CIC benign
is 66 packets/s. The model learned "slow means attack" and UNSW's normal traffic is 40x faster than
CIC's, so the boundary points the wrong way. Do not present the 0.9976 as a general detection rate.

**2. Per-alert explanations** (`src/models/explain.py`). Exact Saabas decomposition of a Random
Forest prediction: `bias + sum(per-feature contributions) == predict_proba`, verified to 1e-15.
Implemented directly rather than via `treeinterpreter`/SHAP so the NIDS container gains no
dependency. Costs ~2.5 ms per flow, so only flows opening a *new* alert are explained, capped at
`EXPLAIN_MAX_PER_BATCH=20` per batch. Alerts now read: `DoS-Slow predicted by full/random_forest
with confidence 0.97, driven by Bwd Packets/s=0.0, Flow Packets/s=0.111, Flow IAT Mean=10500000`.

**3. Autoencoder threshold calibration** (`src/models/calibrate.py`, CLI `calibrate`). Re-derives
the threshold from local traffic. Measured in the lab: 222 completed flows gave median error 0.0776
and p99 0.0904 against the dataset threshold of 0.1463, so the shipped threshold is 1.6x too
tolerant for this network.

Gotchas found while building these:
- **Flush flows poison calibration.** `FlowTable.flush()` emits every still-open flow when capture
  stops; those are truncated and their rates describe the capture window. An early run collected
  12,042 near-identical flows this way and produced a threshold of 0.432 (2.95x too tolerant).
  Fixed by skipping `reason == "flush"` and by refusing any capture whose errors are degenerate
  (median >= 0.999 * p99, or fewer than 20 distinct values). Both are tested.
- **pandas 3.0 turns None into NaN** in object columns regardless of how they are built, and NaN is
  truthy, so `if not netra_class` silently breaks. The `netra_class` column is therefore documented
  as "use `pd.isna()`", and code needing real None reads `CATEGORY_MAP` directly.
- The **nids image bakes in `src/`**, so `docker compose build nids` is required before any new CLI
  command works inside the container.
- UNSW-NB15 data is gitignored (175 MB). Fetch with `bash data/download_unsw.sh` (SHA-256 pinned).

Tests went from 31 to 58: `tests/test_explain.py`, `tests/test_calibrate.py`, `tests/test_unsw.py`.

## Open-set recognition and unknown-family discovery (2026-11-04)

Added after a review found the project architecturally generic: a classifier plus an anomaly score
that emitted `"Anomaly (unknown)"` once per flow, with nothing in it. The ML alerts were already
labelled and explained; the anomaly path was not, and more importantly nothing in the system could
express "this matches none of my classes". This is now the project's distinguishing contribution.
Full method in `docs/REPORT.md` section 4.6, measured results in `reports/OPENSET.md`.

**New modules.** `src/models/openset.py` (conformal open-set test), `src/detection/discovery.py`
(online family clustering and naming), `src/models/openset_eval.py` and
`src/models/discovery_eval.py` (the three experiments). CLI: `openset-fit`, `openset-eval`,
`families [--promote ID NAME]`. API: `GET /api/families`, `POST /api/families/{id}/promote`. The
desktop app gained a "Unknown families discovered" panel with a button that names one.

**What took iterations, so do not redo it from scratch:**

1. **A single Gaussian per class does not work.** The first implementation used the
   class-conditional Mahalanobis score (Lee et al. 2018). CIC benign traffic is multi-modal, so one
   ellipsoid covers the gaps between its modes: UNSW attack flows came out at a median p-value of
   0.52 under Benign and *nothing* was ever rejected. The k-th nearest neighbour distance (k=10) in
   the same whitened metric separates them. Both scores are kept and both are reported, because the
   comparison is a result about the dataset. Do not "simplify" it back to one Gaussian.
2. **alpha = 0.01 is too strict to find novel attacks.** Measured per-class: held-out DoS-Slow is
   rejected 0.55 of the time at alpha 0.01 and 0.98 at 0.05; PortScan 0.004 and 0.385. The default
   is therefore 0.05, and the honest presentation is the whole operating curve, which is in the
   report. The known-traffic rejection rate tracks alpha to three decimals, so the conformal
   guarantee holds empirically.
3. **Euclidean clustering shatters a novel family.** The radius has to be calibrated against the
   known classes, which are dense (400,000 benign training flows), so it ends up far smaller than
   the spread of a novel attack seen a few dozen times: 25 near-identical novel flows produced 24
   families. Clustering on the unit *direction* of deviation from the benign mean, by cosine
   distance, has no scale problem and needs no tuning. `metric="euclidean"` is still available for
   the comparison.
4. **A second, stricter conformal level does NOT work. Do not reintroduce it.** At alpha 0.05 the
   benign tail enters the clusterer and is not always scattered: three marginally-unusual benign
   flows aligned, formed a family and quarantined a healthy host. The first fix was to require
   `DISCOVERY_MIN_FLOWS` flows rejected at a stricter level (0.01), which sounds right and is
   wrong. Measured over the leave-one-class-out folds it reported the novel family in **1 fold of
   7** while still admitting **164** families of ordinary traffic. The cause is structural: the
   routing level has already conditioned on the p-value, so among flows that reached the clusterer
   a rejected benign flow and a rejected novel flow have p-values from much the same range, and
   novel attack flows mostly land *between* the two levels. Combining member p-values (Fisher's
   method) inherits the same defect. What works is size: `DISCOVERY_MIN_FLOWS = 20` flows in a
   family, chosen from the measured curve that `discovery_eval` now emits. Part of the benign tail
   still clusters into reportable families, which is reported as a baselining cost rather than
   hidden; the naming workflow is what resolves those.
5. **A real bug this surfaced in the old engine.** `_raise` derived the firewall action from
   severity at the point of use and mapped everything not "high" to a quarantine, so an autoencoder
   alert at confidence 0.08 rate-limited a host, contradicting the engine's own docstring. The
   policy is now one table, `ACTION_FOR_SEVERITY`, and severity "low" takes no action.
6. **The family store cannot live in `models/`.** The NIDS container mounts it read-only, so
   `config.FAMILIES_PATH` is `logs/unknown_families.json`. It is runtime state, not an artifact.

**Performance notes.** The recogniser is brute-force k-NN against 4000 reference flows per class, so
cost scales with reference size, not training size. The engine's accept/reject path skips p-values
entirely (equivalent by construction, checked in tests) and tries the largest class first, which is
5.6x faster and puts a 2000-flow batch at about 220 ms. Fitting both feature sets takes about 66 s.
The leave-one-class-out sweep refits scaler, forest and recogniser per fold, so it takes tens of
minutes; use `--skip-leave-one-out` when iterating.

Tests went from 58 to 91: `tests/test_openset.py`, `tests/test_discovery.py`,
`tests/test_openset_engine.py`.

## What to do next

Phases 0 to 10 are complete. Remaining optional work:

1. Build the Packet Tracer `.pkt` file by following `docs/PACKET_TRACER_GUIDE.md` (manual, cannot
   be generated from code).
2. Regenerate the slide deck (`python presentation/build_ppt.py`) if the open-set results should
   appear in it; the builder reads `reports/*.json` and does not yet read `reports/openset.json`.
3. **Prose style (required if editing):** plain, direct, no em dashes, no marketing tone. Real
   measured numbers only.

## Notes

- Git: the repository tracks source, docs, `reports/` and the trained `models/` (41 MB, of which the
  two open-set recognisers are 10.6 MB; that is dominated by the reference flows kept per class, so
  `openset.MAX_REFERENCE` is the dial if it ever needs to shrink), so the lab
  runs after a clone without retraining. The CIC-IDS2017 data, `logs/` and `.venv/` are gitignored.
  Regenerate the models with `python -m src.cli train --days all` if needed.
- This is graded coursework. Each phase was confirmed before moving to the next, and the dashboard
  must stay a native desktop app (not a web page) because that was a specific requirement.
