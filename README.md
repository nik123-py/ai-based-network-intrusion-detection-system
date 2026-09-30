# Netra

**NETRA: Network Threat Recognition and Automated response.** Netra is an AI-based network intrusion detection and response system. It trains machine learning models on the CIC-IDS2017 benchmark, scores live network flows with a hybrid of signature rules, supervised classifiers and an unsupervised autoencoder, and responds to detected attacks by blocking the offending source address for a limited time. The complete system, including an attack lab, runs on one laptop with Docker Desktop and no paid services.

> **Safety warning.** The attack scripts in this project (nmap, hping3, slowloris, hydra) must only be run inside the isolated Docker network created by `docker-compose.yml`, against the containers in this project. Do not point them at any other host or network.

## Architecture

Netra has five layers. Packets arrive from live capture, a PCAP file or a replay
of held-out dataset rows, and all three paths produce the same feature schema.

```
  packets ──┬─> signature rules ──────────────┐   (syn_flood, port_scan,
            │   fire in ~1 s, per packet      │    slow_dos, brute_force)
            │                                 v
            └─> flow assembly ──> ML scoring ──> fusion ──> response ──> desktop app
                59 CIC features    full RF        priority   timed        PySide6
                 6 lite features   lite RF        + corrob.  iptables     WebSocket
                                   autoencoder               NETRA chain
```

- **Ingestion** (`src/detection/sniffer.py`, `replay.py`): scapy capture, PCAP
  replay, or dataset replay.
- **Features** (`src/features/flow_features.py`): packets grouped into
  bidirectional flows by 5-tuple, following CICFlowMeter conventions. Produces
  the 59 model features and the 6 lite features computable from live packets.
- **Detection** (`src/detection/`): four packet-level signature rules, a full and
  a lite Random Forest, and an autoencoder trained only on benign traffic.
- **Fusion** (`src/detection/engine.py`): signature hit beats high-confidence
  supervised prediction beats lite/medium/anomaly. Weak evidence needs 3 flagged
  flows from one source within 10 s before it alerts, which suppresses isolated
  false positives.
- **Response** (`src/response/responder.py`): high severity blocks the source
  (DROP), medium rate-limits it, low is logged only. Every rule is timed,
  reversible, and confined to a dedicated `NETRA` iptables chain.
- **Presentation** (`src/dashboard/`): an event bus exposed over WebSocket and
  REST, consumed by a native PySide6 desktop app.

Full detail, including the fusion policy and the Docker topology, is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The enterprise-equivalent topology
is in [docs/PACKET_TRACER_GUIDE.md](docs/PACKET_TRACER_GUIDE.md).

## Presentation

The slide deck is generated, not hand-edited, so it always matches the measured
results. Every metric is read at build time from `reports/metrics_*.json` and
`reports/data_summary.json`:

```bash
python presentation/build_ppt.py        # writes presentation/Netra.pptx (25 slides)
```

Rerun it after any retraining. Slides include speaker notes.

## Validation and tuning

Three commands exercise the system beyond its own training data.

**Cross-dataset evaluation.** Runs the CIC-IDS2017-trained lite model, unchanged,
over UNSW-NB15 to test whether it learned about traffic or about its dataset:

```bash
bash data/download_unsw.sh        # about 175 MB, SHA-256 verified
python -m src.cli cross-eval      # writes reports/CROSS_DATASET.md and a figure
```

The measured answer is that it does not transfer: detection falls from 0.9976
in domain to 0.0003 on UNSW-NB15, because ordinary traffic there runs at roughly
the packet rate CIC-IDS2017 associates with attacks. Details and the feature
comparison that explains it are in [reports/CROSS_DATASET.md](reports/CROSS_DATASET.md)
and section 6.5 of the report.

**Threshold calibration.** The autoencoder threshold ships from CIC-IDS2017
benign flows. This retunes it on the traffic actually being watched:

```bash
python -m src.cli calibrate --seconds 300 --dry-run   # report without saving
python -m src.cli calibrate --seconds 300             # keep the new threshold
python -m src.cli calibrate --reset                   # restore the dataset value
```

Captures that are too uniform to be a sample of normal traffic are refused, and
flows cut off when capture stopped are excluded.

**Alert explanations.** Every alert from a supervised model carries the features
that drove it, computed by exact decision-path attribution, so an alert reads
`DoS-Slow predicted by full/random_forest with confidence 0.97, driven by
Bwd Packets/s=0.0, Flow Packets/s=0.111, Flow IAT Mean=10500000`. Disable with
`NETRA_EXPLAIN_ENABLED=0`.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layer-by-layer design, fusion policy, Docker topology |
| [docs/REPORT.md](docs/REPORT.md) | Paper-style report: methodology, results, discussion |
| [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md) | Step-by-step live demo run sheet and troubleshooting |
| [docs/PRESENTATION_SCRIPT.md](docs/PRESENTATION_SCRIPT.md) | What to say, slide by slide, with demo cues and likely questions |
| [docs/PACKET_TRACER_GUIDE.md](docs/PACKET_TRACER_GUIDE.md) | Cisco Packet Tracer topology build guide |
| [reports/RESULTS.md](reports/RESULTS.md) | Full measured metrics and confusion matrices |
| [reports/CROSS_DATASET.md](reports/CROSS_DATASET.md) | UNSW-NB15 transfer test and why it fails |

## Prerequisites

- Python 3.11
- Docker Desktop (Windows, macOS or Linux)
- About 2 GB of free disk space for the CIC-IDS2017 CSV files

## Setup

```bash
python3.11 -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

If Python 3.11 is not installed, [uv](https://docs.astral.sh/uv/) can provide it:

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv -r requirements.txt
```

## Dataset

Netra uses CIC-IDS2017 (Sharafaldin et al., 2018). Download and verify it with:

```bash
bash data/download_data.sh
```

The script fetches two releases of the same flows. `GeneratedLabelledFlows` (into `data/cicids2017_labelled/`) is the primary input because it includes source and destination IPs and timestamps. `MachineLearningCSV` (into `data/cicids2017/`) is the same data without identifiers. The official source requires a registration form, so the script downloads byte-identical archives from a public mirror and checks their SHA-256. The contents match the published CIC-IDS2017 label counts exactly (2,830,743 labelled flows). To use your own download from UNB instead, place the zip files in `data/` and run the script with `--local`.

Then preprocess:

```bash
python -m src.cli preprocess            # all five days, about 2.5 minutes
python -m src.cli preprocess --days Wednesday,Friday   # smaller subset
```

This writes cleaned, split data to `data/processed/` and the fitted scalers, label encoder and ordered feature list to `models/`. A summary of every cleaning step is saved to `reports/data_summary.json`.

## Training, demo and reset

Train and evaluate all models (writes `models/` and `reports/`):

```bash
python -m src.cli train --days all      # about 8 minutes
```

No-Docker demo (desktop app plus a scripted replay of real attack flows):

```bash
python -m src.cli demo
```

Full attack lab (Docker), with real capture, detection and response:

```bash
docker compose up -d --build            # attacker 10.77.0.66, victim 10.77.0.10, nids
python -m src.cli app --url ws://127.0.0.1:8000/ws   # desktop app, in another terminal
```

Reset (remove every block, then stop the lab):

```bash
python -m src.cli unblock-all --url http://127.0.0.1:8000
docker compose down
```

## Attack lab and demo

The attack scripts in `scripts/attacks/` run inside the isolated Docker lab, from
the attacker container against the victim. Each maps to one detector:

| Script | Tool | Netra alert |
|---|---|---|
| `portscan.sh` | nmap SYN scan | PortScan |
| `synflood.sh` | hping3 SYN flood | DoS |
| `slowloris.sh` | slowhttptest slow headers | DoS-Slow |
| `bruteforce.sh` | hydra against `/admin/` | BruteForce |
| `normal.sh` | curl loop | none (benign baseline) |

Every script refuses any target outside `10.77.0.0/24`, so the tools cannot be
pointed at another host. `scripts/run_demo.sh` drives the whole demo: it starts
the lab, waits for the victim, runs the benign baseline and then each attack, and
clears the blocks at the end.

```bash
bash scripts/run_demo.sh                 # interactive, pauses before each step
bash scripts/run_demo.sh --yes --down    # unattended, tears the lab down at the end
```

Open the desktop app (`python -m src.cli app --url ws://127.0.0.1:8000/ws`) in a
second terminal to watch each alert and the automatic, timed block appear live.

## Known constraints

- `cicflowmeter` releases from 0.3.0 onward require Python 3.12 or newer. Under Python 3.11 the newest usable release is 0.2.0, which is pinned. Netra also includes its own lightweight flow feature extractor and a "lite" model so the live demo does not depend on full CICFlowMeter parity.

- The CIC-IDS2017 TCP flag counters are unreliable: `SYN Flag Count` is 0 on every PortScan flow even though each is a SYN probe (a known CICFlowMeter issue, Engelen et al., 2021). The SYN ratio is therefore computed only from live packets and used by the SYN-flood rule, not learned by the lite model.
- CIC-IDS2017 timestamps have one-minute resolution, so per-source aggregates (distinct ports and hosts contacted) use 60 second windows in both training and live capture.

## Progress

| Phase | Description | Status |
|------|-------------|--------|
| 0 | Scaffold, pinned requirements, config | Done |
| 1 | Data pipeline | Done: 2,195,946 clean flows, 8 classes, 59 model features, no cross-split duplicates |
| 2 | Supervised models | Done: Random Forest selected, full macro F1 0.9570, lite 0.8400 |
| 3 | Autoencoder | Done: NumPy inference matches Keras, ROC-AUC 0.960 |
| 4 | Live capture and features | Done: verified on real packets inside Docker |
| 5 | Detection engine and response | Done: fusion, corroboration, timed iptables blocks |
| 6 | Dashboard | Done: PySide6 desktop app, light and dark |
| 7 | Docker lab | Done: `docker compose up` runs attacker, victim, nids |
| 8 | Attack scripts and demo | Done: four attacks plus `run_demo.sh`, all detected and blocked live |
| 9 | Presentation | Done: `presentation/build_ppt.py` builds a 25-slide `Netra.pptx` |
| 10 | Docs and report | Done: architecture, report, demo guide, Packet Tracer guide |

## References

1. Sharafaldin, I., Lashkari, A. H., and Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP.
2. Moustafa, N., and Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems. MilCIS, IEEE.
3. Tavallaee, M., Bagheri, E., Lu, W., and Ghorbani, A. A. (2009). A Detailed Analysis of the KDD CUP 99 Data Set. IEEE CISDA.
4. Mirsky, Y., Doshi, T., Ju, M., Elovici, Y., and Shabtai, A. (2018). Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection. NDSS.
5. Ring, M., Wunderlich, S., Scheuring, D., Landes, D., and Hotho, A. (2019). A Survey of Network-based Intrusion Detection Data Sets. Computers and Security.
