# Netra architecture

Netra is organised in five layers: ingestion, feature extraction, detection, response, and presentation. Each layer is a separate module under `src/`, and all tunable values live in `src/config.py`.

```
                    +---------------------------------------------------------+
  Live packets ---> | Ingestion        src/detection/sniffer.py               |
  (scapy)           |   parse_packet -> PacketInfo                            |
  PCAP file  -----> |                                                         |
  Dataset rows ---> |   src/detection/replay.py (held-out test flows)         |
                    +-------------+---------------------------+---------------+
                                  | every packet              | every packet
                                  v                           v
                    +---------------------------+   +-------------------------+
                    | Signature rules           |   | Feature extraction      |
                    | src/detection/signatures  |   | src/features/           |
                    |  syn_flood, port_scan,    |   |   flow_features.py      |
                    |  slow_dos, brute_force    |   | FlowTable -> FlowRecord |
                    +-------------+-------------+   |  69 CIC features        |
                                  |                 |  6 lite features        |
                                  |                 +------------+------------+
                                  |                              | completed flows
                                  |                              v
                                  |                 +-------------------------+
                                  |                 | ML scoring (batched)    |
                                  |                 |  full Random Forest     |
                                  |                 |  lite Random Forest     |
                                  |                 |  autoencoder (NumPy)    |
                                  |                 +------------+------------+
                                  v                              v
                    +---------------------------------------------------------+
                    | Fusion and alerting        src/detection/engine.py      |
                    |  priority: signature > supervised > anomaly             |
                    |  corroboration for weak evidence, per-source grouping   |
                    +----------------------------+----------------------------+
                                                 | alert
                                                 v
                    +---------------------------------------------------------+
                    | Response                   src/response/responder.py    |
                    |  block (DROP) or quarantine (rate limit), timed expiry  |
                    |  iptables chain NETRA, JSON-lines log                   |
                    +----------------------------+----------------------------+
                                                 | events (EventBus)
                                                 v
                    +---------------------------------------------------------+
                    | Event API  src/dashboard/api.py  (WebSocket + REST)     |
                    +----------------------------+----------------------------+
                                                 |
                                                 v
                    +---------------------------------------------------------+
                    | Desktop app  src/dashboard/app.py  (PySide6 / Qt)       |
                    +---------------------------------------------------------+
```

## 1. Ingestion

There are three input paths, and all of them produce the same feature schema:

- **Live capture** (`Sniffer.start`): scapy's `AsyncSniffer` on one interface. In the Docker lab the interface is found automatically as the one whose address is in the lab subnet.
- **PCAP replay** (`Sniffer.replay_pcap`): the same packet path fed from a file, optionally in real time.
- **Dataset replay** (`DatasetReplay`): rows from the held-out CIC-IDS2017 test split, scheduled on a scripted timeline. Rows keep their original addresses from the dataset. This path skips packet parsing, so it demonstrates the ML detectors and the responder but not the signature rules.

## 2. Feature extraction

`FlowTable` groups packets into bidirectional flows keyed by the 5-tuple, following CICFlowMeter conventions:

- The sender of the first packet defines the forward direction.
- Lengths are transport payload bytes.
- Durations and inter-arrival times are in microseconds.
- Active and idle periods are separated by gaps longer than 5 seconds.

A flow ends on RST, on FIN from both sides, after 5 seconds without packets, or after 120 seconds of lifetime.

Each completed flow yields:

- **69 CIC features**, the exact ordered list saved in `models/feature_list.json` during training. `align_to_schema` reorders any feature mapping to that list and fills missing or non-finite values with 0. A test checks that the live extractor produces every training feature.
- **6 lite features**: flow duration, packets per second, payload bytes per second, mean payload size, and the number of distinct destination ports and hosts contacted by the source in the last 60 seconds. The 60 second window matches the one-minute resolution of the CIC-IDS2017 timestamps used for training.
- **SYN ratio**, used only by rules. The CIC-IDS2017 TCP flag counters are unreliable (`SYN Flag Count` is 0 on every PortScan flow), so no model is trained on flags from this dataset.

The `cicflowmeter` package release that supports Python 3.11 (0.2.0) only emits a flow after 240 seconds of inactivity, so it is used only for offline PCAP conversion (`cicflowmeter_pcap_to_frame`, with a column mapping to CIC names).

## 3. Detection

**Signature rules** (`signatures.py`) run on every packet and fire within about a second:

| Rule | Condition (default) | Class |
|---|---|---|
| `syn_flood` | more than 100 SYN packets per second from one source | DoS |
| `port_scan` | more than 30 distinct destination ports from one source in 5 s | PortScan |
| `slow_dos` | at least 50 connections older than 5 s from one source, averaging under 50 bytes/s | DoS-Slow |
| `brute_force` | more than 10 HTTP 401 replies to one client in 10 s, or more than 20 new connections to a login port in 5 s | BruteForce |

Each rule has a 10 second cooldown per source.

**Supervised models.** A Random Forest and an XGBoost classifier are trained for each feature set. The one with the higher validation macro F1 is used; Random Forest won in both cases. Class imbalance is handled with balanced class weights on the training split only.

**Autoencoder.** A dense network (69-32-16-8-16-32-69) is trained on benign flows only. A flow is anomalous when its reconstruction error exceeds the 99th percentile of benign validation errors. The weights are exported to NumPy, so the container does not need TensorFlow. A check during training confirms that the NumPy and Keras outputs agree to within 1e-6.

**Fusion** (`engine.py`), per flow:

1. A signature hit raises an alert immediately with severity high.
2. Otherwise the full model is consulted, then the lite model. An attack class with confidence of at least 0.9 is high; confidence between 0.6 and 0.9 is medium.
3. Otherwise an autoencoder error above the threshold raises "Anomaly (unknown)". It is medium if the error is at least twice the threshold, otherwise low.

Weak evidence (the lite model, medium confidence, or an anomaly) must appear on 3 flows from the same source within 10 seconds before an alert is raised. Alerts are grouped per source, class and detector over a 10 second cooldown, so a flood appears as one alert with a rising flow count.

## 4. Response

| Severity | Action | Rule |
|---|---|---|
| high | block for 120 s (90 s in the lab) | `iptables -A NETRA -s IP -j DROP` |
| medium | quarantine for 60 s | accept up to 10 packets/s from the source, drop the rest |
| low | logged only | none |

All rules live in a dedicated `NETRA` chain that is jumped to from INPUT and FORWARD. A background thread removes expired rules every second. A repeated alert extends an existing block instead of adding a duplicate rule, and a block replaces a quarantine. `unblock-all` flushes the chain. Addresses in `NETRA_NEVER_BLOCK` (loopback, lab gateways, the victim itself) are never blocked.

Every alert and action is written as one JSON line to `logs/alerts.jsonl`, rotated at 5 MB with 3 backups. Alerts and actions are also printed to the console.

## 5. Presentation

The engine publishes every event (alert, alert update, action, block list, per-second statistics, status) on an in-process `EventBus`. `api.py` exposes the bus over a WebSocket (`/ws`) plus REST endpoints for the unblock actions. It serves no web page; it is only the channel between the engine (often inside Docker) and the desktop app.

The desktop app (`app.py`, PySide6) shows:

- stat tiles;
- a traffic-rate chart for packets, flows or bytes per second (one metric at a time, one y-axis);
- alerted flows by attack type;
- the alert feed, with severity shown as an icon and a word;
- blocked and quarantined addresses with live countdowns and unblock buttons;
- model and health status.

It reconnects automatically, has light and dark themes, and can save a screenshot for documentation.

## Docker lab topology

```
      host (127.0.0.1:8000 event API, 127.0.0.1:8080 victim web page)
                        |
                 mgmt network 10.78.0.0/24
                        |
   +--------------------+----------------------+
   | victim network namespace                  |
   |   victim (nginx)  10.77.0.10              |
   |   nids   (shares namespace: capture +     |
   |           iptables + event API :8000)     |
   +--------------------+----------------------+
                        |
            lab network 10.77.0.0/24 (internal: no external route)
                        |
                attacker 10.77.0.66
```

The NIDS shares the victim's network namespace (`network_mode: service:victim`), so it captures every packet the victim sends or receives. Its iptables rules act on exactly that traffic. This works like a host-based IPS on the protected server: in the Packet Tracer topology the equivalent is a monitoring host on a SPAN port together with a firewall that applies its blocks (see `PACKET_TRACER_GUIDE.md`).
