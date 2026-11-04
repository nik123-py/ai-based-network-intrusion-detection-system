# Netra architecture

Netra is organised in six layers: ingestion, feature extraction, detection, open-set recognition and discovery, response, and presentation. Each layer is a separate module under `src/`, and all tunable values live in `src/config.py`.

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
                                  |                              | still "Benign"
                                  |                              v
                                  |                 +-------------------------+
                                  |                 | Open-set test           |
                                  |                 |  src/models/openset.py  |
                                  |                 |  conformal, per class   |
                                  |                 |  "none of these"        |
                                  |                 +------------+------------+
                                  |                              | rejected
                                  |                              v
                                  |                 +-------------------------+
                                  |                 | Family discovery        |
                                  |                 |  src/detection/         |
                                  |                 |    discovery.py         |
                                  |                 |  NETRA-U001, fingerprint|
                                  |                 +------------+------------+
                                  v                              v
                    +---------------------------------------------------------+
                    | Fusion and alerting        src/detection/engine.py      |
                    |  priority: signature > supervised > open-set > anomaly  |
                    |  corroboration for weak evidence, per-source grouping   |
                    |  a family alerts once it repeats at the alert level     |
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
3. Otherwise the open-set test is applied (section 4). A rejected flow goes to the clusterer and alerts only once its family repeats.
4. Otherwise an autoencoder error above the threshold sends the flow to the same clusterer, by the other route, carrying its per-feature reconstruction errors.

Weak evidence (the lite model, medium confidence) must appear on 3 flows from the same source within 10 seconds before an alert is raised. Alerts are grouped per source, class and detector over a 10 second cooldown, so a flood appears as one alert with a rising flow count.

The action taken for each severity is declared once, in `ACTION_FOR_SEVERITY`, rather than derived where it is used. That matters because the earlier version inferred it at the point of use and mapped everything that was not high to a quarantine, so a flow barely over the autoencoder threshold rate-limited a host. Severity low is now recorded and shown and touches no firewall rule, which `tests/test_openset_engine.py` checks.

**Explanations** (`src/models/explain.py`). An alert from a supervised model carries the features that produced it. For a Random Forest the predicted probability decomposes exactly into a bias term plus one contribution per feature: follow the sample from root to leaf, and attribute the change in class distribution at each step to the feature that split there. This is the Saabas decomposition, implemented directly so the container needs no extra dependency, and `tests/test_explain.py` checks it reproduces `predict_proba` to within 1e-9. Explaining one flow costs about 2.5 ms, so only flows that open a *new* alert are explained, and at most `EXPLAIN_MAX_PER_BATCH` per scoring batch, which stops a flood stalling the scoring loop. A non-tree model degrades to no explanation rather than a guess.

**Threshold calibration** (`src/models/calibrate.py`). The autoencoder threshold ships from CIC-IDS2017 benign flows. `python -m src.cli calibrate` re-derives it from the deployment network's own traffic. Flows cut off when capture stops are excluded, because their rates describe the capture window rather than the traffic, and a capture whose errors are too uniform to be a sample of normal activity is refused. The dataset threshold is kept as `threshold_dataset`, so `--reset` restores it.

## 4. Open-set recognition and unknown-family discovery

Everything in section 3 is closed-set. A Random Forest returns a distribution over the eight classes it was trained on, so a flow belonging to none of them is still assigned to one, and in practice that one is Benign. This layer supplies the verdict the classifiers cannot express, and then makes the verdict useful.

**The open-set test** (`src/models/openset.py`). Each class is summarised in the scaled feature space by its mean and a Ledoit-Wolf shrunk covariance; shrinkage is needed because Bot has 977 training flows against 59 features, where a sample covariance is singular. Averaging the class precisions gives one global metric, and its factor (`whitener`) turns that Mahalanobis metric into plain Euclidean distance.

The non-conformity of a flow against a class is then the distance to the k-th nearest *training flow* of that class (k = 10), not the distance to the class mean. The distinction is the whole result of this layer. CIC-IDS2017 benign traffic is strongly multi-modal, and a single Gaussian fitted across its modes describes an ellipsoid that also covers the empty space between them: measured on UNSW-NB15, the Gaussian score puts attack flows at a median p-value of 0.52 against Benign and rejects nothing, while under the k-nearest-neighbour score the same flows sit at four times the neighbour distance of real benign traffic. Both scores are fitted and calibrated, and `reports/OPENSET.md` reports both.

Raw scores are not comparable between classes, so each is converted to a conformal p-value against held-out flows of the same class:

```
p_c(x) = (1 + #{i in cal_c : s_c(x_i) >= s_c(x)}) / (n_cal_c + 1)
```

The metric and the reference flows come from the training split and the calibration scores from the validation split, which are disjoint, so p_c is approximately uniform on (0, 1] for a genuine member of class c. A flow is **known** when some class accepts it, `max_c p_c(x) >= alpha`. That gives alpha an exact operational meaning: it is the share of genuine known-class traffic routed to the unknown path. It is a price, known in advance, not a threshold found by trial.

For the engine the accept/reject decision is taken without computing p-values at all, because `p_c >= alpha` is equivalent to comparing the raw score against a fixed quantile of the calibration scores. Classes are tried largest first, so an ordinary benign flow is resolved against one class instead of eight. The two forms are checked to agree on every row in `tests/test_openset.py`. A batch of 2000 flows costs about 220 ms in the 59-feature space.

**Family discovery** (`src/detection/discovery.py`). A rejected flow on its own is the useless alert this project started with. Rejected flows are therefore clustered online by leader clustering, and what they are clustered on is the *direction* in which they deviate from normal traffic: whitened vector, minus the benign mean, normalised to unit length, compared by cosine distance.

Direction rather than distance, for a concrete reason. An absolute radius has to be calibrated against something, and the only things available are the known classes, which are dense: benign traffic has 400,000 training flows, so neighbour spacing inside it is far smaller than the spread of a novel attack seen a few dozen times. A radius that fits the known classes breaks a novel family into one cluster per flow, and a radius wide enough to hold the family absorbs unrelated traffic. Direction has no scale: the same attack run gently and run hard is one family, and the threshold is an angle that means the same thing on any network. Both metrics are implemented and measured.

Each family keeps a stable identifier (`NETRA-U001`), its flow and source counts, the nearest class the models do know with the p-value that class gave, and a fingerprint of the features that make it unusual, quoted in readable units. A family arriving by the autoencoder route uses that detector's per-feature reconstruction errors as its fingerprint instead, so the explanation is "the model could not reproduce this feature" rather than a distance.

**What makes a family worth reporting.** `OPENSET_ALPHA` (0.05) decides what enters the clusterer, and it is set for recall because nothing it admits raises an alert by itself. Reporting is decided by size: a family alerts once it holds `DISCOVERY_MIN_FLOWS` flows (20), a value read off the measured curve in `reports/OPENSET.md` rather than argued for.

Size rather than the strength of the individual rejections, and this was corrected by measurement. An earlier version required a number of flows rejected at a stricter conformal level, on the reasoning that a firmer rejection is better evidence. The leave-one-class-out sweep showed that reasoning fails twice over: it reported the novel family in 1 fold out of 7, because novel attack flows mostly land at p-values between the two levels, and it still admitted 164 families made of ordinary traffic, because deep benign outliers do occur. The p-value cannot do this job because the routing level has already conditioned on it: among the flows that reached the clusterer, a rejected benign flow and a rejected novel flow have p-values drawn from much the same range. What a benign tail does not do is put dozens of flows in the same direction.

Part of the benign tail does cluster, though, and the measurement says so: ordinary traffic produces a double-figure number of reportable families per fold, because some unusual-but-legitimate traffic is unusual the same way every time. These are not errors. They are patterns the deployment has and the training data did not describe, and the naming step is what resolves them: an operator identifies such a family once and it stops being an unexplained alert. That is the ordinary baselining cost of an anomaly detector, reported as a cost rather than hidden.

**Naming.** `promote_family` gives a family a real name, over the API, the CLI (`netra families --promote`) or the app. The name is persisted to `logs/unknown_families.json` with the centroid, so it survives a restart and every later alert about that family uses it. It sits beside the logs rather than in `models/` because it is runtime state and because the NIDS container mounts `models/` read-only. This is the operator's half of the loop: Netra can say "47 flows, 3 hosts, nothing I know"; only a person can say what it is.

## 5. Response

| Severity | Action | Rule |
|---|---|---|
| high | block for 120 s (90 s in the lab) | `iptables -A NETRA -s IP -j DROP` |
| medium | quarantine for 60 s | accept up to 10 packets/s from the source, drop the rest |
| low | logged only | none |

All rules live in a dedicated `NETRA` chain that is jumped to from INPUT and FORWARD. A background thread removes expired rules every second. A repeated alert extends an existing block instead of adding a duplicate rule, and a block replaces a quarantine. `unblock-all` flushes the chain. Addresses in `NETRA_NEVER_BLOCK` (loopback, lab gateways, the victim itself) are never blocked.

Every alert and action is written as one JSON line to `logs/alerts.jsonl`, rotated at 5 MB with 3 backups. Alerts and actions are also printed to the console.

## 6. Presentation

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
