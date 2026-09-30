# Netra: a hybrid network intrusion detection and response system

**NETRA: Network Threat Recognition and Automated response**

## Abstract

Network intrusion detection systems must do two things that pull against each
other: catch attacks that have never been seen before, and raise few enough
false alarms to be usable. Signature systems are precise but blind to anything
not written down in advance. Purely statistical systems generalise but produce
alert volumes that operators learn to ignore. This project builds Netra, a
hybrid detector that combines four packet-level signature rules, two supervised
classifiers trained on CIC-IDS2017, and an autoencoder trained only on benign
traffic, and then acts on what it finds by installing timed, reversible firewall
rules against the attacking source.

On the held-out CIC-IDS2017 test split, which keeps the natural class
distribution, the full Random Forest reaches accuracy 0.9987 and macro F1
0.9570, flagging 99.80 percent of attack flows while misclassifying 0.11 percent
of benign flows. A reduced "lite" model using only six features computable from
live packets reaches macro F1 0.8400. The autoencoder, which never saw an attack
during training, reaches ROC-AUC 0.9603 and detects 38.9 percent of attacks at a
1 percent false-alarm rate. The complete system was then validated live in an
isolated Docker lab against four real attack tools: every attack was detected
within about one second and the attacking host was automatically blocked with a
real iptables rule that expired on its own.

The main findings are negative and methodological. First, the TCP flag counters
in CIC-IDS2017 are unreliable, and models trained on them appear accurate offline
while failing on live traffic; removing all twelve flag features cost little
offline accuracy and was necessary for the system to work at all on real packets.
Second, evaluating the same model on UNSW-NB15, a dataset captured by different
researchers on a different network, drops the detection rate from 99.76 percent
to 0.03 percent. The feature distributions show why: ordinary UNSW-NB15 traffic
runs at roughly the packet rate CIC-IDS2017 associates with attacks, so the
learned boundary points the wrong way. Both failures were invisible to in-domain
metrics, and the reported accuracy should be read as describing CIC-IDS2017
rather than intrusion detection in general.

## 1. Introduction

An intrusion detection system observes network traffic and reports activity that
looks hostile. The classical split is between signature-based detection, which
matches traffic against known-bad patterns, and anomaly-based detection, which
models normal behaviour and reports departures from it. Signature systems
dominate in practice because they are precise and their alerts are explainable,
but they cannot detect an attack nobody has described yet. Anomaly systems
promise exactly that capability, and have promised it since the 1980s, but they
have a persistent reputation for false alarms.

This project takes the position that the choice is a false one, and that the
interesting engineering question is how to combine the two so that each covers
the other's weakness, and then what to do with the result. Detection without
response is only half a system: an alert that no one reads changes nothing.

Netra therefore has three goals:

1. **Detect** attacks using signature rules, supervised classification and
   unsupervised anomaly detection together, with an explicit policy for
   combining evidence of different strengths.
2. **Respond** automatically, by blocking the offending source, in a way that is
   time-limited and reversible so that a false positive is an inconvenience
   rather than an outage.
3. **Demonstrate** the whole thing end to end on live traffic, not only as
   offline metrics on a benchmark, because offline metrics on intrusion
   detection datasets are known to be optimistic.

The contributions are:

- A hybrid detection engine with an explicit fusion policy and a corroboration
  requirement for weak evidence (Section 4.4).
- An automated response layer using timed, reversible firewall rules with a
  never-block list (Section 4.5).
- A reproducible evaluation on CIC-IDS2017 with the natural class distribution
  preserved in validation and test, and with duplicate-driven leakage removed
  (Sections 3 and 6).
- A live validation in an isolated attack lab, showing that offline accuracy does
  not automatically survive contact with real packets, and documenting the
  specific dataset artefact that caused this (Sections 7 and 8.1).

## 2. Related work

**Benchmark datasets.** Intrusion detection research has long depended on a small
number of public datasets, and their flaws propagate into published results.
Tavallaee et al. [3] showed that KDD CUP 99 contains enormous numbers of
duplicate records, which inflate accuracy and bias classifiers toward frequent
attacks; their NSL-KDD revision removed them. Moustafa and Slay [2] introduced
UNSW-NB15 specifically because KDD-era data no longer resembled modern traffic.
Ring et al. [5] survey the field and conclude that dataset choice, labelling
quality and the presence of duplicates matter more to reported performance than
the choice of classifier. This project follows that guidance directly: duplicate
removal and cross-split leakage checks are part of the pipeline, not an
afterthought, and they remove 631,253 rows.

**CIC-IDS2017.** Sharafaldin et al. [1] produced CIC-IDS2017 to address the
realism problem, capturing five days of traffic with profiled benign behaviour
and a documented attack schedule, distributed both as raw PCAPs and as labelled
flow statistics from their CICFlowMeter tool. It is now among the most used
benchmarks in the area, which is why it was chosen here.

However, Engelen et al. [6] audited the dataset and its extraction tool and found
substantial defects, including incorrect TCP flag accounting and flows that are
terminated or labelled inconsistently. This project independently reproduced one
of their findings and found it decisive in practice: the flag counters cannot be
learned from (Section 8.1). This is a good example of Ring et al.'s general
warning becoming a concrete engineering constraint.

**Anomaly detection with autoencoders.** Mirsky et al. [4] introduced Kitsune, an
ensemble of autoencoders performing online anomaly detection on packet streams
without labels, and demonstrated it on real attacks with modest hardware. Netra's
autoencoder is a much simpler single dense network rather than an ensemble, and
is used as one voice in a fusion policy rather than as the whole detector, but it
borrows the central idea: train only on benign traffic and treat reconstruction
error as an anomaly score. The comparison in Section 8.2 is informative about
what a single autoencoder can and cannot do.

## 3. Dataset and preprocessing

### 3.1 Source

Netra uses CIC-IDS2017 [1]. Two releases of the same capture are used:
`GeneratedLabelledFlows`, which retains source and destination addresses and
timestamps, is the primary input, because the per-source window features and the
replay timeline need identifiers. `MachineLearningCSV`, the same flows without
identifiers, is kept as a reference. The published archives were verified by
SHA-256, and the label counts in the downloaded data match the counts published
by the dataset authors exactly, at 2,830,743 labelled flows.

### 3.2 Cleaning

The cleaning pipeline (`src/data/preprocess.py`) applies the following steps, in
order, and records the effect of each in `reports/data_summary.json`:

| Step | Rows removed |
|---|---|
| Rows containing NaN or infinite values | 2,867 |
| Exact duplicate rows | 631,253 |
| Rows with identical features but conflicting labels | 630 |
| Classes with fewer than 100 rows (Heartbleed 11, Infiltration 36) | 47 |
| **Remaining** | **2,195,946** |

Duplicate removal is the single largest effect, removing 22 percent of the data.
This matters because duplicates that survive into both the training and test
splits produce leakage and optimistic scores, which is precisely the criticism
Tavallaee et al. [3] levelled at KDD CUP 99. After splitting, the number of
feature vectors shared between any two splits is verified to be zero.

Fine-grained labels are mapped to eight classes: Benign, DoS, DDoS, DoS-Slow,
BruteForce, WebAttack, PortScan and Bot. DoS Hulk and DoS GoldenEye become DoS;
DoS Slowloris and DoS Slowhttptest become DoS-Slow, because they are slow-rate
attacks with a different traffic signature; FTP-Patator and SSH-Patator become
BruteForce. Matching is done on the lower-cased label with non-ASCII characters
stripped, because the published files contain a mis-encoded dash in the "Web
Attack" labels.

### 3.3 Features

The published CSVs contain 78 flow statistics. These reduce to 59 model inputs:

- one column (`Fwd Header Length.1`) is an exact duplicate of another and is
  dropped;
- twelve TCP flag counters are dropped as unreliable (Section 8.1);
- six bulk-transfer columns are constant across the entire dataset and carry no
  information.

Flow identifiers (addresses, ports, timestamps) are retained as metadata for
replay and windowing but are never used as model inputs, so the models cannot
memorise particular hosts. Destination port is deliberately excluded as well: in
this dataset it acts as a shortcut, since most DoS traffic targets port 80, and a
model leaning on it would not generalise to another network.

A second, reduced feature set of six "lite" features is defined for live
operation: flow duration, packets per second, payload bytes per second, mean
payload size, and the number of distinct destination ports and distinct
destination hosts contacted by the source in the preceding 60 seconds. These are
computable from packet headers alone in any environment. The 60 second window is
not arbitrary: CIC-IDS2017 timestamps have one-minute resolution, so training and
live capture use matching windows.

### 3.4 Splitting

The data is split 70 / 15 / 15 into training, validation and test, stratified by
class. Only the training split is capped, at 400,000 rows per class, which in
practice affects only the Benign class. Validation and test keep the natural
class distribution, so reported metrics reflect realistic traffic in which benign
flows outnumber attacks by roughly five to one. No resampling of any kind is
applied to the test split. The resulting splits are 635,280 training rows and
329,392 rows each for validation and test.

## 4. Methodology

Netra is organised in five layers: ingestion, feature extraction, detection,
response and presentation. The full structure is documented in
`docs/ARCHITECTURE.md`; this section covers the parts that carry the argument.

### 4.1 Ingestion and flow assembly

Three input paths produce the same feature schema: live capture with scapy, PCAP
replay, and replay of held-out dataset rows on a scripted timeline. Packets are
grouped into bidirectional flows keyed by the 5-tuple, following CICFlowMeter
conventions: the sender of the first packet defines the forward direction,
lengths count transport payload bytes, and active and idle periods are separated
by gaps longer than five seconds. A flow ends on RST, on FIN from both sides,
after five seconds idle, or after 120 seconds of life.

One implementation detail proved necessary. The trailing ACK that follows a FIN
would otherwise open a new single-packet flow with a meaningless rate, so the
flow table ignores non-SYN packets on a recently closed 5-tuple for two seconds.

### 4.2 Signature rules

Four rules run on every packet and fire within about a second, before any flow
has completed:

| Rule | Condition | Class |
|---|---|---|
| `syn_flood` | more than 100 SYN/s from one source | DoS |
| `port_scan` | more than 30 distinct destination ports from one source in 5 s | PortScan |
| `slow_dos` | at least 50 connections older than 5 s from one source averaging under 50 B/s | DoS-Slow |
| `brute_force` | more than 10 HTTP 401 replies to one client in 10 s, or more than 20 new connections to a login port in 5 s | BruteForce |

Each rule has a 10 second per-source cooldown, so a flood produces one alert with
a rising flow count rather than thousands of alerts.

### 4.3 Learned detectors

For each feature set, a Random Forest and an XGBoost classifier are trained, and
the one with the higher validation macro F1 is selected. Random Forest won for
both the full and the lite feature sets. Class imbalance is handled with balanced
class weights computed on the training split only. Macro F1 is used for selection
rather than accuracy, because with 85 percent benign traffic accuracy is nearly
uninformative.

The autoencoder is a dense network with layer sizes 69-32-16-8-16-32-69, trained
only on benign flows. A flow is anomalous when its reconstruction error exceeds
the 99th percentile of benign validation errors, which sets the threshold at
0.14632 and fixes the false-alarm rate at approximately 1 percent by
construction. The trained weights are exported to NumPy arrays so that the
deployed container needs no TensorFlow; training verifies that the NumPy and
Keras implementations agree to within 1e-6.

### 4.4 Fusion

Evidence of different strengths is combined by an explicit priority, evaluated
per flow:

1. A signature hit raises an alert immediately, at high severity.
2. Otherwise the full model is consulted, then the lite model. A predicted attack
   class with confidence at least 0.9 is high severity; between 0.6 and 0.9 is
   medium.
3. Otherwise, a reconstruction error above the autoencoder threshold raises
   "Anomaly (unknown)", at medium severity if the error is at least twice the
   threshold and low otherwise.

Weak evidence, meaning a lite-model hit, a medium-confidence prediction or an
anomaly, must be corroborated by three flagged flows from the same source within
10 seconds before any alert is raised. This is the mechanism that suppresses
isolated false positives, and it is why a single anomalous flow never triggers a
block. Alerts are grouped per source, class and detector.

### 4.5 Response

| Severity | Action |
|---|---|
| high | block: `iptables -A NETRA -s IP -j DROP`, 120 s (90 s in the lab) |
| medium | quarantine: accept 10 packets/s from the source, drop the rest, 60 s |
| low | logged only |

Three design choices make automated blocking defensible. Every rule is
time-limited and removed by a background thread on expiry, so the worst case for
a false positive is a bounded outage for one address rather than a permanent
one. All rules live in a dedicated `NETRA` chain, so the system's entire
footprint can be inspected with one command and removed with one more. A
never-block list protects loopback, the gateways and the protected server itself.
A repeated alert extends an existing block rather than stacking duplicate rules,
and a block supersedes a quarantine.

## 5. Experimental setup

Training and evaluation ran on a single Windows 11 laptop under Python 3.11,
using scikit-learn, XGBoost and TensorFlow (training only). The attack lab is
three Docker containers:

- `attacker` (10.77.0.66) with nmap, hping3, slowhttptest and hydra;
- `victim` (10.77.0.10) running stock nginx, serving a static page and a
  basic-auth protected `/admin/` area;
- `nids` running Netra, sharing the victim's network namespace so it observes
  every packet the victim sends or receives and its firewall rules apply to that
  traffic.

The lab network is internal, with no route to the internet, the host LAN or the
host itself, and published ports bind only to the loopback address. The attack
scripts additionally refuse any target outside 10.77.0.0/24. This arrangement is
equivalent to a monitoring host on a switch SPAN port combined with a firewall
that enforces its decisions; `docs/PACKET_TRACER_GUIDE.md` gives the
corresponding enterprise topology.

## 6. Results

All figures are measured on the held-out test split with its natural class
distribution, and are reproduced in `reports/RESULTS.md`.

### 6.1 Full feature set (59 features)

| Model | Accuracy | Macro F1 | Detection rate | False-positive rate | Inference (us/flow) |
|---|---|---|---|---|---|
| Random Forest (selected) | 0.9987 | 0.9570 | 0.9980 | 0.00112 | 2.51 |
| XGBoost | 0.9990 | 0.9561 | 0.9997 | 0.00102 | 5.20 |

In attack-versus-benign terms the Random Forest flags 50,314 of 50,417 attack
flows and wrongly flags 313 of 278,975 benign flows. Per-class F1 exceeds 0.97
for every class except Bot, at 0.7326 on 209 test flows.

The two classifiers are close enough that the choice between them is not
important; Random Forest was selected on validation macro F1 and is also twice as
fast at inference.

### 6.2 Lite feature set (6 features)

| Model | Accuracy | Macro F1 | Detection rate | False-positive rate |
|---|---|---|---|---|
| Random Forest (selected) | 0.9913 | 0.8400 | 0.9976 | 0.00965 |
| XGBoost | 0.9862 | 0.8071 | 0.9988 | 0.01552 |

Reducing 59 features to 6 costs 0.117 macro F1. The loss is not spread evenly.
Volumetric attacks survive almost intact: DDoS F1 0.9976, DoS 0.9923, DoS-Slow
0.9912, all essentially unchanged from the full model. The damage is concentrated
in the two classes that live in packet payloads rather than in traffic shape:
WebAttack collapses from 0.9732 to 0.2503, and Bot falls from 0.7326 to 0.6869.

The WebAttack collapse is worth reading carefully, because it is not a failure to
find attacks. Recall is identical in both models at 0.9626: the lite model finds
the same 309 of 321 WebAttack flows. What changes is precision, from 0.9841 to
0.1439, because the lite model also labels 1,821 benign flows as WebAttack
against only 3 for the full model. The class is not missed, it is drowned, and in
operation that is just as unusable.

This is the expected result and it is worth stating plainly: six header-derived
statistics are sufficient to recognise attacks that change the *shape* of
traffic, and insufficient to recognise attacks that change only its *content*.

### 6.3 Autoencoder

| ROC-AUC | Average precision | Detection rate | False-positive rate | Precision |
|---|---|---|---|---|
| 0.9603 | 0.7990 | 0.3887 | 0.01005 | 0.8748 |

The detection rate is low by design: the threshold is fixed at the 99th
percentile of benign validation error, which buys a 1 percent false-alarm rate
and gives up recall. What it detects is informative:

| Class | Share flagged as anomalous |
|---|---|
| DoS-Slow | 0.7302 |
| DoS | 0.4868 |
| DDoS | 0.2614 |
| PortScan | 0.1835 |
| BruteForce | 0.0036 |
| WebAttack | 0.0031 |
| Bot | 0.0000 |
| Benign | 0.0101 |

The autoencoder sees exactly what deviates from benign traffic in flow
statistics: slow-rate and volumetric denial of service. It is nearly blind to
brute force, web attacks and bot traffic, which are statistically ordinary at the
flow level. As a standalone detector this would be poor. As one input to a fusion
policy whose other members are strong on precisely the classes it misses, it is a
reasonable safety net for attacks with no label and no rule.

### 6.4 Live validation

The complete system was run in the Docker lab with the real iptables backend, and
each attack tool was executed from the attacker container against the victim.

| Attack tool | Alert raised | Detector | Response |
|---|---|---|---|
| nmap SYN scan | PortScan | `signature:port_scan` | source blocked |
| hping3 SYN flood | DoS | `signature:syn_flood` | source blocked |
| slowhttptest slow headers | DoS-Slow | `signature:slow_dos` | source blocked |
| hydra HTTP basic auth | BruteForce | `signature:brute_force` | source blocked |
| curl, normal browsing | none | n/a | none |

Every attack was detected and produced a real `DROP` rule against 10.77.0.66 in
the victim namespace's `NETRA` chain, with a countdown visible in the dashboard,
and `unblock-all` removed it. The benign baseline raised no alert.

Two observations from the live run are worth recording. First, the half-open
connections of the SYN flood also satisfy the slow-DoS rule and raise the
autoencoder's error, so the flood produces several corroborating alerts rather
than one; the intended `syn_flood` alert fires first. Second, the slow HTTP
attack genuinely exhausted nginx's connection pool, with slowhttptest reporting
the service as unavailable, while Netra detected it from the traffic pattern
rather than from the victim's health. Detection did not depend on the victim
being harmed.

### 6.5 Cross-dataset evaluation on UNSW-NB15

Sections 6.1 to 6.4 all measure performance on CIC-IDS2017 or on traffic
generated in a lab built around the same assumptions. They cannot distinguish a
model that learned about network traffic from one that learned about
CIC-IDS2017. To separate the two, the lite model was run unchanged over
UNSW-NB15 [2], a dataset captured by different researchers, on a different
network, with a different flow extractor. Nothing was retrained, refitted or
retuned: the model, the scaler and the feature code are the artifacts the live
system loads, and only the data is new.

Only the lite model can transfer. The 59 full features are CICFlowMeter's own
output and have no counterpart in UNSW-NB15's columns, whereas the six lite
features are generic flow statistics with direct equivalents. The feature
arithmetic is shared code, so a flow is converted identically in training and in
this test. All 2,059,415 UNSW-NB15 flows were scored, of which 99,643 are
attacks across ten categories.

The result is unambiguous:

| Measure | CIC-IDS2017 (in domain) | UNSW-NB15 (unseen) |
|---|---|---|
| Detection rate | 0.9976 | **0.0003** |
| False-positive rate | 0.00965 | 0.00061 |

29 of 99,643 attack flows were flagged. Every one of the ten attack categories
was predicted Benign for essentially all of its flows. This is not an artifact of
the confidence threshold: at a minimum confidence of 0, meaning pure argmax with
no threshold at all, the detection rate is 0.0004. Nor is it an artifact of the
two datasets counting bytes differently (CIC-IDS2017 counts transport payload,
UNSW-NB15 counts whole packets): correcting for an estimated 40 header bytes per
packet moves the detection rate to 0.0002.

The reason is visible in the feature distributions:

| Feature (median) | CIC benign | CIC attack | UNSW benign | UNSW attack |
|---|---|---|---|---|
| flow_duration | 0.06 | 63.12 | 0.03 | 0.30 |
| packets_per_sec | 65.53 | 0.19 | 2775.12 | 79.22 |
| bytes_per_sec | 3762.30 | 138.07 | 304559.25 | 41890.12 |
| mean_packet_size | 73.00 | 897.15 | 161.00 | 84.00 |
| src_unique_dst_ports | 4.00 | 1.00 | 59.00 | 8.00 |
| src_unique_dsts | 26.00 | 1.00 | 10.00 | 8.00 |

The decisive row is `packets_per_sec`. In CIC-IDS2017 a benign flow runs at about
66 packets per second and attacks are far slower, so the model learned that low
rates are suspicious. In UNSW-NB15 ordinary traffic runs two orders of magnitude
faster, and its attacks sit at 79 packets per second, which is almost exactly
where CIC-IDS2017 puts normal traffic. The learned decision boundary is not
merely in the wrong place; on this network it points the wrong way.

Two conclusions follow, and they should be stated separately because they have
different scope. The narrow one is that this model, as trained, does not transfer
to this network: the 0.9976 detection rate in section 6.2 describes CIC-IDS2017,
not intrusion detection in general. The broader one is that six flow statistics
do not carry enough information to define "attack" independently of the network
that produced the training data. Flow rate is a property of the link, the
application mix and the capture conditions at least as much as of hostile
intent. A model trained on absolute rates on one network has no principled reason
to work on another, and here it does not.

This does not invalidate the system. The signature rules, which carry the live
demonstration, are threshold-based and network-independent by construction, and
the autoencoder can be recalibrated against local traffic (section 6.6). It does
invalidate any claim that the supervised component generalises, and that claim is
therefore not made.

### 6.6 Threshold calibration against local traffic

The autoencoder's threshold is the 99th percentile of reconstruction error over
CIC-IDS2017 benign flows, which describes the dataset's idea of normal rather
than the deployment network's. `python -m src.cli calibrate` observes real
traffic, collects reconstruction errors and sets the threshold to the chosen
percentile of those, so the stated false-alarm rate means what it claims on the
network actually being watched.

Measured in the Docker lab over 40 seconds of ordinary web traffic (222
completed flows): median error 0.0776, 95th percentile 0.0861, 99th percentile
0.0904, against the dataset threshold of 0.1463. Calibrating tightens the
threshold to 0.0904, a factor of 0.62. The dataset threshold is therefore
substantially too tolerant for this network, and anomalies scoring between 0.09
and 0.146 would have been missed.

Two safeguards are built in, because calibration assumes the observed traffic is
benign and an unattended threshold change is a way to blind a detector. Flows
that were cut off when capture stopped are excluded, since their duration and
rates describe the capture window rather than the traffic. And a capture whose
errors are too uniform, meaning the median equals the 99th percentile or there
are fewer than 20 distinct error values, is refused outright: that pattern
indicates one repeated event rather than a sample of ordinary activity. The
original dataset threshold is always retained, so `--reset` restores it.

## 7. Discussion

### 7.1 The flag-counter problem

The most important finding in this project is negative, and it was only
discovered because the system was tested on live traffic.

CIC-IDS2017's TCP flag counters are wrong. `SYN Flag Count` is 0 on every
PortScan flow, although every such flow is by definition a SYN probe, and the FIN
and PSH counters are near zero throughout, although ordinary TCP connections
carry both. This matches the audit by Engelen et al. [6].

Models trained on these columns learn the extractor's bug rather than a property
of network traffic. Offline this is invisible, because the test split contains
the same bug. It became visible immediately in the lab: real benign web traffic,
in which connections legitimately carry FIN and PSH, was scored as anomalous, and
a normal client was quarantined.

All twelve flag features were therefore removed, leaving the full model with 59
inputs. The offline cost was small, and after the change benign live flows
score around 0.08 against the autoencoder's 0.146 threshold, comfortably below
it. The SYN ratio used by the SYN-flood rule is computed from live packets
directly and is never learned from the dataset.

The general lesson is the one Ring et al. [5] state and this project encountered
concretely: a model evaluated only against the dataset it was trained on can
score well by learning that dataset's artefacts. Offline metrics cannot detect
this. Live testing can, and did.

### 7.2 What each detector is actually for

The three detectors are not redundant, and the results show why:

- **Signature rules** are what make the live demonstration work. They fire in
  about one second on packets, need no flow to complete, and are unaffected by
  feature-parity problems between training and deployment. They only cover
  attacks that were anticipated.
- **Supervised models** classify flows the rules say nothing about, with high
  precision, but only for attack families present in the training labels.
- **The autoencoder** requires no attack labels at all. It contributes coverage
  for denial-of-service-shaped anomalies that no rule described, at a fixed 1
  percent false-alarm cost.

The fusion policy's corroboration requirement is what makes combining them
practical. Without it, the autoencoder's 1 percent false-alarm rate on 278,975
benign test flows would mean roughly 2,800 spurious alerts; requiring three
flagged flows from one source within 10 seconds before any weak-evidence alert
suppresses isolated errors while leaving sustained attacks, which by their nature
generate many flows from one source, fully detectable.

### 7.3 Limitations

- **The supervised model does not generalise across networks.** This is no
  longer a caveat but a measurement: section 6.5 shows the lite model detects
  0.03 percent of UNSW-NB15 attacks, against 99.76 percent in domain. The
  in-domain numbers describe CIC-IDS2017. Any deployment on another network
  would require retraining on traffic from that network, and the six lite
  features may be too few to support it at all.
- **Payload-blind.** No component inspects packet contents, so WebAttack
  detection in live operation is weak (lite F1 0.2503) and encrypted traffic is
  opaque to the flow-statistic detectors.
- **Source-address response.** Blocking by source address is defeated by
  spoofing and by distributed attacks, and can be weaponised by an attacker who
  spoofs a legitimate address to get it blocked. The timed expiry and never-block
  list bound the damage but do not eliminate this.
- **Lab scale.** The live validation used one attacker, one victim and one
  detector on a single host. Throughput under realistic traffic volumes, and the
  behaviour of the per-source state tables under many thousands of sources, are
  untested.
- **Known attacks in the live test.** The four demonstrated attacks are ones the
  signature rules cover. That makes the demonstration reliable, but it means the
  live test does not independently validate the ML detectors against novel
  attacks; the offline results in Section 6 carry that argument.

## 8. Conclusion and future work

Netra shows that signature rules, supervised classification and unsupervised
anomaly detection can be combined under an explicit fusion policy, and coupled to
an automated response, on hardware as modest as a single laptop. The full model
reaches macro F1 0.9570 with a 0.11 percent false-positive rate; the six-feature
live model reaches 0.8400; the autoencoder adds label-free coverage of
denial-of-service-shaped anomalies at ROC-AUC 0.9603. In live operation against
four real attack tools, every attack was detected within about a second and
answered with a timed, reversible firewall rule, while ordinary traffic raised no
alert.

The project's most useful results are the negative ones, and there are two. An
entire family of features in a widely used benchmark is unusable: models trained
on the TCP flag counters look excellent offline and fail on real packets, and
only live testing revealed it. And the supervised model, which reaches a 99.76
percent detection rate on its own benchmark, detects 0.03 percent of attacks on
a second dataset, because it learned flow rates that are a property of the
network it was trained on rather than of hostile behaviour.

Both failures were invisible to the metrics the project was reporting up to that
point, and both were found by evaluating the system against something other than
its own training distribution. Intrusion detection work that reports offline
metrics on a single benchmark cannot rule out either class of error.

Future work, in order of expected value:

1. **Network-invariant features.** Section 6.5 shows absolute flow rates do not
   transfer. Features expressed relative to a host's own baseline, such as a
   flow's rate as a multiple of that source's median rate, would be a direct
   attempt to fix the cause rather than the symptom, and could be tested with
   the cross-dataset harness already in place.
2. **Training across datasets.** Fitting on CIC-IDS2017 and UNSW-NB15 together
   and testing on a third capture would show whether the problem is this
   dataset or the feature set.
3. **Payload features** for the classes that flow statistics cannot separate,
   which would address the WebAttack and Bot weakness directly.
4. **Automatic recalibration**, extending the manual `calibrate` command of
   section 6.6 into a periodic background process with drift detection, so the
   threshold tracks the network instead of being set once.
5. **Richer response**, including redirection to a honeypot, graduated rate
   limiting before outright blocking, and enforcement through an external
   firewall API rather than local iptables, which would match the SPAN-port
   deployment model in the Packet Tracer topology.
6. **Ensemble anomaly detection** along the lines of Kitsune [4], to test whether
   an ensemble of small autoencoders over feature subsets improves on the single
   network used here.

## References

1. Sharafaldin, I., Lashkari, A. H., and Ghorbani, A. A. (2018). Toward
   Generating a New Intrusion Detection Dataset and Intrusion Traffic
   Characterization. *Proceedings of the 4th International Conference on
   Information Systems Security and Privacy (ICISSP)*.
2. Moustafa, N., and Slay, J. (2015). UNSW-NB15: a comprehensive data set for
   network intrusion detection systems. *Military Communications and Information
   Systems Conference (MilCIS)*, IEEE.
3. Tavallaee, M., Bagheri, E., Lu, W., and Ghorbani, A. A. (2009). A Detailed
   Analysis of the KDD CUP 99 Data Set. *IEEE Symposium on Computational
   Intelligence for Security and Defense Applications (CISDA)*.
4. Mirsky, Y., Doshi, T., Ju, M., Elovici, Y., and Shabtai, A. (2018). Kitsune:
   An Ensemble of Autoencoders for Online Network Intrusion Detection. *Network
   and Distributed System Security Symposium (NDSS)*.
5. Ring, M., Wunderlich, S., Scheuring, D., Landes, D., and Hotho, A. (2019). A
   Survey of Network-based Intrusion Detection Data Sets. *Computers and
   Security*, 86, 147-167.
6. Engelen, G., Rimmer, V., and Joosen, W. (2021). Troubleshooting an Intrusion
   Detection Dataset: the CICIDS2017 Case Study. *IEEE Security and Privacy
   Workshops (SPW)*.
