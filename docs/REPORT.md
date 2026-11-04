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
rules against the attacking source. It adds a fourth detector that the usual
arrangement lacks: a conformal open-set test that allows the system to report
that a flow matches none of the classes it was trained on, together with an
online clusterer that groups such flows into named families an analyst can
identify.

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

The open-set layer is evaluated by removing each attack class from training, from
the feature scaling and from the calibration in turn, and replaying it. The
conformal construction holds: at a significance level of 0.05 it routes a
measured 0.0468 of known traffic to the unknown path, and the agreement between
promised and measured rates holds across two orders of magnitude of that level,
so the layer is configured by a false-alarm budget rather than by trial. In six
of the seven folds the closed-set classifier calls the majority of the unseen
attack benign, and in two it does so for every flow; for the best-separated class
the share of the attack that reaches nobody falls from 0.835 to 0.016. On
UNSW-NB15 it reports 95.1 percent of an entirely foreign network as matching
nothing it knows, against 4.7 percent in domain, which is a statement a
closed-set classifier cannot make at all.

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
3. Otherwise the open-set test of section 4.6 is applied. A flow it rejects
   belongs to no class the models were trained on, and is passed to the
   clusterer rather than alerted on directly.
4. Otherwise, a reconstruction error above the autoencoder threshold passes the
   flow to the same clusterer, carrying its per-feature reconstruction errors.

Weak evidence, meaning a lite-model hit or a medium-confidence prediction, must
be corroborated by three flagged flows from the same source within 10 seconds
before any alert is raised. This is the mechanism that suppresses isolated false
positives, and it is why a single anomalous flow never triggers a block. Alerts
are grouped per source, class and detector.

Steps 3 and 4 carry their own corroboration, of a different kind: the family a
flow is assigned to has to grow before it is reported, which is described in
section 4.6. The action taken for each severity is declared in one table in the
engine rather than derived where it is used. An earlier version inferred it at
the point of use and treated everything that was not high severity as a
quarantine, so a flow barely above the autoencoder threshold rate-limited a host;
severity low now means recorded and shown, with no firewall rule.

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

### 4.6 Open-set recognition and unknown-family discovery

Everything described so far is closed-set. A Random Forest returns a distribution
over the eight classes it was trained on, and `argmax` over that distribution has
no way to express that none of them fits. The consequence is not academic: it is
the mechanism behind the cross-dataset failure in section 6.5, where every attack
category in an unfamiliar network is reported as benign traffic with high
confidence. An intrusion detector that cannot say "I do not recognise this" has
no safe behaviour when it meets something new, which is the case that matters
most.

This section describes the layer that supplies the missing verdict, and then
makes it useful. It has two parts, and they divide the problem the way the
problem divides: a statistical test decides *whether* a flow is recognised, and a
clustering step decides *what* the unrecognised flows are.

#### 4.6.1 A conformal test for "none of these"

Each class is summarised in the scaled feature space by its mean and a covariance
estimated with Ledoit-Wolf shrinkage. Shrinkage is necessary rather than
decorative: Bot has 977 training flows against 59 features, where a sample
covariance is singular and its inverse meaningless. Averaging the per-class
precision matrices gives one global metric, whose matrix factor turns that
Mahalanobis metric into ordinary Euclidean distance, so every later step can use
plain distances.

The non-conformity of a flow with respect to class *c* is then its distance to
the *k*-th nearest training flow of class *c*, with *k* = 10. The alternative,
its Mahalanobis distance to the class mean, is the class-conditional Gaussian
score of Lee et al. (2018), and it was implemented first. It does not work here,
and the reason is a property of the data worth recording. CIC-IDS2017 benign
traffic is strongly multi-modal, mixing idle connections, name lookups,
interactive browsing and bulk transfer, and a single Gaussian fitted across those
modes describes an ellipsoid that also contains the empty space between them.
Measured against UNSW-NB15, the Gaussian score places attack flows at a median
p-value of 0.52 under the benign class, which is to say perfectly typical benign
traffic, and rejects nothing at any usable level. Under the nearest-neighbour
score the same flows sit at four times the neighbour distance of genuine benign
flows. Both scores are fitted and calibrated by the implementation, and both are
reported in section 6.7, because the gap between them is a result about the
dataset rather than a tuning detail.

A raw score cannot be compared across classes, which have different spreads, so
each is converted into a conformal p-value against held-out flows of the same
class:

p_c(x) = (1 + |{i in cal_c : s_c(x_i) >= s_c(x)}|) / (n_cal_c + 1)

The metric and the reference flows are taken from the training split and the
calibration scores from the validation split. The two are disjoint, which is what
makes this a valid conformal p-value: for a genuine member of class *c*, p_c is
approximately uniform on (0, 1]. A flow is called **known** when some class
accepts it at level alpha, that is when max_c p_c(x) >= alpha, and **unknown**
otherwise.

The value of this construction is that alpha is not a threshold discovered by
experiment. It is the share of genuine known-class traffic that the test will
route to the unknown path, fixed in advance by the mathematics and verifiable
afterwards. Section 6.7 reports the measurement against the promise.

For deployment the accept/reject decision is computed without p-values at all,
because p_c >= alpha is equivalent to comparing the raw score against a fixed
quantile of that class's calibration scores. The classes are tried largest first,
so an ordinary benign flow is resolved against one class rather than eight. The
two formulations are checked to agree on every row by the test suite, and a batch
of 2000 flows costs about 220 ms in the 59-feature space, which is well inside
the engine's scoring budget.

#### 4.6.2 From rejected flows to named families

A rejected flow on its own is exactly the alert this project began with: one line
per flow, labelled "Anomaly (unknown)", with nothing in it an operator can act
on. The second part of the layer groups rejected flows online, by leader
clustering, and what it clusters on is the *direction* in which a flow deviates
from normal traffic: the whitened feature vector, minus the benign class mean,
normalised to unit length, compared by cosine distance.

Direction rather than absolute distance, for a reason that only became clear by
measurement. A radius in absolute distance must be calibrated against something,
and the only reference available is the known classes, which are dense: benign
traffic has 400,000 training flows, so the spacing between neighbours inside it
is far smaller than the spread of a novel attack observed a few dozen times. A
radius fitted to the known classes shatters a novel family into one cluster per
flow, which is what the first implementation did; a radius wide enough to hold
the family absorbs unrelated traffic. Direction has no such scale. The same
attack run gently and run hard deviates the same way and forms one family, and
the threshold is an angle, which means the same thing on any network and needs no
dataset-specific tuning. Both metrics are implemented and both are measured in
section 6.7.

Each family carries a stable identifier of the form `NETRA-U001`, its flow and
source counts, the nearest class the models do know together with the p-value
that class assigned, and a fingerprint: the features that make the family
unusual, quoted in units an operator reads. A family that arrived by the
autoencoder route uses that detector's per-feature reconstruction errors as its
fingerprint instead, since "the model could not reproduce this feature" is the
more direct explanation when the autoencoder is what objected.

What decides that a family is worth reporting is its size: it alerts once it
holds `DISCOVERY_MIN_FLOWS` flows. That criterion was arrived at by measurement,
after a more sophisticated one failed, and the failure is worth recording because
the reasoning behind it is superficially convincing.

Routing at alpha = 0.05 admits the outer shell of ordinary benign traffic, and
those flows are not always scattered: in testing, three of them aligned closely
enough to form a family and quarantine a host that was doing nothing unusual. The
first response was to demand stronger evidence per flow, by requiring a number of
flows rejected at a stricter conformal level, 0.01 rather than 0.05, on the
reasoning that a firmer rejection is better evidence. The leave-one-class-out
sweep then showed this fails in both directions at once. It reported the novel
family in one fold out of seven, because a novel attack's flows mostly land at
p-values between the two levels, and it still admitted 164 families made of
ordinary traffic, because deep benign outliers do occur and three of them were
enough.

The reason is structural rather than a matter of picking a better level. The
routing decision has already conditioned on the p-value: among flows that reached
the clusterer at all, a rejected benign flow and a rejected novel flow have
p-values drawn from much the same range, so the p-value carries little further
information. Conditionally on being routed, a flow's p-value under the null is
approximately uniform on (0, alpha), which is exactly the distribution the
novel flows also present. Combining member p-values into a family-level
significance, by Fisher's method or otherwise, inherits the same problem.

What distinguishes a family is therefore not how firmly its members were
rejected but how many there are, because putting dozens of flows in the same
direction is something a benign tail does not do and an attack does by nature.
Section 6.7 reports the measured curve over that threshold, which is how the
value 20 was chosen, and reports honestly what it does not solve: part of the
benign tail does cluster into reportable families, because some
unusual-but-legitimate traffic is unusual the same way every time. Those are
patterns the deployment has and the training data did not describe, and the
naming step below is what resolves them.

Finally, a family can be promoted to a real name, through the desktop app, the
REST API or the command line. The name and the family centroid are persisted, so
the identification survives a restart and every later alert about that family
uses it. This is deliberately the one step the system does not attempt by itself.
Netra can establish that 47 flows from 3 hosts match nothing it was trained on,
and can describe how they differ from normal traffic; deciding what they are is a
judgement that belongs to an analyst, and the contribution here is that the
analyst is given one object to judge instead of several hundred unlabelled lines.

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

### 6.7 Open-set recognition and unknown-attack discovery

The results in this section answer a different question from those above. Sections
6.1 to 6.4 measure how well the system names attacks it was trained on. This one
measures what it does about attacks it was not, which is the case no in-domain
metric can speak to. All figures are produced by `python -m src.cli openset-eval`
and written to `reports/OPENSET.md`.

#### 6.7.1 The test is honest about its own cost

Every flow in the test split belongs to a class the recogniser was fitted on, so
anything it rejects is pure cost: traffic sent to the unknown path for no reason.
The conformal construction promises that share equals alpha, and because alpha is
chosen rather than discovered, the promise can be checked.

| alpha | Promised rejection of known traffic | Measured |
|---|---|---|
| 0.01 | 0.0100 | 0.0085 |
| 0.02 | 0.0200 | 0.0178 |
| 0.05 | 0.0500 | 0.0466 |
| 0.10 | 0.1000 | 0.0947 |
| 0.25 | 0.2500 | 0.2456 |
| 0.50 | 0.5000 | 0.4956 |

Measured over the whole test split at the deployed setting of alpha = 0.05, the
figure is 0.0468 for the nearest-neighbour score and 0.0461 for the Gaussian one.
Both are inside the bound, and the agreement across two orders of magnitude of
alpha is the property that makes this layer configurable by a false-alarm budget
instead of by trial. Per class the rate varies from 0.0000 (Bot) to 0.0585
(DoS-Slow), which is expected: the guarantee is per class and each class's own
p-values are only approximately uniform at finite calibration size.

#### 6.7.2 Attacks the system was never trained on

Each row of the table below is a separate experiment. One attack class is removed
from the training data, from the feature scaling and from the open-set
calibration, and that class's test flows are then replayed. Nothing in the fold
has ever seen the attack, so it stands in for a genuinely novel one. The
closed-set baseline is the Random Forest this project already uses, trained on
the same seven remaining classes.

| Held out | Test flows | AUC | Closed-set calls it Benign | Open-set rejects it | Silent before | Silent after |
|---|---|---|---|---|---|---|
| DoS-Slow | 1,590 | 0.984 | 0.832 | 0.982 | 0.835 | 0.016 |
| DDoS | 19,201 | 0.966 | 0.369 | 0.910 | 0.550 | 0.088 |
| DoS | 27,445 | 0.906 | 0.989 | 0.191 | 0.992 | 0.801 |
| PortScan | 278 | 0.871 | 0.935 | 0.385 | 0.950 | 0.601 |
| BruteForce | 1,373 | 0.866 | 1.000 | 0.206 | 1.000 | 0.794 |
| Bot | 209 | 0.760 | 1.000 | 0.010 | 1.000 | 0.990 |
| WebAttack | 321 | 0.149 | 0.931 | 0.050 | 0.994 | 0.944 |
| **mean** | | **0.786** | **0.865** | **0.390** | **0.903** | **0.605** |

AUC is the probability that a novel flow is ranked more anomalous than a known
one, independent of where any threshold is placed. "Silent" is the share of the
attack that an operator would never see at all, and the two silence columns are
defined to be comparable: before this layer, silence is everything the classifier
did not flag, which is more than the share it called Benign, because a flow
predicted as an attack below the alert confidence is equally invisible.

Three things in this table deserve to be stated plainly rather than averaged
away.

First, where the layer works it changes the outcome completely. For DoS-Slow,
98.4 percent of a wholly unseen attack is surfaced and the silent share falls
from 0.835 to 0.016; the closed-set model, meanwhile, files 83.2 percent of it as
benign traffic and the remainder as ordinary DoS. For DDoS silence falls from
0.550 to 0.088.

Second, in six of the seven folds the closed-set model calls the majority of the
unseen attack Benign, and in two of them it does so for every single flow. That
is the failure this layer exists to address, and it is not visible in any
in-domain metric: the same model reports macro F1 0.9570 on the classes it does
know.

Third, the layer does not rescue every case, and the AUC column says which. Bot
at 0.760 is weakly separable, consistent with it also being the class the
supervised model handles worst (precision 0.6156 in section 6.1). WebAttack at
0.149 is the instructive failure, because an AUC below 0.5 means its flows are
ranked as *more* typical than benign traffic itself. The per-class calibration
medians explain why: the 10-nearest-neighbour distance inside the benign class
has a median of 19.8 in the whitened metric, while held-out WebAttack flows sit
at 0.15, which is to say in the densest part of the benign distribution rather
than outside it. That is the payload-blindness of section 7.3 measured from a new
direction. At the level of flow statistics a SQL injection is an ordinary small
HTTP request, so it is genuinely inside the benign distribution, and no
significance level can place it outside.

The operating curve makes the alpha trade-off explicit. Averaged over the folds:

| alpha | Novel flows rejected | Known flows rejected |
|---|---|---|
| 0.01 | 0.096 | 0.0085 |
| 0.05 | 0.390 | 0.0466 |
| 0.10 | 0.616 | 0.0947 |
| 0.25 | 0.714 | 0.2456 |

The deployed value of 0.05 is low on this curve deliberately, because what alpha
decides is not what is alerted on but what enters the clusterer, and the next
section is what converts a 39 percent per-flow rejection rate into finding the
attack.

#### 6.7.3 The discovered families

Per-flow rates understate what an operator sees, because an attack produces many
flows and a family needs only some of them. This experiment replays the same
folds with the held-out class mixed back into 30,000 ordinary test flows, pushes
the whole mixture through the open-set test and the clusterer in arrival order,
and scores the resulting families against ground truth the clusterer never sees.

| Held out | Rejected | of those novel | Families | Reportable | Purity (class / tool) | Largest family's precision | Flows to report it |
|---|---|---|---|---|---|---|---|
| Bot | 1,395 | 2 | 226 | 2 | 0.996 / 0.996 | 0.667 | never |
| BruteForce | 1,540 | 283 | 188 | 3 | 0.991 / 0.990 | 1.000 | 268 |
| DDoS | 18,875 | 17,479 | 237 | 9 | 0.998 / 0.998 | 1.000 | 111 |
| DoS | 6,771 | 5,241 | 296 | 14 | 0.997 / 0.997 | 1.000 | 108 |
| DoS-Slow | 3,002 | 1,561 | 252 | 10 | 0.983 / 0.943 | 0.977 | 342 |
| PortScan | 1,520 | 107 | 236 | 2 | 0.976 / 0.976 | 0.721 | 1,307 |
| WebAttack | 1,403 | 16 | 235 | 2 | 0.996 / 0.994 | 1.000 | never |
| **mean** | | | | | **0.991 / 0.985** | **0.909** | **268 (median)** |

The novel family was reported in five of the seven folds. Across all seven, 42
families were reported in total and 16 of those were made of ordinary traffic,
which is between two and five per fold. That is the number an operator lives
with, and section 4.6.2's threshold is what sets it: the measured curve over the
reporting threshold is in `reports/OPENSET.md`, and the deployed value of 50
flows gives the same five folds as 20 or 30 do while reporting 16 families of
ordinary traffic instead of 112.

The two folds that are never reported are Bot and WebAttack, and they are the
two the previous section already identified as weakly separable. Their families
do form, correctly and purely, but at 3 and 16 flows they are too small to clear
the reporting threshold. Lowering that threshold to 15 recovers WebAttack at ten
times the baselining cost, which is the trade the curve makes explicit rather
than hiding.

The most interesting result here was not the one being measured. The families do
not correspond to the classes the models were trained on; they correspond to the
individual attack tools, which is finer. Three of CIC-IDS2017's coarse classes
are unions of two tools each, and the clusterer separates them without being
told they are different:

- the dominant BruteForce family is 274 FTP-Patator flows and 2 SSH-Patator;
- the dominant DoS family is 2,639 DoS Hulk flows and no GoldenEye at all;
- the dominant DoS-Slow family is 416 Slowhttptest flows and 10 benign.

This is why the per-fold recall figures should not be read as a defect. A recall
of 0.504 for DoS means the attack occupies two families rather than one, and the
reason is that it is two tools. It is also why purity and the adjusted Rand index
are reported against both ground truths: scoring against the coarse class
penalises the clusterer for making a distinction the label map erased. The
adjusted Rand index rises from 0.069 to 0.088 on average when scored against the
tools, and from 0.205 to 0.286 on the DoS fold specifically.

Those index values are low in absolute terms, and the reason is structural rather
than a failure of the clustering. At alpha = 0.05 roughly 1,400 ordinary flows
per fold enter the clusterer, most of them unusual in their own individual
direction, and they become a long tail of very small families: between 188 and
296 families per fold, of which only 2 to 14 are large enough to report. An index
computed over every flow handed to the clusterer is dominated by that tail.
Purity, which stays at 0.991 on average, says the thing that actually matters:
the families do not mix the novel attack with ordinary traffic. The operator
never sees the tail, because it never reaches the reporting threshold.

#### 6.7.4 Domain shift: a network the models were never trained on

Section 6.5 established that the lite model does not transfer to UNSW-NB15,
detecting 0.03 percent of its attacks. The open-set layer does not recover that
detection rate and cannot: the table of feature medians in section 6.5 shows that
UNSW attack flows run at 79 packets per second against CIC-IDS2017 benign
traffic's 66, so in this feature space they sit inside the benign distribution.
What changes is what the sensor reports about its own competence.

| Score | All flows unknown | UNSW attacks | UNSW normal | In domain, same test |
|---|---|---|---|---|
| nearest neighbour | 0.9509 | 0.0411 | 0.9776 | 0.0468 |
| Gaussian | 0.0022 | 0.0015 | 0.0022 | 0.0461 |

Measured over 500,000 UNSW-NB15 flows, 95.09 percent are reported as matching
nothing the models know, against 4.68 percent in domain: a factor of twenty. A
closed-set softmax cannot express this at all. On the same flows it returns
Benign with high confidence, so an operator reading its output would conclude the
network is quiet, when the correct conclusion is that the sensor is deployed
somewhere it was not trained for and needs retraining. Reporting that is not a
detection, but it is the difference between a wrong answer and no answer.

The row for the Gaussian score is the reason this report carries two
non-conformity scores rather than one. The class-conditional Gaussian is the
standard construction and it was implemented first; here it rejects 0.22 percent
of an entirely foreign network, which is to say it notices nothing. The cause is
that CIC-IDS2017 benign traffic is multi-modal, so one ellipsoid per class also
covers the empty space between the modes, and UNSW flows land in that empty
space with a median p-value of 0.52 against the benign class. The
nearest-neighbour score measures local density instead and does not have this
blind spot. The difference is a property of the data rather than a tuning
choice, which is why both are kept and both are reported.

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

The four detectors are not redundant, and the results show why:

- **Signature rules** are what make the live demonstration work. They fire in
  about one second on packets, need no flow to complete, and are unaffected by
  feature-parity problems between training and deployment. They only cover
  attacks that were anticipated.
- **Supervised models** classify flows the rules say nothing about, with high
  precision, but only for attack families present in the training labels.
- **The autoencoder** requires no attack labels at all. It contributes coverage
  for denial-of-service-shaped anomalies that no rule described, at a fixed 1
  percent false-alarm cost.
- **The open-set test and the clusterer** are the only part of the system that
  can report the absence of a verdict. The other three always produce one: a rule
  matches or stays silent, a classifier returns its best class, and the
  autoencoder returns a number. This layer is what distinguishes "no attack here"
  from "nothing here that I was taught", which are the same output in every other
  part of the pipeline and are not at all the same conclusion. Its contribution
  is not accuracy on known attacks, which it does not change, but a safe
  behaviour for the case the training data did not cover.

The fusion policy's corroboration requirement is what makes combining them
practical. Without it, the autoencoder's 1 percent false-alarm rate on 278,975
benign test flows would mean roughly 2,800 spurious alerts; requiring three
flagged flows from one source within 10 seconds before any weak-evidence alert
suppresses isolated errors while leaving sustained attacks, which by their nature
generate many flows from one source, fully detectable.

The open-set layer needed its own version of that rule, and for the same reason.
Its routing level admits a known share of ordinary traffic by construction, so
the flows it admits cannot be alerted on individually. Requiring a family to
grow to a measured size before it is reported is the equivalent safeguard, and
section 6.7 reports what it costs and what it prevents. Section 4.6.2 records why
the obvious alternative, demanding a firmer rejection per flow rather than more
flows, was tried first and does not work.

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
- **Novelty detection is uneven, and for one class it fails completely.** Section
  6.7 reports the per-class figures. Where an unseen attack occupies a region of
  the feature space that ordinary traffic does not, it is rejected reliably; where
  it does not, no significance level helps. The limiting case is WebAttack, whose
  held-out flows are ranked as *more* typical than benign traffic itself. That is
  not a defect in the test but the same payload-blindness noted above, measured
  from a different direction: at the level of flow statistics a SQL injection is
  an ordinary small HTTP request, so it is genuinely inside the benign
  distribution and no method using only these features can place it outside.
- **A discovered family is a cluster, not an identification.** The system can
  establish that a group of flows matches nothing it was trained on, say how many
  hosts produced them and describe how they differ from normal traffic. It cannot
  say what they are. Naming is left to an analyst by design, and the promoted
  name is not yet fed back into training, so a discovery does not become a ninth
  class until someone retrains.

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

Beyond that combination, the project's distinguishing capability is the ability
to decline to classify. A trained classifier has no way to report an attack it
was never shown: its output is a distribution over the classes in its training
labels, so the attack is assigned to the nearest of them, and the
leave-one-class-out experiment in section 6.7 shows that in six of seven cases
the nearest one is Benign and the attack passes in silence. A conformal open-set
test supplies the missing verdict at a false-alarm cost fixed in advance rather
than tuned, and an online clusterer turns the flows it rejects into named
families with readable fingerprints that an analyst can identify once and name
permanently. What the system contributes is not better accuracy on known attacks,
which it does not change, but a safe and informative behaviour in the case the
training data did not cover.

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
   which would address the WebAttack and Bot weakness directly. Section 6.7
   sharpens the case: held-out WebAttack flows are ranked as more typical than
   benign traffic, so they are not merely hard to separate at this level, they
   are inside the benign distribution, and no threshold or significance level
   can move them out of it.
4. **Retraining from promoted families.** A family an analyst has named is
   labelled data for a class the models do not have. Feeding it back into
   training would make each discovery a ninth class and close the loop that the
   naming step currently opens, which is the natural continuation of section
   4.6.2 and is why the promoted names are persisted rather than kept in memory.
5. **A discriminative embedding for the open-set test.** Distances are currently
   measured in the scaled feature space, where all features count equally once
   whitened. A representation trained to separate the classes, for example the
   co-occurrence structure of the forest's leaves, may raise the weaker
   per-class AUCs in section 6.7.2. The reference-sample cap of 4,000 flows per
   class, which coarsens the density estimate unevenly across classes, is the
   cheaper thing to try first.
6. **Correlating alerts into campaigns.** Alerts are currently per source, class
   and detector. Grouping them by attacker, victim and time into a single
   incident with an ordered kill-chain would turn a multi-stage intrusion into
   one narrative rather than dozens of separate alerts, and the unknown families
   would take their place in it as stages rather than as isolated findings.
7. **Automatic recalibration**, extending the manual `calibrate` command of
   section 6.6 into a periodic background process with drift detection, so the
   threshold tracks the network instead of being set once. The open-set unknown
   rate of section 6.7.4 is a natural trigger for it: in domain it sits at the
   configured alpha, and a sustained departure from that is a calibrated signal
   that the traffic has moved.
8. **Richer response**, including redirection to a honeypot, graduated rate
   limiting before outright blocking, and enforcement through an external
   firewall API rather than local iptables, which would match the SPAN-port
   deployment model in the Packet Tracer topology.
9. **Ensemble anomaly detection** along the lines of Kitsune [4], to test whether
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
