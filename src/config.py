"""Central configuration for Netra.

Every path, threshold and tunable used by more than one module lives here.
Values that need to change between the host and the Docker lab can be
overridden with environment variables prefixed ``NETRA_``.
"""

from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(f"NETRA_{name}", default)


def _env_int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _env_float(name: str, default: float) -> float:
    return float(_env(name, str(default)))


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(_env("DATA_DIR", str(ROOT_DIR / "data")))
# GeneratedLabelledFlows release (features plus IPs and timestamps). Primary input.
CICIDS_LABELLED_DIR = DATA_DIR / "cicids2017_labelled"
# MachineLearningCSV release (same flows, no identifiers). Reference only.
CICIDS_DIR = DATA_DIR / "cicids2017"
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = Path(_env("MODELS_DIR", str(ROOT_DIR / "models")))
REPORTS_DIR = Path(_env("REPORTS_DIR", str(ROOT_DIR / "reports")))
LOG_DIR = Path(_env("LOG_DIR", str(ROOT_DIR / "logs")))

# Artifacts written by training and read by the detection engine.
SCALER_PATH = MODELS_DIR / "scaler.joblib"
LITE_SCALER_PATH = MODELS_DIR / "lite_scaler.joblib"
FEATURES_PATH = MODELS_DIR / "feature_list.json"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"
DATA_SUMMARY_PATH = REPORTS_DIR / "data_summary.json"
SUPERVISED_META_PATH = MODELS_DIR / "supervised_meta.json"
LITE_META_PATH = MODELS_DIR / "lite_meta.json"
AUTOENCODER_PATH = MODELS_DIR / "autoencoder.keras"
AUTOENCODER_META_PATH = MODELS_DIR / "autoencoder_meta.json"


def model_path(kind: str, name: str) -> Path:
    """Path of a trained classifier, e.g. model_path("full", "xgboost")."""
    return MODELS_DIR / f"{kind}_{name}.joblib"

# ---------------------------------------------------------------------------
# Dataset and preprocessing
# ---------------------------------------------------------------------------
RANDOM_STATE = 42
TEST_SIZE = 0.15
VAL_SIZE = 0.15  # fraction of the whole dataset, taken from the non-test part

# Which capture days to load: "all", or a comma-separated list of day names
# such as "Wednesday,Friday" (these two contain DoS, DDoS and port scans).
DAYS = _env("DAYS", "all")

# Cap on rows per class in the TRAINING split only, to keep training time
# reasonable on a laptop. Benign dominates CIC-IDS2017, so in practice this
# only undersamples benign training flows. Validation and test splits keep the
# natural class distribution so reported metrics reflect realistic traffic.
# 0 disables the cap.
MAX_TRAIN_ROWS_PER_CLASS = _env_int("MAX_TRAIN_ROWS_PER_CLASS", 400_000)

# Classes with fewer rows than this after cleaning are dropped (for example
# Heartbleed has 11 rows, too few to learn or to evaluate meaningfully).
MIN_CLASS_COUNT = 100

# Fine-grained CIC-IDS2017 labels mapped to the coarser class set used by the
# models. Matching is done on the lower-cased label with non-ASCII characters
# removed, because the raw files contain a mis-encoded dash in "Web Attack".
LABEL_MAP: dict[str, str] = {
    "benign": "Benign",
    "dos hulk": "DoS",
    "dos goldeneye": "DoS",
    "dos slowloris": "DoS-Slow",
    "dos slowhttptest": "DoS-Slow",
    "ddos": "DDoS",
    "portscan": "PortScan",
    "ftp-patator": "BruteForce",
    "ssh-patator": "BruteForce",
    "bot": "Bot",
    "infiltration": "Infiltration",
    "heartbleed": "Heartbleed",
}
# Prefix rules applied when an exact match is not found.
LABEL_PREFIX_MAP: dict[str, str] = {
    "web attack": "WebAttack",
}
BENIGN_LABEL = "Benign"

# Columns in the CIC-IDS2017 CSVs that identify a flow rather than describe
# its behaviour. They are kept as metadata (for replay and the lite window
# features) but never used as model inputs, so models cannot memorise hosts,
# ports or times. Destination Port is excluded as well: in this dataset it acts
# as a shortcut (for example most DoS rows target port 80), which would not
# generalise to other networks.
META_COLUMNS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Timestamp",
]
LABEL_COLUMN = "Label"
# Exact duplicate of "Fwd Header Length" in every CIC-IDS2017 file.
REDUNDANT_COLUMNS = ["Fwd Header Length.1"]
# TCP flag counters. CICFlowMeter's flag counting is broken in CIC-IDS2017 (Engelen
# et al., 2021): for example SYN Flag Count is 0 on every PortScan flow and FIN Flag
# Count is 0 on almost all flows, although real TCP connections carry these flags.
# Models trained on them learn the tool's bug, and live traffic (where every normal
# connection has FIN and PSH set) then looks anomalous. They are excluded from the
# model inputs; flags are still used by the signature rules, which see real packets.
UNRELIABLE_FLAG_COLUMNS = [
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
]

# ---------------------------------------------------------------------------
# Lite feature set
# ---------------------------------------------------------------------------
# Features that are trivial to compute from live packets in any environment.
# The lite model trained on these guarantees the live demo works even if full
# CICFlowMeter feature parity is imperfect. Packet sizes follow CICFlowMeter
# and count transport payload bytes, not whole IP packets.
LITE_FEATURES = [
    "flow_duration",          # seconds
    "packets_per_sec",
    "bytes_per_sec",          # payload bytes per second
    "mean_packet_size",       # mean payload bytes per packet
    "src_unique_dst_ports",   # distinct destination ports contacted by source in window
    "src_unique_dsts",        # distinct destination IPs contacted by source in window
]
# The per-source aggregates above are computed over this window. CIC-IDS2017
# timestamps only have minute resolution, so training uses one-minute bins and
# live capture uses a matching 60 second window.
LITE_WINDOW_S = 60.0

# SYN ratio (SYN-flagged packets / all packets) is computed live and used by the
# SYN-flood signature, but it is not a lite model input: the CIC-IDS2017 flag
# counters are unreliable (SYN Flag Count is 0 on every PortScan flow, see
# Engelen et al., 2021), so a model cannot learn its real meaning from this data.
LIVE_EXTRA_FEATURES = ["syn_ratio"]

# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------
CAPTURE_INTERFACE = _env("IFACE", "eth0")  # "auto" picks the interface in LAB_SUBNET
LAB_SUBNET = _env("LAB_SUBNET", "10.77.0.0/24")
FLOW_TIMEOUT_S = _env_float("FLOW_TIMEOUT_S", 5.0)  # idle time before a flow is emitted
WINDOW_S = _env_float("WINDOW_S", 5.0)              # sliding window for per-source aggregates

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------
SYN_RATE_THRESHOLD = _env_float("SYN_RATE_THRESHOLD", 100.0)       # SYN packets/s per source
PORTSCAN_PORT_THRESHOLD = _env_int("PORTSCAN_PORT_THRESHOLD", 30)  # unique dst ports per window
SLOWDOS_CONN_THRESHOLD = _env_int("SLOWDOS_CONN_THRESHOLD", 50)    # concurrent open conns per source
SLOWDOS_MAX_BYTES_PER_S = _env_float("SLOWDOS_MAX_BYTES_PER_S", 50.0)
BRUTEFORCE_CONN_THRESHOLD = _env_int("BRUTEFORCE_CONN_THRESHOLD", 20)  # new conns to an auth port per window
BRUTEFORCE_401_THRESHOLD = _env_int("BRUTEFORCE_401_THRESHOLD", 10)  # HTTP 401 replies to one client per 10 s
AUTH_PORTS = {21, 22, 23, 3389}

SUPERVISED_CONFIDENCE = _env_float("SUPERVISED_CONFIDENCE", 0.90)  # "high confidence" alert
SUPERVISED_MIN_CONFIDENCE = _env_float("SUPERVISED_MIN_CONFIDENCE", 0.60)
AE_THRESHOLD_PERCENTILE = 99.0  # percentile of benign validation reconstruction error

# ---------------------------------------------------------------------------
# Explanations
# ---------------------------------------------------------------------------
# Each alert from a supervised model can carry the features that drove the
# prediction (src/models/explain.py). One explanation costs a few milliseconds,
# so only flows that open a NEW alert are explained, and at most this many per
# scoring batch, which bounds the cost during a flood.
EXPLAIN_ENABLED = _env("EXPLAIN_ENABLED", "1") == "1"
EXPLAIN_TOP_K = _env_int("EXPLAIN_TOP_K", 4)
EXPLAIN_MAX_PER_BATCH = _env_int("EXPLAIN_MAX_PER_BATCH", 20)

# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------
RESPONSE_ENABLED = _env("RESPONSE_ENABLED", "1") == "1"
# "iptables" runs real commands (inside the NIDS container), "dry-run" only
# records the rules it would have applied. Dry-run is the default on the host.
FIREWALL_BACKEND = _env("FIREWALL_BACKEND", "dry-run")
BLOCK_DURATION_S = _env_int("BLOCK_DURATION_S", 120)
QUARANTINE_DURATION_S = _env_int("QUARANTINE_DURATION_S", 60)
QUARANTINE_RATE = _env("QUARANTINE_RATE", "10/second")
# Addresses that must never be blocked (the NIDS itself, the lab gateway).
NEVER_BLOCK = set(filter(None, _env("NEVER_BLOCK", "127.0.0.1").split(",")))

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HOST = _env("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = _env_int("DASHBOARD_PORT", 8000)
ALERT_HISTORY = 500  # alerts kept in memory for newly connected browsers

ALERT_LOG_PATH = LOG_DIR / "alerts.jsonl"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3


def ensure_dirs() -> None:
    """Create the output directories if they do not exist."""
    for d in (MODELS_DIR, REPORTS_DIR, LOG_DIR, PROCESSED_DIR):
        d.mkdir(parents=True, exist_ok=True)
