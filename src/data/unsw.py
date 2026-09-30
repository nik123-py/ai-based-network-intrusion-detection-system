"""Load UNSW-NB15 flows into Netra's lite feature schema, for cross-dataset testing.

Every learned component of Netra is trained on CIC-IDS2017. Reported accuracy on
that dataset's own test split cannot say whether the models learned properties of
network traffic or properties of CIC-IDS2017, and section 7.1 of docs/REPORT.md
shows that distinction is not academic: an entire feature family in CIC-IDS2017
turned out to encode a bug in the extraction tool. The standard way to answer the
question is to test on a second dataset collected by different people, on a
different network, with a different tool. UNSW-NB15 (Moustafa and Slay, 2015) is
that dataset.

Only the lite model transfers. The 59 full features are CICFlowMeter's own
output and have no counterpart in UNSW-NB15's 49 columns. The six lite features
are generic flow statistics, and each has a direct equivalent here:

    flow_duration          dur
    packets_per_sec        (spkts + dpkts) / dur
    bytes_per_sec          (sbytes + dbytes) / dur
    mean_packet_size       (sbytes + dbytes) / (spkts + dpkts)
    src_unique_dst_ports   distinct destination ports per source, per 60 s window
    src_unique_dsts        distinct destination hosts per source, per 60 s window

The arithmetic is not reimplemented: ``preprocess.lite_flow_features`` is called
directly, so a flow is turned into features by exactly the same code in training
and in this evaluation. The 60 second window matches config.LITE_WINDOW_S.

One measurement difference cannot be removed, and it matters. CIC-IDS2017's
"Total Length of Fwd/Bwd Packets" counts transport *payload* bytes, whereas
UNSW-NB15's sbytes/dbytes count whole packets including IP and TCP headers. Byte
rates and mean packet sizes are therefore systematically larger here for
identical traffic. ``header_correction=True`` subtracts an estimated 40 bytes of
header per packet to approximate payload, and the cross-evaluation reports both,
so the effect of this mismatch on the result is visible rather than assumed.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from src import config
from src.data.preprocess import lite_flow_features

log = logging.getLogger(__name__)

UNSW_DIR = config.DATA_DIR / "unsw"
UNSW_PARQUET = UNSW_DIR / "UNSW_Flow.parquet"

# Bytes of IPv4 + TCP header assumed per packet when approximating payload.
HEADER_BYTES_PER_PACKET = 40.0

# UNSW-NB15 category -> Netra class, where the two describe the same thing.
# The rest have no Netra equivalent: they are attacks Netra was never trained to
# name, so they count towards binary detection only. Saying so is the point of
# the experiment, not a gap in it.
CATEGORY_MAP: dict[str, str | None] = {
    "normal": config.BENIGN_LABEL,
    "dos": "DoS",
    "reconnaissance": "PortScan",
    "exploits": None,
    "generic": None,
    "fuzzers": None,
    "analysis": None,
    "backdoor": None,
    "backdoors": None,
    "shellcode": None,
    "worms": None,
}

COLUMNS = ["source_ip", "destination_ip", "destination_port", "dur",
           "sbytes", "dbytes", "spkts", "dpkts", "stime", "attack_label", "binary_label"]


def available() -> bool:
    return UNSW_PARQUET.exists()


def load(path=None, header_correction: bool = False, limit: int | None = None) -> pd.DataFrame:
    """UNSW-NB15 flows as Netra lite features, plus labels.

    Returns a frame with config.LITE_FEATURES, ``is_attack`` (bool),
    ``category`` (UNSW label) and ``netra_class`` (mapped class, or None).
    """
    path = path or UNSW_PARQUET
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Fetch it with: bash data/download_unsw.sh")

    df = pd.read_parquet(path, columns=COLUMNS)
    if limit:
        df = df.iloc[:limit].copy()
    log.info("UNSW-NB15: %d flows loaded", len(df))

    packets = (df["spkts"].to_numpy(np.float64) + df["dpkts"].to_numpy(np.float64))
    total_bytes = (df["sbytes"].to_numpy(np.float64) + df["dbytes"].to_numpy(np.float64))
    if header_correction:
        # Approximate transport payload, which is what CIC-IDS2017 counts.
        total_bytes = np.maximum(total_bytes - HEADER_BYTES_PER_PACKET * packets, 0.0)

    out = pd.DataFrame(index=df.index)
    for name, values in lite_flow_features(df["dur"].to_numpy(np.float64), packets, total_bytes).items():
        out[name] = values.astype(np.float32)

    # Per-source aggregates over the same 60 second window used in training.
    window = (df["stime"].to_numpy(np.int64) // int(config.LITE_WINDOW_S))
    grouped = df.assign(_w=window).groupby(["source_ip", "_w"], observed=True, sort=False)
    out["src_unique_dst_ports"] = grouped["destination_port"].transform("nunique").astype(np.float32)
    out["src_unique_dsts"] = grouped["destination_ip"].transform("nunique").astype(np.float32)

    category = df["attack_label"].astype(str).str.strip().str.lower()
    out["category"] = category.to_numpy()
    out["is_attack"] = df["binary_label"].to_numpy().astype(bool)
    # Categories with no Netra equivalent become a missing value here: pandas
    # stores this column as a string dtype and converts None to NaN whatever it
    # is built from. Test it with pd.isna(), not "is None"; NaN is truthy, so a
    # plain "if not netra_class" would silently treat unmapped as mapped. Code
    # that needs the real None should read CATEGORY_MAP directly, as
    # cross_eval.py does.
    out["netra_class"] = [CATEGORY_MAP.get(c) for c in category]

    unknown = sorted(set(category.unique()) - set(CATEGORY_MAP))
    if unknown:
        log.warning("UNSW categories with no mapping entry: %s", unknown)

    missing = [c for c in config.LITE_FEATURES if c not in out.columns]
    if missing:
        raise RuntimeError(f"lite features missing after mapping: {missing}")
    # A non-finite feature would silently poison the scaler; there should be none.
    finite = np.isfinite(out[config.LITE_FEATURES].to_numpy(np.float64)).all(axis=1)
    if not finite.all():
        log.warning("dropping %d UNSW flows with non-finite features", int((~finite).sum()))
        out = out[finite]
    return out.reset_index(drop=True)


def summary(df: pd.DataFrame) -> dict:
    counts = df["category"].value_counts().to_dict()
    return {
        "flows": int(len(df)),
        "attacks": int(df["is_attack"].sum()),
        "benign": int((~df["is_attack"]).sum()),
        "categories": {k: int(v) for k, v in counts.items()},
        "mapped_categories": {k: v for k, v in CATEGORY_MAP.items() if v and k in counts},
    }
