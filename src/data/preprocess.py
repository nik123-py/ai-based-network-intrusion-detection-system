"""Clean CIC-IDS2017, derive lite features, split, scale and persist artifacts.

Pipeline (see ``run``):
 1. Load all selected day files (``loader.load_cicids2017``).
 2. Map fine-grained labels to the coarse class set in ``config.LABEL_MAP``.
 3. Compute lite features. The per-source window aggregates are computed on
    the complete traffic, before any rows are removed, because they describe
    everything a source did in that minute.
 4. Drop rows with NaN or infinite feature values.
 5. Remove duplicates: exact repeats of (features, class) are collapsed to one
    row, and feature vectors that appear with more than one class are dropped
    as ambiguous. After this step every feature vector is unique, so no flow
    can appear in more than one split.
 6. Drop classes with fewer than ``config.MIN_CLASS_COUNT`` rows.
 7. Stratified train/validation/test split.
 8. Cap rows per class in the training split only.
 9. Drop features that are constant in the training split.
10. Fit scalers on the training split only and persist every artifact.
"""

from __future__ import annotations

import json
import logging

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, StandardScaler

from src import config
from src.data.loader import load_cicids2017

log = logging.getLogger(__name__)

CLASS_COLUMN = "Class"
# Columns carried alongside the features for replay and analysis. Never model inputs.
KEEP_META = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp", "Day"]
# Durations below this are treated as this value when computing rates, matching
# the microsecond resolution of CICFlowMeter and of the live extractor.
MIN_DURATION_S = 1e-6


# ---------------------------------------------------------------------------
# Building blocks (also used by tests and by the live feature extractor)
# ---------------------------------------------------------------------------
def signed_log1p(x):
    """sign(x) * log(1 + |x|). Compresses the heavy tails of rate and size features."""
    x = np.asarray(x, dtype=np.float64)
    return np.sign(x) * np.log1p(np.abs(x))


def make_scaler() -> Pipeline:
    return Pipeline([
        ("log", FunctionTransformer(signed_log1p, feature_names_out="one-to-one")),
        ("std", StandardScaler()),
    ])


def map_label(raw: str) -> str | None:
    """Map a normalised CIC-IDS2017 label to the coarse class set, or None if unknown."""
    key = raw.lower()
    if key in config.LABEL_MAP:
        return config.LABEL_MAP[key]
    for prefix, cls in config.LABEL_PREFIX_MAP.items():
        if key.startswith(prefix):
            return cls
    return None


def feature_columns(df: pd.DataFrame) -> list[str]:
    """CICFlowMeter feature columns in file order (identifiers and labels excluded)."""
    excluded = (set(config.META_COLUMNS) | set(config.REDUNDANT_COLUMNS) | set(config.UNRELIABLE_FLAG_COLUMNS)
                | {config.LABEL_COLUMN, CLASS_COLUMN, "Day"} | set(config.LITE_FEATURES))
    return [c for c in df.columns if c not in excluded]


def lite_flow_features(duration_s, total_packets, total_bytes) -> dict[str, np.ndarray]:
    """Per-flow lite features. Shared by training (from CIC columns) and live capture."""
    duration_s = np.asarray(duration_s, dtype=np.float64)
    total_packets = np.maximum(np.asarray(total_packets, dtype=np.float64), 1.0)
    total_bytes = np.asarray(total_bytes, dtype=np.float64)
    effective = np.maximum(duration_s, MIN_DURATION_S)
    return {
        "flow_duration": duration_s,
        "packets_per_sec": total_packets / effective,
        "bytes_per_sec": total_bytes / effective,
        "mean_packet_size": total_bytes / total_packets,
    }


def add_lite_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add the lite feature columns, derived from CIC-IDS2017 columns."""
    duration_s = df["Flow Duration"].to_numpy(np.float64) / 1e6  # CIC durations are microseconds
    packets = (df["Total Fwd Packets"] + df["Total Backward Packets"]).to_numpy(np.float64)
    payload = (df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]).to_numpy(np.float64)
    for name, values in lite_flow_features(duration_s, packets, payload).items():
        df[name] = values.astype(np.float32)

    # Per-source aggregates over one-minute windows (the timestamp resolution).
    window = df["Timestamp"].dt.floor(f"{int(config.LITE_WINDOW_S)}s")
    keys = [df["Day"], df["Source IP"], window]
    grouped = df.groupby(keys, observed=True, sort=False, dropna=False)
    df["src_unique_dst_ports"] = grouped["Destination Port"].transform("nunique").astype(np.float32)
    df["src_unique_dsts"] = grouped["Destination IP"].transform("nunique").astype(np.float32)
    return df


def row_hashes(df: pd.DataFrame, columns: list[str]) -> pd.Series:
    return pd.util.hash_pandas_object(df[columns], index=False)


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------
def clean(df: pd.DataFrame, stats: dict) -> pd.DataFrame:
    stats["rows_loaded"] = len(df)

    for col in config.REDUNDANT_COLUMNS:
        if col in df.columns:
            df = df.drop(columns=col)

    df[CLASS_COLUMN] = df[config.LABEL_COLUMN].map(map_label)
    unknown = df[CLASS_COLUMN].isna()
    if unknown.any():
        log.warning("dropping %d rows with unmapped labels: %s", unknown.sum(),
                    sorted(df.loc[unknown, config.LABEL_COLUMN].unique()))
        df = df[~unknown]

    df = add_lite_features(df)
    feats = feature_columns(df)
    all_feats = feats + config.LITE_FEATURES

    values = df[all_feats].to_numpy()
    bad = ~np.isfinite(values).all(axis=1)
    stats["rows_nan_or_inf_dropped"] = int(bad.sum())
    df = df[~bad]

    before = len(df)
    df = df.drop_duplicates(subset=feats + [CLASS_COLUMN])
    stats["rows_exact_duplicates_dropped"] = before - len(df)

    h = row_hashes(df, feats)
    classes_per_vector = df.groupby(h.values)[CLASS_COLUMN].nunique()
    ambiguous = set(classes_per_vector.index[classes_per_vector > 1])
    conflict = h.isin(ambiguous).to_numpy()
    stats["rows_conflicting_labels_dropped"] = int(conflict.sum())
    df = df[~conflict]

    counts = df[CLASS_COLUMN].value_counts()
    rare = sorted(counts[counts < config.MIN_CLASS_COUNT].index)
    stats["classes_dropped_as_rare"] = {c: int(counts[c]) for c in rare}
    df = df[~df[CLASS_COLUMN].isin(rare)]

    stats["rows_after_cleaning"] = len(df)
    stats["class_counts_after_cleaning"] = {k: int(v) for k, v in df[CLASS_COLUMN].value_counts().items()}
    return df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------
def split(df: pd.DataFrame, seed: int = config.RANDOM_STATE) -> dict[str, pd.DataFrame]:
    """Stratified train/validation/test split (sizes from config)."""
    rest, test = train_test_split(df, test_size=config.TEST_SIZE, stratify=df[CLASS_COLUMN],
                                  random_state=seed)
    val_fraction = config.VAL_SIZE / (1.0 - config.TEST_SIZE)
    train, val = train_test_split(rest, test_size=val_fraction, stratify=rest[CLASS_COLUMN],
                                  random_state=seed)
    return {"train": train, "val": val, "test": test}


def cap_per_class(df: pd.DataFrame, cap: int, seed: int = config.RANDOM_STATE) -> pd.DataFrame:
    if cap <= 0:
        return df
    parts = [g.sample(n=min(len(g), cap), random_state=seed)
             for _, g in df.groupby(CLASS_COLUMN, observed=True)]
    return pd.concat(parts).sample(frac=1.0, random_state=seed)


def cross_split_overlap(splits: dict[str, pd.DataFrame], columns: list[str]) -> dict[str, int]:
    """Count feature vectors shared between each pair of splits (should be zero)."""
    hashes = {name: set(row_hashes(part, columns)) for name, part in splits.items()}
    names = list(hashes)
    return {f"{a}&{b}": len(hashes[a] & hashes[b])
            for i, a in enumerate(names) for b in names[i + 1:]}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run(days: str | None = None) -> dict:
    config.ensure_dirs()
    stats: dict = {"days": days or config.DAYS}

    df = load_cicids2017(days=days)
    df = clean(df, stats)

    splits = split(df)
    del df
    splits["train"] = cap_per_class(splits["train"], config.MAX_TRAIN_ROWS_PER_CLASS)
    stats["max_train_rows_per_class"] = config.MAX_TRAIN_ROWS_PER_CLASS

    candidate = feature_columns(splits["train"])
    constant = [c for c in candidate if splits["train"][c].nunique() <= 1]
    features = [c for c in candidate if c not in constant]
    stats["constant_features_dropped"] = constant
    stats["n_features"] = len(features)
    stats["n_lite_features"] = len(config.LITE_FEATURES)
    stats["cross_split_duplicate_vectors"] = cross_split_overlap(splits, features)

    scaler = make_scaler().fit(splits["train"][features].to_numpy(np.float64))
    lite_scaler = make_scaler().fit(splits["train"][config.LITE_FEATURES].to_numpy(np.float64))
    classes = sorted(splits["train"][CLASS_COLUMN].unique())
    encoder = LabelEncoder().fit(classes)

    joblib.dump(scaler, config.SCALER_PATH)
    joblib.dump(lite_scaler, config.LITE_SCALER_PATH)
    joblib.dump(encoder, config.LABEL_ENCODER_PATH)
    config.FEATURES_PATH.write_text(json.dumps({
        "features": features,
        "lite_features": config.LITE_FEATURES,
        "classes": classes,
        "benign_class": config.BENIGN_LABEL,
        "constant_features_dropped": constant,
    }, indent=2))

    keep = features + config.LITE_FEATURES + [CLASS_COLUMN, config.LABEL_COLUMN] + KEEP_META
    stats["splits"] = {}
    for name, part in splits.items():
        part = part[keep].reset_index(drop=True)
        part["Day"] = part["Day"].astype(str)
        part.to_parquet(config.PROCESSED_DIR / f"{name}.parquet", index=False)
        stats["splits"][name] = {
            "rows": len(part),
            "shape_full": [len(part), len(features)],
            "shape_lite": [len(part), len(config.LITE_FEATURES)],
            "class_counts": {k: int(v) for k, v in part[CLASS_COLUMN].value_counts().items()},
        }

    config.DATA_SUMMARY_PATH.write_text(json.dumps(stats, indent=2))
    return stats


def load_split(name: str) -> pd.DataFrame:
    """Load a processed split written by ``run``."""
    path = config.PROCESSED_DIR / f"{name}.parquet"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Run 'python -m src.cli preprocess' first.")
    return pd.read_parquet(path)


def load_feature_spec() -> dict:
    return json.loads(config.FEATURES_PATH.read_text())


def print_summary(stats: dict) -> None:
    print(f"\nDays loaded: {stats['days']}")
    print(f"Rows loaded:                        {stats['rows_loaded']:>10,}")
    print(f"Dropped, NaN or Inf values:         {stats['rows_nan_or_inf_dropped']:>10,}")
    print(f"Dropped, exact duplicates:          {stats['rows_exact_duplicates_dropped']:>10,}")
    print(f"Dropped, conflicting labels:        {stats['rows_conflicting_labels_dropped']:>10,}")
    print(f"Dropped, rare classes:              {stats['classes_dropped_as_rare']}")
    print(f"Rows after cleaning:                {stats['rows_after_cleaning']:>10,}")
    print(f"Features: {stats['n_features']} full, {stats['n_lite_features']} lite; "
          f"constant features dropped: {stats['constant_features_dropped']}")
    print(f"Duplicate feature vectors shared between splits: {stats['cross_split_duplicate_vectors']}")
    print(f"Training split capped at {stats['max_train_rows_per_class']:,} rows per class\n")

    names = list(stats["splits"])
    classes = sorted({c for s in stats["splits"].values() for c in s["class_counts"]})
    print(f"{'Class':<14}" + "".join(f"{n:>12}" for n in names))
    for c in classes:
        print(f"{c:<14}" + "".join(f"{stats['splits'][n]['class_counts'].get(c, 0):>12,}" for n in names))
    print(f"{'Total':<14}" + "".join(f"{stats['splits'][n]['rows']:>12,}" for n in names))
    for n in names:
        s = stats["splits"][n]
        print(f"{n} X_full shape {tuple(s['shape_full'])}, X_lite shape {tuple(s['shape_lite'])}")
