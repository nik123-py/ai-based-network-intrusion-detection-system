"""Preprocessing tests on synthetic CIC-IDS2017-shaped data (no dataset needed)."""

import numpy as np
import pandas as pd
import pytest

from src import config
from src.data import preprocess as pp
from src.data.loader import normalise_label, parse_timestamps

N_FEATURES = 5


def synthetic(n_per_class: int = 300, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    labels = ["BENIGN", "DoS Hulk", "PortScan", "Web Attack \x96 XSS"]
    rows = []
    for i, lab in enumerate(labels):
        n = n_per_class
        rows.append(pd.DataFrame({
            "Source IP": [f"10.0.{i}.{k % 5}" for k in range(n)],
            "Source Port": rng.integers(1024, 65535, n),
            "Destination IP": "192.168.0.1",
            "Destination Port": rng.integers(1, 1024, n),
            "Timestamp": pd.Timestamp("2017-07-05 09:00") + pd.to_timedelta(rng.integers(0, 600, n), "s"),
            "Flow Duration": rng.integers(1, 10**6, n).astype(np.float32),
            "Total Fwd Packets": rng.integers(1, 20, n).astype(np.float32),
            "Total Backward Packets": rng.integers(0, 20, n).astype(np.float32),
            "Total Length of Fwd Packets": rng.integers(0, 5000, n).astype(np.float32),
            "Total Length of Bwd Packets": rng.integers(0, 5000, n).astype(np.float32),
            "Fwd Header Length.1": 0.0,
            "Label": normalise_label(lab),
            "Day": "Wednesday",
        }))
    df = pd.concat(rows, ignore_index=True)
    # Inject problems that cleaning must handle.
    df.loc[0, "Flow Duration"] = np.inf
    df.loc[1, "Total Fwd Packets"] = np.nan
    dup = df.iloc[[10, 11]].copy()
    return pd.concat([df, dup], ignore_index=True)


def test_label_mapping():
    assert pp.map_label("benign") == "Benign"
    assert pp.map_label(normalise_label("Web Attack \x96 Brute Force")) == "WebAttack"
    assert pp.map_label("dos slowloris") == "DoS-Slow"
    assert pp.map_label("something new") is None


def test_timestamps_twelve_hour_clock():
    ts = parse_timestamps(pd.Series(["5/7/2017 9:15", "5/7/2017 2:43", "03/07/2017 08:55:58"]))
    assert list(ts.dt.hour) == [9, 14, 8]


def test_clean_drops_bad_rows_and_duplicates():
    stats = {}
    df = pp.clean(synthetic(), stats)
    feats = pp.feature_columns(df)
    assert stats["rows_nan_or_inf_dropped"] == 2
    assert stats["rows_exact_duplicates_dropped"] >= 2
    assert np.isfinite(df[feats + config.LITE_FEATURES].to_numpy()).all()
    assert not df.duplicated(subset=feats).any()
    assert "Fwd Header Length.1" not in df.columns
    assert set(df["Class"]) == {"Benign", "DoS", "PortScan", "WebAttack"}


def test_identifier_columns_are_not_features():
    df = pp.clean(synthetic(), {})
    feats = pp.feature_columns(df)
    for col in config.META_COLUMNS + ["Label", "Class", "Day"] + config.LITE_FEATURES:
        assert col not in feats


def test_split_has_no_leakage_and_is_stratified():
    df = pp.clean(synthetic(n_per_class=400), {})
    splits = pp.split(df)
    feats = pp.feature_columns(df)
    assert sum(len(s) for s in splits.values()) == len(df)
    assert all(v == 0 for v in pp.cross_split_overlap(splits, feats).values())
    for part in splits.values():
        assert set(part["Class"]) == set(df["Class"])
    frac = len(splits["test"]) / len(df)
    assert frac == pytest.approx(config.TEST_SIZE, abs=0.01)


def test_cap_applies_per_class():
    df = pp.clean(synthetic(n_per_class=400), {})
    capped = pp.cap_per_class(df, 50)
    assert capped["Class"].value_counts().max() == 50


def test_lite_window_features():
    df = pd.DataFrame({
        "Day": "Friday",
        "Source IP": ["1.1.1.1"] * 3 + ["2.2.2.2"],
        "Destination IP": ["9.9.9.9", "9.9.9.8", "9.9.9.9", "9.9.9.9"],
        "Destination Port": [22, 80, 443, 80],
        "Timestamp": pd.to_datetime(["2017-07-07 10:00:05"] * 3 + ["2017-07-07 10:00:05"]),
        "Flow Duration": [2e6, 0, 1e6, 1e6],
        "Total Fwd Packets": [2, 1, 3, 1], "Total Backward Packets": [2, 0, 1, 0],
        "Total Length of Fwd Packets": [100, 0, 30, 0], "Total Length of Bwd Packets": [100, 0, 10, 0],
    })
    out = pp.add_lite_features(df)
    assert list(out["src_unique_dst_ports"]) == [3, 3, 3, 1]
    assert list(out["src_unique_dsts"]) == [2, 2, 2, 1]
    assert out.loc[0, "packets_per_sec"] == pytest.approx(2.0)
    assert out.loc[0, "mean_packet_size"] == pytest.approx(50.0)
    assert np.isfinite(out.loc[1, "packets_per_sec"])  # zero-duration flow


def test_scaler_is_finite_on_heavy_tails():
    x = np.array([[0.0, 1e9], [5.0, -1.0], [1e3, 3e5]])
    out = pp.make_scaler().fit_transform(x)
    assert np.isfinite(out).all()
