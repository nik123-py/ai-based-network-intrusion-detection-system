"""Tests for the UNSW-NB15 loader used by the cross-dataset evaluation.

The mapping tests run on a synthetic frame with the UNSW column names, so they
work without the 175 MB download. The tests that need the real file are skipped
when it is absent.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src import config
from src.data import unsw

# Published UNSW-NB15 totals for the full flow release.
PUBLISHED_FLOWS = 2_059_415
PUBLISHED_ATTACKS = 99_643


def synthetic(tmp_path):
    """A small frame with UNSW-NB15's column names and known values."""
    # stime // 60 is the window, so 960 to 1019 inclusive is one window.
    rows = [
        # src,        dst,             dport, dur,  sbytes, dbytes, spkts, dpkts, stime, label,    binary
        ("10.0.0.1", "10.0.0.9", 80, 2.0, 1000, 500, 10, 10, 1000, "normal", 0),
        ("10.0.0.1", "10.0.0.9", 443, 4.0, 2000, 1000, 20, 20, 1010, "normal", 0),
        ("10.0.0.1", "10.0.0.8", 22, 1.0, 100, 50, 5, 5, 1015, "dos", 1),
        # A later window for the same source.
        ("10.0.0.1", "10.0.0.7", 8080, 1.0, 100, 100, 4, 4, 5000, "reconnaissance", 1),
        ("10.0.0.2", "10.0.0.9", 80, 0.0, 60, 0, 1, 0, 1005, "worms", 1),
    ]
    df = pd.DataFrame(rows, columns=unsw.COLUMNS)
    path = tmp_path / "synthetic.parquet"
    df.to_parquet(path)
    return path


def test_lite_features_match_the_training_formulas(tmp_path):
    """Feature values must come out of the same arithmetic used in training."""
    df = unsw.load(synthetic(tmp_path))
    assert list(config.LITE_FEATURES) == [c for c in config.LITE_FEATURES if c in df.columns]

    first = df.iloc[0]
    assert first["flow_duration"] == pytest.approx(2.0)
    assert first["packets_per_sec"] == pytest.approx(20 / 2.0)          # (10+10)/2
    assert first["bytes_per_sec"] == pytest.approx(1500 / 2.0)          # (1000+500)/2
    assert first["mean_packet_size"] == pytest.approx(1500 / 20)


def test_zero_duration_does_not_produce_infinity(tmp_path):
    """A zero-duration flow must not become inf and poison the scaler."""
    df = unsw.load(synthetic(tmp_path))
    values = df[config.LITE_FEATURES].to_numpy(np.float64)
    assert np.isfinite(values).all()


def test_window_aggregates_group_by_source_and_window(tmp_path):
    """Distinct ports and hosts are counted per source within a 60 s window."""
    df = unsw.load(synthetic(tmp_path))
    # 10.0.0.1 has three flows in the first window (ports 80, 443, 22; hosts .9, .9, .8)
    first_window = df.iloc[:3]
    assert set(first_window["src_unique_dst_ports"]) == {3}
    assert set(first_window["src_unique_dsts"]) == {2}
    # Its fourth flow falls in a later window and is counted separately.
    assert df.iloc[3]["src_unique_dst_ports"] == 1
    assert df.iloc[3]["src_unique_dsts"] == 1


def test_labels_and_category_mapping(tmp_path):
    df = unsw.load(synthetic(tmp_path))
    assert df["is_attack"].tolist() == [False, False, True, True, True]
    assert df.iloc[0]["netra_class"] == config.BENIGN_LABEL
    assert df.iloc[2]["netra_class"] == "DoS"
    assert df.iloc[3]["netra_class"] == "PortScan"
    # "worms" has no Netra equivalent, so it must be missing rather than guessed
    # at. pandas stores that as NaN, hence pd.isna rather than "is None".
    assert pd.isna(df.iloc[4]["netra_class"])
    # The authoritative mapping still distinguishes "unmapped" from "benign".
    assert unsw.CATEGORY_MAP["worms"] is None


def test_header_correction_lowers_byte_counts(tmp_path):
    """Approximating payload must reduce byte-derived features, never raise them."""
    path = synthetic(tmp_path)
    plain = unsw.load(path)
    corrected = unsw.load(path, header_correction=True)
    assert (corrected["bytes_per_sec"] <= plain["bytes_per_sec"]).all()
    assert (corrected["mean_packet_size"] <= plain["mean_packet_size"]).all()
    # 20 packets * 40 bytes = 800 removed from 1500, over 2 seconds.
    assert corrected.iloc[0]["bytes_per_sec"] == pytest.approx(700 / 2.0)
    assert (corrected[config.LITE_FEATURES].to_numpy() >= 0).all()


def test_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="download_unsw"):
        unsw.load(tmp_path / "absent.parquet")


def test_summary_counts(tmp_path):
    s = unsw.summary(unsw.load(synthetic(tmp_path)))
    assert s["flows"] == 5
    assert s["attacks"] == 3
    assert s["benign"] == 2
    assert s["categories"]["normal"] == 2


@pytest.mark.skipif(not unsw.available(), reason="UNSW-NB15 not downloaded")
def test_real_dataset_matches_published_totals():
    """Guards against a truncated or wrong download."""
    df = unsw.load()
    assert len(df) == PUBLISHED_FLOWS
    assert int(df["is_attack"].sum()) == PUBLISHED_ATTACKS
    assert np.isfinite(df[config.LITE_FEATURES].to_numpy(np.float64)).all()
    # Every category present must have a mapping entry, even if it maps to None.
    assert set(df["category"].unique()) <= set(unsw.CATEGORY_MAP)
