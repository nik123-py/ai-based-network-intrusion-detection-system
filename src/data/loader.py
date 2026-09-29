"""Load the CIC-IDS2017 flow CSVs into a single DataFrame.

The primary input is the GeneratedLabelledFlows release, which has the 78
CICFlowMeter features plus flow identifiers (IPs, ports, protocol, timestamp).
Loading does only format repair: column names are stripped, blank padding rows
are dropped, labels are normalised, feature columns are made numeric, and the
timestamp is parsed. Cleaning decisions (NaN/Inf handling, deduplication,
label mapping) belong to ``preprocess.py``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import numpy as np
import pandas as pd

from src import config

log = logging.getLogger(__name__)

# Capture days in chronological order, matched against the start of each filename.
DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]


def day_of(path: Path) -> str:
    """Return the capture day ("Monday".."Friday") encoded in a CIC-IDS2017 filename."""
    name = path.name.lower()
    for day in DAY_ORDER:
        if name.startswith(day.lower()):
            return day
    raise ValueError(f"cannot infer capture day from filename {path.name!r}")


def list_csvs(directory: Path, days: str = "all") -> list[Path]:
    """List the day CSVs in ``directory``, optionally restricted to some days."""
    files = sorted(directory.glob("*.csv"), key=lambda p: (DAY_ORDER.index(day_of(p)), p.name))
    if not files:
        raise FileNotFoundError(
            f"no CSV files in {directory}. Run 'bash data/download_data.sh' first."
        )
    if days.strip().lower() != "all":
        wanted = {d.strip().capitalize() for d in days.split(",") if d.strip()}
        unknown = wanted - set(DAY_ORDER)
        if unknown:
            raise ValueError(f"unknown day(s) {sorted(unknown)}; choose from {DAY_ORDER}")
        files = [f for f in files if day_of(f) in wanted]
    return files


def normalise_label(label: str) -> str:
    """Make raw labels comparable: drop non-ASCII characters and collapse spaces.

    The raw files encode the dash in "Web Attack - XSS" as a byte that decodes
    to a non-ASCII character, so the same label can appear in several spellings.
    """
    ascii_only = label.encode("ascii", "ignore").decode()
    return re.sub(r"\s+", " ", ascii_only).strip()


def parse_timestamps(ts: pd.Series) -> pd.Series:
    """Parse CIC-IDS2017 timestamps.

    Formats are day-first, either ``d/m/YYYY H:MM`` or ``dd/mm/YYYY HH:MM:SS``.
    Most files use a 12-hour clock without an AM/PM marker; captures ran during
    working hours (about 08:00 to 17:30), so an hour below 8 is an afternoon hour.
    """
    parsed = pd.to_datetime(ts, format="%d/%m/%Y %H:%M", errors="coerce")
    missing = parsed.isna()
    if missing.any():
        parsed[missing] = pd.to_datetime(ts[missing], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    afternoon = parsed.dt.hour < 8
    parsed[afternoon] = parsed[afternoon] + pd.Timedelta(hours=12)
    return parsed


def load_file(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df.dropna(subset=[config.LABEL_COLUMN])  # blank padding rows

    non_features = set(config.META_COLUMNS) | {config.LABEL_COLUMN}
    for col in df.columns:
        if col in non_features:
            continue
        # "Infinity" strings parse to inf; anything else unparseable becomes NaN.
        df[col] = pd.to_numeric(df[col], errors="coerce").astype(np.float32)

    df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].astype(str).map(normalise_label)
    df["Destination Port"] = pd.to_numeric(df["Destination Port"], errors="coerce").astype("Int32")
    df["Timestamp"] = parse_timestamps(df["Timestamp"].astype(str).str.strip())
    df["Day"] = day_of(path)
    return df


def load_cicids2017(directory: Path | None = None, days: str | None = None) -> pd.DataFrame:
    """Load and concatenate the selected CIC-IDS2017 day files."""
    directory = directory or config.CICIDS_LABELLED_DIR
    days = days or config.DAYS
    frames = []
    for path in list_csvs(directory, days):
        df = load_file(path)
        log.info("loaded %-60s %9d rows", path.name, len(df))
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["Day"] = pd.Categorical(df["Day"], categories=DAY_ORDER)
    return df
