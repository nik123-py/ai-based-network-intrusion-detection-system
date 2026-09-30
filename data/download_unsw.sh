#!/usr/bin/env bash
# Download UNSW-NB15 flow records, used by Netra's cross-dataset evaluation.
#
# Netra trains only on CIC-IDS2017. Testing on a second dataset, collected by
# different people on a different network with a different tool, is the only way
# to tell whether the models learned properties of network traffic or properties
# of CIC-IDS2017. UNSW-NB15 (Moustafa and Slay, 2015) is that second dataset.
#
# This fetches a single Parquet file holding all 2,059,415 flow records with
# source and destination addresses, timestamps and labels. Those identifiers are
# required: the per-source window features count distinct ports and hosts per
# source, so the commonly used "training/testing set" CSVs, which drop the
# addresses, cannot reproduce them.
#
# Official source (registration page):
#   https://research.unsw.edu.au/projects/unsw-nb15-dataset
#   The raw release is UNSW-NB15_1.csv .. _4.csv plus NUSW-NB15_features.csv.
#   Place an equivalent Parquet at data/unsw/UNSW_Flow.parquet to skip this.
#
# Without --local the file is downloaded from a public Hugging Face mirror
# (rdpahalavan/UNSW-NB15, Network-Flows/UNSW_Flow.parquet) and its SHA-256 is
# verified. Record counts are checked by the loader against the published totals:
# 2,059,415 flows, of which 99,643 are attacks across 10 categories.
#
# Usage: bash data/download_unsw.sh [--local]

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/unsw"
FILE="$DEST/UNSW_Flow.parquet"
URL="https://huggingface.co/datasets/rdpahalavan/UNSW-NB15/resolve/main/Network-Flows/UNSW_Flow.parquet"
SHA="8129db1cef95763a45072052af30a4c954af18b48abb6176f3d8ab732eb7d274"
LOCAL="${1:-}"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p "$DEST"

if [ -f "$FILE" ]; then
    echo "UNSW-NB15 already present at $FILE"
    exit 0
fi

if [ "$LOCAL" = "--local" ]; then
    echo "No file at $FILE. Place the Parquet there, or run without --local."
    exit 1
fi

echo "Downloading UNSW-NB15 flow records (about 175 MB)..."
curl -fL --retry 3 -o "$FILE" "$URL"

actual="$(sha256_of "$FILE")"
if [ "$SHA" = "REPLACE_ME" ]; then
    echo "Note: no checksum pinned yet. This file's SHA-256 is:"
    echo "  $actual"
elif [ "$actual" != "$SHA" ]; then
    echo "Checksum mismatch: expected $SHA, got $actual" >&2
    echo "Refusing to use the file. Delete it and retry, or download from UNSW directly." >&2
    exit 1
fi

ls -l "$FILE"
echo
echo "Done. Run the cross-dataset evaluation with:"
echo "  python -m src.cli cross-eval"
