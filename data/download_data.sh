#!/usr/bin/env bash
# Download the CIC-IDS2017 flow CSVs used by Netra.
#
# Two releases of the same flows are fetched:
#   data/cicids2017_labelled/  GeneratedLabelledFlows ("TrafficLabelling"): 78 flow
#                              features plus Flow ID, Source/Destination IP and port,
#                              Protocol and Timestamp. This is Netra's primary input,
#                              because source IPs and timestamps are needed for the
#                              per-source window features and for realistic replay.
#   data/cicids2017/           MachineLearningCSV: the same flows without identifiers.
#                              Kept for reference and for comparison with other work.
#
# Official source (registration form required):
#   https://www.unb.ca/cic/datasets/ids-2017.html  ->  CSVs/GeneratedLabelledFlows.zip
#                                                      CSVs/MachineLearningCSV.zip
#   Place either zip next to this script and run with --local to skip downloading.
#
# Without --local, the identical archives are downloaded from a public Hugging Face
# mirror (bencorn/CICIDS2017) and verified by SHA-256. The contents of both were
# also checked against the published per-label counts of CIC-IDS2017: 2,830,743
# labelled flows across 15 labels, all exact. The labelled release additionally
# contains 288,602 blank rows, which the loader drops.
#
# Expected files in each directory (8 per release):
#   Monday-WorkingHours.pcap_ISCX.csv
#   Tuesday-WorkingHours.pcap_ISCX.csv
#   Wednesday-workingHours.pcap_ISCX.csv
#   Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
#   Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
#   Friday-WorkingHours-Morning.pcap_ISCX.csv
#   Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
#   Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
#
# Usage: bash data/download_data.sh [--local]

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MIRROR="https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs"
LOCAL="${1:-}"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch_release() {
    local name="$1" sha="$2" dest="$HERE/$3"
    local zip="$HERE/$name.zip"
    mkdir -p "$dest"
    if [ "$(ls "$dest"/*.pcap_ISCX.csv 2>/dev/null | wc -l)" -eq 8 ]; then
        echo "[$name] all 8 CSV files already present in $dest"
        return
    fi
    if [ "$LOCAL" != "--local" ]; then
        echo "[$name] downloading..."
        curl -fL --retry 3 -o "$zip" "$MIRROR/$name.zip"
    fi
    [ -f "$zip" ] || { echo "[$name] missing $zip; see instructions at the top of this script"; exit 1; }
    echo "[$name] verifying SHA-256..."
    local actual; actual="$(sha256_of "$zip")"
    if [ "$actual" != "$sha" ]; then
        echo "[$name] checksum mismatch: expected $sha, got $actual"; exit 1
    fi
    echo "[$name] extracting to $dest..."
    local tmp="$HERE/_extract_$name"
    rm -rf "$tmp"; unzip -q -o "$zip" -d "$tmp"
    find "$tmp" -name "*.csv" -exec mv {} "$dest"/ \;
    rm -rf "$tmp" "$zip"
    ls -l "$dest"
}

fetch_release GeneratedLabelledFlows 7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a cicids2017_labelled
fetch_release MachineLearningCSV     c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928 cicids2017
echo "Done."
