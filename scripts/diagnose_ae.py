"""Capture normal lab flows and show which features drive the autoencoder error.

Run inside the NIDS container while ordinary web requests are made to the victim:
    docker compose exec nids python scripts/diagnose_ae.py --seconds 25
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from src import config  # noqa: E402
from src.data.preprocess import load_feature_spec  # noqa: E402
from src.detection.sniffer import Sniffer, resolve_interface  # noqa: E402
from src.features.flow_features import align_to_schema  # noqa: E402
from src.models.autoencoder import CLIP, AutoencoderScorer  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--seconds", type=float, default=25)
args = ap.parse_args()

spec = load_feature_spec()
features = spec["features"]
scaler = joblib.load(config.SCALER_PATH)
ae = AutoencoderScorer()
flows = []
s = Sniffer(iface=resolve_interface("auto"))
s.on_flow(flows.append)
s.start()
time.sleep(args.seconds)
s.stop()

X = scaler.transform(np.vstack([align_to_schema(f.cic, features) for f in flows]))
Xc = np.clip(X, -CLIP, CLIP)
per_feature = (ae.reconstruct(Xc) - Xc) ** 2
err = per_feature.mean(axis=1)
print(f"{len(flows)} flows, threshold {ae.threshold:.3f}, errors: min {err.min():.3f} "
      f"median {np.median(err):.3f} max {err.max():.3f}, above threshold: {(err > ae.threshold).sum()}")
contrib = per_feature.mean(axis=0) / len(features)
for i in np.argsort(contrib)[::-1][:8]:
    raw = [align_to_schema(f.cic, features)[i] for f in flows]
    print(f"  {features[i]:<28} share of error {contrib[i] / err.mean():6.1%}  "
          f"scaled median {np.median(X[:, i]):7.2f}  raw median {np.median(raw):.1f}")
