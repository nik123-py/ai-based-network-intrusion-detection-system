"""Train the supervised multi-class classifiers.

Two model families are trained on the same data and compared on the
validation split by macro F1 (every class counts equally, so small attack
classes matter as much as benign traffic):

* Random Forest with ``class_weight="balanced_subsample"``.
* XGBoost with balanced per-sample weights and early stopping on validation loss.

Both are saved. The better one is recorded in the metadata file and is the one
the detection engine loads. This is done for two feature sets:

* ``full``: the CICFlowMeter features (benchmark model).
* ``lite``: the small live-computable feature set (guarantees the live demo).

Class imbalance is handled with class weights only; the test split is never
resampled or reweighted.
"""

from __future__ import annotations

import json
import logging
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from src import config
from src.data.preprocess import CLASS_COLUMN, load_feature_spec, load_split

log = logging.getLogger(__name__)

KINDS = ("full", "lite")
META_PATHS = {"full": config.SUPERVISED_META_PATH, "lite": config.LITE_META_PATH}


def load_xy(split: str, kind: str):
    """Scaled feature matrix, encoded labels and the raw frame for one split."""
    spec = load_feature_spec()
    cols = spec["features"] if kind == "full" else spec["lite_features"]
    scaler = joblib.load(config.SCALER_PATH if kind == "full" else config.LITE_SCALER_PATH)
    encoder = joblib.load(config.LABEL_ENCODER_PATH)
    df = load_split(split)
    X = scaler.transform(df[cols].to_numpy(np.float64)).astype(np.float32)
    y = encoder.transform(df[CLASS_COLUMN])
    return X, y, df


def make_candidates(n_classes: int) -> dict:
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=config.RANDOM_STATE,
        ),
        "xgboost": XGBClassifier(
            n_estimators=1000,
            learning_rate=0.1,
            max_depth=8,
            subsample=0.8,
            colsample_bytree=0.8,
            tree_method="hist",
            objective="multi:softprob",
            num_class=n_classes,
            eval_metric="mlogloss",
            early_stopping_rounds=30,
            n_jobs=-1,
            random_state=config.RANDOM_STATE,
        ),
    }


def fit(name: str, model, X, y, X_val, y_val):
    weights = compute_sample_weight("balanced", y)
    if name == "xgboost":
        model.fit(X, y, sample_weight=weights, eval_set=[(X_val, y_val)], verbose=False)
    else:
        model.fit(X, y)  # class_weight is set on the estimator
    return model


def train(kind: str = "full") -> dict:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    X, y, _ = load_xy("train", kind)
    X_val, y_val, _ = load_xy("val", kind)
    classes = list(joblib.load(config.LABEL_ENCODER_PATH).classes_)
    log.info("[%s] train %s, val %s, %d classes", kind, X.shape, X_val.shape, len(classes))

    results = {}
    for name, model in make_candidates(len(classes)).items():
        start = time.time()
        fit(name, model, X, y, X_val, y_val)
        train_s = time.time() - start
        pred = model.predict(X_val)
        results[name] = {
            "path": config.model_path(kind, name).name,
            "train_seconds": round(train_s, 1),
            "val_accuracy": float(accuracy_score(y_val, pred)),
            "val_macro_f1": float(f1_score(y_val, pred, average="macro")),
            "val_weighted_f1": float(f1_score(y_val, pred, average="weighted")),
        }
        if name == "xgboost":
            results[name]["best_iteration"] = int(model.best_iteration)
        joblib.dump(model, config.model_path(kind, name), compress=3)
        log.info("[%s] %-13s macro F1 %.4f  weighted F1 %.4f  (%.0f s)", kind, name,
                 results[name]["val_macro_f1"], results[name]["val_weighted_f1"], train_s)

    best = max(results, key=lambda n: results[n]["val_macro_f1"])
    meta = {
        "kind": kind,
        "best": best,
        "selection_metric": "validation macro F1",
        "classes": classes,
        "features": load_feature_spec()["features" if kind == "full" else "lite_features"],
        "imbalance_handling": "balanced class weights (training split only)",
        "candidates": results,
    }
    META_PATHS[kind].write_text(json.dumps(meta, indent=2))
    log.info("[%s] selected %s", kind, best)
    return meta


def load_model(kind: str = "full", name: str | None = None):
    """Load a trained classifier (the selected one unless ``name`` is given) and its metadata."""
    meta = json.loads(META_PATHS[kind].read_text())
    name = name or meta["best"]
    return joblib.load(config.model_path(kind, name)), meta
