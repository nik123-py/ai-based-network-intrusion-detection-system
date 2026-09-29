"""Unsupervised anomaly detector: a small dense autoencoder trained on benign flows only.

The autoencoder learns to reconstruct normal traffic. A flow whose
reconstruction error is above a threshold, chosen as a percentile of the errors
on benign validation flows, is flagged as an anomaly. Because it never sees an
attack label, it can flag traffic that matches no known class (the "novel
attack" case; compare Kitsune, Mirsky et al., 2018).

Training uses Keras. For deployment, the weights are exported to a NumPy file
and inference runs with ``AutoencoderScorer``, so the NIDS container does not
need TensorFlow.
"""

from __future__ import annotations

import json
import logging
import os
import time

import numpy as np

from src import config

log = logging.getLogger(__name__)

WEIGHTS_NPZ = config.MODELS_DIR / "autoencoder_weights.npz"
HIDDEN = (32, 16, 8, 16, 32)
CLIP = 10.0  # scaled inputs are clipped to +-CLIP standard deviations


class AutoencoderScorer:
    """NumPy-only inference: reconstruction error of scaled feature vectors."""

    def __init__(self, weights_path=WEIGHTS_NPZ, meta_path=config.AUTOENCODER_META_PATH):
        data = np.load(weights_path)
        n = len([k for k in data.files if k.startswith("W")])
        self.layers = [(data[f"W{i}"], data[f"b{i}"]) for i in range(n)]
        self.meta = json.loads(meta_path.read_text())
        self.threshold = float(self.meta["threshold"])

    def reconstruct(self, X: np.ndarray) -> np.ndarray:
        h = np.clip(np.asarray(X, dtype=np.float32), -CLIP, CLIP)
        for i, (W, b) in enumerate(self.layers):
            h = h @ W + b
            if i < len(self.layers) - 1:
                h = np.maximum(h, 0.0)  # ReLU on hidden layers, linear output
        return h

    def score(self, X: np.ndarray) -> np.ndarray:
        """Mean squared reconstruction error per row."""
        Xc = np.clip(np.asarray(X, dtype=np.float32), -CLIP, CLIP)
        return np.mean((self.reconstruct(Xc) - Xc) ** 2, axis=1)

    def is_anomaly(self, X: np.ndarray) -> np.ndarray:
        return self.score(X) > self.threshold


def build_model(n_features: int):
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
    import keras
    from keras import layers

    keras.utils.set_random_seed(config.RANDOM_STATE)
    inputs = keras.Input(shape=(n_features,))
    h = inputs
    for units in HIDDEN:
        h = layers.Dense(units, activation="relu")(h)
    outputs = layers.Dense(n_features, activation="linear")(h)
    model = keras.Model(inputs, outputs, name="netra_autoencoder")
    model.compile(optimizer=keras.optimizers.Adam(1e-3), loss="mse")
    return model


def export_weights(model) -> None:
    arrays = {}
    for i, layer in enumerate(model.layers[1:]):  # skip the Input layer
        W, b = layer.get_weights()
        arrays[f"W{i}"], arrays[f"b{i}"] = W.astype(np.float32), b.astype(np.float32)
    np.savez(WEIGHTS_NPZ, **arrays)


def train(epochs: int = 100, batch_size: int = 1024) -> dict:
    import keras

    from src.models.train_supervised import load_xy

    X_train, y_train, _ = load_xy("train", "full")
    X_val, y_val, _ = load_xy("val", "full")
    classes = list(json.loads(config.FEATURES_PATH.read_text())["classes"])
    benign = classes.index(config.BENIGN_LABEL)

    Xb_train = np.clip(X_train[y_train == benign], -CLIP, CLIP)
    Xb_val = np.clip(X_val[y_val == benign], -CLIP, CLIP)
    log.info("autoencoder: %d benign training flows, %d benign validation flows",
             len(Xb_train), len(Xb_val))

    model = build_model(Xb_train.shape[1])
    start = time.time()
    history = model.fit(
        Xb_train, Xb_train, validation_data=(Xb_val, Xb_val), epochs=epochs, batch_size=batch_size,
        callbacks=[keras.callbacks.EarlyStopping(patience=4, restore_best_weights=True)], verbose=2)
    train_s = time.time() - start
    model.save(config.AUTOENCODER_PATH)
    export_weights(model)

    # Threshold from benign validation errors only (no attack data involved).
    val_err = np.mean((model.predict(Xb_val, batch_size=8192, verbose=0) - Xb_val) ** 2, axis=1)
    threshold = float(np.percentile(val_err, config.AE_THRESHOLD_PERCENTILE))
    meta = {
        "architecture": [Xb_train.shape[1], *HIDDEN, Xb_train.shape[1]],
        "input_clip": CLIP,
        "epochs_run": len(history.history["loss"]),
        "final_train_loss": float(history.history["loss"][-1]),
        "best_val_loss": float(min(history.history["val_loss"])),
        "train_seconds": round(train_s, 1),
        "threshold_percentile": config.AE_THRESHOLD_PERCENTILE,
        "threshold": threshold,
        "features": json.loads(config.FEATURES_PATH.read_text())["features"],
    }
    config.AUTOENCODER_META_PATH.write_text(json.dumps(meta, indent=2))

    # The NumPy scorer must reproduce Keras exactly.
    scorer = AutoencoderScorer()
    diff = float(np.max(np.abs(scorer.score(Xb_val[:2000]) - val_err[:2000])))
    log.info("autoencoder: threshold %.5f, NumPy/Keras max score difference %.2e", threshold, diff)
    if diff > 1e-3:
        raise RuntimeError(f"NumPy scorer disagrees with Keras (max diff {diff})")
    return meta


def evaluate() -> dict:
    """Separation of benign and attack flows on the test split."""
    from sklearn.metrics import average_precision_score, roc_auc_score

    from src.models.train_supervised import load_xy

    X, y, df = load_xy("test", "full")
    scorer = AutoencoderScorer()
    err = scorer.score(X)
    classes = json.loads(config.FEATURES_PATH.read_text())["classes"]
    benign = classes.index(config.BENIGN_LABEL)
    is_attack = y != benign
    flagged = err > scorer.threshold

    per_class = {}
    for i, c in enumerate(classes):
        mask = y == i
        per_class[c] = {"flows": int(mask.sum()), "flagged_share": float(flagged[mask].mean()),
                        "median_error": float(np.median(err[mask]))}
    result = {
        "threshold": scorer.threshold,
        "threshold_percentile": scorer.meta["threshold_percentile"],
        "roc_auc": float(roc_auc_score(is_attack, err)),
        "average_precision": float(average_precision_score(is_attack, err)),
        "detection_rate": float(flagged[is_attack].mean()),
        "false_positive_rate": float(flagged[~is_attack].mean()),
        "precision": float(is_attack[flagged].mean()) if flagged.any() else 0.0,
        "per_class": per_class,
    }
    (config.REPORTS_DIR / "metrics_autoencoder.json").write_text(json.dumps(result, indent=2))
    plot_errors(err, is_attack, scorer.threshold, per_class, config.REPORTS_DIR / "autoencoder_errors.png")
    return result


def plot_errors(err, is_attack, threshold, per_class, path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from src.models.evaluate import INK, INK_2, GRID, MUTED, SURFACE, _style

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.8), facecolor=SURFACE,
                                   gridspec_kw={"width_ratios": [1.3, 1]})
    for ax in (ax1, ax2):
        _style(ax)
    bins = np.logspace(np.log10(max(err.min(), 1e-5)), np.log10(err.max()), 80)
    for mask, color, label in ((~is_attack, "#2a78d6", "Benign"), (is_attack, "#eb6834", "Attack (all classes)")):
        ax1.hist(err[mask], bins=bins, weights=np.full(mask.sum(), 1.0 / max(mask.sum(), 1)),
                 color=color, alpha=0.7, label=label)
    ax1.axvline(threshold, color=INK, linewidth=1.2, linestyle="--")
    ax1.text(threshold * 1.15, ax1.get_ylim()[1] * 0.92, "threshold", color=INK_2, fontsize=8.5)
    ax1.set_xscale("log")
    ax1.set_xlabel("Reconstruction error (MSE, log scale)", color=INK_2)
    ax1.set_ylabel("Share of flows in group", color=INK_2)
    ax1.legend(frameon=False, fontsize=9, labelcolor=INK_2)
    ax1.set_title("Reconstruction error on the test split", color=INK, fontsize=11, loc="left")

    names = [c for c in per_class if c != config.BENIGN_LABEL]
    shares = [per_class[c]["flagged_share"] for c in names]
    ax2.barh(names, shares, height=0.55, color="#eb6834")
    for yi, s in enumerate(shares):
        ax2.text(s + 0.01, yi, f"{s:.1%}", va="center", fontsize=8, color=INK_2)
    ax2.invert_yaxis()
    ax2.set_xlim(0, 1.12)
    ax2.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.set_xlabel("Share of flows above threshold", color=INK_2)
    fp = per_class[config.BENIGN_LABEL]["flagged_share"]
    ax2.set_title(f"Flagged by class (benign false positives: {fp:.2%})", color=INK, fontsize=11, loc="left")
    fig.text(0.01, 0.01, "The autoencoder is trained on benign flows only and never sees attack labels.",
             color=MUTED, fontsize=8)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)
