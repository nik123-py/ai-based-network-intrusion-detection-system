"""Group the flows nothing recognises into families, and name them.

The open-set layer (``src.models.openset``) can say that a flow matches no class
the models were trained on. On its own that is still the useless alert this
project started with: "Anomaly (unknown)", once per flow, with nothing an
operator can act on. This module is the second half. It answers three questions
about a rejected flow:

* **Is this the same thing I saw a minute ago?** Rejected flows are clustered
  online, so a novel attack becomes one object that grows rather than hundreds
  of identical alerts. The cluster keeps a stable identifier, ``NETRA-U001``,
  across restarts.
* **What does it look like?** A fingerprint of the features that make the family
  unusual, quoted in the units an operator reads, plus the nearest class the
  models do know and how firmly that class rejects it. A flow that is almost
  DoS-Slow is a different report from one that is like nothing at all.
* **What is it?** Once identified, a family can be promoted to a real name. The
  promotion is recorded and the family keeps its label from then on, so the next
  training run can use it.

Why clustering is what makes this work, and what it does not do. The open-set
threshold alpha is a routing decision, not an alert: at the default 0.05, roughly
five in a hundred ordinary flows are rejected, because they are the tail of
normal traffic. Most of those are scattered, each unusual in its own direction,
and they never accumulate into a family. A real attack repeats, lands in the same
place every time, and crosses ``MIN_FAMILY_FLOWS`` quickly. Precision comes from
the repetition, not from the threshold.

Part of that benign tail, however, is not scattered. Measured on the held-out
folds, ordinary traffic produces a double-figure number of families large enough
to report, because some unusual-but-legitimate traffic is unusual the same way
every time. Those are not noise and they are not errors; they are recurring
patterns that a deployment has and the training data did not describe. What the
layer offers for them is the naming step: an operator identifies such a family
once, promotes it, and it stops being an unexplained alert. That is the normal
baselining cost of any anomaly detector, and it is reported as a cost rather
than hidden, with the measured numbers per reporting threshold in
``reports/OPENSET.md``.

Clustering method. Leader clustering (Hartigan, 1975): each flow joins the
nearest family within ``radius``, or starts a new family. One pass, no
retraining, no stored history, bounded memory, and the result does not depend on
how many flows have arrived.

What a family is, precisely. Each flow is reduced to the *direction* in which it
deviates from normal traffic: take the whitened feature vector (whitened by the
recogniser's mean class precision, so the coordinates are comparable), subtract
the benign class mean, and normalise to unit length. Two flows belong to the same
family when those directions are close, measured as cosine distance.

The alternative, Euclidean distance in the same space, is also implemented and
is worse, for a reason worth stating. A radius in absolute distance has to be
calibrated against something, and everything available to calibrate it against
is a known class, which is dense: CIC-IDS2017 benign traffic has 400,000
training flows, so the typical distance between neighbours inside it is far
smaller than the spread of a novel attack seen a few dozen times. A radius that
fits the known classes shatters a novel family into one cluster per flow, and a
radius wide enough to hold a novel family swallows unrelated traffic. Direction
has no such scale: an attack that deviates in the same way is in the same family
whether it is run gently or hard, and the threshold is an angle, which means the
same thing on any network and needs no dataset-specific tuning.

``src.models.discovery_eval`` measures both metrics as cluster purity and
adjusted Rand index against held-out ground truth, and the numbers are in
``reports/OPENSET.md``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter

import numpy as np

from src import config

log = logging.getLogger(__name__)

# Flows a family must hold before it is worth an operator's attention. Defined
# in one place, src/config.py, so the engine, the clusterer and the evaluation
# cannot disagree about it.
MIN_FAMILY_FLOWS = config.DISCOVERY_MIN_FLOWS
METRICS = ("cosine", "euclidean")
DEFAULT_METRIC = "cosine"
# Cosine distance within which two deviation directions are the same family.
# 0.05 is about 18 degrees. Measured against held-out ground truth in
# src/models/discovery_eval.py.
COSINE_RADIUS = 0.05
# Multiple of the calibrated neighbourhood scale used as the Euclidean radius,
# for the comparison only.
RADIUS_FACTOR = 1.0
# Families held in memory. Beyond this the least useful (fewest flows, oldest
# last seen) are dropped, so a long run cannot grow without bound.
MAX_FAMILIES = 200
# Distinct sources, destinations and ports remembered per family.
MAX_PEERS = 32
# Features quoted in a fingerprint.
FINGERPRINT_K = 4


def families_path():
    return config.FAMILIES_PATH


class UnknownFamily:
    """One cluster of flows that matched no known class."""

    def __init__(self, family_id: str, centroid: np.ndarray, now: float,
                 min_flows: int = MIN_FAMILY_FLOWS):
        self.id = family_id
        self.centroid = np.asarray(centroid, dtype=np.float64)
        self.min_flows = int(min_flows)
        self.n_flows = 0
        # The firmest rejection any member received, kept for the description so
        # an operator can see how clearly this family is outside everything
        # known. It does not decide whether the family is reported.
        self.best_p = 1.0
        self.first_seen = now
        self.last_seen = now
        self.sources: Counter = Counter()
        self.destinations: Counter = Counter()
        self.ports: Counter = Counter()
        self.routes: Counter = Counter()
        self.nearest_class: str | None = None
        self.nearest_p: float = 0.0
        self.fingerprint: list[dict] = []
        self.promoted_name: str | None = None
        self.alerted_at: float = 0.0

    @property
    def label(self) -> str:
        """What the alert calls this family."""
        return self.promoted_name or self.id

    @property
    def alertable(self) -> bool:
        """Worth an operator's attention: the family has to have grown.

        Size, and not the strength of the individual rejections, is what
        separates a real family from the tail of normal traffic, and this was
        measured rather than assumed. An earlier version of this code required a
        number of flows rejected at a stricter conformal level, on the reasoning
        that a firmer rejection is better evidence. The leave-one-class-out
        sweep showed that reasoning is wrong twice over: it reported the novel
        family in 1 fold out of 7, because novel attack flows mostly land at
        p-values between the two levels, and it still admitted 164 families made
        of ordinary traffic, because deep benign outliers do occur and three of
        them are enough.

        The reason the p-value cannot do this job is that the routing level has
        already conditioned on it. Among flows that reached the clusterer at
        all, a rejected benign flow and a rejected novel flow have p-values
        drawn from much the same range, so the p-value adds little. What a
        benign tail does not do is put dozens of flows in the same direction.
        The threshold is therefore a count, chosen from the measured curve in
        reports/OPENSET.md rather than by argument.
        """
        return self.n_flows >= self.min_flows

    def add(self, z: np.ndarray, src, dst, dport, route: str, now: float,
            p_max: float | None = None) -> None:
        self.n_flows += 1
        if p_max is not None:
            self.best_p = min(self.best_p, float(p_max))
        # Running mean, so the centroid needs no stored history.
        self.centroid += (np.asarray(z, dtype=np.float64) - self.centroid) / self.n_flows
        self.last_seen = now
        for counter, value in ((self.sources, src), (self.destinations, dst),
                               (self.ports, dport), (self.routes, route)):
            if value is None:
                continue
            if len(counter) >= MAX_PEERS and value not in counter:
                continue
            counter[value] += 1

    def describe(self) -> str:
        """One line an operator can act on, in place of "Anomaly (unknown)"."""
        parts = [f"{self.label}: {self.n_flows} unrecognised "
                 f"flow{'s' if self.n_flows != 1 else ''} from "
                 f"{len(self.sources)} source{'s' if len(self.sources) != 1 else ''}"]
        if self.fingerprint:
            parts.append(", ".join(_phrase(f) for f in self.fingerprint))
        if self.nearest_class:
            parts.append(f"nearest known class {self.nearest_class} (p={self.nearest_p:.3f})")
        else:
            parts.append("no known class is close")
        return ". ".join(parts)

    def to_dict(self, with_centroid: bool = False) -> dict:
        d = {
            "id": self.id, "label": self.label, "promoted_name": self.promoted_name,
            "flows": self.n_flows, "alertable": self.alertable,
            "best_p": round(self.best_p, 4),
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "sources": [s for s, _ in self.sources.most_common(8)],
            "n_sources": len(self.sources),
            "destinations": [d for d, _ in self.destinations.most_common(8)],
            "ports": [p for p, _ in self.ports.most_common(8)],
            "routes": dict(self.routes),
            "nearest_class": self.nearest_class, "nearest_p": round(self.nearest_p, 4),
            "fingerprint": self.fingerprint, "description": self.describe(),
        }
        if with_centroid:
            d["centroid"] = self.centroid.tolist()
        return d


class FamilyTracker:
    """Online leader clustering of rejected flows, with stable names."""

    def __init__(self, recognizer, radius: float | None = None, kind: str = "full",
                 store_path=None, persist: bool = True, metric: str = DEFAULT_METRIC,
                 min_flows: int | None = None):
        if metric not in METRICS:
            raise ValueError(f"metric must be one of {METRICS}, got {metric!r}")
        self.rec = recognizer
        self.kind = kind
        self.metric = metric
        self.min_flows = config.DISCOVERY_MIN_FLOWS if min_flows is None else int(min_flows)
        if radius is not None:
            self.radius = float(radius)
        elif metric == "cosine":
            self.radius = COSINE_RADIUS
        else:
            self.radius = calibrated_radius(recognizer)
        self.families: dict[str, UnknownFamily] = {}
        self.promoted: dict[str, str] = {}
        self._next_id = 1
        self._lock = threading.RLock()
        self._store = store_path or families_path()
        self.persist = persist
        self.dropped = 0
        # Benign reference, so a fingerprint can say how far from normal a
        # feature is in units an operator can judge.
        self._benign_mean = None
        if recognizer is not None and config.BENIGN_LABEL in recognizer.classes:
            self._benign_mean = recognizer.means[recognizer.classes.index(config.BENIGN_LABEL)]
        self._load()

    # -- clustering -----------------------------------------------------------
    def observe(self, x_scaled, raw: dict | None = None, src=None, dst=None, dport=None,
                route: str = "openset", p_values=None, ae_errors=None,
                now: float | None = None) -> dict:
        """Add one rejected flow to a family and return that family's state.

        ``x_scaled`` is the scaled feature vector the models saw, ``raw`` maps
        feature name to the unscaled value, ``route`` records which detector
        rejected the flow, ``p_values`` is the recogniser's p-value row (used to
        name the nearest known class) and ``ae_errors`` the autoencoder's
        per-feature errors when the flow arrived by that route.
        """
        now = time.time() if now is None else now
        x = np.asarray(x_scaled, dtype=np.float64).ravel()
        z = self.embed(x)
        p_max, nearest = None, None
        if p_values is not None:
            p = np.asarray(p_values, dtype=np.float64).ravel()
            nearest = int(p.argmax())
            p_max = float(p[nearest])
        with self._lock:
            family = self._assign(z, now)
            family.add(z, src, dst, dport, route, now, p_max=p_max)
            # Describe the family by its most firmly rejected member, not its
            # most recent one, so the description settles instead of drifting
            # with every flow that arrives.
            if nearest is not None and p_max <= family.best_p:
                family.nearest_class = self.rec.classes[nearest]
                family.nearest_p = p_max
            if not family.fingerprint or family.n_flows <= family.min_flows:
                family.fingerprint = self.fingerprint(x, raw, ae_errors)
            if family.promoted_name is None and family.id in self.promoted:
                family.promoted_name = self.promoted[family.id]
            self._evict()
            return family.to_dict()

    def embed(self, x_scaled) -> np.ndarray:
        """The vector a family is defined by.

        For the cosine metric this is the unit direction in which the flow
        deviates from benign traffic, in the whitened space where coordinates
        are comparable. For the Euclidean metric it is the whitened vector
        itself.
        """
        x = np.asarray(x_scaled, dtype=np.float64).ravel()
        z = self.rec.whiten(x)[0] if self.rec is not None else x
        if self.metric != "cosine":
            return z
        if self._benign_mean is not None:
            z = z - (self.rec.whiten(self._benign_mean)[0] if self.rec is not None
                     else self._benign_mean)
        norm = float(np.linalg.norm(z))
        return z / norm if norm > 0 else z

    def _distance(self, z: np.ndarray, centroid: np.ndarray) -> float:
        if self.metric == "cosine":
            denominator = float(np.linalg.norm(z) * np.linalg.norm(centroid))
            if denominator == 0:
                return 1.0
            return float(1.0 - np.dot(z, centroid) / denominator)
        return float(np.linalg.norm(z - centroid))

    def _assign(self, z: np.ndarray, now: float) -> UnknownFamily:
        """Nearest family within the radius, or a new one.

        This is a Python loop over at most MAX_FAMILIES centroids, so it costs
        on the order of 300 microseconds per flow. That is immaterial on the
        live path, where only the rejected minority of flows reach it, but it
        dominates the offline sweeps in src/models/discovery_eval.py, which push
        every rejected flow of a whole test split through it. If that ever needs
        to be faster, hold the centroids in one matrix and take the argmin of a
        single product; building it in insertion order keeps the tie-breaking
        identical to this loop.
        """
        best, best_d = None, np.inf
        for family in self.families.values():
            d = self._distance(z, family.centroid)
            if d < best_d:
                best, best_d = family, d
        if best is not None and best_d <= self.radius:
            return best
        family_id = self._mint_id()
        family = UnknownFamily(family_id, z, now, min_flows=self.min_flows)
        self.families[family_id] = family
        # Debug, not info: most new families are one-off flows from the tail of
        # normal traffic, and on a busy link there are many of them.
        log.debug("new unknown family %s (%d held, radius %.3f)",
                  family_id, len(self.families), self.radius)
        return family

    def _mint_id(self) -> str:
        while True:
            family_id = f"NETRA-U{self._next_id:03d}"
            self._next_id += 1
            if family_id not in self.families:
                return family_id

    def _evict(self) -> None:
        """Keep memory bounded by dropping the families least worth reporting.

        Least worth reporting means fewest flows, oldest last.
        A family an operator has named is never dropped, so the loop keeps
        going past one rather than stopping at a fixed slice, which would leave
        the tracker over its cap whenever the weakest families happen to be the
        named ones.
        """
        over = len(self.families) - MAX_FAMILIES
        if over <= 0:
            return
        ordered = sorted(self.families.values(), key=lambda f: (f.n_flows, f.last_seen))
        for family in ordered:
            if over <= 0:
                break
            if family.promoted_name:
                continue
            del self.families[family.id]
            self.dropped += 1
            over -= 1

    # -- fingerprints ---------------------------------------------------------
    def fingerprint(self, x_scaled, raw: dict | None = None, ae_errors=None) -> list[dict]:
        """The features that make this flow unusual, in readable units.

        Deviation is measured against the benign class mean in scaled units, so
        the number is a standard-deviation-like distance from normal traffic and
        is comparable between features. When the flow came in through the
        autoencoder its per-feature reconstruction errors are used instead,
        because then "the model could not reproduce this feature" is the more
        direct explanation.
        """
        features = self.rec.features if self.rec is not None else []
        if not features:
            return []
        if ae_errors is not None:
            weight = np.asarray(ae_errors, dtype=np.float64).ravel()
            total = float(weight.sum())
            order = np.argsort(-weight)
            out = []
            for i in order[:FINGERPRINT_K]:
                if total <= 0 or weight[i] / total < 0.01:
                    continue
                item = {"feature": features[i], "share": round(float(weight[i] / total), 3),
                        "basis": "reconstruction error"}
                if raw and features[i] in raw:
                    item["value"] = _round(raw[features[i]])
                out.append(item)
            return out
        x = np.asarray(x_scaled, dtype=np.float64).ravel()
        deviation = x - self._benign_mean if self._benign_mean is not None else x
        out = []
        for i in np.argsort(-np.abs(deviation))[:FINGERPRINT_K]:
            item = {"feature": features[i], "deviation": round(float(deviation[i]), 2),
                    "basis": "distance from benign mean"}
            if raw and features[i] in raw:
                item["value"] = _round(raw[features[i]])
            out.append(item)
        return out

    # -- naming ---------------------------------------------------------------
    def promote(self, family_id: str, name: str) -> dict:
        """Give a discovered family a real name.

        The name sticks to that family, is persisted, and is what later alerts
        report. This is the step that closes the loop: the operator identifies
        what Netra found, and Netra keeps the identification.
        """
        with self._lock:
            name = str(name).strip()
            if not name:
                raise ValueError("a promoted family needs a name")
            family = self.families.get(family_id)
            if family is None:
                raise KeyError(family_id)
            family.promoted_name = name
            self.promoted[family_id] = name
            self._save()
            log.info("family %s promoted to %r after %d flows", family_id, name, family.n_flows)
            return family.to_dict()

    def snapshot(self) -> list[dict]:
        """Every family, most recently seen first, for the API and the app."""
        with self._lock:
            return [f.to_dict() for f in sorted(self.families.values(),
                                                key=lambda f: -f.last_seen)]

    # -- persistence ----------------------------------------------------------
    def _save(self) -> None:
        if not self.persist:
            return
        try:
            self._store.parent.mkdir(parents=True, exist_ok=True)
            self._store.write_text(json.dumps({
                "kind": self.kind, "metric": self.metric, "radius": self.radius,
                "next_id": self._next_id, "promoted": self.promoted,
                "families": [f.to_dict(with_centroid=True) for f in self.families.values()],
            }, indent=2))
        except OSError:
            log.warning("could not write %s", self._store, exc_info=True)

    def _load(self) -> None:
        if not self.persist or not self._store.exists():
            return
        try:
            d = json.loads(self._store.read_text())
        except (OSError, json.JSONDecodeError):
            log.warning("ignoring unreadable %s", self._store, exc_info=True)
            return
        if d.get("metric", DEFAULT_METRIC) != self.metric:
            # Centroids mean different things under the two metrics, so a store
            # written by one is not readable by the other.
            log.info("ignoring %s: written for the %s metric, this tracker uses %s",
                     self._store, d.get("metric"), self.metric)
            return
        self.promoted = dict(d.get("promoted", {}))
        self._next_id = int(d.get("next_id", 1))
        for rec in d.get("families", []):
            centroid = rec.get("centroid")
            # A stored family without a centroid cannot be matched against, and
            # a centroid of the wrong width belongs to a different feature set.
            if not centroid or (self.rec is not None and len(centroid) != len(self.rec.features)):
                continue
            family = UnknownFamily(rec["id"], np.asarray(centroid, dtype=np.float64),
                                   rec.get("first_seen", time.time()),
                                   min_flows=self.min_flows)
            family.n_flows = int(rec.get("flows", 0))
            family.best_p = float(rec.get("best_p", 1.0))
            family.last_seen = rec.get("last_seen", family.first_seen)
            family.sources.update({s: 1 for s in rec.get("sources", [])})
            family.destinations.update({s: 1 for s in rec.get("destinations", [])})
            family.ports.update({p: 1 for p in rec.get("ports", [])})
            family.nearest_class = rec.get("nearest_class")
            family.nearest_p = float(rec.get("nearest_p") or 0.0)
            family.fingerprint = rec.get("fingerprint", [])
            family.promoted_name = rec.get("promoted_name") or self.promoted.get(rec["id"])
            self.families[family.id] = family
        if self.families:
            log.info("restored %d unknown famil%s from %s", len(self.families),
                     "y" if len(self.families) == 1 else "ies", self._store)

    def save(self) -> None:
        with self._lock:
            self._save()


def calibrated_radius(recognizer, factor: float = RADIUS_FACTOR) -> float:
    """Cluster radius taken from the recogniser's own calibration.

    The calibration arrays hold, for each class, the distance from held-out
    flows of that class to the 10th nearest training flow of the same class.
    Their median is the typical size of a local neighbourhood inside a class, in
    exactly the whitened units the clusterer works in, so it is the natural
    scale for "close enough to be the same thing" and needs no tuning.
    """
    if recognizer is None:
        return 1.0
    cal = recognizer.calibration.get("knn") or []
    medians = [float(np.median(c)) for c in cal if len(c)]
    if not medians:
        return 1.0
    return factor * float(np.median(medians))


def _phrase(item: dict) -> str:
    """One fingerprint entry, written the way it reads best."""
    name = item["feature"]
    value = item.get("value")
    if "share" in item:
        head = f"{name}={value}" if value is not None else name
        return f"{head} ({item['share']:.0%} of the error)"
    sign = "above" if item.get("deviation", 0) >= 0 else "below"
    head = f"{name}={value}" if value is not None else name
    return f"{head} ({abs(item.get('deviation', 0)):.1f} {sign} benign)"


def _round(v):
    """Present a feature value the way a person would read it."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return v
    if not np.isfinite(f):
        return 0.0
    return round(f, 3) if abs(f) < 1000 else int(round(f))
