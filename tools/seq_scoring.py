#!/usr/bin/env python3
"""
Component 6 (Sequence Anomaly Scoring) as specified in Deliverable 3, Sec. III-E.

One Isolation Forest per entity type, fitted on every STRIDE-th baseline window;
raw scores turned into S_seq by a mixture of two empirical CDFs of HELD-OUT
baseline windows (the ones the stride left out): the host's own and the
entity type's pooled one, weighted w = n_h / (n_h + SHRINK_N0) by the host's
held-out count n_h (method from 2026-10-23; CONTEXTSIEM_CALIB=own_pooled
restores the earlier own-CDF-or-pooled-fallback rule at MIN_HOST_CAL). Each seed is a
complete, independent replica: callers get one score vector per seed and report
the spread, rather than averaging scores (which would only make a bigger forest
and hide the seed variance the protocol is meant to show).

Why held-out calibration: the trees were grown from the training points, so a
CDF fitted on them is biased for unseen benign windows. Measured on synthetic
heavy-tailed data (6 reps, psi 4096): 5.19% of unseen benign vectors above the
95th percentile with training-window calibration vs 5.06% held-out, and roughly
twice the variance across seeds. Small, but removed for free: the stride
already leaves 9 of every 10 baseline windows out of training.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

import window_builder as W

STRIDE = 10
N_TREES = 200
PSI_MAX = 4096
MIN_HOST_CAL = 500                    # Sec. III-E fallback threshold (provisional)
# Sensitivity runs override it with CONTEXTSIEM_MIN_HOST_CAL (2026-10-23: 100 tested).
# Per-host equal-share training (Sec. III-E) is the method from 2026-10-23.
# CONTEXTSIEM_STRATIFY=0 restores the pooled (volume-weighted) training that every
# earlier result was produced with.
import os as _os
STRATIFY = _os.environ.get("CONTEXTSIEM_STRATIFY", "1") != "0"
MIN_HOST_CAL = int(_os.environ.get("CONTEXTSIEM_MIN_HOST_CAL", MIN_HOST_CAL))
# Calibration mode (2026-10-23 study of hosts with small baselines):
#   own_pooled  host's own held-out CDF if it has >= MIN_HOST_CAL windows, else the pooled CDF
#   locscale    raw scores standardised by the host's own median and robust spread, then
#               converted to a percentile of the pooled STANDARDISED distribution, so the
#               host sets the centre and scale and the pool supplies the tail
#   shrink      w * own CDF + (1 - w) * pooled CDF, w = n_h / (n_h + SHRINK_N0)
CALIB = _os.environ.get("CONTEXTSIEM_CALIB", "shrink")    # shrink adopted 2026-10-23
MIN_LOC = 20                          # windows needed to estimate a host's centre and spread
SHRINK_N0 = int(_os.environ.get("CONTEXTSIEM_SHRINK_N0", 100))   # held-out windows at which own and pooled weigh equally
MIN_TRAIN = 200                       # below this no forest is fitted for the type
NIGHT = W.FEATURE_NAMES.index("night_fraction")


class TypeModel:
    """Forest + calibration for one entity type, one seed."""

    def __init__(self, seed: int, stratify: bool | None = None, min_host_cal: int | None = None,
                 fallback: str = "pooled"):
        """fallback: what a host with fewer than min_host_cal held-out windows is
        calibrated against -- "pooled" (the entity type's held-out distribution)
        or "none" (left unscored: -1, which callers treat as no temporal evidence)."""
        self.fallback = fallback
        self.seed = seed
        self.stratify = STRATIFY if stratify is None else stratify
        self.min_host_cal = MIN_HOST_CAL if min_host_cal is None else min_host_cal
        self.forest = None
        self.cal_host: dict = {}          # host -> sorted held-out raw scores
        self.cal_type = None              # pooled held-out raw scores
        self.n_train = 0
        self.train_share: dict = {}       # host -> windows in the training set
        self.cal_source: dict = {}        # host -> ("own" | "pooled", held-out windows)

    def _train_mask(self, n: int, hosts: np.ndarray) -> np.ndarray:
        """Every STRIDE-th baseline window; with stratify, each host then keeps at
        most an equal quota (the stride budget divided by the number of hosts),
        taken evenly over its own baseline so the period stays covered. Hosts
        with fewer windows than the quota keep all of theirs. Windows dropped by
        the quota were never seen by the trees and join the calibration set."""
        tr = np.arange(n) % STRIDE == 0
        if not self.stratify:
            return tr
        hs = sorted(set(hosts[tr]))
        quota = int(np.ceil(tr.sum() / max(1, len(hs))))
        out = np.zeros(n, bool)
        for h in hs:
            idx = np.flatnonzero(tr & (hosts == h))
            if len(idx) > quota:
                idx = idx[np.linspace(0, len(idx) - 1, quota).round().astype(int)]
            out[idx] = True
        return out

    @staticmethod
    def prep(F: np.ndarray, entries: bool) -> np.ndarray:
        X = W.log_transform(F, entries=entries)
        return np.delete(X, NIGHT, axis=1)

    def fit(self, F_base: np.ndarray, hosts_base: list, entries: bool):
        """F_base: baseline feature rows in stream order; hosts_base: host of
        each row (the host of the alert that produced the window)."""
        X = self.prep(F_base, entries)
        hosts = np.asarray(hosts_base, dtype=object)
        tr = self._train_mask(len(X), hosts)
        self.n_train = int(tr.sum())
        if self.n_train < MIN_TRAIN:
            return False
        self.train_share = {h: int((tr & (hosts == h)).sum()) for h in set(hosts)}
        self.forest = IsolationForest(n_estimators=N_TREES,
                                      max_samples=min(PSI_MAX, self.n_train),
                                      random_state=self.seed).fit(X[tr])
        self._calibrate(-self.forest.score_samples(X[~tr]), hosts[~tr], set(hosts))
        return True

    def _raw_scores(self, F, entries):
        return -self.forest.score_samples(self.prep(F, entries))

    @staticmethod
    def _loc_scale(v):
        med = float(np.median(v))
        sc = 1.4826 * float(np.median(np.abs(v - med)))
        if sc <= 0:
            q75, q25 = np.percentile(v, [75, 25]); sc = float(q75 - q25) / 1.349
        if sc <= 0:
            sc = float(np.std(v))
        return med, (sc if sc > 0 else 1e-9)

    def _calibrate(self, raw, hb, all_hosts):
        """Fit the per-host calibration from held-out raw scores `raw` of hosts `hb`."""
        self.calib = CALIB
        self.cal_type = np.sort(raw)
        self.held = {h: np.sort(raw[hb == h]) for h in all_hosts}
        for h in all_hosts:
            v = self.held[h]
            if len(v) >= self.min_host_cal:
                self.cal_host[h] = v
        if self.calib == "locscale":
            self.glob = self._loc_scale(raw)
            self.ls = {h: self._loc_scale(v) for h, v in self.held.items() if len(v) >= MIN_LOC}
            z = np.concatenate([(v - self.ls.get(h, self.glob)[0]) / self.ls.get(h, self.glob)[1]
                                for h, v in self.held.items() if len(v)])
            self.ref_z = np.sort(z)
        for h in all_hosts:
            n = len(self.held[h])
            if self.calib == "locscale":
                src = "own" if n >= MIN_LOC else "pooled"
            elif self.calib == "shrink":
                src = "own" if n >= SHRINK_N0 else "pooled"      # own weight >= 0.5
            else:
                src = "own" if n >= self.min_host_cal else "pooled"
            self.cal_source[h] = (src, int(n))

    def _to_percent(self, raw, hosts):
        out = np.empty(len(raw))
        hs = np.asarray(hosts, dtype=object)
        for h in set(hs):
            m = hs == h
            if self.calib == "locscale":
                med, sc = self.ls.get(h, self.glob)
                out[m] = 100.0 * np.searchsorted(self.ref_z, (raw[m] - med) / sc, side="right") / len(self.ref_z)
                continue
            if self.calib == "shrink":
                v = self.held.get(h, np.empty(0)); n = len(v)
                pool = np.searchsorted(self.cal_type, raw[m], side="right") / len(self.cal_type)
                own = np.searchsorted(v, raw[m], side="right") / n if n else 0.0
                w = n / (n + SHRINK_N0)
                out[m] = 100.0 * (w * own + (1 - w) * pool)
                continue
            if h not in self.cal_host and self.fallback == "none":
                out[m] = -1.0; continue
            ref = self.cal_host.get(h, self.cal_type)
            out[m] = 100.0 * np.searchsorted(ref, raw[m], side="right") / len(ref)
        return out

    def score(self, F: np.ndarray, hosts: list, entries: bool) -> np.ndarray:
        """S_seq in [0, 100] for each row (-1 where fallback="none" leaves a host unscored)."""
        return self._to_percent(self._raw_scores(F, entries), hosts)


class RobustZModel(TypeModel):
    """Comparator B2' (Deliverable 3, Sec. IV-B): the forest replaced by a robust
    z-score, max_j |x_j - median_j| / (1.4826 * MAD_j) over the same model inputs,
    with the same training subsample and the same held-out per-host calibration.
    Deterministic: the seed is ignored.

    Scale: 1.4826 * MAD, the normal-consistent MAD. Most window features are
    discrete with a dominant value, so the MAD is often zero; dividing by a tiny
    constant then turns any departure into a near-infinite z and the score into a
    count of departures (measured on shaw: 9 of 14 features had zero MAD). The
    usual modified-z fallback is used instead (Iglewicz and Hoaglin): 1.2533 *
    mean absolute deviation from the median, then the standard deviation, and a
    unit scale only for a feature that is exactly constant on the baseline."""

    def fit(self, F_base, hosts_base, entries):
        X = self.prep(F_base, entries)
        hosts = np.asarray(hosts_base, dtype=object)
        tr = self._train_mask(len(X), hosts)
        self.n_train = int(tr.sum())
        if self.n_train < MIN_TRAIN:
            return False
        self.med = np.median(X[tr], axis=0)
        dev = np.abs(X[tr] - self.med)
        mad = 1.4826 * np.median(dev, axis=0)
        meanad = 1.2533 * dev.mean(axis=0)
        sd = X[tr].std(axis=0)
        self.mad = np.where(mad > 0, mad, np.where(meanad > 0, meanad, np.where(sd > 0, sd, 1.0)))
        self.forest = True
        self._calibrate(self._raw(X[~tr]), hosts[~tr], set(hosts))
        return True

    def _raw(self, X):
        return np.max(np.abs(X - self.med) / self.mad, axis=1)

    def _raw_scores(self, F, entries):
        return self._raw(self.prep(F, entries))
