#!/usr/bin/env python3
"""
Component 6 (Sequence Anomaly Scoring) as specified in Deliverable 3, Sec. III-E.

One Isolation Forest per entity type, fitted on every STRIDE-th baseline window;
raw scores turned into S_seq by the empirical CDF of the host's own HELD-OUT
baseline windows (the ones the stride left out), falling back to the type-level
held-out CDF when the host has fewer than MIN_HOST_CAL of them. Each seed is a
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
MIN_TRAIN = 200                       # below this no forest is fitted for the type
NIGHT = W.FEATURE_NAMES.index("night_fraction")


class TypeModel:
    """Forest + calibration for one entity type, one seed."""

    def __init__(self, seed: int):
        self.seed = seed
        self.forest = None
        self.cal_host: dict = {}          # host -> sorted held-out raw scores
        self.cal_type = None              # pooled held-out raw scores
        self.n_train = 0

    @staticmethod
    def prep(F: np.ndarray, entries: bool) -> np.ndarray:
        X = W.log_transform(F, entries=entries)
        return np.delete(X, NIGHT, axis=1)

    def fit(self, F_base: np.ndarray, hosts_base: list, entries: bool):
        """F_base: baseline feature rows in stream order; hosts_base: host of
        each row (the host of the alert that produced the window)."""
        X = self.prep(F_base, entries)
        idx = np.arange(len(X))
        tr = idx % STRIDE == 0
        self.n_train = int(tr.sum())
        if self.n_train < MIN_TRAIN:
            return False
        self.forest = IsolationForest(n_estimators=N_TREES,
                                      max_samples=min(PSI_MAX, self.n_train),
                                      random_state=self.seed).fit(X[tr])
        raw = -self.forest.score_samples(X[~tr])
        hb = np.asarray(hosts_base, dtype=object)[~tr]
        self.cal_type = np.sort(raw)
        for h in set(hb):
            v = raw[hb == h]
            if len(v) >= MIN_HOST_CAL:
                self.cal_host[h] = np.sort(v)
        return True

    def score(self, F: np.ndarray, hosts: list, entries: bool) -> np.ndarray:
        """S_seq in [0, 100] for each row."""
        raw = -self.forest.score_samples(self.prep(F, entries))
        out = np.empty(len(raw))
        hs = np.asarray(hosts, dtype=object)
        for h in set(hs):
            m = hs == h
            ref = self.cal_host.get(h, self.cal_type)
            out[m] = 100.0 * np.searchsorted(ref, raw[m], side="right") / len(ref)
        return out
