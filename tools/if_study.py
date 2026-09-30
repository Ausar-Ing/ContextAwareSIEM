#!/usr/bin/env python3
"""
Sensitivity study for Component 6 (Isolation Forest) of system_model.md.

This does NOT predict performance on the project's real data -- that data does
not exist yet. It characterises how the METHOD behaves as a function of the
things the project controls: baseline duration, subsample size psi, window
overlap, and whether the baseline covers the normal behaviour modes present at
evaluation time. Those relationships are properties of Isolation Forest and of
the window construction, not of any particular alert stream, so they transfer.

Stream generator, window builder and feature map are the real ones
(window_builder.py) so the study exercises the code the system would run.

Outputs: figures + a printed results table.
"""
from __future__ import annotations

import collections
import json
import math
import sys

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.covariance import MinCovDet

sys.path.insert(0, "/home/claude/work")
from window_builder import (Alert, WindowBuilder, FEATURE_NAMES, log_transform)

DAY = 86400.0
HOUR = 3600.0
T0 = 1_760_000_000.0  # arbitrary epoch anchor

# ---------------------------------------------------------------------------
# Stream generator
# ---------------------------------------------------------------------------
# Each normal mode is a plausible source of Wazuh alerts on a monitored host.
# The point of having several is that a baseline which misses one of them is a
# baseline that will flag that mode as anomalous at evaluation time (E4).

NORMAL_MODES = {
    # name:        (rules, levels, tactics, per-day rate, hour window, burstiness)
    "interactive": (["18107", "18149", "60122"], [3, 3, 4], ["TA0001"], 40, (8, 19), 1),
    "admin":       (["2902", "2904", "5901", "5902"], [3, 7, 8, 8], ["TA0003"], 8, (9, 18), 3),
    "nightly":     (["533", "591", "2501"], [7, 3, 5], ["TA0005"], 25, (1, 4), 12),
    "netsvc":      (["533", "530"], [7, 3], [], 6, (0, 24), 1),
    "patchday":    (["2901", "2902", "2903"], [3, 3, 3], [], 30, (10, 12), 20),
}

# An attack chain: rules rare for the entity, escalating level, advancing tactics.
ATTACK_CHAIN = [
    ("60103", 5, "TA0007"),   # discovery
    ("60103", 5, "TA0007"),
    ("18152", 8, "TA0006"),   # credential access
    ("18152", 8, "TA0006"),
    ("18152", 8, "TA0006"),
    ("60109", 10, "TA0008"),  # lateral movement
    ("92213", 12, "TA0003"),  # persistence
    ("92052", 12, "TA0005"),  # defense evasion
]


def _hour_of(ts: float) -> int:
    return int((ts % DAY) // HOUR)


def gen_stream(rng, days: float, n_hosts: int = 3, n_users: int = 4,
               modes=None, start: float = T0, attacks_per_day: float = 0.0):
    """Generate a time-ordered alert stream. Returns list[Alert]."""
    modes = modes or list(NORMAL_MODES)
    hosts = [f"h{i:03d}" for i in range(n_hosts)]
    users = [f"u{i}" for i in range(n_users)]
    out = []
    seq = 0

    for m in modes:
        rules, levels, tactics, rate, (h0, h1), burst = NORMAL_MODES[m]
        n_events = rng.poisson(rate * days * n_hosts)
        for _ in range(n_events):
            host = hosts[rng.integers(n_hosts)]
            # BUGFIX 2026-09-11: day must be a WHOLE day index. As a float it
            # carried a random fraction of a day into t, which smeared every
            # mode's (h0,h1) hour window uniformly across the clock -- so the
            # generator had no time-of-day structure at all and night_fraction
            # was pure noise. _hour_of() at the top of this file is dead code
            # left over from the same oversight.
            day = int(rng.integers(0, max(1, int(math.ceil(days)))))
            hr = rng.uniform(h0, h1) % 24
            t = start + day * DAY + hr * HOUR + rng.uniform(0, 60)
            k = 1 + rng.poisson(burst - 1) if burst > 1 else 1
            for j in range(k):
                i = rng.integers(len(rules))
                ents = [("host", host)]
                if m == "interactive":
                    ents.append(("user", users[rng.integers(n_users)]))
                seq += 1
                out.append(Alert(
                    alert_id=f"n{seq}", ingest_seq=seq,
                    ts=t + j * abs(rng.normal(3, 2)),
                    rule_id=rules[i], rule_level=levels[i],
                    rule_groups=("windows",),
                    techniques=(f"T{9000+i}",) if tactics else (),
                    tactics=tuple(tactics), entities=tuple(ents), label=0))

    n_attacks = rng.poisson(attacks_per_day * days)
    for _ in range(n_attacks):
        host = hosts[rng.integers(n_hosts)]
        user = users[rng.integers(n_users)]
        t = start + rng.uniform(0, days) * DAY + rng.uniform(0, DAY)
        for j, (rid, lvl, tac) in enumerate(ATTACK_CHAIN):
            seq += 1
            out.append(Alert(
                alert_id=f"a{seq}", ingest_seq=seq,
                ts=t + j * abs(rng.normal(25, 12)),
                rule_id=rid, rule_level=lvl,
                rule_groups=("windows",),
                techniques=(f"T1{j:03d}",), tactics=(tac,),
                entities=(("host", host), ("user", user)), label=1))

    out.sort(key=lambda a: (a.ts, a.ingest_seq))
    for i, a in enumerate(out):
        a.ingest_seq = i
    return out


def build_windows(stream, baseline_rules=None, learn=False, N=20, T_hours=24.0):
    """Run the real window builder over a stream. Returns (X, y, meta)."""
    wb = WindowBuilder(N=N, T_hours=T_hours, baseline_rules=baseline_rules,
                       learn_rules=learn)
    X, y, ent_type, aid = [], [], [], []
    for a in stream:
        for e, f, scoreable in wb.push(a):
            if not scoreable:
                continue
            X.append(f)
            y.append(a.label)
            ent_type.append(e[0])
            aid.append(a.alert_id)
    return (np.array(X), np.array(y), np.array(ent_type), np.array(aid),
            wb.baseline_rules)


# ---------------------------------------------------------------------------
# Scorers
# ---------------------------------------------------------------------------
def fit_iforest(Xtr, psi=256, n_estimators=200, seed=0):
    psi = min(psi, len(Xtr))
    m = IsolationForest(n_estimators=n_estimators, max_samples=psi,
                        max_features=1.0, random_state=seed, n_jobs=1)
    m.fit(Xtr)
    return m


def raw_if_score(m, X):
    """Higher = more anomalous. sklearn's score_samples is the NEGATIVE of the
    published anomaly score, so flip it. This sign is the single most common
    Isolation Forest implementation bug."""
    return -m.score_samples(X)


def percentile_calibrate(train_scores):
    """Section 4.3.4. Returns f(scores) -> [0,100] percentile under baseline."""
    ref = np.sort(train_scores)
    def f(s):
        return 100.0 * np.searchsorted(ref, s, side="right") / len(ref)
    return f


def maxz_score(Xtr, X):
    med = np.median(Xtr, axis=0)
    mad = np.median(np.abs(Xtr - med), axis=0)
    mad = np.where(mad < 1e-9, 1.0, mad) * 1.4826
    return np.max(np.abs((X - med) / mad), axis=1)


def mahalanobis_score(Xtr, X, seed=0):
    """Robust covariance. Unlike Isolation Forest this DOES see linear
    correlation between features."""
    keep = Xtr.std(axis=0) > 1e-9
    try:
        mcd = MinCovDet(random_state=seed, support_fraction=0.9).fit(Xtr[:, keep])
        return mcd.mahalanobis(X[:, keep])
    except Exception:
        return maxz_score(Xtr, X)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def ndcg_at_k(scores, labels, k=20):
    order = np.argsort(-scores)
    rel = labels[order][:k]
    disc = 1.0 / np.log2(np.arange(2, len(rel) + 2))
    dcg = float((rel * disc).sum())
    ideal = np.sort(labels)[::-1][:k]
    idcg = float((ideal * disc[:len(ideal)]).sum())
    return dcg / idcg if idcg > 0 else float("nan")


def precision_at_k(scores, labels, k=20):
    order = np.argsort(-scores)
    return float(labels[order][:k].mean())


def auc(scores, labels):
    pos, neg = scores[labels == 1], scores[labels == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    allv = np.concatenate([pos, neg])
    r = allv.argsort().argsort().astype(float) + 1
    # average ties
    _, inv, cnts = np.unique(allv, return_inverse=True, return_counts=True)
    if (cnts > 1).any():
        sums = np.zeros(len(cnts))
        np.add.at(sums, inv, r)
        r = (sums / cnts)[inv]
    rp = r[:len(pos)].sum()
    return float((rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def stride_subsample(X, stride):
    return X[::stride]
