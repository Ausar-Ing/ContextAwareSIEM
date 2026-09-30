#!/usr/bin/env python3
"""
How many full-24h nights does a duty-cycled baseline need?

Context. The monitored host is a desktop that has been shut down nightly
(measured 25 Aug - 11 Sep 2026: 50.9% uptime, 12.2 h/day). Running it
continuously for five weeks is not practical. The protocol's fallback is a
handful of deliberate awake nights. This study asks how many.

Two effects are separated, because they point in opposite directions:

  A. COVERAGE LOSS. Behaviour that only happens at night (the `nightly` mode:
     scheduled tasks, maintenance, backups) is under-represented in the
     baseline, so the model has not learned it.

  B. SPURIOUS INFLATION. `night_fraction` is near-constant in a duty-cycled
     baseline, so any evaluation window at night is flagged anomalous for a
     reason that has nothing to do with attack behaviour. That makes AUC look
     BETTER than it should. Reporting that number would be dishonest.

Design. Baseline 35 days on a 10:00-22:00 duty cycle, with k nights held open.
Evaluation runs 24/7 with attacks at any hour. Training-pool size is held
constant across k so the sweep measures coverage, not volume. The active-time
correction is applied in every arm. psi=4096 (component6_isolation_forest.md).

Arms:
  full15  - all fifteen features, as specified
  no_nf   - night_fraction removed
  ref     - baseline collected 24/7 (the unreachable ideal), both feature sets
"""
from __future__ import annotations
import json, sys, warnings
import numpy as np
sys.path.insert(0, "/home/claude/work")
from if_study import (gen_stream, fit_iforest, raw_if_score, auc,
                      precision_at_k, ndcg_at_k, DAY, HOUR)
from window_builder import (WindowBuilder, FEATURE_NAMES, log_transform,
                            INTER_ARRIVAL_FLOOR_S, SITE_UTC_OFFSET_H)
warnings.filterwarnings("ignore")

TZ = SITE_UTC_OFFSET_H * 3600.0
# anchor so that generator hour-of-day == SITE LOCAL hour-of-day
T0 = (1_760_000_000 // 86400) * 86400 - TZ + 86400.0

BASE_DAYS, EVAL_DAYS = 35, 12
UP_START, UP_END = 10.0, 22.0        # local hours the host is normally on
PSI, STRIDE, SEEDS = 4096, 10, list(range(10))
NIGHT_IDX = FEATURE_NAMES.index("night_fraction")


# --------------------------------------------------------------------------
def downtime_intervals(days, awake_nights: set) -> np.ndarray:
    """Nights the host is OFF: [22:00 day d, 10:00 day d+1]."""
    iv = []
    for d in range(days):
        if d in awake_nights:
            continue
        iv.append((T0 + d * DAY + UP_END * HOUR,
                   T0 + (d + 1) * DAY + UP_START * HOUR))
    return np.array(iv, dtype=float).reshape(-1, 2)


class ActiveWindowBuilder(WindowBuilder):
    """WindowBuilder + the active-time correction of protocol 2.2:
    the host being off is not the entity being quiet."""

    def set_downtime(self, iv: np.ndarray):
        if len(iv) == 0:
            self.st = self.en = self.cum = None
            return
        order = iv[:, 0].argsort()
        iv = iv[order]
        self.st, self.en = iv[:, 0], iv[:, 1]
        self.cum = np.concatenate([[0.0], np.cumsum(self.en - self.st)[:-1]])

    def _down_before(self, t):
        t = np.asarray(t, dtype=float)
        i = np.searchsorted(self.st, t, side="right") - 1
        out = np.zeros_like(t)
        ok = i >= 0
        if ok.any():
            j = i[ok]
            out[ok] = self.cum[j] + np.minimum(t[ok], self.en[j]) - self.st[j]
        return out

    def _active(self, a, b):
        return (b - a) - (self._down_before(b) - self._down_before(a))

    def features(self, w, cur, ent=None):
        f = super().features(w, cur, ent)
        if self.st is None or len(w) < 2:
            return f
        ts = np.array([x.ts for x in w])
        f[1] = max(float(self._active(ts[0], ts[-1])), 0.0)
        g = np.maximum(self._active(ts[:-1], ts[1:]), INTER_ARRIVAL_FLOOR_S)
        f[10], f[11] = float(g.mean()), float(g.min())
        return f


def build(stream, downtime, baseline_rules=None, learn=False):
    # downtime_gap_s=None: this class applies its OWN batch correction from the
    # generator's true off intervals. Leaving the online correction on as well
    # would correct twice and change the recorded results (night_coverage_note).
    wb = ActiveWindowBuilder(baseline_rules=baseline_rules, learn_rules=learn,
                             downtime_gap_s=None)
    wb.set_downtime(downtime)
    X, y, et = [], [], []
    for a in stream:
        for e, f, ok in wb.push(a):
            if ok and e[0] == "host":
                X.append(f); y.append(a.label); et.append(e[0])
    return np.array(X), np.array(y), wb.baseline_rules


def apply_duty_cycle(stream, downtime):
    """Drop alerts that occur while the host is off."""
    if len(downtime) == 0:
        return stream
    st, en = downtime[:, 0], downtime[:, 1]
    keep = []
    for a in stream:
        i = np.searchsorted(st, a.ts, side="right") - 1
        if i >= 0 and a.ts <= en[i]:
            continue
        keep.append(a)
    return keep


# --------------------------------------------------------------------------
print("generating streams ...")
rng = np.random.default_rng(7)
base_full = gen_stream(rng, days=BASE_DAYS, n_hosts=1, n_users=3,
                       start=T0, attacks_per_day=0.0)
eval_stream = gen_stream(rng, days=EVAL_DAYS, n_hosts=1, n_users=3,
                         start=T0 + (BASE_DAYS + 5) * DAY, attacks_per_day=2.0)
print(f"  baseline alerts (24/7) {len(base_full)}   eval alerts {len(eval_stream)}")

K_VALUES = [0, 1, 2, 3, 5, 8, 12, 20, BASE_DAYS]

# pass 1: pool sizes, so every arm can train on the same n
pools, cache = {}, {}
for k in K_VALUES:
    nights = set(np.linspace(0, BASE_DAYS - 1, k).round().astype(int).tolist()) if k else set()
    dt_iv = downtime_intervals(BASE_DAYS, nights)
    stream = apply_duty_cycle(base_full, dt_iv)
    Xb, _, rules = build(stream, dt_iv, learn=True)
    Xe, ye, _ = build(eval_stream, np.zeros((0, 2)), baseline_rules=rules)
    pool = Xb[::STRIDE]
    cache[k] = (pool, Xe, ye, len(stream))
    pools[k] = len(pool)
    nf = pool[:, NIGHT_IDX]
    print(f"  k={k:2d}  alerts kept {len(stream):6d}  pool {len(pool):5d}  "
          f"night_fraction mean {nf.mean():.3f} sd {nf.std():.3f}")

N_FIX = min(pools.values())
print(f"\ntraining-pool size held at n={N_FIX} across all arms\n")

rows = []
for k in K_VALUES:
    pool, Xe, ye, nkept = cache[k]
    rec = dict(k=k, alerts_kept=nkept, pool=pools[k],
               night_fraction_sd=float(pool[:, NIGHT_IDX].std()))
    for arm, drop_nf in (("full15", False), ("no_nf", True)):
        cols = [i for i in range(15) if not (drop_nf and i == NIGHT_IDX)]
        A, B = log_transform(pool)[:, cols], log_transform(Xe)[:, cols]
        aucs, p20 = [], []
        for s in SEEDS:
            r = np.random.default_rng(500 + s)
            idx = r.choice(len(A), size=N_FIX, replace=False)
            m = fit_iforest(A[idx], psi=PSI, seed=s)
            sc = raw_if_score(m, B)
            aucs.append(auc(sc, ye)); p20.append(precision_at_k(sc, ye, 20))
        rec[f"{arm}_auc"] = float(np.mean(aucs))
        rec[f"{arm}_sd"] = float(np.std(aucs))
        rec[f"{arm}_p20"] = float(np.mean(p20))
    rows.append(rec)
    print(f"  k={k:2d}  full15 {rec['full15_auc']:.3f}+-{rec['full15_sd']:.3f}   "
          f"no_nf {rec['no_nf_auc']:.3f}+-{rec['no_nf_sd']:.3f}   "
          f"nf_sd {rec['night_fraction_sd']:.3f}")

json.dump(dict(config=dict(base_days=BASE_DAYS, eval_days=EVAL_DAYS,
                           up_hours=[UP_START, UP_END], psi=PSI, stride=STRIDE,
                           seeds=len(SEEDS), n_fixed=N_FIX),
               rows=rows), open("/home/claude/work/night_coverage.json", "w"), indent=2)
print("\nwrote night_coverage.json")
