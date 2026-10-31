#!/usr/bin/env python3
"""Check of the accumulator's window-surprise correction (Deliverable 3, Phase 7, Step 2) on the
workstation (secondary corpus): is the window term flat for the workstation host across a benign day?

Why: S_seq is uniform on benign data, so a decayed running maximum of S_seq itself approaches its
ceiling for any busy entity and carries no information. Phase 7 therefore feeds the accumulator the
surprise q(a, e) = 100 min(1, -log10(1 - u^n_e) / lambda), u = S_seq/100, n_e = entries opened by the
entity in the preceding T divided by N. This script measures both forms on the same benign data.

Data and fit as in ws_eval.py: the frozen baseline (T0 <= t < T1), forests and calibration fitted on
everything before the hold-out week, host windows, entries N = 20, delta = 60 s, active-time correction on.
Measured: for the workstation host, the window term returned by accumulator.Accumulator.push (decayed running
maximum over the last T, half-life h, weight a_s) at every hold-out alert of the host, on the 0-100 scale
(divided by a_s); and the same with q replaced by S_seq itself (the uncorrected form). Per local day of the
hold-out week with at least one awake hour: the share of alert times at which the term is at its ceiling
(>= 99) and its interquartile range.

Criterion, fixed before the first run (2026-10-31): the corrected window term is NOT flat if, on the median
hold-out day, (i) it is at its ceiling at fewer than half of the host's alert times and (ii) its
interquartile range spans at least 10 points. The uncorrected form is reported for contrast only.

usage: ws_qcheck.py <wb_dir> <frozen_corpus.json> <out.json> [--seeds 5]
"""
import sys, json, argparse, collections, datetime as dt
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("corpus"); ap.add_argument("out")
ap.add_argument("--seeds", type=int, default=5)
args = ap.parse_args()
sys.path.insert(0, args.wb)
import window_builder as W
import seq_scoring as C6
import accumulator as C8

T0 = dt.datetime(2026, 9, 12, 5, 14, tzinfo=dt.timezone.utc).timestamp()     # COLLECTION_RECORD A.1
T1 = dt.datetime(2026, 10, 17, 16, 15, tzinfo=dt.timezone.utc).timestamp()   # 23:15 +07, Part E
HOLD = T1 - 7 * 86400
TZ = 7 * 3600.0
CEIL, MIN_IQR = 99.0, 10.0

A = []
with open(args.corpus) as f:
    for i, line in enumerate(f):
        try:
            a = W.parse_wazuh(json.loads(line), i)
        except (ValueError, KeyError):
            continue
        if T0 <= a.ts < T1:
            A.append(a)
A.sort(key=lambda a: (a.ts, a.ingest_seq))
ts = np.array([a.ts for a in A])
host_of = lambda a: next(v for t, v in a.entities if t == "host")
hosts = np.array([host_of(a) for a in A], dtype=object)
G = W.DOWNTIME_GAP_S
hts = np.sort(ts); down = [(x, y) for x, y in zip(hts[:-1], hts[1:]) if y - x > G]


def awake_hours(lo, hi):
    tot = hi - lo
    for x, y in down:
        tot -= max(0.0, min(y, hi) - max(x, lo))
    return tot / 3600


wb = W.WindowBuilder(N=20, learn_rules=True, collapse_s=60.0)
rows = collections.defaultdict(lambda: {"j": [], "ev": [], "F": [], "ok": []})
for j, a in enumerate(A):
    if a.ts >= HOLD and wb.learn_rules:
        wb.learn_rules = False
    for e, f_, ok in wb.push(a):
        d = rows[e[0]]; d["j"].append(j); d["ev"].append(e[1]); d["F"].append(f_); d["ok"].append(ok)
d = rows["host"]
d = {k: np.array(v, dtype=object if k == "ev" else None) for k, v in d.items()}
RUN = W.ENTRY_FEATURE_NAMES.index("current_run_length")
tsw = ts[d["j"]]; hw = hosts[d["j"]]
days_all = ((tsw + TZ) // 86400).astype(int)
hold_days = [dd for dd in np.unique(days_all[tsw >= HOLD])
             if awake_hours(max(HOLD, dd * 86400 - TZ), min(T1, (dd + 1) * 86400 - TZ)) >= 1.0]


def window_term(S, corrected):
    """window term / a_s on the 0-100 scale at every host-window alert, in stream order"""
    orig = C8.q_score
    if not corrected:
        C8.q_score = lambda s, n_e, lam=C8.LAMBDA: float(s)      # the uncorrected form: S_seq itself
    try:
        acc = C8.Accumulator(20)
        out = np.empty(len(S))
        for i in range(len(S)):
            j = d["j"][i]; a = A[j]
            _, _, w = acc.push(("host", d["ev"][i]), a.ts, a.rule_id, 0.0, 0.0, S[i], d["F"][i, RUN] == 1, a.tactics)
            out[i] = w / acc.a_s
    finally:
        C8.q_score = orig
    return out


res = {"criterion": {"ceiling": CEIL, "max_ceiling_share_median_day": 0.5, "min_iqr_median_day": MIN_IQR},
       "holdout_days": [int(x) for x in hold_days], "seeds": []}
for seed in range(args.seeds):
    base = d["ok"].astype(bool) & (tsw < HOLD)
    m = C6.TypeModel(seed)
    S = np.full(len(d["j"]), -1.0)
    ok = d["ok"].astype(bool)
    if not m.fit(np.stack(d["F"][base]), list(hw[base]), True):
        sys.exit("no host forest")
    S[ok] = m.score(np.stack(d["F"][ok]), list(hw[ok]), True)
    r = {"seed": seed}
    for name, corr in (("corrected", True), ("uncorrected", False)):
        wt = window_term(S, corr)
        per_day = []
        for dd in hold_days:
            msk = days_all == dd
            v = wt[msk]
            if len(v) == 0:
                continue
            q25, q50, q75 = np.percentile(v, [25, 50, 75])
            per_day.append({"day": int(dd), "alerts": int(len(v)), "ceiling_share": float((v >= CEIL).mean()),
                            "q25": float(q25), "median": float(q50), "q75": float(q75), "iqr": float(q75 - q25)})
        med_ceil = float(np.median([x["ceiling_share"] for x in per_day]))
        med_iqr = float(np.median([x["iqr"] for x in per_day]))
        r[name] = {"median_day_ceiling_share": med_ceil, "median_day_iqr": med_iqr, "per_day": per_day,
                   "not_flat": bool(med_ceil < 0.5 and med_iqr >= MIN_IQR)}
    res["seeds"].append(r)
    print(f"seed {seed}: corrected ceiling share {r['corrected']['median_day_ceiling_share']:.3f}, IQR "
          f"{r['corrected']['median_day_iqr']:.1f} -> not flat: {r['corrected']['not_flat']} | uncorrected ceiling share "
          f"{r['uncorrected']['median_day_ceiling_share']:.3f}, IQR {r['uncorrected']['median_day_iqr']:.1f}", flush=True)
res["pass_all_seeds"] = all(x["corrected"]["not_flat"] for x in res["seeds"])
json.dump(res, open(args.out, "w"), indent=1)
print("PASS (not flat on every seed)" if res["pass_all_seeds"] else "FAIL on at least one seed")
