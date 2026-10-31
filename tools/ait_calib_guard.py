#!/usr/bin/env python3
"""Calibration guard of the tuning protocol (tools/ait_lab_verdict.py, line 62) applied to the ablation arm
B2_pooled (2026-10-31): for seed 0, the share of each host's BENIGN evaluation-period host windows whose
S_seq exceeds 99, under the method's shrinkage calibration and under pooled-only calibration (the same forest),
and the number of hosts (with >= 5 benign windows) above 5% -- the guard's 'bad' count.

usage (in the directory holding the evalcache_*_clean_sid1.pkl files written by ait_eval.py):
  ait_calib_guard.py <wb_dir> <scenario> [<scenario> ...]
"""
import sys, pickle, collections
import numpy as np
sys.path.insert(0, sys.argv[1])
import window_builder as W
import seq_scoring as C6
import eval_metrics as M

tot = {"shrink": 0, "pooled": 0}
for sc in sys.argv[2:]:
    A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
    wb = W.WindowBuilder(N=20, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
    J, F, OK = [], [], []
    for j, a in enumerate(A):
        if a.ts >= t_atk and wb.learn_rules:
            wb.learn_rules = False
        for e, f, ok in wb.push(a):
            if e[0] == "host":
                J.append(j); F.append(f); OK.append(ok)
    J, F, OK = np.array(J), np.array(F), np.array(OK)
    host = np.array([next(v for t, v in A[j].entities if t == "host") for j in J], dtype=object)
    ts = np.array([A[j].ts for j in J])
    base = OK & (ts < t_atk)
    m = C6.TypeModel(0)
    assert m.fit(F[base], list(host[base]), True)
    ev = OK & (ts >= t_atk) & np.array([labels[j] in M.BENIGN for j in J])
    s_sh = m.score(F[ev], list(host[ev]), True); s_po = m.score_pooled(F[ev], True)
    line = [sc]
    for name, s in (("shrink", s_sh), ("pooled", s_po)):
        per = {}
        for h in sorted(set(host[ev])):
            k = host[ev] == h
            if k.sum() >= 5:
                per[h] = float((s[k] > 99).mean())
        bad = sum(v > 0.05 for v in per.values()); tot[name] += bad
        line.append(f"{name}: hosts above 5% {bad}, worst {100 * max(per.values()):.0f}% "
                    f"({', '.join(f'{h} {100 * v:.0f}%' for h, v in sorted(per.items(), key=lambda x: -x[1])[:4])})")
    print(" | ".join(line), flush=True)
print(f"TOTAL hosts above 5%: shrink {tot['shrink']}, pooled {tot['pooled']} -> guard "
      f"{'REJECTS pooled' if tot['pooled'] > tot['shrink'] else 'does not reject pooled'}")
