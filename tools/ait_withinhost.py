#!/usr/bin/env python3
"""Within-host separation: for each host carrying non-scan attack alerts, the AUC of
attack (non-scan) against benign alerts ON THAT HOST, per score. Host rarity (B0_host)
is constant within a host, so it scores 0.5 here by construction: this isolates what
the sequence score adds beyond "this machine rarely alerts". Reads ait_eval.py dumps
(DUMP_DIR, with raw scores). Tuning scenarios only.

usage: ait_withinhost.py <dump_dir> <wb_dir> [scenario ...]
"""
import sys, glob
import numpy as np
from scipy.stats import mannwhitneyu
dd, wb = sys.argv[1:3]
scs = sys.argv[3:] or ["harrison", "russellmitchell", "shaw", "wheeler"]
assert not {"fox", "santos", "wardbeck", "wilson"} & set(scs), "tuning scenarios only"
sys.path.insert(0, wb)
import eval_metrics as M


def auc(p, n):
    return mannwhitneyu(p, n).statistic / (len(p) * len(n)) if len(p) and len(n) else np.nan


print("within-host AUC, attack non-scan vs benign alerts on the same host, mean over seeds")
print(f"{'scenario':15s} {'host role':16s} {'S_seq':>6s} {'host-win':>8s} {'raw host':>8s} {'level':>6s}  n_attack n_benign")
for sc in scs:
    res = {}
    for f in sorted(glob.glob(f"{dd}/{sc}_seed*.npz")):
        z = np.load(f, allow_pickle=True)
        L, role = z["labels"], z["role"]
        att = np.array([(l not in M.BENIGN) and (l not in M.SCANS) for l in L]); ben = np.isin(L, list(M.BENIGN))
        for r in sorted(set(role[att])):
            m = role == r
            res.setdefault(r, []).append([auc(z[k][m & att], z[k][m & ben]) for k in ("se", "se_host", "raw_host", "lvl")]
                                         + [int((m & att).sum()), int((m & ben).sum())])
    for r, R in res.items():
        R = np.array(R, float)
        if R[0, 5] == 0:
            continue
        print(f"{sc:15s} {r:16s} " + " ".join(f"{np.nanmean(R[:, i]):{w}.3f}" for i, w in zip(range(4), (6, 8, 8, 6)))
              + f"  {int(R[0, 4]):8d} {int(R[0, 5]):8d}")
