#!/usr/bin/env python3
"""Protocol verdict for lab variants (ait_feature_lab.py output) against an incumbent:
objective alpha-nDCG@20 with the tie rule (larger seed SD; MRR tie-break only when the
MRR difference exceeds its larger seed SD, otherwise the incumbent stays) and the
first-item veto (rejected if first items are later on a majority of non-scan stage
occurrences). Also reports within-host AUC and the calibration check, which a variant
must not worsen to be adopted.

usage: ait_lab_verdict.py <wb_dir> <incumbent> <lab.json> [<lab.json> ...]
"""
import sys, json
import numpy as np

wb, inc = sys.argv[1:3]
sys.path.insert(0, wb)
import eval_metrics as M

R = {}
for p in sys.argv[3:]:
    for sc, v in json.load(open(p)).items():
        R.setdefault(sc, {}).update(v)
scs = sorted(R)
variants = [v for v in R[scs[0]] if all(v in R[sc] for sc in scs)]


def summary(v):
    seeds = len(R[scs[0]][v])
    nd = np.array([np.mean([R[sc][v][i]["andcg20"] for sc in scs]) for i in range(seeds)])
    mr = np.array([np.mean([R[sc][v][i]["mrr"] for sc in scs]) for i in range(seeds)])
    first = {(sc, st): float(np.mean([r["first"][st] for r in R[sc][v]])) for sc in scs for st in R[sc][v][0]["first"]}
    within = float(np.nanmean([np.nanmean([r["within"] for r in R[sc][v]]) for sc in scs
                               if not all(np.isnan(r["within"]) for r in R[sc][v])]))
    # calibration check, seed 0: share of hosts above 5% (with >= 5 benign windows) and the worst host
    bad, worst = 0, 0.0
    for sc in scs:
        for h, (share, n) in R[sc][v][0]["calib"].items():
            if n >= 5:
                bad += share > 0.05; worst = max(worst, share)
    per = {sc: float(np.mean([r["andcg20"] for r in R[sc][v]])) for sc in scs}
    unscored = float(np.mean([np.mean([r["unscored_eval_share"] for r in R[sc][v]]) for sc in scs]))
    return dict(nd=nd.mean(), nd_sd=nd.std(), mrr=mr.mean(), mrr_sd=mr.std(), first=first, within=within,
                bad=bad, worst=worst, per=per, unscored=unscored)


S = {v: summary(v) for v in variants}
I = S[inc]
print(f"incumbent {inc}: alpha-nDCG@20 {I['nd']:.3f} (sd {I['nd_sd']:.3f}), MRR {I['mrr']:.3f} (sd {I['mrr_sd']:.3f}), "
      f"within-host {I['within']:.3f}, hosts above 5% {I['bad']} (worst {100*I['worst']:.0f}%)\n")
print(f"{'variant':12s} {'@20':>6s} {'sd':>6s} {'MRR':>6s} {'within':>7s} {'>5%':>4s} {'unscored':>8s}  per scenario (" +
      ", ".join(s[:5] for s in scs) + ")   first items vs incumbent   verdict")
for v in variants:
    C = S[v]
    if v == inc:
        print(f"{v:12s} {C['nd']:6.3f} {C['nd_sd']:6.3f} {C['mrr']:6.3f} {C['within']:7.3f} {C['bad']:4d} {C['unscored']:8.3f}  "
              + " ".join(f"{C['per'][sc]:.3f}" for sc in scs) + "   (incumbent)")
        continue
    tie = abs(C["nd"] - I["nd"]) < max(C["nd_sd"], I["nd_sd"])
    mrr_clear = abs(C["mrr"] - I["mrr"]) > max(C["mrr_sd"], I["mrr_sd"])
    prefers = (not tie and C["nd"] > I["nd"]) or (tie and mrr_clear and C["mrr"] > I["mrr"])
    p = M.paired_ranks(C["first"], I["first"])
    veto = prefers and p["b_better"] > p["n"] / 2
    guard = C["within"] >= I["within"] - 0.01 and C["bad"] <= I["bad"]
    verdict = ("VETOED (first items)" if veto else "rejected (within-host or calibration)" if prefers and not guard
               else "ADOPT" if prefers else "keep incumbent")
    print(f"{v:12s} {C['nd']:6.3f} {C['nd_sd']:6.3f} {C['mrr']:6.3f} {C['within']:7.3f} {C['bad']:4d} {C['unscored']:8.3f}  "
          + " ".join(f"{C['per'][sc]:.3f}" for sc in scs)
          + f"   earlier {p['a_better']}, later {p['b_better']}, tied {p['tied']} (p={p['wilcoxon_p']:.3f})   {verdict}")
