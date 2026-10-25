#!/usr/bin/env python3
"""Protocol verdict for ait_param_lab.py variants against `base`: Delta is judged on B2
(the queue), the Component 8 constants on B3. Objective alpha-nDCG@20 with the tie rule
(larger seed SD; MRR only if it differs by more than its larger seed SD, else the
incumbent stays) and the first-item veto (rejected if first items are later on a
majority of non-scan stage occurrences). C8 variants must also not raise the number of
benign incidents (summed over scenarios, mean over seeds), the false-promotion guard.

usage: ait_param_verdict.py <wb_dir> <lab.json> [<lab.json> ...]
"""
import sys, json
import numpy as np
sys.path.insert(0, sys.argv[1])
import eval_metrics as M

R = {}
for p in sys.argv[2:]:
    for sc, v in json.load(open(p)).items():
        R.setdefault(sc, {}).update(v)
scs = sorted(R)
variants = [v for v in R[scs[0]] if all(v in R[sc] for sc in scs)]


def summ(v, sysn):
    seeds = min(len(R[sc][v]) for sc in scs)
    nd = np.array([np.mean([R[sc][v][i][sysn]["andcg20"] for sc in scs]) for i in range(seeds)])
    mr = np.array([np.mean([R[sc][v][i][sysn]["mrr"] for sc in scs]) for i in range(seeds)])
    first = {(sc, st): float(np.mean([R[sc][v][i][sysn]["first"][st] for i in range(seeds)]))
             for sc in scs for st in R[sc][v][0][sysn]["first"]}
    ben = float(np.mean([sum(R[sc][v][i]["B3"]["benign_incidents"] for sc in scs) for i in range(seeds)]))
    inc = float(np.mean([sum(R[sc][v][i]["B3"]["incidents"] for sc in scs) for i in range(seeds)]))
    per = {sc: float(np.mean([R[sc][v][i][sysn]["andcg20"] for i in range(seeds)])) for sc in scs}
    return dict(nd=nd.mean(), sd=nd.std(), mrr=mr.mean(), mrr_sd=mr.std(), first=first, ben=ben, inc=inc, per=per, seeds=seeds)


for sysn, group in (("B2", [v for v in variants if v.startswith("delta")]),
                    ("B3", [v for v in variants if v.startswith("delta")] + [v for v in variants if v != "base" and not v.startswith("delta")])):
    I = summ("base", sysn)
    print(f"\n== judged on {sysn}; incumbent base: {I['nd']:.3f} (sd {I['sd']:.3f}), MRR {I['mrr']:.3f} (sd {I['mrr_sd']:.3f}), "
          f"incidents {I['inc']:.1f}, benign {I['ben']:.1f}, seeds {I['seeds']}")
    print(f"{'variant':11s} {'@20':>6s} {'sd':>6s} {'MRR':>6s} {'inc':>5s} {'benign':>6s}  per scenario ({', '.join(s[:5] for s in scs)})   first items vs base   verdict")
    for v in group:
        C = summ(v, sysn)
        tie = abs(C["nd"] - I["nd"]) < max(C["sd"], I["sd"])
        clear = abs(C["mrr"] - I["mrr"]) > max(C["mrr_sd"], I["mrr_sd"])
        prefers = (not tie and C["nd"] > I["nd"]) or (tie and clear and C["mrr"] > I["mrr"])
        p = M.paired_ranks(C["first"], I["first"])
        veto = prefers and p["b_better"] > p["n"] / 2
        guard = sysn == "B2" or C["ben"] <= I["ben"]
        verdict = "VETOED" if veto else ("rejected (benign incidents)" if prefers and not guard else
                                         "ADOPT" if prefers else "keep base")
        print(f"{v:11s} {C['nd']:6.3f} {C['sd']:6.3f} {C['mrr']:6.3f} {C['inc']:5.1f} {C['ben']:6.1f}  "
              + " ".join(f"{C['per'][sc]:.3f}" for sc in scs)
              + f"   earlier {p['a_better']}, later {p['b_better']}, tied {p['tied']} (p={p['wilcoxon_p']:.3f})   {verdict}")
