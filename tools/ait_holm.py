#!/usr/bin/env python3
"""Pre-registered paired comparisons with Holm correction (Deliverable 3, Sec. IV-C;
provenance/ait/PREREGISTRATION.md). Pairs first-item ranks of non-scan stage occurrences,
keyed (scenario, stage), seeded systems entering by their mean rank over seeds; Wilcoxon
signed-rank per comparison; Holm step-down over the whole family below.

usage: ait_holm.py <wb_dir> <eval.json> [<eval.json> ...]
"""
import sys, json
import numpy as np

sys.path.insert(0, sys.argv[1])
import eval_metrics as M

PRIMARY = [("B2", "B0_host"), ("B2", "B0_rank")]
SECONDARY = [("B2", "B0"), ("B2", "B1"), ("B2", "B2'"), ("B2", "B2_nov"), ("B2", "B2_alert"),
             ("B2", "B2_max"), ("B3", "B2"), ("B3", "B3_bestgrp"), ("B3", "B3_noabs")]
FAMILY = PRIMARY + SECONDARY

R = {}
for p in sys.argv[2:]:
    R.update(json.load(open(p)))
scs = sorted(R)


def firsts(name):
    out = {}
    for sc in scs:
        r = R[sc]
        rows = r["seeded"].get(name) or [r["deterministic"][name]]
        for st in rows[0]["first"]:
            out[(sc, st)] = float(np.mean([x["first"][st] for x in rows if st in x["first"]]))
    return out


res = []
for a, b in FAMILY:
    if not all(x in R[sc]["seeded"] or x in R[sc]["deterministic"] for sc in scs for x in (a, b)):
        res.append((a, b, None)); continue
    res.append((a, b, M.paired_ranks(firsts(a), firsts(b))))
ps = [(i, r[2]["wilcoxon_p"]) for i, r in enumerate(res) if r[2] is not None]
m = len(ps)
adj, run_max = {}, 0.0
for rank, (i, p) in enumerate(sorted(ps, key=lambda x: x[1])):
    run_max = max(run_max, min(1.0, (m - rank) * p))
    adj[i] = run_max
print(f"scenarios: {', '.join(scs)}; family of {m} comparisons, Holm step-down\n")
for i, (a, b, p) in enumerate(res):
    tag = "primary  " if (a, b) in PRIMARY else "secondary"
    if p is None:
        print(f"{tag} {a:10s} vs {b:10s}: not available"); continue
    print(f"{tag} {a:10s} vs {b:10s}: n={p['n']:2d}  {a} earlier {p['a_better']:2d}, {b} earlier {p['b_better']:2d}, "
          f"tied {p['tied']:2d}  p={p['wilcoxon_p']:.3f}  Holm p={adj[i]:.3f}")
