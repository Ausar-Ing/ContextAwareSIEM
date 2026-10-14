#!/usr/bin/env python3
"""Aggregate ait_eval.py outputs: per-system means over scenarios (seeded systems:
mean of per-seed values, then sd across seeds of the scenario-mean), and paired
first-item-rank comparisons over non-scan stage occurrences keyed (scenario, stage).

usage: ait_report.py <wb_dir> <eval.json> [<eval.json> ...]
"""
import sys, json
import numpy as np

sys.path.insert(0, sys.argv[1])
import eval_metrics as M

R = {}
for p in sys.argv[2:]:
    R.update(json.load(open(p)))
scs = sorted(R)
systems = ["B0", "B0_rank", "B1", "B2_nov", "B2'", "B2_def", "B2_alert", "B2", "B3"]


def per_scenario(sc, name):
    """list over seeds (deterministic systems: one entry) of metric dicts"""
    r = R[sc]
    return r["seeded"][name] if name in r["seeded"] else [r["deterministic"][name]]


print(f"scenarios: {', '.join(scs)}")
print(f"{'system':9s} {'aNDCG@10':>9s} {'@20':>13s} {'@50':>7s} {'MRR':>7s} {'macroAUC':>9s}")
for name in systems:
    vals = {m: [] for m in ("andcg10", "andcg20", "andcg50", "mrr", "macro_auc")}
    seeds = max(len(per_scenario(sc, name)) for sc in scs)
    by_seed20 = []
    for si in range(seeds):
        by_seed20.append(np.mean([per_scenario(sc, name)[min(si, len(per_scenario(sc, name)) - 1)]["andcg20"] for sc in scs]))
    for sc in scs:
        rows = per_scenario(sc, name)
        for m in vals:
            v = [x.get(m) for x in rows if x.get(m) is not None]
            if v:
                vals[m].append(np.mean(v))
    f = lambda m: f"{np.mean(vals[m]):.3f}" if vals[m] else "  -  "
    sd = f"±{np.std(by_seed20):.3f}" if seeds > 1 else "      "
    print(f"{name:9s} {f('andcg10'):>9s} {f('andcg20'):>7s}{sd} {f('andcg50'):>7s} {f('mrr'):>7s} {f('macro_auc'):>9s}")

def firsts(name):
    """{(scenario, stage): mean first rank over seeds}"""
    out = {}
    for sc in scs:
        rows = per_scenario(sc, name)
        for st in rows[0]["first"]:
            out[(sc, st)] = float(np.mean([r["first"][st] for r in rows if st in r["first"]]))
    return out

print("\npaired first-item ranks of non-scan stages (a better = earlier)")
for a, b in [("B2", "B0"), ("B2", "B0_rank"), ("B2", "B1"), ("B2", "B2'"), ("B2", "B2_nov"), ("B2", "B2_alert"),
             ("B3", "B2")]:
    p = M.paired_ranks(firsts(a), firsts(b))
    print(f"  {a:4s} vs {b:8s}: n={p['n']:2d}  {a} better {p['a_better']:2d}, {b} better {p['b_better']:2d}, "
          f"tied {p['tied']:2d}, Wilcoxon p={p['wilcoxon_p']:.3f}")

print("\nB3 incidents per scenario (seed 0): total / attack / benign, time to first attack notable (h), stages")
for sc in scs:
    r = R[sc]["seeded"]["B3"][0]
    print(f"  {sc:16s} {r['incidents']} / {r['attack_incidents']} / {r['benign_incidents']}   "
          f"{r['time_to_notable_h'] if r['time_to_notable_h'] is not None else '-'}   max stages {r['max_stages_in_incident']}")
print("\ntraining windows after stride (entries):")
for sc in scs:
    print(f"  {sc:16s} {R[sc]['meta']['training_windows']}")
