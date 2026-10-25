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
systems = ["B0", "B0_rank", "B0_host", "B1", "B2_nov", "B2'", "B2_def", "B2_alert", "B2_pi", "B2_max", "B2_novterm", "B2", "B3", "B3_bestgrp", "B3_noabs", "B3_novterm"]


def per_scenario(sc, name):
    """list over seeds (deterministic systems: one entry) of metric dicts"""
    r = R[sc]
    return r["seeded"][name] if name in r["seeded"] else [r["deterministic"][name]]


print(f"scenarios: {', '.join(scs)}")
print(f"{'system':9s} {'aNDCG@10':>9s} {'@20':>13s} {'@50':>7s} {'MRR':>7s} {'macroAUC':>9s} {'withinAUC':>9s}")
for name in systems:
    if not all(name in R[sc]["seeded"] or name in R[sc]["deterministic"] for sc in scs):
        continue
    vals = {m: [] for m in ("andcg10", "andcg20", "andcg50", "mrr", "macro_auc", "within_auc")}
    seeds = max(len(per_scenario(sc, name)) for sc in scs)
    by_seed20 = []
    for si in range(seeds):
        by_seed20.append(np.mean([per_scenario(sc, name)[min(si, len(per_scenario(sc, name)) - 1)]["andcg20"] for sc in scs]))
    for sc in scs:
        rows = per_scenario(sc, name)
        for m in vals:
            v = [x.get(m) for x in rows if x.get(m) is not None and not (isinstance(x.get(m), float) and np.isnan(x.get(m)))]
            if v:
                vals[m].append(np.mean(v))
    f = lambda m: f"{np.mean(vals[m]):.3f}" if vals[m] else "  -  "
    sd = f"±{np.std(by_seed20):.3f}" if seeds > 1 else "      "
    print(f"{name:9s} {f('andcg10'):>9s} {f('andcg20'):>7s}{sd} {f('andcg50'):>7s} {f('mrr'):>7s} {f('macro_auc'):>9s} {f('within_auc'):>9s}")

print("\nrobustness and per-day ranking (means over scenarios and seeds): alpha-nDCG@20 with the protocol grades,"
      " binary grades, grades (2,1,1), alpha = 1; per-day alpha-nDCG@20 and MRR")
print(f"{'system':11s} {'@20':>6s} {'binary':>7s} {'(2,1,1)':>8s} {'alpha=1':>8s} {'day@20':>7s} {'dayMRR':>7s}")
for name in systems:
    if not all(name in R[sc]["seeded"] or name in R[sc]["deterministic"] for sc in scs):
        continue
    def mm(key):
        v = [np.nanmean([x[key] for x in per_scenario(sc, name) if x.get(key) is not None]) for sc in scs
             if any(x.get(key) is not None for x in per_scenario(sc, name))]
        return f"{np.mean(v):.3f}" if v else "  -  "
    print(f"{name:11s} {mm('andcg20'):>6s} {mm('andcg20_bin'):>7s} {mm('andcg20_211'):>8s} {mm('andcg20_a1'):>8s} "
          f"{mm('day_andcg20'):>7s} {mm('day_mrr'):>7s}")


def firsts(name):
    """{(scenario, stage): mean first rank over seeds}"""
    out = {}
    for sc in scs:
        rows = per_scenario(sc, name)
        for st in rows[0]["first"]:
            out[(sc, st)] = float(np.mean([r["first"][st] for r in rows if st in r["first"]]))
    return out

print("\npaired first-item ranks of non-scan stages (a better = earlier)")
for a, b in [("B2", "B0"), ("B2", "B0_rank"), ("B2", "B0_host"), ("B2", "B1"), ("B2", "B2'"), ("B2", "B2_nov"), ("B2", "B2_alert"),
             ("B2", "B2_pi"), ("B2", "B2_max"), ("B2_novterm", "B2"), ("B2_novterm", "B0_host"), ("B3", "B2"), ("B3", "B3_bestgrp"), ("B3", "B3_noabs"), ("B3_novterm", "B3")]:
    if not all(x in R[sc]["seeded"] or x in R[sc]["deterministic"] for sc in scs for x in (a, b)):
        continue
    p = M.paired_ranks(firsts(a), firsts(b))
    print(f"  {a:4s} vs {b:8s}: n={p['n']:2d}  {a} better {p['a_better']:2d}, {b} better {p['b_better']:2d}, "
          f"tied {p['tied']:2d}, Wilcoxon p={p['wilcoxon_p']:.3f}")

def split(fdict, calibrated):
    return {k: v for k, v in fdict.items()
            if R[k[0]]["meta"].get("stage_calibration", {}).get(k[1], {}).get("calibrated") == calibrated}

print("\npaired first-item ranks, split by whether the stage's host has its own calibration")
for cal in (True, False):
    for a, b in [("B2", "B0_host"), ("B2", "B0_rank"), ("B2", "B0")]:
        p = M.paired_ranks(split(firsts(a), cal), split(firsts(b), cal))
        print(f"  {'calibrated  ' if cal else 'uncalibrated'} {a} vs {b:8s}: n={p['n']:2d}  {a} better {p['a_better']:2d}, "
              f"{b} better {p['b_better']:2d}, tied {p['tied']:2d}, Wilcoxon p={p['wilcoxon_p']:.3f}")
print("\nstage hosts and calibration:")
for sc in scs:
    print(f"  {sc:16s} " + "; ".join(f"{st}: {'/'.join(v['hosts'])} ({'own' if v['calibrated'] else 'pooled'})"
                                      for st, v in R[sc]["meta"].get("stage_calibration", {}).items()))

print("\ncalibration check: benign evaluation host windows above S_seq 99 (should be ~1%), seed 0")
for sc in scs:
    cc = R[sc]["meta"].get("calib_check", {})
    print(f"  {sc:16s} [{R[sc]['meta'].get('calib_mode', 'own_pooled')}] " +
          ", ".join(f"{k.split('[')[0]} {100*v[0]:.0f}%" for k, v in sorted(cc.items(), key=lambda kv: -kv[1][0])))

print("\nwithin-host AUC per eligible host (>= 5 non-scan attack and >= 5 benign alerts), B2 seed mean vs B0_rank")
for sc in scs:
    r2 = R[sc]["seeded"]["B2"]; r0 = R[sc]["deterministic"]["B0_rank"]
    for h in r0.get("within_hosts", {}):
        print(f"  {sc:16s} host {h:4s} n={r0['within_hosts'][h][1]}/{r0['within_hosts'][h][2]}: B2 "
              f"{np.mean([x['within_hosts'][h][0] for x in r2]):.3f}, B0_rank {r0['within_hosts'][h][0]:.3f}, "
              f"B0_host {R[sc]['deterministic']['B0_host']['within_hosts'][h][0]:.3f}")

print("\nB3 incidents per scenario (seed 0): total / attack / benign, time to first attack notable (h), stages")
for sc in scs:
    r = R[sc]["seeded"]["B3"][0]
    print(f"  {sc:16s} {r['incidents']} / {r['attack_incidents']} / {r['benign_incidents']}   "
          f"{r['time_to_notable_h'] if r['time_to_notable_h'] is not None else '-'}   max stages {r['max_stages_in_incident']}")
print("\ntraining windows after stride (entries):")
for sc in scs:
    print(f"  {sc:16s} {R[sc]['meta']['training_windows']}")
