#!/usr/bin/env python3
"""Tune the risk-based alerting comparator B_RBA (tools/rba.py) on the tuning scenarios only
(provisional decision on Q9, 2026-10-27). Same queue as every other system: repeat groups
(host, rule, gap Delta = 24 h) over the evaluation period, group priority = maximum of the
members' scores, graded alpha-nDCG@20 as the objective. Oracle-cleaned baselines (the tuning
convention), like the other systems' tuning.

Selection mirrors Uetz et al.: (1) for each module the window and shape with the best
alpha-nDCG@20 on its own (mean over the four scenarios); (2) module weights on the simplex in
steps of 0.1 (1001 combinations), weighted arithmetic mean; the best alpha-nDCG@20 wins, ties
(within 0.001) broken by MRR. Deterministic: no seeds.

usage: ait_rba_tune.py <wb_dir> <out_config.json> <out_report.json>
"""
import sys, os, pickle, json, itertools, time, collections
import numpy as np

wb, out_cfg, out_rep = sys.argv[1:4]
sys.path.insert(0, wb)
import rba
import eval_metrics as M

SCS = ["harrison", "russellmitchell", "shaw", "wheeler"]
DELTA = 86400.0


def host_of(a):
    return next(v for t, v in a.entities if t == "host")


def prepare(sc):
    cache = f"rbacache_{sc}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
    adm = [j for j, a in enumerate(A) if a.admissible]
    ts = np.array([A[j].ts for j in adm]); host = np.array([host_of(A[j]) for j in adm], dtype=object)
    rule = np.array([A[j].rule_id for j in adm], dtype=object); lvl = np.array([A[j].rule_level for j in adm], float)
    score_idx = np.flatnonzero(ts >= t_atk)
    t0 = time.time()
    S = rba.module_scores(ts, host, rule, lvl, t_atk, score_idx)
    L = np.array([labels[adm[i]] for i in score_idx], dtype=object)
    gid, last, cur, nxt = [], {}, {}, 0
    for i in score_idx:
        key = (host[i], rule[i])
        if key not in last or ts[i] - last[key] > DELTA:
            cur[key] = nxt; nxt += 1
        last[key] = ts[i]; gid.append(cur[key])
    D = {"S": S, "L": L, "gid": np.array(gid), "G": nxt}
    pickle.dump(D, open(cache, "wb"))
    print(f"{sc}: {len(score_idx)} evaluation alerts, {nxt} groups, module scores {time.time() - t0:.0f}s", flush=True)
    return D


def metrics(D, s):
    g = np.full(D["G"], -np.inf); np.maximum.at(g, D["gid"], s)
    st = M.item_stages(D["gid"], D["L"], D["G"])
    f = M.first_item_ranks(g, st)
    return M.alpha_ndcg(g, st, 20), M.mrr_nonscan(f), {k: float(v) for k, v in f.items()}


DS = {sc: prepare(sc) for sc in SCS}
names = rba.variant_names()
single = {}
for m, vs in names.items():
    for v in vs:
        r = [metrics(DS[sc], DS[sc]["S"][v]) for sc in SCS]
        single[v] = {"andcg20": float(np.mean([x[0] for x in r])), "mrr": float(np.mean([x[1] for x in r])),
                     "per_scenario": {sc: x[0] for sc, x in zip(SCS, r)}}
best_variant = {m: max(vs, key=lambda v: (round(single[v]["andcg20"], 3), single[v]["mrr"])) for m, vs in names.items()}
GRID = [w for w in itertools.product(range(11), repeat=5) if sum(w) == 10]
combos = []
for w in GRID:
    cfg = {"variants": best_variant, "weights": {m: x / 10 for m, x in zip(rba.MODULES, w)}}
    r = [metrics(DS[sc], rba.combine(DS[sc]["S"], cfg)) for sc in SCS]
    combos.append({"weights": cfg["weights"], "andcg20": float(np.mean([x[0] for x in r])), "mrr": float(np.mean([x[1] for x in r])),
                   "per_scenario": {sc: x[0] for sc, x in zip(SCS, r)},
                   "first": {f"{sc}/{k}": v for sc, x in zip(SCS, r) for k, v in x[2].items() if k not in M.SCANS}})
combos.sort(key=lambda c: (-round(c["andcg20"], 3), -c["mrr"]))
chosen = combos[0]
cfg = {"variants": best_variant, "weights": chosen["weights"], "delta_s": DELTA, "aggregation": "group maximum",
       "windows": "trailing only; normalizers from the pre-attack period", "selected_on": SCS,
       "source": "tools/rba.py (after Uetz et al. 2026, CATS commit 628cf48)", "date": "2026-10-27"}
json.dump(cfg, open(out_cfg, "w"), indent=1)
json.dump({"single_modules": single, "best_variant": best_variant, "top_combinations": combos[:30],
           "n_combinations": len(combos)}, open(out_rep, "w"), indent=1)
print("best variant per module (alone):")
for m in rba.MODULES:
    v = best_variant[m]; print(f"  {m:13s} {v:26s} aNDCG@20 {single[v]['andcg20']:.3f} MRR {single[v]['mrr']:.3f}")
print("top weight combinations:")
for c in combos[:8]:
    print(f"  {c['weights']} aNDCG@20 {c['andcg20']:.3f} MRR {c['mrr']:.3f}")
print("chosen:", chosen["weights"])
