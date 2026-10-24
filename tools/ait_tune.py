#!/usr/bin/env python3
"""Tuning on the AIT-ADS tuning scenarios only, objective = mean graded
alpha-nDCG@20 (Deliverable 3, Sec. IV-C), from per-seed alert scores saved by
ait_sweep.py (SAVE_DIR) with the Suricata signature as rule identity.

Part A  window x group score, S_seq only (re-check of earlier choices under the
        new objective).
Part B  hybrid group priority  w_r*S_rule(g) + w_c*S_exp(g) + w_s*seq(g):
        weight simplex in steps of 0.1; S_rule linear (100*l/15) or level rank
        within the host's baseline; seq(g) = 100*min(1, pi(g)/lambda), lambda 4 or 8.
        Every member of a queue group shares host and rule, so S_rule and S_exp
        are constant within a group. lam = "max": the sequence term is instead the group's
        highest member S_seq (the group score adopted on 2026-10-24).

usage: ait_tune.py <scores_dir> <host_roles.json> <wb_dir> <out.json>
"""
import sys, glob, json, collections, itertools
import numpy as np

sd, roles_path, wb_dir, out_path = sys.argv[1:5]
sys.path.insert(0, wb_dir)
import eval_metrics as M

ROLES = json.load(open(roles_path))
TUNING = ["harrison", "wheeler", "russellmitchell", "shaw"]
U_MAX = 1 - 1e-5


def surprise(u, n):
    u = np.clip(u, 1e-12, U_MAX)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


def load(sc, cfg):
    z = np.load(f"{sd}/{sc}_{cfg}.npz", allow_pickle=True)
    gid = z["gid"]; G = gid.max() + 1
    L = z["labels"]; lvl = z["lvl"].astype(float); ip = z["agent_ip"]
    base = z["base_levels"][0]
    k = np.bincount(gid, minlength=G).astype(float)
    # alert-level static terms
    s_rule_lin = 100 * lvl / 15
    s_rule_rank = np.empty(len(lvl))
    for h in set(ip):
        m = ip == h
        b = base.get(h)
        if b is None or len(b) == 0:
            s_rule_rank[m] = s_rule_lin[m]; continue
        b = np.sort(b)
        lo = np.searchsorted(b, lvl[m], side="left"); hi = np.searchsorted(b, lvl[m], side="right")
        s_rule_rank[m] = 100 * (lo + 0.5 * (hi - lo)) / len(b)
    s_exp = np.array([ROLES[sc][h]["s_exp"] for h in ip])
    gmax = lambda v: (lambda o: (np.maximum.at(o, gid, v), o)[1])(np.full(G, -np.inf))
    stages = M.item_stages(gid, L, G)
    seeds = []
    for s in z["sseq"]:
        mx = gmax(s)
        mean = np.bincount(gid, weights=s, minlength=G) / k
        seeds.append({"max": mx, "mean": mean, "pi": surprise(mx / 100, k)})
    # host rarity (B0_host): 100 * (1 - host's share of baseline admitted alerts)
    cnt = {h: len(v) for h, v in base.items()}; tot = max(1, sum(cnt.values()))
    s_hostr = np.array([100 * (1 - cnt.get(h, 0) / tot) for h in ip])
    return dict(G=G, stages=stages, rule_lin=gmax(s_rule_lin), rule_rank=gmax(s_rule_rank),
                exp=gmax(s_exp), hostr=gmax(s_hostr), seeds=seeds, L=L, sseq=z["sseq"])


def score_queue(item_scores, stages):
    f = M.first_item_ranks(item_scores, stages)
    return {"andcg10": M.alpha_ndcg(item_scores, stages, 10), "andcg20": M.alpha_ndcg(item_scores, stages, 20),
            "andcg50": M.alpha_ndcg(item_scores, stages, 50), "mrr": M.mrr_nonscan(f),
            "ns_top20": M.coverage(f, 20)["nonscan"][0], "ns_total": M.coverage(f, 20)["nonscan"][1],
            "first": {s: float(v) for s, v in f.items()}}


def summarise(rows):
    keys = ["andcg10", "andcg20", "andcg50", "mrr", "ns_top20"]
    return {k: float(np.nanmean([r[k] for r in rows])) for k in keys} | \
           {"andcg20_sd_over_seeds": float(np.std([np.mean([r["andcg20"] for r in rows if r["seed"] == s])
                                                  for s in sorted({r["seed"] for r in rows})]))}


OUT = {}
cfgs = sorted({p.split("_", 1)[1][:-4] for p in glob.glob(f"{sd}/*.npz")})
D = {(sc, c): load(sc, c) for sc in TUNING for c in cfgs}

print("=== Part A: S_seq only, group score x window (mean over 4 scenarios x seeds)")
print(f"{'window':12s} {'group':6s} {'aNDCG@10':>9s} {'@20':>6s} {'@50':>6s} {'MRR':>6s} {'ns@20':>6s}")
OUT["A"] = {}
for c in cfgs:
    for gs in ("max", "mean", "pi"):
        rows = []
        for sc in TUNING:
            d = D[(sc, c)]
            for si, sd_ in enumerate(d["seeds"]):
                rows.append(score_queue(sd_[gs], d["stages"]) | {"seed": si, "sc": sc})
        sm = summarise(rows); OUT["A"][f"{c}/{gs}"] = sm
        print(f"{c:12s} {gs:6s} {sm['andcg10']:9.3f} {sm['andcg20']:6.3f} {sm['andcg50']:6.3f} {sm['mrr']:6.3f} {sm['ns_top20']:6.2f}")

print("\n=== Part B: hybrid weights (objective: mean alpha-nDCG@20)")
grid = [(r / 10, c / 10, round(1 - r / 10 - c / 10, 1)) for r in range(11) for c in range(11 - r)]
OUT["B"] = {}
for c in cfgs:
    res = []
    for (wr, wc, ws), rv, lam in itertools.product(grid, ("lin", "rank"), (4, 8, "max")):
        rows = []
        for sc in TUNING:
            d = D[(sc, c)]
            for si, sd_ in enumerate(d["seeds"]):
                seq = sd_["max"] if lam == "max" else 100 * np.minimum(1, sd_["pi"] / lam)
                pr = wr * d[f"rule_{rv}"] + wc * d["exp"] + ws * seq
                q = score_queue(pr, d["stages"]); q.update(seed=si, sc=sc); rows.append(q)
        sm = summarise(rows); sm.update(w=(wr, wc, ws), rule=rv, lam=lam)
        per_sc = {sc: float(np.mean([r["andcg20"] for r in rows if r["sc"] == sc])) for sc in TUNING}
        sm["per_scenario_andcg20"] = per_sc
        res.append(sm)
    res.sort(key=lambda r: (-r["andcg20"], -r["mrr"]))
    OUT["B"][c] = res
    pick = lambda w, rv="lin", lam=4: next(r for r in res if r["w"] == w and r["rule"] == rv and r["lam"] == lam)
    hr = [score_queue(D[(sc, c)]["hostr"], D[(sc, c)]["stages"]) | {"seed": 0, "sc": sc} for sc in TUNING]
    OUT.setdefault("B0_host", summarise(hr))
    print(f"\n-- window {c}")
    print(f"  {'B0_host host rarity':24s} aNDCG@20 {OUT['B0_host']['andcg20']:.3f} (@10 {OUT['B0_host']['andcg10']:.3f}, "
          f"@50 {OUT['B0_host']['andcg50']:.3f}) MRR {OUT['B0_host']['mrr']:.3f}")
    for name, r in [("best", res[0]), ("2nd", res[1]), ("3rd", res[2]),
                    ("B0 rule only", pick((1.0, 0.0, 0.0))), ("B1 rule+exp (0.6,0.4,0)", pick((0.6, 0.4, 0.0))),
                    ("S_seq only", pick((0.0, 0.0, 1.0))), ("default (0.3,0.2,0.5)", pick((0.3, 0.2, 0.5)))]:
        print(f"  {name:24s} w={r['w']} S_rule={r['rule']:4s} lam={r['lam']} | aNDCG@20 {r['andcg20']:.3f} "
              f"(@10 {r['andcg10']:.3f}, @50 {r['andcg50']:.3f}) MRR {r['mrr']:.3f} ns@20 {r['ns_top20']:.2f} | "
              + " ".join(f"{k[:5]} {v:.2f}" for k, v in r["per_scenario_andcg20"].items()))
    # how flat is the optimum: configs within 0.01 of the best
    near = [r for r in res if r["andcg20"] >= res[0]["andcg20"] - 0.01]
    print(f"  {len(near)} of {len(res)} configurations within 0.01 of the best; their w_r range "
          f"{min(r['w'][0] for r in near)}-{max(r['w'][0] for r in near)}, w_c {min(r['w'][1] for r in near)}-"
          f"{max(r['w'][1] for r in near)}, w_s {min(r['w'][2] for r in near)}-{max(r['w'][2] for r in near)}")
json.dump(OUT, open(out_path, "w"), indent=1, default=float)
