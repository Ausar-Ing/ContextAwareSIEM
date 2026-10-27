#!/usr/bin/env python3
"""Priority weights with an explicit novelty term (2026-10-27, provisional decision on Q1/Q8):
P(g) = w_r S_rule(g) + w_c S_exp(g) + w_s 100 min(1, pi(g)/8) + w_n 100 nu(g),
with nu(g) = 1 when a member's host window flags its rule as novel. Weights on the simplex in
steps of 0.1 (286 configurations); S_rule linear (100 * level / 15; the rank form tied it in
Table IX wherever w_r = 0). Tuning scenarios only; Delta = 24 h, host windows, shrinkage
calibration, the forests cached by ait_param_lab.py (plabrows_*, plabfit_*), 5 seeds.

Selection follows the tuning protocol (Sec. IV-C): candidates in order of the objective
(mean graded alpha-nDCG@20); a candidate within the larger seed SD of the incumbent (0, 0, 1, 0)
is a tie, broken by MRR only if the MRR difference exceeds the larger MRR SD, else the
incumbent stays; a candidate that places first items of non-scan stages later than the
incumbent on a majority of stage occurrences is vetoed. The first candidate that passes is
adopted; among configurations with identical rankings the one with the smallest novelty weight is listed first. The calibration and within-host guards do not apply: weights change neither the
forest nor its calibration.

usage: ait_weight_lab.py <wb_dir> <host_roles.json> <out.json> [--seeds 5]
"""
import sys, os, json, pickle, argparse, itertools, time
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("roles"); ap.add_argument("out")
ap.add_argument("--seeds", type=int, default=5)
ap.add_argument("--delta", type=float, default=86400.0)
args = ap.parse_args()
sys.path.insert(0, args.wb)
import window_builder as W
import eval_metrics as M

SCS = ["harrison", "russellmitchell", "shaw", "wheeler"]
NOV = W.ENTRY_FEATURE_NAMES.index("novel_rule_flag")
LAMBDA_Q = 8.0


def surprise(u, n):
    u = np.clip(u, 1e-12, 1 - 1e-5)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


def gmax(gid, G, v):
    o = np.full(G, -np.inf); np.maximum.at(o, gid, v); return o


def terms(sc, seed):
    P = pickle.load(open(f"plabrows_{sc}.pkl", "rb"))
    Se = pickle.load(open(f"plabfit_{sc}_s{seed}.pkl", "rb"))
    a = P["alert"]; ev = P["ev"]; L = P["L"]
    gid, last, cur, nxt = [], {}, {}, 0
    for j in ev:
        key = (a["host"][j], a["rule"][j])
        if key not in last or a["ts"][j] - last[key] > args.delta:
            cur[key] = nxt; nxt += 1
        last[key] = a["ts"][j]; gid.append(cur[key])
    gid = np.array(gid); G = nxt
    k = np.bincount(gid, minlength=G).astype(float)
    n = len(a["ts"]); d = P["rows"]["host"]
    se_all = np.full(n, -1.0); np.maximum.at(se_all, d["j"], Se["host"])
    se = se_all[ev]; s = np.where(se < 0, 50.0, se)
    seq = 100 * np.minimum(1, surprise(gmax(gid, G, s) / 100, k) / LAMBDA_Q)
    nv = np.zeros(n); np.maximum.at(nv, d["j"], np.where(d["ok"], d["F"][:, NOV], 0.0))
    nu = 100 * gmax(gid, G, nv[ev])
    rule = gmax(gid, G, 100 * a["lvl"][ev] / 15)
    exp_ = gmax(gid, G, a["sexp"][ev])
    stages = M.item_stages(gid, L, G)
    return np.vstack([rule, exp_, seq, nu]), stages


GRID = [w for w in itertools.product(range(11), repeat=4) if sum(w) == 10]
GRID = [tuple(x / 10 for x in w) for w in GRID]
INC = (0.0, 0.0, 1.0, 0.0)

t0 = time.time()
res = {w: {"andcg20": [], "mrr": [], "first": {}} for w in GRID}   # per seed: mean over scenarios
cache = {}
for seed in range(args.seeds):
    acc = {w: {"a": [], "m": []} for w in GRID}
    for sc in SCS:
        T, stages = terms(sc, seed)
        for w in GRID:
            prio = np.asarray(w) @ T
            f = M.first_item_ranks(prio, stages)
            acc[w]["a"].append(M.alpha_ndcg(prio, stages, 20)); acc[w]["m"].append(M.mrr_nonscan(f))
            for st, r in f.items():
                if st not in M.SCANS:
                    res[w]["first"].setdefault(f"{sc}/{st}", []).append(float(r))
    for w in GRID:
        res[w]["andcg20"].append(float(np.mean(acc[w]["a"]))); res[w]["mrr"].append(float(np.mean(acc[w]["m"])))
    print(f"seed {seed} done ({time.time() - t0:.0f}s)", flush=True)

summ = []
for w in GRID:
    r = res[w]
    summ.append({"w": w, "andcg20": float(np.mean(r["andcg20"])), "sd": float(np.std(r["andcg20"])),
                 "mrr": float(np.mean(r["mrr"])), "mrr_sd": float(np.std(r["mrr"])),
                 "first": {k: float(np.mean(v)) for k, v in r["first"].items()}})
summ.sort(key=lambda x: (-round(x["andcg20"], 12), x["w"][3], x["w"][1], x["w"][0]))
inc = next(x for x in summ if x["w"] == INC)


def judge(c):
    tie_sd = max(c["sd"], inc["sd"]); mrr_sd = max(c["mrr_sd"], inc["mrr_sd"])
    d = c["andcg20"] - inc["andcg20"]
    if abs(d) <= tie_sd:
        dm = c["mrr"] - inc["mrr"]
        obj = "tie, MRR prefers" if dm > mrr_sd else ("tie, MRR rejects" if dm < -mrr_sd else "tie, incumbent stays")
    else:
        obj = "prefers" if d > 0 else "rejects"
    keys = [k for k in inc["first"]]
    e = sum(c["first"][k] < inc["first"][k] - 1e-9 for k in keys)
    l = sum(c["first"][k] > inc["first"][k] + 1e-9 for k in keys)
    t = len(keys) - e - l
    veto = l > len(keys) / 2
    ok = obj in ("prefers", "tie, MRR prefers") and not veto
    return obj, e, l, t, veto, ok


adopted = None
rows = []
for c in summ:
    if c["w"] == INC:
        continue
    obj, e, l, t, veto, ok = judge(c)
    c.update({"objective": obj, "earlier": e, "later": l, "tied": t, "vetoed": veto, "passes": ok})
    if ok and adopted is None:
        adopted = c
out = {"_meta": {"script": "ait_weight_lab.py", "delta_s": args.delta, "seeds": args.seeds, "grid": "simplex step 0.1, 286 configurations",
                 "incumbent": INC, "order": ["w_rule", "w_exp", "w_seq", "w_novelty"]},
       "incumbent": inc, "adopted": adopted, "all": summ}
json.dump(out, open(args.out, "w"), indent=1)
print(f"incumbent {INC}: {inc['andcg20']:.3f} (sd {inc['sd']:.3f}) MRR {inc['mrr']:.3f} (sd {inc['mrr_sd']:.3f})")
for c in summ[:25]:
    if c["w"] == INC:
        print(f"  {str(c['w']):24s} {c['andcg20']:.3f} {c['sd']:.3f} {c['mrr']:.3f}   (incumbent)")
        continue
    print(f"  {str(c['w']):24s} {c['andcg20']:.3f} {c['sd']:.3f} {c['mrr']:.3f}  {c['objective']:20s} earlier {c['earlier']}, later {c['later']}, tied {c['tied']}"
          f"{'  VETOED' if c['vetoed'] else ''}{'  <- adopted' if c is adopted else ''}")
print("adopted:", adopted["w"] if adopted else "none (incumbent stays)")
