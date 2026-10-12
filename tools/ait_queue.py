#!/usr/bin/env python3
"""How should a repeat group (C9 queue item) be scored? Offline analysis of the
per-seed alert scores saved by ait_sweep.py (SAVE_DIR), tuning scenarios only.

Variants of the group score from its members' S_seq:
  max        current D3 rule: the most alarming member
  first      the member that opened the group (score at onset)
  mean       average member
  q_k        surprise of the max given k_g draws:   -log10(1 - u_max^{k_g})
  q_kN       same with n = max(1, k_g / N), overlapping windows discounted
  q_runs     same with n = number of runs inside the group (gaps > 60 s split runs)

The q variants ask how often k benign draws would produce a maximum this high,
the same correction Component 8 already applies to its window term. They are
ranked uncapped (no lambda) so the queue has no ties at the top.

usage: ait_queue.py <scores_dir> <config> [<config> ...]
"""
import sys, glob, json, collections
import numpy as np

SCANS = {"dirb", "wpscan", "service_scan"}
U_MAX = 1 - 1e-5            # percentile resolution: keeps -log10(.) finite at S_seq = 100


def ranks_desc(x):
    order = np.argsort(-x, kind="mergesort")
    r = np.empty(len(x)); r[order] = np.arange(1, len(x) + 1)
    _, inv, cnt = np.unique(-x, return_inverse=True, return_counts=True)
    return (np.bincount(inv, weights=r) / cnt)[inv]


def surprise(u, n):
    u = np.clip(u, 1e-12, U_MAX)
    p = -np.expm1(n * np.log(u))           # 1 - u^n, stable for u near 1
    return -np.log10(np.maximum(p, 1e-300))


def group_scores(s, gid, G, ts, N):
    k = np.bincount(gid, minlength=G).astype(float)
    mx = np.full(G, -np.inf); np.maximum.at(mx, gid, s)
    mean = np.bincount(gid, weights=s, minlength=G) / k
    first = np.full(G, np.nan)
    seen = np.zeros(G, bool)
    for i, g in enumerate(gid):            # ev is in stream order
        if not seen[g]:
            first[g] = s[i]; seen[g] = True
    # runs: a new run starts when a member follows its predecessor in the group by > 60 s
    last = np.full(G, -np.inf); runs = np.zeros(G)
    for i, g in enumerate(gid):
        if ts[i] - last[g] > 60:
            runs[g] += 1
        last[g] = ts[i]
    u = mx / 100.0
    return {"max": mx, "first": first, "mean": mean,
            "q_k": surprise(u, k), "q_kN": surprise(u, np.maximum(1, k / N)),
            "q_runs": surprise(u, runs)}, k


def evaluate(path):
    z = np.load(path, allow_pickle=True)
    gid, L, ts, N = z["gid"], z["labels"], z["ts"], int(z["N"])
    G = gid.max() + 1
    stages = sorted({l for l in L if l not in ("-", "unmatched")})
    items = {st: np.unique(gid[L == st]) for st in stages}
    attack_item = np.zeros(G, bool)
    for st in stages:
        attack_item[items[st]] = True
    out = collections.defaultdict(list)
    diag = []
    for s in z["sseq"]:
        gs, k = group_scores(s, gid, G, ts, N)
        ben = ~attack_item
        # diagnostic: does the max reward size among benign groups?
        from scipy.stats import spearmanr
        diag.append(spearmanr(np.log(k[ben]), gs["max"][ben]).correlation)
        for v, score in gs.items():
            r = ranks_desc(score)
            first = {st: float(r[items[st]].min()) for st in stages}
            ns = [first[st] for st in stages if st not in SCANS]
            top20 = np.argsort(-score, kind="mergesort")[:20]
            out[v].append({
                "mean_rank_nonscan": float(np.mean(ns)), "worst_rank_nonscan": float(np.max(ns)),
                "mrr_nonscan": float(np.mean([1 / x for x in ns])),
                "nonscan_top10": int(sum(x <= 10 for x in ns)), "nonscan_top20": int(sum(x <= 20 for x in ns)),
                "cov20": int(sum(x <= 20 for x in first.values())),
                "benign_in_top20": int((~attack_item[top20]).sum()),
                "median_k_benign_top20": float(np.median(k[top20][~attack_item[top20]])) if (~attack_item[top20]).any() else 0.0,
                "first": first})
    return out, float(np.mean(diag)), len(stages), sum(st not in SCANS for st in stages)


if __name__ == "__main__":
    sd = sys.argv[1]
    ALL = {}
    for cfg in sys.argv[2:]:
        agg = collections.defaultdict(lambda: collections.defaultdict(list))
        print(f"\n=== {cfg}")
        for path in sorted(glob.glob(f"{sd}/*_{cfg}.npz")):
            sc = path.split("/")[-1].split("_")[0]
            out, rho, ns, nn = evaluate(path)
            print(f"  {sc:16s} benign groups: Spearman(log size, max S_seq) = {rho:+.2f}")
            ALL.setdefault(cfg, {})[sc] = {v: r for v, r in out.items()}
            for v, runs in out.items():
                for key in ("mean_rank_nonscan", "worst_rank_nonscan", "mrr_nonscan", "nonscan_top10",
                            "nonscan_top20", "cov20", "benign_in_top20", "median_k_benign_top20"):
                    agg[v][key].append([r[key] for r in runs])
        print(f"  {'variant':8s} {'meanRk':>7s} {'worstRk':>8s} {'MRR':>6s} {'ns@10':>6s} {'ns@20':>6s} {'cov20':>6s} {'benTop20':>8s} {'medK':>7s}   (non-scan stages: means over scenarios, sums for counts; per-seed averaged)")
        for v, d in agg.items():
            A = {k: np.array(x) for k, x in d.items()}      # [scenario, seed]
            print(f"  {v:8s} {A['mean_rank_nonscan'].mean():7.1f} {A['worst_rank_nonscan'].max(0).mean():8.1f} "
                  f"{A['mrr_nonscan'].mean():6.3f} {A['nonscan_top10'].sum(0).mean():6.1f} {A['nonscan_top20'].sum(0).mean():6.1f} "
                  f"{A['cov20'].sum(0).mean():6.1f} {A['benign_in_top20'].mean():8.1f} {np.median(A['median_k_benign_top20']):7.0f}")
    json.dump(ALL, open(f"{sd}/queue_variants.json", "w"))
