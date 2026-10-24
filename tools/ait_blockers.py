#!/usr/bin/env python3
"""Who outranks the attack? For every non-scan stage in the tuning scenarios, the
queue groups ranked above the stage's first item under B2, classified by cause.
Reads the per-seed dumps written by ait_eval.py with DUMP_DIR set. Tuning scenarios only.

Classes of a blocking group (benign unless stated):
  attack      another attack stage (scan or non-scan) -- not a failure of ranking
  quiet       benign, on a host whose calibration rests mostly on the pooled
              distribution (held-out windows n_h < n0, i.e. w_h < 0.5)
  size        benign, own-calibrated host, outranks only because of group size:
              its maximum S_seq is BELOW the attack item's, pi lifts it through k
  unusual     benign, own-calibrated host, maximum S_seq at or above the attack item's

usage: ait_blockers.py <dump_dir> <wb_dir> [n0=100] [scenario ...]
"""
import sys, json, glob, collections
import numpy as np

dd, wb = sys.argv[1:3]
n0 = float(sys.argv[3]) if len(sys.argv) > 3 else 100.0
scs = sys.argv[4:] or ["harrison", "russellmitchell", "shaw", "wheeler"]
assert not {"fox", "santos", "wardbeck", "wilson"} & set(scs), "tuning scenarios only"
sys.path.insert(0, wb)
import eval_metrics as M

U_MAX = 1 - 1e-5


def surprise(u, n):
    u = np.clip(u, 1e-12, U_MAX)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


tot = collections.Counter()
rows_out = []
for sc in scs:
    files = sorted(glob.glob(f"{dd}/{sc}_seed*.npz"))
    for f in files:
        z = np.load(f, allow_pickle=True)
        seed = int(f.rsplit("seed", 1)[1].split(".")[0])
        gid, L, k, b2 = z["gid"], z["labels"], z["k"], z["b2"]
        G = len(k)
        cal = json.loads(z["cal"][0])
        w_of = {h: v[1] / (v[1] + n0) for h, v in cal.items()}
        gmax = lambda v: (lambda o: (np.maximum.at(o, gid, v), o)[1])(np.full(G, -np.inf))
        u = gmax(np.where(z["se"] < 0, 50.0, z["se"])) / 100
        uh = gmax(z["se_host"]); us = gmax(z["se_srcip"])
        pi = surprise(u, k)
        first_j = {}
        for i, g in enumerate(gid):
            first_j.setdefault(g, i)
        g_host = np.array([z["host"][first_j[g]] for g in range(G)], dtype=object)
        g_role = np.array([z["role"][first_j[g]] for g in range(G)], dtype=object)
        g_rule = np.array([z["rule"][first_j[g]] for g in range(G)], dtype=object)
        stages = M.item_stages(gid, L, G)
        fr = M.first_item_ranks(b2, stages)
        for st, r in fr.items():
            items = [g for g in range(G) if st in stages[g]]
            top = max(items, key=lambda g: b2[g])
            blk = [g for g in range(G) if b2[g] > b2[top]]
            cls = collections.Counter()
            detail = []
            for g in blk:
                if stages[g]:
                    c = "attack"
                elif w_of.get(g_host[g], 0) < 0.5:
                    c = "quiet"
                elif u[g] < u[top]:
                    c = "size"
                else:
                    c = "unusual"
                cls[c] += 1
                detail.append((b2[g], c, g_role[g], g_rule[g], int(k[g]), u[g], pi[g], w_of.get(g_host[g], 0),
                               "host" if uh[g] >= us[g] else "srcip"))
            tot.update({(st in M.SCANS, c): v for c, v in cls.items()})
            rows_out.append(dict(sc=sc, seed=seed, stage=st, rank=float(r), u=float(u[top]), k=int(k[top]),
                                 pi=float(pi[top]), w=w_of.get(g_host[top], 0), role=g_role[top],
                                 rule=g_rule[top], by="host" if uh[top] >= us[top] else "srcip", cls=dict(cls),
                                 detail=sorted(detail, key=lambda x: -x[0])))

print(f"n0 = {n0:g}; blockers = queue groups ranked above the stage's first item under B2\n")
print(f"{'scenario':15s} {'stage':24s} {'rank(mean,5 seeds)':>18s}  attack item: role rule k u_max pi w by | "
      "blockers per seed: attack quiet size unusual")
for sc in scs:
    for st in sorted({r["stage"] for r in rows_out if r["sc"] == sc}):
        R = [r for r in rows_out if r["sc"] == sc and r["stage"] == st]
        if st in M.SCANS:
            continue
        r0 = R[0]
        c = {x: np.mean([r["cls"].get(x, 0) for r in R]) for x in ("attack", "quiet", "size", "unusual")}
        print(f"{sc:15s} {st:24s} {np.mean([r['rank'] for r in R]):18.1f}  {r0['role']} {r0['rule']} k={r0['k']} "
              f"u={np.mean([r['u'] for r in R]):.4f} pi={np.mean([r['pi'] for r in R]):.2f} w={r0['w']:.2f} {r0['by']} | "
              f"{c['attack']:.1f} {c['quiet']:.1f} {c['size']:.1f} {c['unusual']:.1f}")

print("\nseed 0, top blockers per non-scan stage (b2, class, role, rule, k, u_max, pi, w_host, entity type of max):")
for r in rows_out:
    if r["seed"] != 0 or r["stage"] in M.SCANS:
        continue
    print(f"  {r['sc']} {r['stage']} (rank {r['rank']:.1f}; attack u={r['u']:.4f} k={r['k']} pi={r['pi']:.2f})")
    for d in r["detail"][:12]:
        print(f"      {d[0]:6.1f} {d[1]:8s} {d[2]:16s} {d[3]:>18s} k={d[4]:<6d} u={d[5]:.4f} pi={d[6]:.2f} w={d[7]:.2f} {d[8]}")
    if len(r["detail"]) > 12:
        print(f"      ... {len(r['detail']) - 12} more")

print("\nall non-scan stages, all seeds: blockers by class")
for c in ("attack", "quiet", "size", "unusual"):
    print(f"  {c:8s} {tot[(False, c)]}")
json.dump(rows_out, open(f"{dd}/blockers.json", "w"), indent=1, default=str)
