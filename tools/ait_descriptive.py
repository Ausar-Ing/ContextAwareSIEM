#!/usr/bin/env python3
"""Descriptive comparisons pre-registered on 2026-11-02 (PREREGISTRATION.md Section 9).
Formats outputs of ait_eval.py; computes no new scores and runs no test.

  9.1 within-host AUC, B2 vs B_RBA, per eligible host, with the fixed verdict rule
  9.2 recorded vs no-reconnaissance: alpha-nDCG@20 and MRR per system and their change
  9.3 B3 vs B_RBA: paired first-item counts of non-scan stages (no p-value)

usage: ait_descriptive.py <wb_dir> <recorded.json> <norecon.json>
"""
import sys, json
import numpy as np

sys.path.insert(0, sys.argv[1])
import eval_metrics as M

RUNS = {"recorded": json.load(open(sys.argv[2])), "no-recon": json.load(open(sys.argv[3]))}


def rows(R, sc, name):
    r = R[sc]
    if name in r["seeded"]:
        return r["seeded"][name]
    if name in r["deterministic"]:
        return [r["deterministic"][name]]
    return []


def host_auc(R, name):
    """{(scenario, host): (mean AUC over seeds, n_attack, n_benign)}"""
    out = {}
    for sc in sorted(R):
        acc = {}
        for x in rows(R, sc, name):
            for h, (a, na, nb) in (x.get("within_hosts") or {}).items():
                acc.setdefault(h, []).append((a, na, nb))
        for h, v in acc.items():
            out[(sc, h)] = (float(np.mean([t[0] for t in v])), v[0][1], v[0][2])
    return out


def verdict(per):
    """per: list of (scenario, b2, rba). Rule fixed in PREREGISTRATION.md 9.1."""
    m = len(per)
    if m < 3:
        return f"{m} eligible host(s): too few, no comparison is stated"
    hi = [(s, a, b) for s, a, b in per if round(a, 3) > round(b, 3)]
    lo = [(s, a, b) for s, a, b in per if round(a, 3) < round(b, 3)]
    scen = len({s for s, _, _ in hi})
    if len(hi) > m / 2 and scen >= 2:
        return f"B2 higher on {len(hi)} of {m} hosts ({scen} scenarios): statement 9.1 allowed"
    return f"B2 higher on {len(hi)}, lower on {len(lo)} of {m} hosts ({scen} scenario(s) with B2 higher): mixed, no statement"


def firsts(R, name):
    out = {}
    for sc in sorted(R):
        rr = rows(R, sc, name)
        if not rr:
            continue
        for st in rr[0]["first"]:
            out[(sc, st)] = float(np.mean([r["first"][st] for r in rr if st in r["first"]]))
    return out


def mean_metric(R, name, key):
    v = []
    for sc in sorted(R):
        x = [r[key] for r in rows(R, sc, name) if r.get(key) is not None and not np.isnan(r[key])]
        if x:
            v.append(np.mean(x))
    return float(np.mean(v)) if v else float("nan")


for run, R in RUNS.items():
    print(f"== 9.1 within-host AUC, {run} run (scenarios: {', '.join(sorted(R))})")
    b2, rba = host_auc(R, "B2"), host_auc(R, "B_RBA")
    print(f"  {'scenario':16s} {'host':>5s} {'n_att':>6s} {'n_ben':>6s} {'B2':>6s} {'B_RBA':>6s} {'B0_host':>7s}")
    per = []
    for key in sorted(b2):
        a, na, nb = b2[key]; b = rba.get(key, (float("nan"),))[0]
        per.append((key[0], a, b))
        print(f"  {key[0]:16s} {key[1]:>5s} {na:6d} {nb:6d} {a:6.3f} {b:6.3f} {0.5:7.3f}")
    print(f"  verdict ({'governs the statement' if run == 'recorded' else 'reported beside the headline'}): {verdict(per)}\n")

print("== 9.2 recorded vs no-reconnaissance (means over scenarios and seeds); change is relative")
print(f"  {'system':8s} {'nDCG@20 rec':>11s} {'no-recon':>9s} {'change':>7s}   {'MRR rec':>7s} {'no-recon':>9s} {'change':>7s}")
for name in ("B0_host", "B0_rank", "B_RBA", "B2", "B3"):
    a, b = mean_metric(RUNS["recorded"], name, "andcg20"), mean_metric(RUNS["no-recon"], name, "andcg20")
    c, d = mean_metric(RUNS["recorded"], name, "mrr"), mean_metric(RUNS["no-recon"], name, "mrr")
    print(f"  {name:8s} {a:11.3f} {b:9.3f} {(b - a) / a:+7.0%}   {c:7.3f} {d:9.3f} {(d - c) / c:+7.0%}")

print("\n== 9.3 B3 vs B_RBA, paired first-item ranks of non-scan stages (descriptive, no test)")
for run, R in RUNS.items():
    p = M.paired_ranks(firsts(R, "B3"), firsts(R, "B_RBA"))
    print(f"  {run:9s}: n={p['n']:2d}  B3 earlier {p['a_better']:2d}, B_RBA earlier {p['b_better']:2d}, tied {p['tied']:2d}")
