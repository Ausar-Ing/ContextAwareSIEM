#!/usr/bin/env python3
"""Post-hoc descriptive comparisons on the locked-run outputs (2026-11-04). NOT part of the pre-registered protocol.

Reads only the frozen JSON in provenance/ait/test/ (no data, no model fitting, no test scenario re-read) and prints:
  1. first-item rank of every non-scan stage for B0, B0_host, B_RBA, B2 and B2_pooled (mean over seeds, as ait_holm.py);
  2. paired first-item counts (earlier / later / tied, no p-value) for comparisons the protocol does not contain:
     B2_pooled vs B_RBA, B2_pooled vs B0_host, B2_pooled vs B0;
  3. santos recorded beside santos oracle-cleaned (PREREGISTRATION Section 6) for the main systems.
Listed in provenance/ait/DEVIATIONS.md as a post-hoc analysis. Output: provenance/ait/posthoc_2026-11-04.txt.

usage: python3 tools/ait_posthoc.py tools provenance/ait/test > provenance/ait/posthoc_2026-11-04.txt
"""
import json, os, sys
import numpy as np
sys.path.insert(0, sys.argv[1])
import eval_metrics as M

OUT = sys.argv[2]
SHOW = ("B0", "B0_host", "B_RBA", "B2", "B2_pooled")
PAIRS = (("B2_pooled", "B_RBA"), ("B2_pooled", "B0_host"), ("B2_pooled", "B0"))


def firsts(r, name):
    """{stage: first-item rank}, seeded systems by their mean over the seeds that hold the stage (as ait_holm.py)"""
    rows = r["seeded"].get(name) or [r["deterministic"][name]]
    return {st: float(np.mean([x["first"][st] for x in rows if st in x["first"]])) for st in rows[0]["first"]}


def measure(r, name, key):
    rows = r["seeded"].get(name) or [r["deterministic"][name]]
    return float(np.mean([x[key] for x in rows]))


print("POST-HOC, descriptive only (not in PREREGISTRATION.md; see DEVIATIONS.md). Lower rank = earlier.\n")
for run in ("recorded", "norecon"):
    R = json.load(open(os.path.join(OUT, f"test_{run}.json")))
    print(f"== {run}: first-item rank of non-scan stages")
    print(f"  {'scenario':9s} {'stage':24s} " + " ".join(f"{s:>9s}" for s in SHOW))
    F = {sc: {n: firsts(r, n) for n in SHOW} for sc, r in R.items()}
    for sc in R:
        for st in sorted(s for s in F[sc]["B2"] if s not in M.SCANS):
            print(f"  {sc:9s} {st:24s} " + " ".join(f"{F[sc][n][st]:9.1f}" for n in SHOW))
    print(f"\n  paired first-item counts, non-scan stages ({run}; no test)")
    for a, b in PAIRS:
        d = [F[sc][a][st] - F[sc][b][st] for sc in R for st in F[sc][a] if st not in M.SCANS]
        e = sum(x < 0 for x in d); l = sum(x > 0 for x in d); t = sum(x == 0 for x in d)
        print(f"    {a:10s} vs {b:8s}: n={len(d):2d}  {a} earlier {e:2d}, {b} earlier {l:2d}, tied {t}")
    print()

print("== santos: recorded (headline) beside oracle-cleaned (PREREGISTRATION Section 6)")
rec = json.load(open(os.path.join(OUT, "test_recorded.json")))["santos"]
cln = json.load(open(os.path.join(OUT, "test_santos_cleaned.json")))["santos"]
print(f"  {'system':9s} {'aNDCG@20 rec':>12s} {'cleaned':>8s} {'MRR rec':>8s} {'cleaned':>8s}   first-item ranks rec -> cleaned")
for n in ("B0_host", "B0_rank", "B_RBA", "B2", "B2_pooled", "B3"):
    fr, fc = firsts(rec, n), firsts(cln, n)
    ranks = ", ".join(f"{st.split('_')[-1]} {fr[st]:.1f}->{fc[st]:.1f}" for st in sorted(fr) if st not in M.SCANS)
    print(f"  {n:9s} {measure(rec, n, 'andcg20'):12.3f} {measure(cln, n, 'andcg20'):8.3f} "
          f"{measure(rec, n, 'mrr'):8.3f} {measure(cln, n, 'mrr'):8.3f}   {ranks}")
