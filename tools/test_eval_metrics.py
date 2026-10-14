#!/usr/bin/env python3
"""Checks for eval_metrics.py on hand-computed toy queues.   python3 tools/test_eval_metrics.py"""
import math, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_metrics as M
FAILED = []
def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  -- ' + detail) if detail else ''}")
    if not ok: FAILED.append(name)

print("eval_metrics")
# items: 0 benign, 1 sudo (3), 2 dirb (1), 3 dirb (1, repeat), 4 cracking (2)
st = [set(), {"escalated_sudo_command"}, {"dirb"}, {"dirb"}, {"online_cracking"}]
ideal = np.array([0, 5, 3, 1, 4.0])          # sudo, cracking, dirb, dirb(repeat), benign
check("ideal order scores 1", abs(M.alpha_ndcg(ideal, st, 5) - 1) < 1e-12)
worst = np.array([5, 1, 2, 3, 0.0])
v = M.alpha_ndcg(worst, st, 5)
# hand: order benign, dirb(3), dirb(2), sudo, cracking  -> gains 0,1,0.5,3,2
dcg = 1/math.log2(3) + 0.5/math.log2(4) + 3/math.log2(5) + 2/math.log2(6)
idcg = 3/math.log2(2) + 2/math.log2(3) + 1/math.log2(4) + 0.5/math.log2(5)
check("hand-computed alpha-nDCG", abs(v - dcg/idcg) < 1e-12, f"{v:.4f} vs {dcg/idcg:.4f}")
check("repeat of a stage earns (1-alpha) of its grade",
      M.alpha_ndcg(np.array([0, 1, 5, 4, 0.5]), st, 2) < M.alpha_ndcg(np.array([0, 5, 4, 1, 0.5]), st, 2))
tied = np.zeros(5)
t = M.alpha_ndcg(tied, st, 5)
check("all-tied queue gets the expected value, strictly between worst and best", v < t < 1, f"{t:.3f}")
f = M.first_item_ranks(ideal, st)
check("first-item ranks", f == {"escalated_sudo_command": 1, "online_cracking": 2, "dirb": 3}, str(f))
check("MRR over non-scan stages", abs(M.mrr_nonscan(f) - (1 + 1/2) / 2) < 1e-12)
check("coverage split scan / non-scan", M.coverage(f, 2) == {"nonscan": (2, 2), "scan": (0, 1)})
lab = np.array(["-", "-", "dnsteal", "dnsteal", "dnsteal", "escalated_sudo_command"], dtype=object)
sc = np.array([0, 1, 2, 3, 4, 0.5])
check("macro-AUC weights stages equally", abs(M.macro_auc(sc, lab) - (1.0 + 0.5) / 2) < 1e-12)
p = M.paired_ranks({("x", "dirb"): 1, ("x", "dnsteal"): 2, ("y", "dnsteal"): 9},
                   {("x", "dirb"): 5, ("x", "dnsteal"): 4, ("y", "dnsteal"): 3})
check("paired comparison skips scans, keys by (scenario, stage)", p["n"] == 2 and p["a_better"] == 1 and p["b_better"] == 1, str(p))
print(f"\n{'ALL PASS' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}")
sys.exit(1 if FAILED else 0)
