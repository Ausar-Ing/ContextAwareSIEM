#!/usr/bin/env python3
"""First-item veto of the tuning protocol (Deliverable 3, Sec. IV-C), from the
per-seed alert scores saved by ait_sweep.py (SAVE_DIR). Tuning scenarios only.

The tuning objective is the mean graded alpha-nDCG@20; a difference smaller than the
larger of the two configurations' seed standard deviations is a tie, broken by MRR when
the MRR difference exceeds the larger MRR seed standard deviation; otherwise the
incumbent is kept.
Veto: a configuration preferred by the objective is rejected if, against the
incumbent, it places the first item of a non-scan stage LATER on a majority of the
stage occurrences (first-item ranks averaged over seeds, paired by scenario and stage),
because the paired first-item comparison is the protocol's primary test.

usage: ait_veto.py <scores_dir> <wb_dir> [incumbent=entry20d60:pi]
"""
import sys
import numpy as np

sd, wb = sys.argv[1:3]
inc_spec = sys.argv[3] if len(sys.argv) > 3 else "entry20d60:pi"
sys.path.insert(0, wb)
import eval_metrics as M

TUNING = ["harrison", "wheeler", "russellmitchell", "shaw"]
U = 1 - 1e-5


def surprise(u, n):
    u = np.clip(u, 1e-12, U)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


def evaluate(cfg, kind):
    """(mean alpha-nDCG@20, seed sd, MRR, {(scenario, stage): mean first rank})"""
    firsts, mrr = {}, None
    seeds_nd = None
    for sc in TUNING:
        z = np.load(f"{sd}/{sc}_{cfg}.npz", allow_pickle=True)
        gid = z["gid"]; G = gid.max() + 1; k = np.bincount(gid, minlength=G).astype(float)
        st = M.item_stages(gid, z["labels"], G)
        fs, nds, mr = [], [], []
        for s in z["sseq"]:
            mx = np.full(G, -np.inf); np.maximum.at(mx, gid, s)
            score = {"max": mx, "mean": np.bincount(gid, weights=s, minlength=G) / k,
                     "pi": surprise(mx / 100, k),                       # uncapped (w_s = 1)
                     "pi4": 100 * np.minimum(1, surprise(mx / 100, k) / 4)}[kind]
            f = M.first_item_ranks(score, st); fs.append(f); nds.append(M.alpha_ndcg(score, st, 20))
            mr.append(M.mrr_nonscan(f))
        seeds_nd = np.array(nds) if seeds_nd is None else seeds_nd + np.array(nds)
        mrr = np.array(mr) if mrr is None else mrr + np.array(mr)
        for s_ in fs[0]:
            firsts[(sc, s_)] = float(np.mean([f[s_] for f in fs]))
    seeds_nd /= len(TUNING); mrr /= len(TUNING)
    return float(seeds_nd.mean()), float(seeds_nd.std()), float(mrr.mean()), firsts, float(mrr.std())


inc_cfg, inc_kind = inc_spec.split(":")
I = evaluate(inc_cfg, inc_kind)
print(f"incumbent {inc_spec}: alpha-nDCG@20 {I[0]:.3f} (seed sd {I[1]:.3f}), MRR {I[2]:.3f} (seed sd {I[4]:.3f})\n")
print(f"{'candidate':22s} {'@20':>6s} {'sd':>6s} {'MRR':>6s}  objective          first items vs incumbent   verdict")
for cfg in ("entry20d60", "alert20", "alert5"):
    for kind in ("max", "mean", "pi", "pi4"):
        if f"{cfg}:{kind}" == inc_spec:
            continue
        C = evaluate(cfg, kind)
        tie = abs(C[0] - I[0]) < max(C[1], I[1])
        mrr_clear = abs(C[2] - I[2]) > max(C[4], I[4])
        obj = (("tie, MRR " + ("prefers" if C[2] > I[2] else "rejects")) if mrr_clear else "tie, MRR tie") if tie \
            else ("prefers" if C[0] > I[0] else "rejects")
        p = M.paired_ranks(C[3], I[3])
        prefers = (not tie and C[0] > I[0]) or (tie and mrr_clear and C[2] > I[2])
        veto = prefers and p["b_better"] > p["n"] / 2
        verdict = "VETOED" if veto else ("adopt" if prefers else "keep incumbent")
        print(f"{cfg + ':' + kind:22s} {C[0]:6.3f} {C[1]:6.3f} {C[2]:6.3f}  {obj:18s} earlier {p['a_better']}, later {p['b_better']}, "
              f"tied {p['tied']} (p={p['wilcoxon_p']:.3f})  {verdict}")
