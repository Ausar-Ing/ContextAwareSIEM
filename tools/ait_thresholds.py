#!/usr/bin/env python3
"""Load thresholds for the workstation (Deliverable 3, Sec. IV-C): per system, the
priority above which half of the non-scan stages' first items fall on the AIT tuning
set, i.e. the median, over non-scan stage occurrences and seeds, of the priority of each
stage's first queue item. Uses the caches of ait_param_lab.py (plabrows_*, plabfit_*),
the method as specified (Delta 1 h, host windows, pi, Component 8 defaults).

usage: ait_thresholds.py <wb_dir> <host_roles.json> <out.json> [--seeds 5]
"""
import sys, json, pickle, argparse
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("roles"); ap.add_argument("out"); ap.add_argument("--seeds", type=int, default=5)
args = ap.parse_args()
sys.path.insert(0, args.wb)
import window_builder as W
import accumulator as C8
import seq_scoring as C6
import eval_metrics as M

SCS = ["harrison", "russellmitchell", "shaw", "wheeler"]
NOV = W.FEATURE_NAMES.index("novel_rule_flag")
RUN = W.ENTRY_FEATURE_NAMES.index("current_run_length")


def surprise(u, n):
    u = np.clip(u, 1e-12, 1 - 1e-5)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


def first_prio(prio, stages):
    out = {}
    for it, ss in enumerate(stages):
        for s in ss:
            if s in M.SCANS:
                continue
            out[s] = max(out.get(s, -np.inf), prio[it])
    return list(out.values())


vals = {k: [] for k in ("B0", "B0_rank", "B2", "B2_novterm", "B3")}
for sc in SCS:
    P = pickle.load(open(f"plabrows_{sc}.pkl", "rb"))
    A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
    a = P["alert"]; ev = P["ev"]; L = P["L"]
    gid, last, cur, nxt = [], {}, {}, 0
    for j in ev:
        key = (a["host"][j], a["rule"][j])
        if key not in last or a["ts"][j] - last[key] > C6.GROUP_GAP_S:
            cur[key] = nxt; nxt += 1
        last[key] = a["ts"][j]; gid.append(cur[key])
    gid = np.array(gid); G = nxt; k = np.bincount(gid, minlength=G).astype(float)
    gmax = lambda v: (lambda o: (np.maximum.at(o, gid, v), o)[1])(np.full(G, -np.inf))
    stages = M.item_stages(gid, L, G)
    lvl = a["lvl"][ev]
    vals["B0"] += first_prio(gmax(100 * lvl / 15), stages)
    ip = np.array([A[j].agent_ip for j in ev], dtype=object)
    base_lv = {}
    for x in A:
        if x.ts < t_atk and x.admissible:
            base_lv.setdefault(x.agent_ip, []).append(x.rule_level)
    s_rank = np.empty(len(ev))
    for i, (h, l) in enumerate(zip(ip, lvl)):
        b = np.sort(base_lv.get(h, []))
        s_rank[i] = 100 * l / 15 if not len(b) else \
            100 * (np.searchsorted(b, l, "left") + 0.5 * (np.searchsorted(b, l, "right") - np.searchsorted(b, l, "left"))) / len(b)
    vals["B0_rank"] += first_prio(gmax(s_rank), stages)
    gid_of = dict(zip(ev.tolist(), gid.tolist()))
    dh = P["rows"]["host"]
    nv = np.zeros(len(a["ts"])); np.maximum.at(nv, dh["j"], np.where(dh["ok"], dh["F"][:, NOV], 0.0))
    for seed in range(args.seeds):
        Se = pickle.load(open(f"plabfit_{sc}_s{seed}.pkl", "rb"))
        se_all = np.full(len(a["ts"]), -1.0); np.maximum.at(se_all, dh["j"], Se["host"])
        se = np.where(se_all[ev] < 0, 50.0, se_all[ev])
        b2 = 100 * np.minimum(1, surprise(gmax(se) / 100, k) / 8.0)
        vals["B2"] += first_prio(b2, stages)
        vals["B2_novterm"] += first_prio(0.8 * b2 + 20 * gmax(nv[ev]), stages)
        stream = []
        for et, d in P["rows"].items():
            for i in range(len(d["j"])):
                j = d["j"][i]
                stream.append((a["ts"][j], a["seq"][j], et, d["ev"][i], j, Se[et][i], d["F"][i, RUN] == 1))
        stream.sort(key=lambda x: (x[0], x[1]))

        def gen():
            for t_, _, et, evv, j, s_, opened in stream:
                yield {"ent": (et, evv), "etype": et, "t": t_, "rule": a["rule"][j], "s_rule": 100 * a["lvl"][j] / 15,
                       "s_exp": a["sexp"][j], "s_seq": s_, "opened": bool(opened), "tactics": a["tactics"][j],
                       "gid": gid_of.get(j), "baseline": t_ < t_atk}
        R_base, _ = C8.run(gen(), 20)
        theta = C8.calibrate_theta(R_base)
        _, nbs = C8.run(gen(), 20, theta=theta)
        inc = C8.merge_notables([nb for nb in nbs if nb["gids"]])
        absorbed = set().union(*[x["gids"] for x in inc]) if inc else set()
        keep = np.array([g not in absorbed for g in range(G)])
        sortedR = {et: np.sort(v) for et, v in R_base.items()}
        prio3 = list(b2[keep]); st3 = [stages[g] for g in range(G) if keep[g]]
        for x in inc:
            prio3.append(max(100 * np.searchsorted(sortedR[et], x["R_peak"], "right") / len(sortedR[et])
                             for et in x["etypes"] if et in sortedR))
            st3.append(set().union(*[stages[g] for g in x["gids"]]))
        vals["B3"] += first_prio(np.array(prio3), st3)
    print(sc, "done", flush=True)
th = {k: float(np.median(v)) for k, v in vals.items()}
th["_n"] = {k: len(v) for k, v in vals.items()}
print(json.dumps(th, indent=1))
json.dump(th, open(args.out, "w"), indent=1)
