#!/usr/bin/env python3
"""Is an explicit novelty term host rarity in disguise? Tuning scenarios, seed 0.

For each scenario: the share of BENIGN queue groups whose host window flags their rule
as novel, on the quiet hosts (intranet server, file share, cloud share) and on the rest
(if novelty fired mostly on quiet hosts' benign groups it would reward rarely active
hosts, as host rarity does); and the within-host AUC (attack non-scan vs benign alerts
on the same host) of the alert-level score (1 - w) * S_seq + w * 100 * novel, which a
host-level signal cannot raise above 0.5.

usage: ait_novelty_check.py <wb_dir> <host_roles.json> [w=0.2]
"""
import sys, json, pickle
import numpy as np

wb, roles_path = sys.argv[1:3]
w = float(sys.argv[3]) if len(sys.argv) > 3 else 0.2
sys.path.insert(0, wb)
import window_builder as W
import seq_scoring as C6
import eval_metrics as M

ROLES = json.load(open(roles_path))
QUIET = {"intranet_server", "internal_share", "cloud_share"}
NOV = W.ENTRY_FEATURE_NAMES.index("novel_rule_flag")
print(f"w = {w}\n{'scenario':15s} benign groups novel: quiet hosts | other hosts    within-host AUC: S_seq | novelty | (1-w)S_seq + w*novelty")
for sc in ["harrison", "russellmitchell", "shaw", "wheeler"]:
    D = pickle.load(open(f"labrows_{sc}.pkl", "rb"))
    d = D["rows"]["host"]; tsw = D["ts"][d["j"]]; hw = D["hosts"][d["j"]]
    base = d["ok"] & (tsw < D["t_atk"])
    m = C6.TypeModel(0); m.fit(d["F"][base], list(hw[base]), True)
    S = np.full(len(d["j"]), -1.0); S[d["ok"]] = m.score(d["F"][d["ok"]], list(hw[d["ok"]]), True)
    n = len(D["ts"]); ev, gid, G, L = D["ev"], D["gid"], D["G"], D["L"]
    sa = np.full(n, -1.0); np.maximum.at(sa, d["j"], S)
    nv = np.zeros(n); np.maximum.at(nv, d["j"], np.where(d["ok"], d["F"][:, NOV], 0.0))
    se = np.where(sa[ev] < 0, 50.0, sa[ev]); na = nv[ev]
    gn = np.zeros(G); np.maximum.at(gn, gid, na)
    stages = M.item_stages(gid, L, G)
    first = {}
    for i, g in enumerate(gid):
        first.setdefault(g, i)
    role = np.array([ROLES[sc][D["ip"][ev[first[g]]]]["role"] for g in range(G)], dtype=object)
    ben = np.array([not s_ for s_ in stages])
    q = ben & np.isin(role, list(QUIET)); o = ben & ~np.isin(role, list(QUIET))
    hosts_ev = D["hosts"][ev]
    wa = [M.within_host_auc(x, L, hosts_ev)["macro"] for x in (se, 100 * na, (1 - w) * se + w * 100 * na)]
    print(f"{sc:15s} {gn[q].mean() if q.any() else float('nan'):6.2f} ({int(q.sum())} groups) | {gn[o].mean():6.2f} ({int(o.sum())} groups)"
          f"          {wa[0]:.3f} | {wa[1]:.3f} | {wa[2]:.3f}")
