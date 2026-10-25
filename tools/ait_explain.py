#!/usr/bin/env python3
"""Per-item explanation of the queue (Deliverable 3, Sec. III-G): for the top queue
items of a tuning scenario, the terms of the hybrid priority, the member that set the
group's S_seq, and the window features that most influenced that member's score.

Feature influence: the change in the forest's raw score when the feature is replaced
by its median over the same host's baseline windows (positive = the feature made the
window more unusual for that host), the measure used in the wheeler diagnosis. Method
as specified: entries N=20, delta=60 s, host windows, shrinkage calibration, pi group
score, weights (0, 0, 1). Seed 0.

usage: ait_explain.py <wb_dir> <host_roles.json> <scenario> [top=20]
"""
import sys, os, json, pickle, datetime as dt
import numpy as np

wb, roles_path, sc = sys.argv[1:4]
top = int(sys.argv[4]) if len(sys.argv) > 4 else 20
assert sc not in {"fox", "santos", "wardbeck", "wilson"}, "tuning scenarios only"
sys.path.insert(0, wb)
import window_builder as W
import seq_scoring as C6
import eval_metrics as M

ROLES = json.load(open(roles_path))
D = pickle.load(open(f"labrows_{sc}.pkl", "rb"))       # written by ait_calib_lab.py
A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
names = [n for n in W.ENTRY_FEATURE_NAMES if n != "night_fraction"]
d = D["rows"]["host"]; tsw = D["ts"][d["j"]]; hw = D["hosts"][d["j"]]
base = d["ok"] & (tsw < t_atk)
m = C6.TypeModel(0)
m.fit(d["F"][base], list(hw[base]), True)
S = np.full(len(d["j"]), -1.0); ok = d["ok"]
S[ok] = m.score(d["F"][ok], list(hw[ok]), True)
X = m.prep(d["F"], True)
raw = np.full(len(d["j"]), np.nan); raw[ok] = -m.forest.score_samples(X[ok])
med = {h: np.median(X[base & (hw == h)], axis=0) for h in set(hw[base])}
row_of = {}                                       # alert index -> host-window row
for i, j in enumerate(d["j"]):
    row_of[j] = i

ev, gid, G, L = D["ev"], D["gid"], D["G"], D["L"]
s_alert = np.array([S[row_of[j]] if j in row_of else -1.0 for j in ev])
s_eff = np.where(s_alert < 0, 50.0, s_alert)
gm = np.full(G, -np.inf); np.maximum.at(gm, gid, s_eff)
k = np.bincount(gid, minlength=G).astype(float)
u = np.clip(gm / 100, 1e-12, 1 - 1e-5)
pi = -np.log10(np.maximum(-np.expm1(k * np.log(u)), 1e-300))
stages = M.item_stages(gid, L, G)
order = np.argsort(-pi, kind="mergesort")


def explain(i_row):
    x = X[i_row]; h = hw[i_row]; mu = med.get(h)
    if mu is None or np.isnan(raw[i_row]):
        return []
    out = []
    for f in range(len(names)):
        x2 = x.copy(); x2[f] = mu[f]
        out.append((raw[i_row] - (-m.forest.score_samples(x2[None, :])[0]), names[f], x[f], mu[f]))
    return sorted(out, reverse=True)[:3]


print(f"{sc}, seed 0: top {top} of {G} queue items under B2 (priority = pi; S_rule and S_exp shown for the hybrid's terms)\n")
for rank, g in enumerate(order[:top], 1):
    mem = np.flatnonzero(gid == g)
    j_best = ev[mem[np.argmax(s_eff[mem])]]
    a = A[j_best]
    role = ROLES[sc][a.agent_ip]["role"]
    lab = "/".join(sorted(stages[g])) or "benign"
    t0, t1 = dt.datetime.utcfromtimestamp(A[ev[mem[0]]].ts), dt.datetime.utcfromtimestamp(A[ev[mem[-1]]].ts)
    print(f"#{rank:2d} [{lab}] {role} rule {a.rule_id} (level {a.rule_level}) x{int(k[g])}, {t0:%m-%d %H:%M}-{t1:%H:%M}")
    print(f"     terms: S_seq(max) {gm[g]:.2f} -> pi {pi[g]:.2f} (weight 1); S_rule {100*a.rule_level/15:.0f}, "
          f"S_exp {ROLES[sc][a.agent_ip]['s_exp']:.0f} (weight 0)")
    ex = explain(row_of[j_best]) if j_best in row_of else []
    if ex:
        print("     window features: " + "; ".join(f"{n} {v:.2f} vs host median {mu_:.2f} ({c:+.3f})" for c, n, v, mu_ in ex))
    else:
        print("     window features: no temporal evidence (window unscored)")
