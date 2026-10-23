#!/usr/bin/env python3
"""Does volume-weighted training plus the calibration fallback favour quiet
hosts? Tuning scenarios only; B2 (entries, N=20, delta=60 s, group score pi,
lambda 8, weights (0,0,1)); five seeds.

Variants of Component 6:
  V0  pooled training (every 10th window, all hosts), own calibration only with >= 500 held-out windows   (as run so far)
  V1  per-host equal-share training, fallback at 500
  V2  per-host equal-share training, fallback at 100
  V3  pooled training, fallback at 100
  V4  per-host equal-share training; hosts with < 100 held-out windows left unscored (no pooled fallback):
      measures how much of the ranking comes from hosts the model cannot calibrate

Diagnostics:
  calibration check  share of BENIGN evaluation-period host windows above S_seq 99, by host role.
                     Under correct per-host calibration and stationarity it is about 1% for every host.
  queue bias         benign queue items in the top 20, split into quiet hosts (intranet server, file
                     share, cloud share: each under 1% of baseline windows) and the rest.
  fallback log       which hosts were calibrated against their own baseline.

usage: ait_strat.py <host_roles.json> <wb_dir> <out.json> <scenario> [...]
       (expects evalcache_<scenario>_clean_sid1.pkl from ait_eval.py in the current directory)
"""
import sys, json, pickle, collections
import numpy as np

roles_path, wb_dir, out_path = sys.argv[1:4]
scenarios = sys.argv[4:]
assert not set(scenarios) & {"fox", "santos", "wardbeck", "wilson"}, "tuning scenarios only"
sys.path.insert(0, wb_dir)
import window_builder as W
import seq_scoring as C6
import eval_metrics as M

ROLES = json.load(open(roles_path))
QUIET = {"intranet_server", "internal_share", "cloud_share"}
VARIANTS = {"V0 pooled, fallback 500": (False, 500), "V1 equal-share, fallback 500": (True, 500),
            "V2 equal-share, fallback 100": (True, 100), "V3 pooled, fallback 100": (False, 100),
            "V4 equal-share, under 100 unscored": (True, 100, "none")}
SEEDS, LAMBDA_Q, DELTA_Q = 5, 8.0, 3600.0


def host_of(a):
    return next(v for t, v in a.entities if t == "host")


def surprise(u, n):
    u = np.clip(u, 1e-12, 1 - 1e-5)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


OUT = {}
for sc in scenarios:
    A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
    n = len(A)
    ip_of_host = {host_of(a): a.agent_ip for a in A}
    role = lambda h: ROLES[sc][ip_of_host[h]]["role"]
    wb = W.WindowBuilder(N=20, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
    rows = collections.defaultdict(lambda: {"j": [], "F": [], "ok": []})
    for j, a in enumerate(A):
        if a.ts >= t_atk and wb.learn_rules:
            wb.learn_rules = False
        for e, f, ok in wb.push(a):
            d = rows[e[0]]; d["j"].append(j); d["F"].append(f); d["ok"].append(ok)
    rows = {k: {"j": np.array(v["j"]), "F": np.array(v["F"]), "ok": np.array(v["ok"])} for k, v in rows.items()}
    ev = np.array([j for j, a in enumerate(A) if a.ts >= t_atk and a.admissible])
    L = np.array([labels[j] for j in ev], dtype=object)
    gid, last, cur, nxt = [], {}, {}, 0
    for j in ev:
        key = (host_of(A[j]), A[j].rule_id)
        if key not in last or A[j].ts - last[key] > DELTA_Q:
            cur[key] = nxt; nxt += 1
        last[key] = A[j].ts; gid.append(cur[key])
    gid = np.array(gid); G = nxt
    k = np.bincount(gid, minlength=G).astype(float)
    stages = M.item_stages(gid, L, G)
    g_host = np.empty(G, dtype=object)
    for i, j in enumerate(ev):
        g_host[gid[i]] = host_of(A[j])
    benign_item = np.array([not stages[g] for g in range(G)])
    OUT[sc] = {}
    for vname, spec in VARIANTS.items():
        strat, mincal = spec[0], spec[1]
        fb = spec[2] if len(spec) > 2 else "pooled"
        recs = []
        for seed in range(SEEDS):
            s_alert = np.full(n, -1.0)
            calib = collections.defaultdict(list)       # role -> [S_seq of benign eval host windows]
            fallback, share = {}, {}
            for et, d in rows.items():
                ts = np.array([A[j].ts for j in d["j"]])
                hosts = np.array([host_of(A[j]) for j in d["j"]], dtype=object)
                base = d["ok"] & (ts < t_atk)
                if base.sum() == 0:
                    continue
                m = C6.TypeModel(seed, stratify=strat, min_host_cal=mincal, fallback=fb)
                if not m.fit(d["F"][base], list(hosts[base]), True):
                    continue
                okm = d["ok"]
                s = np.full(len(d["j"]), -1.0)
                s[okm] = m.score(d["F"][okm], list(hosts[okm]), True)
                np.maximum.at(s_alert, d["j"], s)
                if et == "host":
                    fallback = {role(h) + f"[{h}]": v for h, v in m.cal_source.items()}
                    share = {role(h) + f"[{h}]": v for h, v in m.train_share.items()}
                    evb = okm & (ts >= t_atk) & np.array([labels[j] in M.BENIGN for j in d["j"]])
                    for h, v in zip(hosts[evb], s[evb]):
                        if v >= 0:
                            calib[role(h)].append(v)
            se = np.where(s_alert[ev] < 0, 50.0, s_alert[ev])
            mx = np.full(G, -np.inf); np.maximum.at(mx, gid, se)
            prio = 100 * np.minimum(1, surprise(mx / 100, k) / LAMBDA_Q)
            f = M.first_item_ranks(prio, stages)
            top = np.argsort(-prio, kind="mergesort")[:20]
            recs.append({"andcg20": M.alpha_ndcg(prio, stages, 20), "mrr": M.mrr_nonscan(f),
                         "first": {s_: float(v) for s_, v in f.items()},
                         "benign_top20_quiet": int(sum(benign_item[g] and role(g_host[g]) in QUIET for g in top)),
                         "benign_top20_other": int(sum(benign_item[g] and role(g_host[g]) not in QUIET for g in top)),
                         "above99_by_role": {r: float(np.mean(np.array(v) > 99)) for r, v in calib.items()},
                         "fallback": fallback, "train_share": share})
        OUT[sc][vname] = recs
        r0 = recs[0]
        print(f"{sc:16s} {vname:30s} aNDCG@20 {np.mean([r['andcg20'] for r in recs]):.3f} MRR {np.mean([r['mrr'] for r in recs]):.3f} "
              f"| benign top-20 quiet {np.mean([r['benign_top20_quiet'] for r in recs]):.1f} other {np.mean([r['benign_top20_other'] for r in recs]):.1f}",
              flush=True)
        print("    benign host windows above S 99, by role: " +
              ", ".join(f"{k_} {100*np.mean([r['above99_by_role'].get(k_, np.nan) for r in recs]):.1f}%" for k_ in sorted(r0["above99_by_role"])))
        print("    calibration source (host windows held out): " +
              ", ".join(f"{k_.split('[')[0]} {v[0]} {v[1]}" for k_, v in sorted(r0["fallback"].items())), flush=True)
    json.dump(OUT, open(out_path, "w"), indent=1, default=float)
