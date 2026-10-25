#!/usr/bin/env python3
"""Tuning the queue and accumulator parameters that Deliverable 3 says are selected
on the tuning set but had stayed at their provisional values: the repeat-group gap
Delta (C9) and the accumulator's theta percentile, contribution floor, weights a,
decay h and lambda (C8). Tuning scenarios only; the method otherwise as specified
(entries N=20 delta=60 s, host windows for the sequence term, shrinkage calibration,
pi group score, weights (0, 0, 1)); every entity type feeds C8, as in ait_eval.py.

Forest scores are computed once per scenario and seed and cached; each variant then
recomputes the queue groups, B2 and B3 exactly as ait_eval.py does (variant `base`
must reproduce Table X). One parameter is changed at a time from the incumbent.

usage: ait_param_lab.py <wb_dir> <host_roles.json> <out.json> [--seeds 5] [--variants v,...] [scenario ...]
variants: base, delta900, delta172800, delta1000000000 (no split), delta1800, delta14400, delta86400, thq99, thq995, thq9999,
          cf05, cf20, h1, h12, lam2, lam8, a001, a226, a505, a424
"""
import sys, os, json, pickle, collections, argparse, time, math
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("roles"); ap.add_argument("out")
ap.add_argument("--seeds", type=int, default=5)
ap.add_argument("--variants", default="base")
ap.add_argument("scenarios", nargs="*")
args = ap.parse_args()
scs = args.scenarios or ["harrison", "russellmitchell", "shaw", "wheeler"]
assert not {"fox", "santos", "wardbeck", "wilson"} & set(scs), "tuning scenarios only"
sys.path.insert(0, args.wb)
import window_builder as W
import seq_scoring as C6
import accumulator as C8
import eval_metrics as M

ROLES = json.load(open(args.roles))
host_of = lambda a: next(v for t, v in a.entities if t == "host")
U_MAX = 1 - 1e-5
LAMBDA_Q = 8.0


def surprise(u, n):
    u = np.clip(u, 1e-12, U_MAX)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


def prepare(sc):
    cache = f"plabrows_{sc}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
    wb = W.WindowBuilder(N=20, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
    rows = collections.defaultdict(lambda: {"j": [], "ev": [], "F": [], "ok": []})
    for j, a in enumerate(A):
        if a.ts >= t_atk and wb.learn_rules:
            wb.learn_rules = False
        for e, f, ok in wb.push(a):
            d = rows[e[0]]; d["j"].append(j); d["ev"].append(e[1]); d["F"].append(f); d["ok"].append(ok)
    rows = {k: {"j": np.array(v["j"]), "ev": np.array(v["ev"], dtype=object), "F": np.array(v["F"]),
                "ok": np.array(v["ok"])} for k, v in rows.items()}
    ev = np.array([j for j, a in enumerate(A) if a.ts >= t_atk and a.admissible])
    alert = dict(ts=np.array([a.ts for a in A]), seq=np.array([a.ingest_seq for a in A]),
                 host=np.array([host_of(a) for a in A], dtype=object),
                 rule=np.array([a.rule_id for a in A], dtype=object),
                 lvl=np.array([a.rule_level for a in A], float),
                 sexp=np.array([ROLES[sc].get(a.agent_ip, {"s_exp": 0.0})["s_exp"] for a in A]),
                 tactics=[a.tactics for a in A])
    out = dict(rows=rows, ev=ev, L=np.array([labels[j] for j in ev], dtype=object), t_atk=t_atk, alert=alert)
    pickle.dump(out, open(cache, "wb"))
    return out


def scores(sc, P, seed):
    cache = f"plabfit_{sc}_s{seed}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    a = P["alert"]; Se = {}
    for et, d in P["rows"].items():
        s = np.full(len(d["j"]), -1.0)
        tsw = a["ts"][d["j"]]; hw = a["host"][d["j"]]
        base = d["ok"] & (tsw < P["t_atk"])
        if base.sum() > 0 and d["ok"].sum() > 0:
            m = C6.TypeModel(seed)
            if m.fit(d["F"][base], list(hw[base]), True):
                s[d["ok"]] = m.score(d["F"][d["ok"]], list(hw[d["ok"]]), True)
        Se[et] = s
    pickle.dump(Se, open(cache, "wb"))
    return Se


def params(v):
    p = dict(delta=3600.0, thq=99.9, cf=0.10, h=4 * 3600.0,  # the incumbent of the 2026-10-25 sweep; lam=4.0, a=(0.3, 0.2, 0.5))
    for part in v.split("+"):
        p.update(_param(part))
    return p


def _param(v):
    """one parameter change; variants may combine several with '+' (e.g. delta86400+h1)"""
    p = {}
    if v.startswith("delta"): p["delta"] = float(v[5:])
    elif v.startswith("thq"): p["thq"] = {"thq99": 99.0, "thq995": 99.5, "thq9999": 99.99}[v]
    elif v.startswith("cf"): p["cf"] = int(v[2:]) / 100
    elif v in ("h1", "h12"): p["h"] = int(v[1:]) * 3600.0
    elif v.startswith("lam"): p["lam"] = float(v[3:])
    elif v.startswith("a") and v != "base":
        p["a"] = tuple(int(c) / 10 for c in v[1:])
    return p


def run(P, Se, v):
    p = params(v); a = P["alert"]; ev = P["ev"]; L = P["L"]; t_atk = P["t_atk"]
    # queue groups: same host, same rule, gaps <= Delta
    gid, last, cur, nxt = [], {}, {}, 0
    for j in ev:
        key = (a["host"][j], a["rule"][j])
        if key not in last or a["ts"][j] - last[key] > p["delta"]:
            cur[key] = nxt; nxt += 1
        last[key] = a["ts"][j]; gid.append(cur[key])
    gid = np.array(gid); G = nxt
    k = np.bincount(gid, minlength=G).astype(float)
    stages = M.item_stages(gid, L, G)
    gid_of = dict(zip(ev.tolist(), gid.tolist()))
    first_ts = np.full(G, np.inf); np.minimum.at(first_ts, gid, a["ts"][ev])
    days = (first_ts // 86400).astype(int)
    # B2: host windows, pi
    n = len(a["ts"])
    se_all = np.full(n, -1.0); d = P["rows"]["host"]; np.maximum.at(se_all, d["j"], Se["host"])
    se = se_all[ev]
    s = np.where(se < 0, 50.0, se)
    gm = np.full(G, -np.inf); np.maximum.at(gm, gid, s)
    b2 = 100 * np.minimum(1, surprise(gm / 100, k) / LAMBDA_Q)
    f2 = M.first_item_ranks(b2, stages)
    out = {"B2": {"andcg20": M.alpha_ndcg(b2, stages, 20), "mrr": M.mrr_nonscan(f2),
                  "first": {x: float(y) for x, y in f2.items()}}}
    # B3: Component 8 over every entity type
    RUN = W.ENTRY_FEATURE_NAMES.index("current_run_length")
    stream = []
    for et, dd in P["rows"].items():
        for i in range(len(dd["j"])):
            j = dd["j"][i]
            stream.append((a["ts"][j], a["seq"][j], et, dd["ev"][i], j, Se[et][i], dd["F"][i, RUN] == 1))
    stream.sort(key=lambda x: (x[0], x[1]))

    def gen():
        for ts, _, et, evv, j, s_, opened in stream:
            yield {"ent": (et, evv), "etype": et, "t": ts, "rule": a["rule"][j], "s_rule": 100 * a["lvl"][j] / 15,
                   "s_exp": a["sexp"][j], "s_seq": s_, "opened": bool(opened), "tactics": a["tactics"][j],
                   "gid": gid_of.get(j), "baseline": ts < t_atk}
    kw = dict(a_r=p["a"][0], a_c=p["a"][1], a_s=p["a"][2], h=p["h"], lam=p["lam"])
    C8.CONTRIB_FRAC = p["cf"]
    R_base, _ = C8.run(gen(), 20, **kw)
    theta = C8.calibrate_theta(R_base, p["thq"])
    _, nbs = C8.run(gen(), 20, theta=theta, **kw)
    C8.CONTRIB_FRAC = 0.10
    incidents = C8.merge_notables([nb for nb in nbs if nb["gids"]])
    sortedR = {et: np.sort(vv) for et, vv in R_base.items()}
    absorbed = set().union(*[inc["gids"] for inc in incidents]) if incidents else set()
    keep = np.array([g not in absorbed for g in range(G)])
    prio3 = list(b2[keep]); st3 = [stages[g] for g in range(G) if keep[g]]
    benign = 0
    for inc in incidents:
        pct = max(100 * np.searchsorted(sortedR[et], inc["R_peak"], "right") / len(sortedR[et])
                  for et in inc["etypes"] if et in sortedR)
        sset = set().union(*[stages[g] for g in inc["gids"]])
        prio3.append(pct); st3.append(sset); benign += (not sset)
    f3 = M.first_item_ranks(np.array(prio3), st3)
    out["B3"] = {"andcg20": M.alpha_ndcg(np.array(prio3), st3, 20), "mrr": M.mrr_nonscan(f3),
                 "first": {x: float(y) for x, y in f3.items()}, "incidents": len(incidents), "benign_incidents": benign,
                 "items": len(prio3)}
    out["B2"]["items"] = G
    return out


OUT = json.load(open(args.out)) if os.path.exists(args.out) else {}
for sc in scs:
    P = prepare(sc)
    for seed in range(args.seeds):
        Se = scores(sc, P, seed)
        for v in args.variants.split(","):
            if len(OUT.get(sc, {}).get(v, [])) > seed:
                continue
            t0 = time.time()
            OUT.setdefault(sc, {}).setdefault(v, []).append(run(P, Se, v))
            r = OUT[sc][v][-1]
            print(f"{sc} seed {seed} {v}: B2 {r['B2']['andcg20']:.3f} B3 {r['B3']['andcg20']:.3f} "
                  f"incidents {r['B3']['incidents']} benign {r['B3']['benign_incidents']} ({time.time() - t0:.0f}s)", flush=True)
            json.dump(OUT, open(args.out, "w"), indent=1)
