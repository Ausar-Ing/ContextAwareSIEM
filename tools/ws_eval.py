#!/usr/bin/env python3
"""Workstation (secondary corpus) evaluation, Deliverable 3 Sec. IV-C "Workstation":
false promotion on a real person's benign activity. No attacks, no labels.

Corpus: the frozen baseline (COLLECTION_RECORD.md Part E), agents 001 + 002 aliased to
one host, T0 <= t < T1. The hold-out is the final week before T1; the layer is fitted on
the rest. Configuration inherited from the AIT tuning set and frozen (Table III): entries
N = 20, delta = 60 s, active-time correction on (G = 1800 s, site zone UTC+7), shrinkage
calibration, host windows for the queue's sequence term, pi group score, Delta = 1 h,
Component 8 with every entity type and theta at the 99.9th baseline percentile.

Measures, per seed (forest seeds 0..S-1):
  drift     share of hold-out windows (host; user) above the 99th baseline percentile,
            expected 1% under stationarity; 95% CI by resampling whole local days
  load      queue items per awake hour whose priority exceeds the system's threshold,
            fixed on the AIT tuning set (ws_thresholds.json from ait_thresholds.py), counted
            at or above it:
            the priority above which half of the non-scan stages' first items fall
  notables  risk notables (B3) per awake hour
  awake     hold-out hours outside detected downtime (gaps > G in the host's stream)
  vulndet   vulnerability-detector alerts: count, share of admitted alerts, burstiness,
            and the load with them excluded at admission (an open admission decision)

usage: ws_eval.py <wb_dir> <frozen_corpus.json> <ws_thresholds.json> <out.json> [--seeds 5]
"""
import sys, os, json, argparse, collections, datetime as dt, time
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("corpus"); ap.add_argument("thresholds"); ap.add_argument("out")
ap.add_argument("--seeds", type=int, default=5)
ap.add_argument("--exclude-vulndet", action="store_true")
args = ap.parse_args()
sys.path.insert(0, args.wb)
import window_builder as W
import seq_scoring as C6
import accumulator as C8
import eval_metrics as M

T0 = dt.datetime(2026, 9, 12, 5, 14, tzinfo=dt.timezone.utc).timestamp()     # COLLECTION_RECORD A.1
T1 = dt.datetime(2026, 10, 17, 16, 15, tzinfo=dt.timezone.utc).timestamp()   # 23:15 +07, Part E
HOLD = T1 - 7 * 86400
TZ = 7 * 3600.0
G = W.DOWNTIME_GAP_S
DELTA_Q = C6.GROUP_GAP_S
LAMBDA_Q = 8.0
TH = json.load(open(args.thresholds))
VULN = "vulnerability-detector"


def load():
    A, bad = [], 0
    with open(args.corpus) as f:
        for i, line in enumerate(f):
            try:
                a = W.parse_wazuh(json.loads(line), i)
            except (ValueError, KeyError):
                bad += 1; continue
            if T0 <= a.ts < T1:
                A.append(a)
    A.sort(key=lambda a: (a.ts, a.ingest_seq))
    return A, bad


def surprise(u, n):
    u = np.clip(u, 1e-12, 1 - 1e-5)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


t_start = time.time()
A, bad = load()
host_of = lambda a: next(v for t, v in a.entities if t == "host")
vuln = np.array([VULN in a.rule_groups for a in A])
if args.exclude_vulndet:
    # excluded alerts still prove the machine was on: keep them, as inadmissible
    for a, v in zip(A, vuln):
        if v:
            a.rule_groups = tuple(a.rule_groups) + ("sca",)   # routes through the compliance exclusion
ts = np.array([a.ts for a in A])
adm = np.array([a.admissible for a in A])
print(f"{len(A)} alerts in [T0, T1), {bad} unparseable lines, {adm.sum()} admitted; hold-out from "
      f"{dt.datetime.fromtimestamp(HOLD, dt.timezone(dt.timedelta(hours=7))):%Y-%m-%d %H:%M} +07", flush=True)

# awake time in the hold-out: gaps > G in the (aliased) host's global stream are downtime
hts = np.sort(ts)
gaps = np.diff(hts)
down = [(a_, b_) for a_, b_, g in zip(hts[:-1], hts[1:], gaps) if g > G]
def awake_hours(lo, hi):
    tot = hi - lo
    for a_, b_ in down:
        tot -= max(0.0, min(b_, hi) - max(a_, lo))
    return tot / 3600
awake = awake_hours(HOLD, T1)

# windows
wb = W.WindowBuilder(N=20, learn_rules=True, collapse_s=60.0)
rows = collections.defaultdict(lambda: {"j": [], "ev": [], "F": [], "ok": []})
for j, a in enumerate(A):
    if a.ts >= HOLD and wb.learn_rules:
        wb.learn_rules = False
    for e, f, ok in wb.push(a):
        d = rows[e[0]]; d["j"].append(j); d["ev"].append(e[1]); d["F"].append(f); d["ok"].append(ok)
rows = {k: {"j": np.array(v["j"]), "ev": np.array(v["ev"], dtype=object), "F": np.array(v["F"]),
            "ok": np.array(v["ok"])} for k, v in rows.items()}
hosts = np.array([host_of(a) for a in A], dtype=object)
print("windows:", {k: int(v["ok"].sum()) for k, v in rows.items()}, flush=True)

# queue groups over the hold-out
ev = np.array([j for j in range(len(A)) if A[j].ts >= HOLD and A[j].admissible])
gid, last, cur, nxt = [], {}, {}, 0
for j in ev:
    key = (hosts[j], A[j].rule_id)
    if key not in last or A[j].ts - last[key] > DELTA_Q:
        cur[key] = nxt; nxt += 1
    last[key] = A[j].ts; gid.append(cur[key])
gid = np.array(gid); G_ = nxt
k = np.bincount(gid, minlength=G_).astype(float)
gmax = lambda v: (lambda o: (np.maximum.at(o, gid, v), o)[1])(np.full(G_, -np.inf))
lvl = np.array([A[j].rule_level for j in ev], float)
base_lv = np.sort([a.rule_level for a in A if a.ts < HOLD and a.admissible])
s_rule = 100 * lvl / 15
lo = np.searchsorted(base_lv, lvl, "left"); hi = np.searchsorted(base_lv, lvl, "right")
s_rank = 100 * (lo + 0.5 * (hi - lo)) / len(base_lv)
NOV = W.FEATURE_NAMES.index("novel_rule_flag")


def load_per_hour(prio, name):
    th = TH.get(name)
    return None if th is None else float((prio >= th).sum() / awake)


res = {"meta": {"alerts": len(A), "admitted": int(adm.sum()), "unparseable": bad, "awake_hours_holdout": awake,
                "holdout_start_utc": HOLD, "T0": T0, "T1": T1, "groups_holdout": int(G_),
                "admitted_holdout": int(len(ev)), "exclude_vulndet": args.exclude_vulndet, "thresholds": TH,
                "downtime_intervals_holdout": sum(1 for a_, b_ in down if b_ > HOLD and a_ < T1)},
       "deterministic": {}, "seeded": collections.defaultdict(list)}
g_rule, g_rank = gmax(s_rule), gmax(s_rank)
res["deterministic"]["B0"] = {"load_per_awake_h": load_per_hour(g_rule, "B0"), "items": int(G_)}
res["deterministic"]["B0_rank"] = {"load_per_awake_h": load_per_hour(g_rank, "B0_rank")}
# vulnerability-detector profile
vj = [j for j in range(len(A)) if vuln[j]]
vts = ts[vj] if vj else np.array([])
res["meta"]["vulndet"] = {"alerts": len(vj), "admitted": int(sum(A[j].admissible for j in vj)),
                          "share_of_admitted": float(sum(A[j].admissible for j in vj) / max(1, adm.sum())),
                          "distinct_minutes": int(len(np.unique((vts // 60).astype(int)))) if len(vts) else 0,
                          "max_per_minute": int(np.max(np.unique((vts // 60).astype(int), return_counts=True)[1])) if len(vts) else 0,
                          "levels": dict(collections.Counter(int(A[j].rule_level) for j in vj)),
                          "groups_holdout": int(len({gid[i] for i, j in enumerate(ev) if vuln[j]}))}


def day_boot(flags, days, reps=2000, rng=np.random.default_rng(0)):
    ud = np.unique(days); per = {d: flags[days == d] for d in ud}
    vals = []
    for _ in range(reps):
        pick = rng.choice(ud, len(ud), replace=True)
        x = np.concatenate([per[d] for d in pick]); vals.append(x.mean())
    return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]


for seed in range(args.seeds):
    Se = {}
    for et, d in rows.items():
        s = np.full(len(d["j"]), -1.0)
        tsw = ts[d["j"]]; hw = hosts[d["j"]]
        base = d["ok"] & (tsw < HOLD)
        m = C6.TypeModel(seed)
        if base.sum() and m.fit(d["F"][base], list(hw[base]), True):
            s[d["ok"]] = m.score(d["F"][d["ok"]], list(hw[d["ok"]]), True)
        Se[et] = s
    r = {}
    # drift per entity type on hold-out windows
    for et, d in rows.items():
        mh = (Se[et] >= 0) & (ts[d["j"]] >= HOLD)
        if mh.sum() == 0:
            continue
        flags = (Se[et][mh] > 99).astype(float)
        days = ((ts[d["j"]][mh] + TZ) // 86400).astype(int)
        r[f"drift_{et}"] = [float(flags.mean())] + day_boot(flags, days) + [int(mh.sum())]
    # B2 and the candidate novelty arm
    se_all = np.full(len(A), -1.0); dh = rows["host"]; np.maximum.at(se_all, dh["j"], Se["host"])
    se = np.where(se_all[ev] < 0, 50.0, se_all[ev])
    b2 = 100 * np.minimum(1, surprise(gmax(se) / 100, k) / LAMBDA_Q)
    nv = np.zeros(len(A)); np.maximum.at(nv, dh["j"], np.where(dh["ok"], dh["F"][:, NOV], 0.0))
    b2n = 0.8 * b2 + 20 * gmax(nv[ev])
    r["B2_load"] = load_per_hour(b2, "B2"); r["B2_novterm_load"] = load_per_hour(b2n, "B2_novterm")
    r["B2_top_share_100"] = float((b2 >= 62.4).mean())
    # B3: Component 8 over every entity type, baseline + hold-out
    RUN = W.ENTRY_FEATURE_NAMES.index("current_run_length")
    stream = []
    for et, d in rows.items():
        for i in range(len(d["j"])):
            j = d["j"][i]
            stream.append((A[j].ts, A[j].ingest_seq, et, d["ev"][i], j, Se[et][i], d["F"][i, RUN] == 1))
    stream.sort(key=lambda x: (x[0], x[1]))
    gid_of = dict(zip(ev.tolist(), gid.tolist()))

    def gen():
        for t_, _, et, evv, j, s_, opened in stream:
            a = A[j]
            yield {"ent": (et, evv), "etype": et, "t": t_, "rule": a.rule_id, "s_rule": 100 * a.rule_level / 15,
                   "s_exp": 0.0, "s_seq": s_, "opened": bool(opened), "tactics": a.tactics,
                   "gid": gid_of.get(j), "baseline": t_ < HOLD}
    R_base, _ = C8.run(gen(), 20)
    theta = C8.calibrate_theta(R_base)
    _, nbs = C8.run(gen(), 20, theta=theta)
    incidents = C8.merge_notables([nb for nb in nbs if nb["gids"]])
    absorbed = set().union(*[inc["gids"] for inc in incidents]) if incidents else set()
    keep = np.array([g not in absorbed for g in range(G_)])
    sortedR = {et: np.sort(v) for et, v in R_base.items()}
    nprio = [max(100 * np.searchsorted(sortedR[et], inc["R_peak"], "right") / len(sortedR[et])
                 for et in inc["etypes"] if et in sortedR) for inc in incidents]
    prio3 = np.array(list(b2[keep]) + nprio)
    r["B3_load"] = load_per_hour(prio3, "B3")
    r["notables"] = len(incidents); r["notables_per_awake_h"] = len(incidents) / awake
    rule_of_g = {}
    for i_, g_ in enumerate(gid):
        rule_of_g.setdefault(int(g_), A[ev[i_]].rule_id)
    r["notable_detail"] = [{"t_open": inc["t_open"], "groups": len(inc["gids"]), "tactics": sorted(inc["tactics"]),
                            "rules": sorted({rule_of_g[g_] for g_ in inc["gids"] if g_ in rule_of_g})[:8],
                            "entities": [list(m_) for m_ in inc["members"]][:4]} for inc in incidents]
    res["seeded"]["run"].append(r)
    print(f"seed {seed}: drift host {r.get('drift_host')}, user {r.get('drift_user')}; load B2 {r['B2_load']}, "
          f"B3 {r['B3_load']}; notables {r['notables']} ({r['notables_per_awake_h']:.3f}/awake h)", flush=True)
res["meta"]["seconds"] = round(time.time() - t_start)
json.dump(res, open(args.out, "w"), indent=1, default=lambda o: sorted(o) if isinstance(o, set) else float(o))
