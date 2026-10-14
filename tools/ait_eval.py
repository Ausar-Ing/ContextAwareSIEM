#!/usr/bin/env python3
"""Evaluation harness for AIT-ADS (Deliverable 3, Sec. IV): every system, every
metric, one run per scenario, per-seed results and paired comparisons.

Systems (group priority in the repeat-group queue; S_rule and S_exp are constant
within a group because its members share host and rule):
  B0        S_rule (100 * level / 15)
  B0_rank   S_rule as the mid-rank percentile of the level among the host's baseline alerts
  B1        0.8 S_rule + 0.2 S_exp          (best static weights on the tuning set)
  B2        sequence term 100 min(1, pi(g)/8), entries N=20 delta=60 s   (tuned: w_r = w_c = 0)
  B2_def    0.3 S_rule + 0.2 S_exp + 0.5 * sequence term                 (former default weights)
  B2'       B2 with the forest replaced by a robust z-score
  B2_nov    B2 with the sequence term replaced by 100 * [any member's rule is novel for its entity]
  B2_alert  B2 with the window of the last 5 alerts
  B3        B2 + risk notables (Component 8) absorbing their contributing groups

Guard: test scenarios (fox, santos, wardbeck, wilson) are refused unless
--allow-test is given. The protocol is run on them once, after every choice is
fixed on the tuning set.

usage: ait_eval.py <zip> <labels.csv> <alerts_csv_dir> <wb_dir> <host_roles.json> <out.json>
                   --scenarios s1 [s2 ...] [--seeds 10] [--recorded] [--allow-test]
  --recorded   keep AIT-ADS's designed pre-attack exfiltration alerts in the baseline
               (default: oracle-cleaned, the tuning convention)
"""
import sys, os, json, zipfile, csv, collections, time, pickle, argparse, math
import numpy as np

ap = argparse.ArgumentParser()
for a in ("zip", "labels", "csv_dir", "wb_dir", "roles", "out"):
    ap.add_argument(a)
ap.add_argument("--scenarios", nargs="+", required=True)
ap.add_argument("--seeds", type=int, default=10)
ap.add_argument("--recorded", action="store_true")
ap.add_argument("--allow-test", action="store_true")
args = ap.parse_args()
TEST = {"fox", "santos", "wardbeck", "wilson"}
if TEST & set(args.scenarios) and not args.allow_test:
    sys.exit("refusing test scenarios without --allow-test")
sys.path.insert(0, args.wb_dir)
import window_builder as W
import seq_scoring as C6
import accumulator as C8
import eval_metrics as M

ROLES = json.load(open(args.roles))
LAMBDA_Q = 8.0
DELTA_Q = 3600.0
phases = collections.defaultdict(list)
for r in csv.DictReader(open(args.labels)):
    phases[r["scenario"]].append((r["attack"], float(r["start"]), float(r["end"])))


def load(sc):
    cache = f"evalcache_{sc}_{'rec' if args.recorded else 'clean'}_sid{int(W.SURICATA_SIGNATURE_IDENTITY)}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    lab = collections.defaultdict(list)
    for r in csv.DictReader(open(f"{args.csv_dir}/{sc}_alerts.txt")):
        nm = r["name"]
        if nm.startswith("Wazuh: "):
            nm = nm[7:]
        elif not nm.startswith("Suricata: "):
            continue
        lab[(int(r["time"]), r["ip"], nm)].append(r["event_label"])
    A, labels = [], []
    with zipfile.ZipFile(args.zip).open(f"{sc}_wazuh.json") as f:
        for i, line in enumerate(f):
            r = json.loads(line)
            if str(r.get("location", "")).endswith("suricata/fast.log"):
                continue
            try:
                a = W.parse_wazuh(r, i)
            except (KeyError, ValueError):
                continue
            key = (int(a.ts), r["agent"].get("ip"), r["rule"].get("description"))
            l = lab[key].pop() if lab.get(key) else "unmatched"
            a.label = 0 if l in M.BENIGN else 1
            a.agent_ip = r["agent"].get("ip")
            A.append(a); labels.append(l)
    order = sorted(range(len(A)), key=lambda j: (A[j].ts, A[j].ingest_seq))
    A = [A[j] for j in order]; labels = [labels[j] for j in order]
    t_atk = min(s for _, s, _ in phases[sc])
    if not args.recorded:
        keep = [j for j in range(len(A)) if not (A[j].ts < t_atk and labels[j] not in M.BENIGN)]
        A = [A[j] for j in keep]; labels = [labels[j] for j in keep]
    pickle.dump((A, labels, t_atk), open(cache, "wb"))
    return A, labels, t_atk


def build_windows(A, t_atk, N, delta):
    wb = W.WindowBuilder(N=N, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=delta)
    rows = collections.defaultdict(lambda: {"j": [], "ev": [], "F": [], "ok": []})
    for j, a in enumerate(A):
        if a.ts >= t_atk and wb.learn_rules:
            wb.learn_rules = False
        for e, f, ok in wb.push(a):
            d = rows[e[0]]
            d["j"].append(j); d["ev"].append(e[1]); d["F"].append(f); d["ok"].append(ok)
    return {k: {"j": np.array(v["j"]), "ev": np.array(v["ev"], dtype=object), "F": np.array(v["F"]),
                "ok": np.array(v["ok"])} for k, v in rows.items()}


def host_of(a):
    return next(v for t, v in a.entities if t == "host")


def score_types(rows, A, t_atk, model_cls, seed, entries):
    """{etype: S array aligned with rows[etype]} (-1 where unscoreable or no model)."""
    out = {}
    for et, d in rows.items():
        s = np.full(len(d["j"]), -1.0)
        ts = np.array([A[j].ts for j in d["j"]])
        hosts = [host_of(A[j]) for j in d["j"]]
        base = d["ok"] & (ts < t_atk)
        if base.sum() > 0 and d["ok"].sum() > 0:
            m = model_cls(seed)
            if m.fit(d["F"][base], [h for h, b in zip(hosts, base) if b], entries):
                okm = d["ok"]
                s[okm] = m.score(d["F"][okm], [h for h, o in zip(hosts, okm) if o], entries)
        out[et] = s
    return out


def alert_max(rows, S, n_alerts):
    mx = np.full(n_alerts, -1.0)
    for et, d in rows.items():
        np.maximum.at(mx, d["j"], S[et])
    return mx


def surprise(u, n):
    u = np.clip(u, 1e-12, 1 - 1e-5)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


def group_max(gid, G, v):
    o = np.full(G, -np.inf); np.maximum.at(o, gid, v); return o


def seq_term(gid, G, k, s_alert):
    s = np.where(s_alert < 0, 50.0, s_alert)          # cold start: baseline median
    return 100 * np.minimum(1, surprise(group_max(gid, G, s) / 100, k) / LAMBDA_Q)


def queue_metrics(prio, stages, ev_scores=None, labels=None):
    f = M.first_item_ranks(prio, stages)
    out = {"andcg10": M.alpha_ndcg(prio, stages, 10), "andcg20": M.alpha_ndcg(prio, stages, 20),
           "andcg50": M.alpha_ndcg(prio, stages, 50), "mrr": M.mrr_nonscan(f),
           "cov20": M.coverage(f, 20), "first": {s: float(v) for s, v in f.items()}, "items": len(prio)}
    if ev_scores is not None:
        out["macro_auc"] = M.macro_auc(ev_scores, labels)
    return out


RESULTS = json.load(open(args.out)) if os.path.exists(args.out) else {}
for sc in args.scenarios:
    t0 = time.time()
    A, labels, t_atk = load(sc)
    n = len(A)
    ev = np.array([j for j, a in enumerate(A) if a.ts >= t_atk and a.admissible])
    L = np.array([labels[j] for j in ev], dtype=object)
    # queue groups over the evaluation period: same host, same rule, gaps <= 1 h
    gid, last, cur, nxt = [], {}, {}, 0
    for j in ev:
        key = (host_of(A[j]), A[j].rule_id)
        if key not in last or A[j].ts - last[key] > DELTA_Q:
            cur[key] = nxt; nxt += 1
        last[key] = A[j].ts; gid.append(cur[key])
    gid = np.array(gid); G = nxt
    k = np.bincount(gid, minlength=G).astype(float)
    stages = M.item_stages(gid, L, G)
    gid_of = dict(zip(ev.tolist(), gid.tolist()))
    # static terms
    lvl = np.array([A[j].rule_level for j in ev], float)
    ip = [A[j].agent_ip for j in ev]
    s_rule = 100 * lvl / 15
    base_lv = collections.defaultdict(list)
    for a in A:
        if a.ts < t_atk and a.admissible:
            base_lv[a.agent_ip].append(a.rule_level)
    base_lv = {h: np.sort(v) for h, v in base_lv.items()}
    s_rank = np.empty(len(ev))
    for i, (h, l) in enumerate(zip(ip, lvl)):
        b = base_lv.get(h)
        s_rank[i] = s_rule[i] if b is None or not len(b) else \
            100 * (np.searchsorted(b, l, "left") + 0.5 * (np.searchsorted(b, l, "right") - np.searchsorted(b, l, "left"))) / len(b)
    s_exp = np.array([ROLES[sc][h]["s_exp"] for h in ip])
    g_rule, g_rank, g_exp = group_max(gid, G, s_rule), group_max(gid, G, s_rank), group_max(gid, G, s_exp)
    res = {"meta": {"alerts": n, "eval_admitted": int(len(ev)), "queue_items": int(G),
                    "baseline": "recorded" if args.recorded else "oracle-cleaned", "seeds": args.seeds}}
    det = {"B0": queue_metrics(g_rule, stages, s_rule, L), "B0_rank": queue_metrics(g_rank, stages, s_rank, L),
           "B1": queue_metrics(0.8 * g_rule + 0.2 * g_exp, stages, 0.8 * s_rule + 0.2 * s_exp, L)}
    res["deterministic"] = det
    # windows
    rows_e = build_windows(A, t_atk, 20, 60.0)
    rows_a = build_windows(A, t_atk, 5, None)
    res["meta"]["training_windows"] = {et: int((d["ok"] & (np.array([A[j].ts for j in d["j"]]) < t_atk)).sum() // C6.STRIDE)
                                       for et, d in rows_e.items()}
    evpos = np.full(n, -1); evpos[ev] = np.arange(len(ev))
    # novelty (deterministic): any entity's window flags the rule as novel
    nov = np.zeros(n)
    for et, d in rows_e.items():
        np.maximum.at(nov, d["j"], d["F"][:, W.FEATURE_NAMES.index("novel_rule_flag")])
    res["deterministic"]["B2_nov"] = queue_metrics(100 * group_max(gid, G, nov[ev]), stages, nov[ev], L)
    rz = score_types(rows_e, A, t_atk, C6.RobustZModel, 0, True)
    s_rz = alert_max(rows_e, rz, n)[ev]
    res["deterministic"]["B2'"] = queue_metrics(seq_term(gid, G, k, s_rz), stages, s_rz, L)
    # seeded systems
    per_seed = collections.defaultdict(list)
    for seed in range(args.seeds):
        Se = score_types(rows_e, A, t_atk, C6.TypeModel, seed, True)
        Sa = score_types(rows_a, A, t_atk, C6.TypeModel, seed, False)
        se_all = alert_max(rows_e, Se, n); se = se_all[ev]
        sa = alert_max(rows_a, Sa, n)[ev]
        b2 = seq_term(gid, G, k, se)
        per_seed["B2"].append(queue_metrics(b2, stages, se, L))
        per_seed["B2_def"].append(queue_metrics(0.3 * g_rule + 0.2 * g_exp + 0.5 * b2, stages, None))
        per_seed["B2_alert"].append(queue_metrics(seq_term(gid, G, k, sa), stages, sa, L))
        # ---- Component 8: one stream of (alert, entity) in time order, baseline and evaluation
        stream = []
        RUN = W.ENTRY_FEATURE_NAMES.index("current_run_length")
        for et, d in rows_e.items():
            for i in range(len(d["j"])):
                j = d["j"][i]; a = A[j]
                stream.append((a.ts, a.ingest_seq, et, d["ev"][i], j, Se[et][i], d["F"][i, RUN] == 1))
        stream.sort(key=lambda x: (x[0], x[1]))
        def gen():
            for ts, _, et, evv, j, s, opened in stream:
                a = A[j]
                yield {"ent": (et, evv), "etype": et, "t": ts, "rule": a.rule_id,
                       "s_rule": 100 * a.rule_level / 15,
                       "s_exp": ROLES[sc].get(a.agent_ip, {"s_exp": 0.0})["s_exp"],
                       "s_seq": s, "opened": bool(opened), "tactics": a.tactics,
                       "gid": gid_of.get(j), "baseline": ts < t_atk}
        R_base, _ = C8.run(gen(), 20)
        theta = C8.calibrate_theta(R_base)
        _, nbs = C8.run(gen(), 20, theta=theta)
        incidents = C8.merge_notables([nb for nb in nbs if nb["gids"]])
        sortedR = {et: np.sort(v) for et, v in R_base.items()}
        absorbed = set().union(*[inc["gids"] for inc in incidents]) if incidents else set()
        keep = np.array([g not in absorbed for g in range(G)])
        prio3 = list(b2[keep]); st3 = [stages[g] for g in range(G) if keep[g]]
        inc_info = []
        for inc in incidents:
            pct = max(100 * np.searchsorted(sortedR[et], inc["R_peak"], "right") / len(sortedR[et])
                      for et in inc["etypes"] if et in sortedR)
            sset = set().union(*[stages[g] for g in inc["gids"]])
            prio3.append(pct); st3.append(sset)
            inc_info.append({"t_open_h": (inc["t_open"] - t_atk) / 3600, "stages": sorted(sset),
                             "groups": len(inc["gids"]), "entities": len(inc["members"])})
        q3 = queue_metrics(np.array(prio3), st3)
        att = [x for x in inc_info if x["stages"]]
        q3["incidents"] = len(inc_info); q3["attack_incidents"] = len(att)
        q3["benign_incidents"] = len(inc_info) - len(att)
        q3["time_to_notable_h"] = min((x["t_open_h"] for x in att), default=None)
        q3["max_stages_in_incident"] = max((len([s for s in x["stages"]]) for x in att), default=0)
        q3["theta"] = theta
        per_seed["B3"].append(q3)
        print(f"  {sc} seed {seed}: B2 aNDCG@20 {per_seed['B2'][-1]['andcg20']:.3f} | B3 {q3['andcg20']:.3f} "
              f"incidents {q3['incidents']} (attack {q3['attack_incidents']}) ttn {q3['time_to_notable_h']}", flush=True)
    res["seeded"] = per_seed
    res["meta"]["seconds"] = round(time.time() - t0)
    RESULTS[sc] = res
    json.dump(RESULTS, open(args.out, "w"), indent=1, default=lambda o: sorted(o) if isinstance(o, set) else float(o))
    summ = {name: np.mean([r["andcg20"] for r in v]) for name, v in per_seed.items()}
    summ.update({name: v["andcg20"] for name, v in det.items()})
    print(f"=== {sc} ({res['meta']['seconds']}s): " + ", ".join(f"{k} {v:.3f}" for k, v in summ.items()), flush=True)
