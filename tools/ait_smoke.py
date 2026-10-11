#!/usr/bin/env python3
"""Smoke test of the pipeline design on AIT-ADS: does the time-window + Isolation
Forest design separate attack activity from benign on public labelled data?

Not the evaluation. One run, one seed set, no tuning. Purpose: check the design
transfers before writing the specification.

usage: ait_smoke.py <ait_ads.zip> <labels.csv> <alerts_csv_dir> <window_builder_dir> <scenario> [...]
"""
import sys, os, json, zipfile, csv, collections, math, time
import numpy as np

zip_path, labels_path, csv_dir, wb_dir = sys.argv[1:5]
scenarios = sys.argv[5:]
sys.path.insert(0, wb_dir)
import window_builder as W
from sklearn.ensemble import IsolationForest

FI = {n: i for i, n in enumerate(W.FEATURE_NAMES)}
MODEL_IDX = [i for n, i in FI.items() if n != "night_fraction"]
STRIDE, N_TREES, PSI = 10, 200, 4096
SCANS = {"dirb", "wpscan", "service_scan"}

phases = collections.defaultdict(list)
for r in csv.DictReader(open(labels_path)):
    phases[r["scenario"]].append((r["attack"], float(r["start"]), float(r["end"])))


def ranks_desc(x):
    """Average rank (1 = top) with ties shared, for discrete scores like rule level."""
    order = np.argsort(-x, kind="mergesort")
    r = np.empty(len(x)); r[order] = np.arange(1, len(x) + 1)
    # average ties
    _, inv, cnt = np.unique(-x, return_inverse=True, return_counts=True)
    sums = np.bincount(inv, weights=r)
    return (sums / cnt)[inv]


def auc(pos, neg):
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    allv = np.concatenate([pos, neg]); r = ranks_desc(-allv)  # ascending ranks
    return (r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


SUMMARY = []
for sc in scenarios:
    t_start = time.time()
    # ---- per-alert labels from the AIT CSV: key (second, agent ip, description)
    lab = collections.defaultdict(list)
    for r in csv.DictReader(open(f"{csv_dir}/{sc}_alerts.txt")):
        nm = r["name"]
        if nm.startswith("Wazuh: "):
            nm = nm[7:]               # Wazuh rules carry the prefix in the label file
        elif not nm.startswith("Suricata: "):
            continue                  # AMiner: a different detector, not in the Wazuh stream
        lab[(int(r["time"]), r["ip"], nm)].append(r["event_label"])   # causal label, not the time window
    # ---- parse
    z = zipfile.ZipFile(zip_path)
    A, labels, dup_fast = [], [], 0
    with z.open(f"{sc}_wazuh.json") as f:
        for i, line in enumerate(f):
            r = json.loads(line)
            if str(r.get("location", "")).endswith("suricata/fast.log"):
                dup_fast += 1          # same Suricata alert as eve.json: drop the copy
                continue
            try:
                a = W.parse_wazuh(r, i)
            except (KeyError, ValueError):
                continue
            key = (int(a.ts), r["agent"].get("ip"), r["rule"].get("description"))
            l = lab[key].pop() if lab.get(key) else "unmatched"
            a.label = 0 if l in ("-", "unmatched") else 1
            A.append(a); labels.append(l)
    order = sorted(range(len(A)), key=lambda j: (A[j].ts, A[j].ingest_seq))
    A = [A[j] for j in order]; labels = [labels[j] for j in order]
    t_atk = min(s for _, s, _ in phases[sc])
    # CLEAN=1: oracle-cleaned baseline. Drop event-labelled attack alerts that occur
    # before the first attack step (AIT-ADS runs its exfiltration from the start of
    # every simulation by design), so the forest, the calibration table and the
    # novelty set all learn from a clean baseline. The evaluation period is untouched.
    n_removed = 0
    if os.environ.get("CLEAN") == "1":
        keep = [j for j in range(len(A)) if not (A[j].ts < t_atk and labels[j] not in ("-", "unmatched"))]
        n_removed = len(A) - len(keep)
        A = [A[j] for j in keep]; labels = [labels[j] for j in keep]
        print(f"  [CLEAN] removed {n_removed} labelled attack alerts from the pre-attack baseline")
    lab_ct = collections.Counter(labels)
    print(f"\n=== {sc}: {len(A)} alerts (dropped {dup_fast} fast.log duplicates); "
          f"labels matched: {sum(v for k, v in lab_ct.items() if k != 'unmatched')}, unmatched {lab_ct['unmatched']}")
    # ---- windows: correction off (servers are always on); learn novelty on baseline only
    wb = W.WindowBuilder(learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0)
    rows = []   # (alert_idx, etype, feats, scoreable)
    for j, a in enumerate(A):
        if a.ts >= t_atk and wb.learn_rules:
            wb.learn_rules = False      # freeze baseline rule set at the attack start
        for e, f, ok in wb.push(a):
            rows.append((j, e[0], f, ok))
    ent_ct = collections.Counter(e for a in A if a.admissible for e, _ in a.entities)
    n_adm = sum(a.admissible for a in A)
    print("  entity resolution:", {k: f"{100*v/n_adm:.1f}%" for k, v in ent_ct.items()})
    # ---- train one forest per entity type on baseline windows (stride 10), percentile-calibrate
    S = collections.defaultdict(dict)    # alert idx -> {etype: S_seq}
    for et in sorted({r[1] for r in rows}):
        base = [r for r in rows if r[1] == et and r[3] and A[r[0]].ts < t_atk]
        evalr = [r for r in rows if r[1] == et and r[3] and A[r[0]].ts >= t_atk]
        if len(base) < 200 or not evalr:
            print(f"  {et}: {len(base)} baseline windows — too few, skipped"); continue
        Xb = W.log_transform(np.array([r[2] for r in base]))[:, MODEL_IDX][::STRIDE]
        Xe = W.log_transform(np.array([r[2] for r in evalr]))[:, MODEL_IDX]
        const = [W.FEATURE_NAMES[MODEL_IDX[k]] for k in range(Xb.shape[1]) if Xb[:, k].std() < 1e-12]
        sc_all = []
        for seed in range(3):
            m = IsolationForest(n_estimators=N_TREES, max_samples=min(PSI, len(Xb)), random_state=seed).fit(Xb)
            raw_b = -m.score_samples(Xb); raw_e = -m.score_samples(Xe)
            sc_all.append(100 * np.searchsorted(np.sort(raw_b), raw_e, side="right") / len(raw_b))
        s_e = np.mean(sc_all, axis=0)
        for (j, _, _, _), v in zip(evalr, s_e):
            S[j][et] = max(S[j].get(et, 0), v)
        print(f"  {et}: baseline windows {len(base)} (training pool {len(Xb)}), eval windows {len(evalr)}, constant on baseline: {const or 'none'}")
    # ---- rank the evaluation period's admitted alerts
    ev = [j for j, a in enumerate(A) if a.ts >= t_atk and a.admissible]
    lvl = np.array([A[j].rule_level for j in ev], float)
    sseq = np.array([max(S[j].values()) if S[j] else 50.0 for j in ev])
    y = np.array([A[j].label for j in ev]); L = [labels[j] for j in ev]
    # novelty comparator: 1 if any of the alert's entities never fired this rule in
    # the baseline, ties broken by rule level. If this matches S_seq, the forest
    # is not earning its place.
    novmap = collections.defaultdict(float)
    for (jj, _, f, ok) in rows:
        novmap[jj] = max(novmap[jj], f[FI["novel_rule_flag"]])
    nov = np.array([novmap[j] for j in ev]) * 100 + lvl
    systems = {"B0 rule level": lvl * 100 / 15, "novelty only": nov, "S_seq only": sseq,
               "hybrid (0.3 rule + 0.5 seq)": 0.3 * lvl * 100 / 15 + 0.5 * sseq}
    deep = np.array([l not in SCANS and l not in ("-", "unmatched") for l in L])
    ben = y == 0
    print(f"  evaluation period: {len(ev)} admitted alerts, attack {int(y.sum())}, of which non-scan {int(deep.sum())}")
    stages = sorted({l for l in L if l not in ("-", "unmatched")})
    for name, s in systems.items():
        r = ranks_desc(s)
        a_all = auc(s[y == 1], s[ben]); a_deep = auc(s[deep], s[ben])
        first = {st: int(min(r[[i for i, l in enumerate(L) if l == st]])) for st in stages}
        cov100 = sum(1 for st in stages if first[st] <= 100)
        per = {st: auc(s[np.array([l == st for l in L])], s[ben]) for st in stages if st not in SCANS}
        print(f"  {name:28s} per-stage AUC: " + ", ".join(f"{k[:14]} {v:.3f}" for k, v in per.items()))
        print(f"  {name:28s} AUC non-scan {a_deep:.3f} | stages top-100 {cov100}/{len(stages)} | first rank: " + ", ".join(f"{k[:12]} {v}" for k, v in first.items()))
        SUMMARY.append((sc, name, a_deep, cov100, len(stages), first))
    # ---- grouped queue: one item per repeat group = same host, same rule, no gap > 1 h.
    # Item score = max member score; item label = any member labelled. Measures whether
    # collapsing floods into single queue items fixes the burial of post-scan stages.
    host_of = [next((v for t, v in A[j].entities if t == "host"), None) for j in ev]
    gid, last, cur = [], {}, {}
    for k, j in enumerate(ev):
        key = (host_of[k], A[j].rule_id)
        if key not in last or A[j].ts - last[key] > 3600:
            cur[key] = len(cur) + sum(1 for _ in ()) if False else (max(cur.values()) + 1 if cur else 0)
        last[key] = A[j].ts; gid.append(cur[key])
    gid = np.array(gid); G = gid.max() + 1
    print(f"  grouped queue: {len(ev)} alerts -> {G} queue items")
    for name, s in systems.items():
        gs = np.full(G, -1e9); np.maximum.at(gs, gid, s)
        r = ranks_desc(gs)
        first = {}
        for st in stages:
            gl = np.unique(gid[[i for i, l in enumerate(L) if l == st]])
            first[st] = int(min(r[gl]))
        cov = sum(1 for v in first.values() if v <= 20)
        print(f"  [grouped] {name:26s} stages in top-20 items {cov}/{len(stages)} | first item rank: " + ", ".join(f"{k[:12]} {v}" for k, v in first.items()))
        SUMMARY.append((sc, "[grouped] " + name, None, cov, len(stages), first))
    print(f"  ({time.time()-t_start:.0f}s)")

import pickle; pickle.dump(SUMMARY, open(f"summary_{'_'.join(scenarios)}{'_clean' if os.environ.get('CLEAN') == '1' else ''}.pkl", "wb"))
