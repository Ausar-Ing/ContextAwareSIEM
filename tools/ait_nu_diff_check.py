#!/usr/bin/env python3
"""Decides finding 2 of the code review (2026-11-03), on the TUNING scenarios only.

For each tuning scenario and condition (recorded, recorded without reconnaissance, oracle-cleaned) it
counts the queue groups whose novelty term nu(g) changes when host windows of fewer than 3 alerts may
also flag novelty (option 2), and lists the attack stages in those groups. It also prints, for the two
UNCLEAR items of the review, the attack step that sets t_atk and any event label without a grade.

It reproduces ait_eval.py at commit 84a6c4d (loading, host windows, queue groups) and fits no model, so
it needs no seed and takes a few minutes. It reads no test scenario. Not run by the reviewer.

usage, from the repository root:
    python3 tools/ait_nu_diff_check.py data/ait_ads/ait_ads.zip data/ait_ads/labels.csv data/ait_ads/alerts_csv

Written by the code reviewer (2026-11-03); committed unchanged apart from this path. Output of the run that
decided finding 2: provenance/ait/nu_diff_tuning.txt.
"""
import collections, csv, json, os, sys, zipfile
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import window_builder as W
import eval_metrics as M

TUNING = ("harrison", "russellmitchell", "shaw", "wheeler")
TEST = {"fox", "santos", "wardbeck", "wilson"}
assert not TEST & set(TUNING)
DELTA_Q = 86400.0                                   # seq_scoring.GROUP_GAP_S default
NOVEL = W.FEATURE_NAMES.index("novel_rule_flag")
zip_path, labels_path, csv_dir = sys.argv[1:4]

phases = collections.defaultdict(list)
for r in csv.DictReader(open(labels_path)):
    if r["scenario"] in TUNING:
        phases[r["scenario"]].append((float(r["start"]), r["attack"]))


def load(sc):
    """ait_eval.load() without the cache: (alerts in time order, event labels, t_atk)"""
    lab = collections.defaultdict(list)
    for r in csv.DictReader(open(f"{csv_dir}/{sc}_alerts.txt")):
        nm = r["name"]
        if nm.startswith("Wazuh: "):
            nm = nm[7:]
        elif not nm.startswith("Suricata: "):
            continue
        lab[(int(r["time"]), r["ip"], nm)].append(r["event_label"])
    A, labels = [], []
    with zipfile.ZipFile(zip_path).open(f"{sc}_wazuh.json") as f:
        for i, line in enumerate(f):
            r = json.loads(line)
            if str(r.get("location", "")).endswith("suricata/fast.log"):
                continue
            try:
                a = W.parse_wazuh(r, i)
            except (KeyError, ValueError):
                continue
            key = (int(a.ts), r["agent"].get("ip"), r["rule"].get("description"))
            labels.append(lab[key].pop() if lab.get(key) else "unmatched")
            A.append(a)
    order = sorted(range(len(A)), key=lambda j: (A[j].ts, A[j].ingest_seq))
    return [A[j] for j in order], [labels[j] for j in order], min(s for s, _ in phases[sc])


def host_of(a):
    return next(v for t, v in a.entities if t == "host")


def compare(A, labels, t_atk):
    """queue groups whose nu(g) differs between scoreable-only host windows (the code) and every host window"""
    wb = W.WindowBuilder(N=20, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
    nov_ok, nov_any = np.zeros(len(A)), np.zeros(len(A))
    for j, a in enumerate(A):
        if a.ts >= t_atk and wb.learn_rules:
            wb.learn_rules = False
        for e, f, ok in wb.push(a):
            if e[0] == "host":
                nov_any[j] = max(nov_any[j], f[NOVEL])
                if ok:
                    nov_ok[j] = max(nov_ok[j], f[NOVEL])
    ev = [j for j, a in enumerate(A) if a.ts >= t_atk and a.admissible]
    gid, last, cur, nxt = [], {}, {}, 0
    for j in ev:
        key = (host_of(A[j]), A[j].rule_id)
        if key not in last or A[j].ts - last[key] > DELTA_Q:
            cur[key] = nxt; nxt += 1
        last[key] = A[j].ts; gid.append(cur[key])
    gid = np.array(gid)
    g_ok, g_any = np.zeros(nxt), np.zeros(nxt)
    np.maximum.at(g_ok, gid, nov_ok[ev]); np.maximum.at(g_any, gid, nov_any[ev])
    stages = M.item_stages(gid, [labels[j] for j in ev], nxt)
    size = np.bincount(gid, minlength=nxt)
    return nxt, [(g, int(size[g]), sorted(stages[g])) for g in np.flatnonzero(g_ok != g_any)]


total = 0
for sc in TUNING:
    A0, L0, t_atk = load(sc)
    first = min(phases[sc])[1]
    ungraded = sorted(set(L0) - M.BENIGN - set(M.GRADES))
    print(f"{sc}: t_atk set by '{first}'{'  <-- CHECK: exfiltration should not set the split' if first == 'dnsteal' else ''}; "
          f"unmatched {sum(l == 'unmatched' for l in L0)}; labels without a grade: {', '.join(ungraded) or 'none'}")
    for cond in ("recorded", "recorded, no reconnaissance", "oracle-cleaned"):
        keep = range(len(A0))
        if cond == "oracle-cleaned":
            keep = [j for j in keep if not (A0[j].ts < t_atk and L0[j] not in M.BENIGN)]
        if cond == "recorded, no reconnaissance":
            keep = [j for j in keep if L0[j] not in M.SCANS]
        A = [A0[j] for j in keep]; L = [L0[j] for j in keep]
        G, diff = compare(A, L, t_atk)
        total += len(diff)
        attack = [d for d in diff if d[2]]
        print(f"  {cond:28s} {G:4d} queue groups; nu(g) differs on {len(diff)} ({len(attack)} holding attack stages)")
        for g, k, st in attack:
            print(f"      group {g}: {k} alerts, stages {', '.join(st)}")
print(f"\n{'No group changes: option 2 moves no tuning number.' if total == 0 else 'Some groups change: see the guide, finding 2.'}")
