#!/usr/bin/env python3
"""Window-definition sweep on the AIT-ADS TUNING scenarios only.

Compares the D2 alert window (last N alerts within T) with entry windows (last N
collapsed runs within T, runs split at gaps > delta) at several N. Component 6
as specified (seq_scoring.py): per-entity-type forest, psi = min(4096, n),
stride 10, per-host calibration on HELD-OUT baseline windows with type-level
fallback, S_seq = max over entities. Each seed is an independent replica;
metrics are computed per seed and reported as mean and sd (SEEDS, default 5). The baseline is oracle-cleaned (CLEAN semantics of ait_smoke.py) so
AIT-ADS's designed exfiltration contamination does not decide the comparison.

The held-out scenarios (fox, santos, wardbeck, wilson) are NOT read here.

usage: ait_sweep.py <ait_ads.zip> <labels.csv> <alerts_csv_dir> <window_builder_dir> <out.json> <scenario> [...]
"""
import sys, os, json, zipfile, csv, collections, time, pickle
import numpy as np

zip_path, labels_path, csv_dir, wb_dir, out_path = sys.argv[1:6]
scenarios = sys.argv[6:]
HELD_OUT = {"fox", "santos", "wardbeck", "wilson"}
assert not HELD_OUT & set(scenarios), "held-out scenarios must not be used for selection"
sys.path.insert(0, wb_dir)
import window_builder as W
import seq_scoring as C6

SEEDS = int(os.environ.get("SEEDS", "5"))
SCANS = {"dirb", "wpscan", "service_scan"}
CONFIGS = [("alert", n, None) for n in (5, 10, 20, 40)] + \
          [("entry", n, d) for d in (60, 300, 900) for n in (5, 10, 20, 40)]
if os.environ.get("CONFIGS"):
    keep = set(os.environ["CONFIGS"].split(","))
    CONFIGS = [c for c in CONFIGS if f"{c[0]}{c[1]}" + (f"d{c[2]}" if c[2] else "") in keep]

phases = collections.defaultdict(list)
for r in csv.DictReader(open(labels_path)):
    phases[r["scenario"]].append((r["attack"], float(r["start"]), float(r["end"])))


def ranks_desc(x):
    order = np.argsort(-x, kind="mergesort")
    r = np.empty(len(x)); r[order] = np.arange(1, len(x) + 1)
    _, inv, cnt = np.unique(-x, return_inverse=True, return_counts=True)
    return (np.bincount(inv, weights=r) / cnt)[inv]


def auc(pos, neg):
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    allv = np.concatenate([pos, neg]); r = ranks_desc(-allv)
    return (r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def load(sc):
    cache = f"cache_{sc}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
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
            l = lab[key].pop() if lab.get(key) else "unmatched"
            a.label = 0 if l in ("-", "unmatched") else 1
            A.append(a); labels.append(l)
    order = sorted(range(len(A)), key=lambda j: (A[j].ts, A[j].ingest_seq))
    A = [A[j] for j in order]; labels = [labels[j] for j in order]
    t_atk = min(s for _, s, _ in phases[sc])
    keep = [j for j in range(len(A)) if not (A[j].ts < t_atk and labels[j] not in ("-", "unmatched"))]
    A = [A[j] for j in keep]; labels = [labels[j] for j in keep]
    pickle.dump((A, labels, t_atk), open(cache, "wb"))
    return A, labels, t_atk


RESULTS = json.load(open(out_path)) if os.path.exists(out_path) else {}
for sc in scenarios:
    A, labels, t_atk = load(sc)
    ev = [j for j, a in enumerate(A) if a.ts >= t_atk and a.admissible]
    L = [labels[j] for j in ev]
    y = np.array([A[j].label for j in ev])
    deep = np.array([l not in SCANS and l not in ("-", "unmatched") for l in L])
    ben = y == 0
    stages = sorted({l for l in L if l not in ("-", "unmatched")})
    lvl = np.array([A[j].rule_level for j in ev], float)
    # grouped queue items (host, rule, gap <= 1 h): fixed across configs
    host_of = [next((v for t, v in A[j].entities if t == "host"), None) for j in ev]
    gid, last, cur, nxt = [], {}, {}, 0
    for k, j in enumerate(ev):
        key = (host_of[k], A[j].rule_id)
        if key not in last or A[j].ts - last[key] > 3600:
            cur[key] = nxt; nxt += 1
        last[key] = A[j].ts; gid.append(cur[key])
    gid = np.array(gid); G = nxt
    stage_items = {st: np.unique(gid[[i for i, l in enumerate(L) if l == st]]) for st in stages}
    for mode, N, delta in CONFIGS:
        name = f"{mode}{N}" + (f"d{delta}" if delta else "")
        if RESULTS.get(sc, {}).get(name):
            continue
        t0 = time.time()
        wb = W.WindowBuilder(N=N, learn_rules=True, downtime_gap_s=None,
                             site_utc_offset_h=0.0, collapse_s=delta)
        rows = []
        for j, a in enumerate(A):
            if a.ts >= t_atk and wb.learn_rules:
                wb.learn_rules = False
            for e, f, ok in wb.push(a):
                rows.append((j, e[0], f, ok))
        # redundancy: share of scoreable baseline HOST windows holding one rule only
        hb = np.array([r[2] for r in rows if r[1] == "host" and r[3] and A[r[0]].ts < t_atk])
        single_rule = float((hb[:, 2] == 1).mean()) if len(hb) else float("nan")
        ent_mode = delta is not None
        host_j = lambda j: next((v for t, v in A[j].entities if t == "host"), None)
        types = sorted({r[1] for r in rows})
        by_type = {}
        for et in types:
            base = [r for r in rows if r[1] == et and r[3] and A[r[0]].ts < t_atk]
            evalr = [r for r in rows if r[1] == et and r[3] and A[r[0]].ts >= t_atk]
            if base and evalr:
                by_type[et] = (np.array([r[2] for r in base]), [host_j(r[0]) for r in base],
                               np.array([r[2] for r in evalr]), [host_j(r[0]) for r in evalr],
                               [r[0] for r in evalr])
        evpos = {j: i for i, j in enumerate(ev)}
        per_seed = []
        for seed in range(SEEDS):
            sseq = np.full(len(ev), -1.0)
            for et, (Fb, hb, Fe, he, je) in by_type.items():
                m = C6.TypeModel(seed)
                if not m.fit(Fb, hb, ent_mode):
                    continue
                for j, v in zip(je, m.score(Fe, he, ent_mode)):
                    k = evpos.get(j)
                    if k is not None and v > sseq[k]:
                        sseq[k] = v
            sseq[sseq < 0] = 50.0          # cold start / no forest: baseline median
            per_seed.append(sseq)
        res = {"single_rule_host_windows": round(single_rule, 3), "seeds": SEEDS}
        for sysname, f in (("S_seq", lambda x: x), ("hybrid", lambda x: 0.3 * lvl * 100 / 15 + 0.5 * x)):
            aucs, c20, c50, firsts = [], [], [], []
            for sseq in per_seed:
                s_ = f(sseq)
                gs = np.full(G, -1e9); np.maximum.at(gs, gid, s_)
                gr = ranks_desc(gs)
                first = {st: int(min(gr[stage_items[st]])) for st in stages}
                aucs.append(auc(s_[deep], s_[ben])); firsts.append(first)
                c20.append(sum(v <= 20 for v in first.values())); c50.append(sum(v <= 50 for v in first.values()))
            res[sysname] = {
                "auc_nonscan": round(float(np.mean(aucs)), 4), "auc_sd": round(float(np.std(aucs)), 4),
                "auc_per_seed": [round(a, 4) for a in aucs],
                "grouped_top20": round(float(np.mean(c20)), 2), "grouped_top20_per_seed": c20,
                "grouped_top50": round(float(np.mean(c50)), 2),
                "n_stages": len(stages), "first_item_per_seed": firsts,
                "median_first_item": float(np.median([np.median(list(fi.values())) for fi in firsts])),
            }
        res["seconds"] = round(time.time() - t0)
        RESULTS.setdefault(sc, {})[name] = res
        json.dump(RESULTS, open(out_path, "w"), indent=1)
        print(f"{sc:16s} {name:10s} single-rule {single_rule:.2f} | S_seq AUC {res['S_seq']['auc_nonscan']:.3f}±{res['S_seq']['auc_sd']:.3f} "
              f"top20 {res['S_seq']['grouped_top20']}/{len(stages)} med-first {res['S_seq']['median_first_item']:.0f} | "
              f"hybrid AUC {res['hybrid']['auc_nonscan']:.3f} top20 {res['hybrid']['grouped_top20']} | {res['seconds']}s",
              flush=True)
