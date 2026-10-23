#!/usr/bin/env python3
"""Small analyses behind numbers quoted in Deliverable 3 that are not printed
directly by the main scripts. Each subcommand reproduces one claim.

  calib-synthetic
      Sec. III-E: calibration on training windows vs held-out windows, on
      synthetic heavy-tailed data. Prints the share of unseen benign vectors
      above the 95th / 99th percentile under each (6 repetitions, psi 4096).
      Quoted: 5.2% vs 5.0% above the 95th, about twice the seed variance.

  sweep-ranks <window_sweep.json>
      Table VII rank columns and the sweep paragraph: per configuration, the
      mean and worst first queue item of the non-scan stages (per seed, then
      averaged), MRR, and non-scan stages in the top 10 per run.

  step-coverage <ait_stats.json> <labels.csv> <alerts_csv_dir>
      Sec. IV-A "What reaches the layer": for each of the ten attack steps, in
      how many scenarios it raised a Wazuh or Suricata alert after admission,
      and which detectors label it at all in the authors' CSVs (AMiner too).

  host-rarity <wb_dir> <scenario> [...]
      The host-rarity ranking (2026-10-23): queue groups ranked only by how
      rarely their host alerted in the baseline, no temporal context at all.
      Needs evalcache_<scenario>_clean_sid1.pkl from ait_eval.py in the
      current directory. Tuning scenarios only.

usage: ait_analyses.py <subcommand> [args]
"""
import sys, json, csv, glob, collections, os
import numpy as np

SCANS = {"dirb", "wpscan", "service_scan"}


def calib_synthetic():
    from sklearn.ensemble import IsolationForest
    res = {"training-window calibration": [], "held-out calibration": []}
    for rep in range(6):
        rng = np.random.default_rng(rep)
        X = rng.standard_t(3, size=(60000, 14)); Xn = rng.standard_t(3, size=(40000, 14))
        tr = np.arange(len(X)) % 10 == 0
        f = IsolationForest(n_estimators=200, max_samples=4096, random_state=rep).fit(X[tr])
        rt = np.sort(-f.score_samples(X[tr])); rh = np.sort(-f.score_samples(X[~tr])); rn = -f.score_samples(Xn)
        for name, ref in (("training-window calibration", rt), ("held-out calibration", rh)):
            S = 100 * np.searchsorted(ref, rn, side="right") / len(ref)
            res[name].append((S.mean(), (S > 95).mean() * 100, (S > 99).mean() * 100))
    for name, v in res.items():
        v = np.array(v)
        print(f"{name:28s} mean S {v[:,0].mean():.2f}  >95th {v[:,1].mean():.2f}% (sd {v[:,1].std():.2f})  "
              f">99th {v[:,2].mean():.2f}% (sd {v[:,2].std():.2f})")


def sweep_ranks(path):
    R = json.load(open(path))
    scs = [s for s in R if not s.startswith("_")]
    cfgs = [c for c in R[scs[0]] if not c.startswith("_")]
    order = sorted(cfgs, key=lambda c: (not c.startswith("alert"), int(''.join(ch for ch in c.split('d')[0] if ch.isdigit())),
                                         c))
    print(f"{'config':12s} {'meanRank':>9s} {'worstRank':>10s} {'MRR':>6s} {'nonscan@10':>11s}   (S_seq only, per seed then averaged)")
    for c in order:
        seeds = len(R[scs[0]][c]["S_seq"]["first_item_per_seed"])
        mean_r, worst, mrr, ns10 = [], [], [], []
        for si in range(seeds):
            ranks = [v for sc in scs for st, v in R[sc][c]["S_seq"]["first_item_per_seed"][si].items() if st not in SCANS]
            mean_r.append(np.mean(ranks)); worst.append(max(ranks)); mrr.append(np.mean([1 / v for v in ranks]))
            ns10.append(sum(v <= 10 for v in ranks))
        print(f"{c:12s} {np.mean(mean_r):9.1f} {np.mean(worst):10.1f} {np.mean(mrr):6.3f} {np.mean(ns10):11.1f}")


def step_coverage(stats_path, labels_path, csv_dir):
    stats = json.load(open(stats_path))
    steps = collections.OrderedDict()
    for r in csv.DictReader(open(labels_path)):
        steps.setdefault(r["attack"], set()).add(r["scenario"])
    # attack steps (labels.csv) -> event labels (alerts CSV) they can produce
    step_labels = {"network_scans": [], "service_scans": ["service_scan"], "dirb": ["dirb"], "wpscan": ["wpscan"],
                   "webshell": ["webshell_cmd"], "cracking": ["online_cracking", "crack_passwords"],
                   "reverse_shell": [], "privilege_escalation": ["attacker_change_user", "escalated_sudo_command"],
                   "service_stop": [], "dnsteal": ["dnsteal"]}
    by_det = collections.defaultdict(collections.Counter)
    for f in sorted(glob.glob(os.path.join(csv_dir, "*_alerts.txt"))):
        for r in csv.DictReader(open(f)):
            if r["event_label"] == "-":
                continue
            det = "AMiner" if r["name"].startswith("AMiner") else ("Suricata" if r["name"].startswith("Suricata") else "Wazuh")
            by_det[r["event_label"]][det] += 1
    print(f"{'attack step':22s} {'in scen.':>8s} {'Wazuh/Suricata-alerted (admitted)':>34s}   detectors labelling it at all")
    for st, scs in steps.items():
        labs = step_labels.get(st, [])
        hit = [s for s in stats if any(stats[s]["stages"].get(l, 0) > 0 for l in labs)]
        dets = {l: dict(by_det.get(l, {})) for l in labs} or "no event label in any detector"
        print(f"{st:22s} {len(scs):8d} {len(hit):34d}   {dets}")


def host_rarity(wb_dir, scenarios):
    import pickle
    sys.path.insert(0, wb_dir)
    import eval_metrics as M
    assert not set(scenarios) & {"fox", "santos", "wardbeck", "wilson"}, "tuning scenarios only"
    res = []
    for sc in scenarios:
        A, L, t = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
        host = lambda a: next(v for k, v in a.entities if k == "host")
        base = collections.Counter(host(a) for a in A if a.ts < t and a.admissible)
        ev = [j for j, a in enumerate(A) if a.ts >= t and a.admissible]
        Lv = np.array([L[j] for j in ev], dtype=object)
        gid, last, cur, nxt = [], {}, {}, 0
        for j in ev:
            key = (host(A[j]), A[j].rule_id)
            if key not in last or A[j].ts - last[key] > 3600:
                cur[key] = nxt; nxt += 1
            last[key] = A[j].ts; gid.append(cur[key])
        gid = np.array(gid); G = nxt; st = M.item_stages(gid, Lv, G)
        gh = np.empty(G, dtype=object)
        for i, j in enumerate(ev):
            gh[gid[i]] = host(A[j])
        tot = sum(base.values())
        prio = np.array([100 * (1 - base.get(h, 0) / tot) for h in gh])
        f = M.first_item_ranks(prio, st)
        r = (M.alpha_ndcg(prio, st, 20), M.mrr_nonscan(f)); res.append(r)
        print(f"{sc:16s} host rarity: aNDCG@20 {r[0]:.3f}  MRR {r[1]:.3f}")
    print(f"mean             aNDCG@20 {np.mean([r[0] for r in res]):.3f}  MRR {np.mean([r[1] for r in res]):.3f}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "calib-synthetic":
        calib_synthetic()
    elif cmd == "sweep-ranks":
        sweep_ranks(sys.argv[2])
    elif cmd == "host-rarity":
        host_rarity(sys.argv[2], sys.argv[3:])
    elif cmd == "step-coverage":
        step_coverage(*sys.argv[2:5])
    else:
        print(__doc__); sys.exit(1)
