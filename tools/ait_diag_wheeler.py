#!/usr/bin/env python3
"""Why do wheeler's privilege-escalation windows look ordinary for the intranet
server once it is calibrated against its own baseline? Tuning scenario only.

For the intranet server's HOST windows: the baseline distribution of each model
feature, the attack windows' feature values and their percentile within that
baseline, per-feature attribution (replace the feature by its baseline median,
report the change in the raw score), the windows' contents, and how many benign
evaluation windows of the same host outscore them.

usage: ait_diag_wheeler.py <host_roles.json> <wb_dir> [scenario=wheeler] [min_host_cal=100]
"""
import sys, json, pickle, collections, datetime as dt
import numpy as np

roles_path, wb_dir = sys.argv[1:3]
sc = sys.argv[3] if len(sys.argv) > 3 else "wheeler"
mincal = int(sys.argv[4]) if len(sys.argv) > 4 else 100
assert sc not in {"fox", "santos", "wardbeck", "wilson"}, "tuning scenarios only"
sys.path.insert(0, wb_dir)
import window_builder as W
import seq_scoring as C6

ROLES = json.load(open(roles_path))
ATTACK = {"attacker_change_user", "escalated_sudo_command"}
A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
host_of = lambda a: next(v for t, v in a.entities if t == "host")
ip_of = {host_of(a): a.agent_ip for a in A}
target = next(h for h, ip in ip_of.items() if ROLES[sc][ip]["role"] == "intranet_server")

wb = W.WindowBuilder(N=20, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
rows = []                                       # host-entity windows only
for j, a in enumerate(A):
    if a.ts >= t_atk and wb.learn_rules:
        wb.learn_rules = False
    for e, f, ok in wb.push(a):
        if e[0] == "host" and ok:
            rows.append((j, e[1], f, [x.rule_id for x in wb.win[e]], [x.count for x in wb.win[e]]))
j_arr = np.array([r[0] for r in rows]); hosts = np.array([r[1] for r in rows], dtype=object)
F = np.array([r[2] for r in rows]); ts = np.array([A[j].ts for j in j_arr])
base = ts < t_atk
m = C6.TypeModel(0, stratify=True, min_host_cal=mincal)
m.fit(F[base], list(hosts[base]), True)
names = [n for n in W.ENTRY_FEATURE_NAMES if n != "night_fraction"]
X = m.prep(F, True)
raw = -m.forest.score_samples(X)
own = m.cal_host.get(target)
pct_own = (100 * np.searchsorted(own, raw, side="right") / len(own)) if own is not None else None
pct_pool = 100 * np.searchsorted(m.cal_type, raw, side="right") / len(m.cal_type)

is_t = hosts == target
tb = is_t & base
lab = np.array([labels[j] for j in j_arr], dtype=object)
att = is_t & ~base & np.isin(lab, list(ATTACK))
ben_eval = is_t & ~base & np.isin(lab, ["-", "unmatched"])
print(f"{sc}: intranet server = host {target}; baseline windows {tb.sum()}, held-out for calibration "
      f"{m.cal_source[target][1]} ({m.cal_source[target][0]}), training {m.train_share.get(target, 0)} of {m.n_train}")
print(f"evaluation windows on it: {att.sum()} attack (privilege escalation), {ben_eval.sum()} benign\n")

print("feature                    baseline median [p10, p90]      attack windows (values; percentile in baseline)")
Xb = X[tb]
for k, n in enumerate(names):
    med, p10, p90 = np.median(Xb[:, k]), np.percentile(Xb[:, k], 10), np.percentile(Xb[:, k], 90)
    vals = X[att, k]
    pcts = [100 * np.mean(Xb[:, k] <= v) for v in vals]
    print(f"  {n:24s} {med:7.2f} [{p10:6.2f}, {p90:6.2f}]   " +
          ", ".join(f"{v:.2f} ({p:.0f})" for v, p in zip(vals[:6], pcts[:6])) + (" ..." if len(vals) > 6 else ""))

print("\nattack windows: raw score, percentile vs own baseline / vs pooled, benign eval windows of this host scoring higher")
order = np.argsort(ts[att])
idx = np.flatnonzero(att)[order]
for i in idx:
    a = A[j_arr[i]]
    higher = int((raw[ben_eval] > raw[i]).sum())
    print(f"  {dt.datetime.utcfromtimestamp(a.ts):%m-%d %H:%M:%S} rule {a.rule_id:>6s} lvl {a.rule_level} [{lab[i]}] "
          f"raw {raw[i]:.3f} | own {pct_own[i] if pct_own is not None else float('nan'):5.1f} pooled {pct_pool[i]:5.1f} | "
          f"benign eval windows above: {higher}/{ben_eval.sum()}")
    print(f"      window rules (oldest->newest): {rows[i][3]}  counts {rows[i][4]}")

print("\nattribution for the attack windows (mean change in raw score when the feature is set to the baseline median;"
      " positive = the feature made the window MORE anomalous)")
med_vec = np.median(Xb, axis=0)
contrib = np.zeros(len(names))
for i in idx:
    for k in range(len(names)):
        x2 = X[i].copy(); x2[k] = med_vec[k]
        contrib[k] += raw[i] - (-m.forest.score_samples(x2[None, :])[0])
contrib /= max(1, len(idx))
for k in np.argsort(-np.abs(contrib)):
    print(f"  {names[k]:24s} {contrib[k]:+.4f}")

print("\nthe intranet server's held-out baseline windows with the highest raw scores (they set the calibration ceiling)")
held = np.flatnonzero(base)[~m._train_mask(int(base.sum()), hosts[base])]
held = held[hosts[held] == target]
for i in held[np.argsort(-raw[held])][:6]:
    a = A[j_arr[i]]
    print(f"  {dt.datetime.utcfromtimestamp(a.ts):%m-%d %H:%M:%S} rule {a.rule_id:>16s} lvl {a.rule_level} raw {raw[i]:.3f} [{lab[i]}]")

print("\nrules on the intranet server: baseline vs evaluation (benign) vs attack")
cb = collections.Counter(A[j].rule_id for j in j_arr[tb]); ce = collections.Counter(A[j].rule_id for j in j_arr[ben_eval])
ca = collections.Counter(A[j].rule_id for j in j_arr[att])
for r in sorted(set(cb) | set(ce) | set(ca), key=lambda r: -(cb[r] + ce[r] + ca[r]))[:15]:
    print(f"  rule {r:>16s}: baseline {cb[r]:5d}  eval benign {ce[r]:5d}  attack {ca[r]:3d}")
