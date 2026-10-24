#!/usr/bin/env python3
"""Test 2: why do benign held-out windows of the attacked host outscore its
privilege-escalation windows? Tuning scenario only (default wheeler).

For the attacked host's HOST windows, seed by seed: the held-out baseline windows
whose raw score exceeds the attack windows' (the ones that cap the attack's
percentile within the host's own distribution), grouped into episodes; their
feature values beside the attack windows' and the host's baseline median; and a
per-feature attribution for both (raw-score change when the feature is set to the
host's baseline median; positive = the feature makes the window more anomalous).
The question is whether the two kinds of window are anomalous for the SAME reasons
(then the features cannot tell a maintenance burst from an intrusion) or for
different ones (then a feature or weighting change could).

usage: ait_diag_burst.py <host_roles.json> <wb_dir> [scenario=wheeler] [seeds=5]
"""
import sys, json, pickle, collections, datetime as dt
import numpy as np

roles_path, wb_dir = sys.argv[1:3]
sc = sys.argv[3] if len(sys.argv) > 3 else "wheeler"
n_seeds = int(sys.argv[4]) if len(sys.argv) > 4 else 5
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
rows = []
for j, a in enumerate(A):
    if a.ts >= t_atk and wb.learn_rules:
        wb.learn_rules = False
    for e, f, ok in wb.push(a):
        if e[0] == "host" and ok:
            rows.append((j, e[1], f, [x.rule_id for x in wb.win[e]]))
j_arr = np.array([r[0] for r in rows]); hosts = np.array([r[1] for r in rows], dtype=object)
F = np.array([r[2] for r in rows]); ts = np.array([A[j].ts for j in j_arr])
lab = np.array([labels[j] for j in j_arr], dtype=object)
base = ts < t_atk
names = [n for n in W.ENTRY_FEATURE_NAMES if n != "night_fraction"]
is_t = hosts == target
att = is_t & ~base & np.isin(lab, list(ATTACK))

agg_attr_att, agg_attr_cap, caps_per_seed, episodes_all = [], [], [], collections.Counter()
for seed in range(n_seeds):
    m = C6.TypeModel(seed)
    m.fit(F[base], list(hosts[base]), True)
    X = m.prep(F, True)
    raw = -m.forest.score_samples(X)
    bi = np.flatnonzero(base)
    held = bi[~m._train_mask(len(bi), hosts[bi])]
    held_t = held[hosts[held] == target]
    att_max = raw[att].max()
    cap = held_t[raw[held_t] > att_max]
    caps_per_seed.append(len(cap))
    Xb = X[base & is_t]; med = np.median(Xb, axis=0)
    def attribution(idx):
        c = np.zeros(len(names))
        for i in idx:
            for k in range(len(names)):
                x2 = X[i].copy(); x2[k] = med[k]
                c[k] += raw[i] - (-m.forest.score_samples(x2[None, :])[0])
        return c / max(1, len(idx))
    agg_attr_att.append(attribution(np.flatnonzero(att)))
    if len(cap):
        agg_attr_cap.append(attribution(cap))
    # episodes: capping windows within 1 h of each other
    tt = np.sort(ts[cap])
    ep_start = [tt[0]] if len(tt) else []
    for a_, b_ in zip(tt[:-1], tt[1:]):
        if b_ - a_ >= 3600:
            ep_start.append(b_)
    for t0 in ep_start:
        episodes_all[dt.datetime.utcfromtimestamp(t0).strftime("%m-%d %H:%M")] += 1
    if seed == 0:
        print(f"{sc}: intranet server = host {target}; held-out baseline windows {len(held_t)}, "
              f"attack windows {att.sum()} (raw max {att_max:.3f})")
        print(f"seed 0: {len(cap)} held-out windows outscore every attack window\n")
        print(f"{'feature':24s} {'base med':>8s} {'attack (mean)':>13s} {'cap (mean)':>10s}  attack pct / cap pct in host baseline")
        for k, n in enumerate(names):
            va, vc = X[att, k].mean(), (X[cap, k].mean() if len(cap) else np.nan)
            pa = 100 * np.mean(Xb[:, k] <= va); pc = 100 * np.mean(Xb[:, k] <= vc) if len(cap) else np.nan
            print(f"  {n:22s} {med[k]:8.2f} {va:13.2f} {vc:10.2f}  {pa:5.0f} / {pc:5.0f}")
        print("\nseed 0, capping windows: time, raw, rules in window (newest last)")
        for i in cap[np.argsort(-raw[cap])][:8]:
            print(f"  {dt.datetime.utcfromtimestamp(ts[i]):%m-%d %H:%M:%S} raw {raw[i]:.3f}  {rows[i][3][-8:]}")
        print("seed 0, attack windows:")
        for i in np.flatnonzero(att)[np.argsort(ts[att])]:
            print(f"  {dt.datetime.utcfromtimestamp(ts[i]):%m-%d %H:%M:%S} raw {raw[i]:.3f} [{lab[i]}]  {rows[i][3][-8:]}")

print(f"\ncapping windows per seed: {caps_per_seed}; episodes they come from (start time: seeds): {dict(episodes_all)}")
ca = np.mean(agg_attr_att, axis=0); cc = np.mean(agg_attr_cap, axis=0) if agg_attr_cap else np.zeros(len(names))
print("\nattribution, mean over seeds (raw-score change when the feature is set to the host's baseline median)")
print(f"{'feature':24s} {'attack':>8s} {'cap':>8s}")
for k in np.argsort(-(np.abs(ca) + np.abs(cc))):
    print(f"  {names[k]:22s} {ca[k]:+8.4f} {cc[k]:+8.4f}")
top = lambda c: set(np.array(names)[np.argsort(-c)[:3]])
print(f"\ntop-3 drivers: attack {sorted(top(ca))}; capping windows {sorted(top(cc))}; shared {sorted(top(ca) & top(cc))}")
