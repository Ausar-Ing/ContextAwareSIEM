#!/usr/bin/env python3
"""Throughput, latency and memory of the layer on an AIT-ADS replay (tuning scenario;
default harrison, the largest: ~470k alerts). Single process, single thread, the
reference Python implementation; numbers are for this machine and indicate scale,
not an optimized system.

Stages timed:
  C2 parse       Wazuh JSON line -> Alert (first 100k lines of the scenario's file)
  C5 windows     WindowBuilder.push over the whole stream (all entity types)
  C6 fit         forest fit + held-out calibration per entity type (offline, once)
  C6 score       raw score + calibration for every scoreable window
  C9 groups      repeat-group assignment and pi over the evaluation period
  C8 accumulate  Accumulator over every (alert, entity) pair
Also: per-alert latency percentiles of C5 + C6 scoring for the host window (one alert at
a time, as an online deployment would), and peak memory of the window state.

usage: ait_throughput.py <wb_dir> <ait_ads.zip> [scenario=harrison]
"""
import sys, os, json, time, pickle, zipfile, collections, tracemalloc
import numpy as np

wb, zpath = sys.argv[1:3]
sc = sys.argv[3] if len(sys.argv) > 3 else "harrison"
assert sc not in {"fox", "santos", "wardbeck", "wilson"}, "tuning scenarios only"
sys.path.insert(0, wb)
import window_builder as W
import seq_scoring as C6
import accumulator as C8

out = {"scenario": sc, "python": sys.version.split()[0], "cpu": os.cpu_count()}
# C2 parse
with zipfile.ZipFile(zpath).open(f"{sc}_wazuh.json") as f:
    lines = [next(f) for _ in range(100000)]
t0 = time.perf_counter(); n_ok = 0
for i, ln in enumerate(lines):
    try:
        W.parse_wazuh(json.loads(ln), i); n_ok += 1
    except (KeyError, ValueError):
        pass
out["parse_alerts_per_s"] = n_ok / (time.perf_counter() - t0)

A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
out["alerts"] = len(A)
host_of = lambda a: next(v for t, v in a.entities if t == "host")
# C5 windows (with peak memory of the builder state)
tracemalloc.start()
b = W.WindowBuilder(N=20, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
rows = collections.defaultdict(lambda: {"j": [], "ev": [], "F": [], "ok": []})
t0 = time.perf_counter()
for j, a in enumerate(A):
    if a.ts >= t_atk and b.learn_rules:
        b.learn_rules = False
    for e, f, ok in b.push(a):
        d = rows[e[0]]; d["j"].append(j); d["ev"].append(e[1]); d["F"].append(f); d["ok"].append(ok)
dt = time.perf_counter() - t0
cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
out["windows_alerts_per_s"] = len(A) / dt
out["window_rows"] = {k: len(v["j"]) for k, v in rows.items()}
out["entities"] = len(b.win)
out["peak_traced_MB_windows_incl_outputs"] = peak / 2**20
rows = {k: {"j": np.array(v["j"]), "ev": v["ev"], "F": np.array(v["F"]), "ok": np.array(v["ok"])} for k, v in rows.items()}
# C6 fit and score
ts = np.array([a.ts for a in A]); hosts = np.array([host_of(a) for a in A], dtype=object)
fit_s, score_n, score_s, models = 0.0, 0, 0.0, {}
for et, d in rows.items():
    base = d["ok"] & (ts[d["j"]] < t_atk)
    m = C6.TypeModel(0)
    t0 = time.perf_counter(); okfit = m.fit(d["F"][base], list(hosts[d["j"]][base]), True); fit_s += time.perf_counter() - t0
    if not okfit:
        continue
    models[et] = m
    t0 = time.perf_counter(); m.score(d["F"][d["ok"]], list(hosts[d["j"]][d["ok"]]), True); score_s += time.perf_counter() - t0
    score_n += int(d["ok"].sum())
out["fit_seconds_all_types"] = fit_s
out["score_windows_per_s_batch"] = score_n / score_s
# per-alert latency, online: push one alert, score its host window alone
m = models["host"]
b2 = W.WindowBuilder(N=20, learn_rules=False, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
lat = []
for j, a in enumerate(A[:20000]):
    t0 = time.perf_counter()
    for e, f, ok in b2.push(a):
        if e[0] == "host" and ok:
            m.score(np.asarray(f)[None, :], [e[1]], True)
    lat.append(time.perf_counter() - t0)
lat = np.array(lat) * 1000
out["online_latency_ms_p50_p95_p99"] = [float(np.percentile(lat, q)) for q in (50, 95, 99)]
# C8 accumulate
stream = []
for et, d in rows.items():
    for i in range(len(d["j"])):
        stream.append((ts[d["j"][i]], A[d["j"][i]].ingest_seq, et, d["ev"][i], d["j"][i]))
stream.sort(key=lambda x: (x[0], x[1]))
acc = C8.Accumulator(20)
t0 = time.perf_counter()
for t, _, et, evv, j in stream:
    a = A[j]
    acc.push((et, evv), t, a.rule_id, 100 * a.rule_level / 15, 50.0, 60.0, False, a.tactics)
out["accumulator_pushes_per_s"] = len(stream) / (time.perf_counter() - t0)
out["accumulator_pushes"] = len(stream)
# end-to-end estimate for the online path (parse + windows + host scoring + accumulate)
per_alert = (1 / out["parse_alerts_per_s"] + 1 / out["windows_alerts_per_s"]
             + np.mean(lat) / 1000 + (len(stream) / len(A)) / out["accumulator_pushes_per_s"])
out["online_alerts_per_s_estimate"] = 1 / per_alert
for k, v in out.items():
    print(f"{k:40s} {v if not isinstance(v, float) else round(v, 3)}")
json.dump(out, open(f"throughput_{sc}.json", "w"), indent=1)
