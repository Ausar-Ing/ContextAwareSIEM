#!/usr/bin/env python3
"""
Regression tests for the active-time correction in window_builder.py
(baseline_collection_protocol.md 2.1). Synthetic data only -- no corpus needed.

    python3 tools/test_active_time.py

Every check prints PASS/FAIL; exit status is non-zero if any fails.
"""
from __future__ import annotations

import datetime as dt
import os
import random
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import window_builder as W                      # noqa: E402
from baseline_check import detect_downtime      # noqa: E402

FI = {n: i for i, n in enumerate(W.FEATURE_NAMES)}
TIMING = {"window_duration_s", "inter_arrival_mean_s", "inter_arrival_min_s"}
TZ = dt.timezone(dt.timedelta(hours=W.SITE_UTC_OFFSET_H))
FAILED = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  -- ' + detail) if detail else ''}")
    if not ok:
        FAILED.append(name)


def duty_cycled_rows(days=4, seed=3):
    """Real Wazuh JSON shape. Awake 09:00-23:00 local, ~3% compliance alerts,
    user resolvable on about half the alerts."""
    rnd = random.Random(seed)
    t = dt.datetime(2026, 9, 12, 9, 0, tzinfo=TZ)
    end = t + dt.timedelta(days=days)
    rows = []
    while t < end:
        if 9 <= t.hour < 23:
            comp = rnd.random() < .03
            user = "ing" if rnd.random() < .5 else "SYSTEM"
            rows.append({
                "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0700",
                "id": str(len(rows)),
                "rule": {"id": "19007" if comp else rnd.choice(["67027", "60106", "92052"]),
                         "level": 3, "groups": ["sca"] if comp else ["windows"]},
                "agent": {"id": "001"},
                "data": {"win": {"system": {"eventID": "4688"},
                                 "eventdata": {"subjectUserName": user}}}})
        t += dt.timedelta(seconds=rnd.expovariate(1 / 25))
    return rows


def run(stream, **kw):
    wb = W.WindowBuilder(learn_rules=True, **kw)
    out = []
    for a in stream:
        for e, f, ok in wb.push(a):
            if ok:
                out.append((a.alert_id, e, f))
    return wb, out


def main():
    alerts = [W.parse_wazuh(r, i) for i, r in enumerate(duty_cycled_rows())]
    wb_on, F_on = run(alerts)
    _, F_off = run(alerts, downtime_gap_s=None)
    X_on = np.array([f for *_, f in F_on])
    X_off = np.array([f for *_, f in F_off])
    host_on = np.array([f for _, e, f in F_on if e[0] == "host"])

    print("active-time correction")

    d_off = X_off[:, FI["window_duration_s"]].max()
    d_on = X_on[:, FI["window_duration_s"]].max()
    check("overnight gap removed from window_duration_s", d_on < W.DOWNTIME_GAP_S < d_off,
          f"max {d_off:.0f} s wall-clock -> {d_on:.0f} s active")

    ts = np.array([a.ts for a in alerts])
    batch, thr = detect_downtime(ts)
    online = [(s, e) for _, s, e in wb_on.downtime_log]
    check("online intervals == the gate's batch detection",
          thr == W.DOWNTIME_GAP_S and batch == online,
          f"{len(online)} intervals at G = {thr:.0f} s")

    k = len(alerts) * 2 // 3
    _, F_pre = run(alerts[:k])
    lid = alerts[k - 1].alert_id
    a = [f for i, _, f in F_on if i == lid]
    b = [f for i, _, f in F_pre if i == lid]
    check("causal: an alert's features do not depend on later alerts",
          len(a) == len(b) > 0 and all(np.array_equal(x, y) for x, y in zip(a, b)))

    mk = lambda i, t, comp: W.Alert(str(i), i, t, "19007" if comp else "67027", 3,
                                    ("sca",) if comp else ("windows",),
                                    entities=(("host", "001"),))
    q = [mk(0, 0.0, 0), mk(1, 10.0, 0), mk(2, 1500.0, 1), mk(3, 3000.0, 0)]
    wb_all, _ = run(q)
    wb_adm, _ = run([x for x in q if x.admissible])
    check("compliance alerts count as proof of life",
          len(wb_all.downtime_log) == 0 and len(wb_adm.downtime_log) == 1,
          "fed everything: 0 intervals; fed admitted only: 1 (the wrong way to call it)")

    changed = {n for n, i in FI.items() if not np.array_equal(X_on[:, i], X_off[:, i])}
    check("only the timing features change", changed <= TIMING and bool(changed),
          f"{sorted(changed)}; {(np.abs(X_on - X_off).sum(1) > 0).sum()} of {len(X_on)} rows")

    floor = (host_on[:, FI["inter_arrival_min_s"]] <= W.INTER_ARRIVAL_FLOOR_S).sum()
    floor_off = (np.array([f for _, e, f in F_off if e[0] == "host"])
                 [:, FI["inter_arrival_min_s"]] <= W.INTER_ARRIVAL_FLOOR_S).sum()
    check("no spurious 'simultaneous alerts' on morning host windows", floor == floor_off,
          f"rows at the {W.INTER_ARRIVAL_FLOOR_S} s floor: {floor_off} off, {floor} on")

    # correction OFF == plain wall-clock definitions (protects the frozen studies)
    ok = True
    wb =W.WindowBuilder(learn_rules=True, downtime_gap_s=None)
    for a in alerts[:3000]:
        for e, f, s in wb.push(a):
            if not s:
                continue
            w = list(wb.win[e])
            t = np.array([x.ts for x in w])
            g = np.maximum(np.diff(t), W.INTER_ARRIVAL_FLOOR_S)
            ok &= (np.isclose(f[FI["window_duration_s"]], t[-1] - t[0])
                   and np.isclose(f[FI["inter_arrival_mean_s"]], g.mean())
                   and np.isclose(f[FI["inter_arrival_min_s"]], g.min()))
    check("downtime_gap_s=None gives plain wall-clock timing", bool(ok))

    q = [mk(0, 0.0, 0), mk(1, 5000.0, 0)]
    wb = W.WindowBuilder(learn_rules=True)
    for x in q:
        wb.push(x)
    f = wb.features(list(wb.win[("host", "001")]), q[-1], ("host", "001"))
    check("window whose only gap is downtime: duration 0, inter-arrival 0",
          f[FI["window_duration_s"]] == 0 and f[FI["inter_arrival_mean_s"]] == 0
          and f[FI["inter_arrival_min_s"]] == 0)

    print(f"\n{'ALL PASS' if not FAILED else str(len(FAILED)) + ' FAILED: ' + ', '.join(FAILED)}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
