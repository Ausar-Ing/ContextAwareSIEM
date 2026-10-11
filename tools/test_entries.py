#!/usr/bin/env python3
"""
Regression tests for entry mode (collapse_s) in window_builder.py.
Synthetic data only -- no corpus needed.

    python3 tools/test_entries.py

Every check prints PASS/FAIL; exit status is non-zero if any fails.
"""
from __future__ import annotations

import os
import random
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import window_builder as W                      # noqa: E402

FE = {n: i for i, n in enumerate(W.ENTRY_FEATURE_NAMES)}
FAILED = []
HOST = ("host", "h1")


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  -- ' + detail) if detail else ''}")
    if not ok:
        FAILED.append(name)


def al(seq, ts, rule, level=3, tac=()):
    return W.Alert(alert_id=str(seq), ingest_seq=seq, ts=ts, rule_id=rule,
                   rule_level=level, tactics=tac, entities=(HOST,))


def run(alerts, **kw):
    wb = W.WindowBuilder(downtime_gap_s=None, learn_rules=True, **kw)
    last = None
    for a in alerts:
        for e, f, ok in wb.push(a):
            last = (f, ok)
    return wb, last


print("entry mode")
# 1. a flood of one rule occupies one slot
A = [al(i, 1000.0 + i, "A") for i in range(100)] + [al(100, 1100.5, "B", level=10)]
wb, (f, ok) = run(A, N=20, collapse_s=300)
d = wb.win[HOST]
check("flood collapses to one entry", len(d) == 2 and d[0].count == 100,
      f"entries={len(d)} counts={[x.count for x in d]}")
check("window_entries counts entries", f[FE["window_entries"]] == 2)
check("current_run_length of the new rule is 1", f[FE["current_run_length"]] == 1)
check("volume_share_max = 100/101", abs(f[FE["volume_share_max"]] - 100 / 101) < 1e-12)
check("rule_level_max sees the single high alert", f[FE["rule_level_max"]] == 10)
# what the flood costs in alert mode: an earlier rule C is pushed out of the window
C = [al(-1, 900.0, "C", level=8, tac=("TA0006",))] + A
_, (f_raw, _) = run(C, N=20)
_, (f_ent, _) = run(C, N=20, collapse_s=300)
check("alert mode: flood evicts the earlier rule (2 distinct, no tactic)",
      f_raw[2] == 2 and f_raw[8] == 0, f"distinct={f_raw[2]}, tactics={f_raw[8]}")
check("entry mode: earlier rule survives the flood (3 distinct, 1 tactic)",
      f_ent[2] == 3 and f_ent[8] == 1, f"distinct={f_ent[2]}, tactics={f_ent[8]}")

# 2. a gap larger than delta splits the run
wb, (f, _) = run([al(0, 0.0, "A"), al(1, 100.0, "A"), al(2, 500.0, "A")], N=20, collapse_s=300)
check("gap > delta opens a new entry", [x.count for x in wb.win[HOST]] == [2, 1])
check("inter-arrival is measured between entry starts", f[FE["inter_arrival_mean_s"]] == 500.0)
check("duration runs to the current alert", f[FE["window_duration_s"]] == 500.0)

# 3. interleaved rules keep one run each
wb, (f, _) = run([al(i, 10.0 * i, "AB"[i % 2]) for i in range(40)], N=20, collapse_s=300)
check("interleaved A B A B -> two entries", [x.count for x in wb.win[HOST]] == [20, 20])
check("merge into an earlier-started entry: run length 20", f[FE["current_run_length"]] == 20)

# 4. count bound is in entries
wb, (f, _) = run([al(i, float(i), f"R{i}") for i in range(30)], N=20, collapse_s=300)
check("N bounds entries", len(wb.win[HOST]) == 20 and wb.win[HOST][0].rule_id == "R10")

# 5. time bound uses the newest member; a stale entry behind a live one is dropped
T = 3600.0
s = [al(0, 0.0, "LIVE")] + [al(1, 10.0, "STALE")] + \
    [al(2 + i, 200.0 * (i + 1), "LIVE") for i in range(20)]       # LIVE every 200 s to 4000 s
wb, _ = run(s, N=20, T_hours=1.0, collapse_s=300)
rules = [x.rule_id for x in wb.win[HOST]]
check("live run kept, stale entry dropped", rules == ["LIVE"], f"{rules}")

# 6. tactics are the union over a run's members
wb, (f, _) = run([al(0, 0.0, "A", tac=("TA0006",)), al(1, 1.0, "A", tac=("TA0008",)),
                  al(2, 2.0, "A")], N=20, collapse_s=300)
check("tactic union inside an entry", f[FE["distinct_tactic_count"]] == 2)
check("cold start counts alerts, not entries (3 alerts, 1 entry -> scoreable)",
      run([al(i, float(i), "A") for i in range(3)], collapse_s=300)[1][1] is True)

# 7. alert mode is unchanged by the refactor: compare with the frozen copy if given
ref = os.environ.get("WB_REF")
if ref:
    import importlib.util
    spec = importlib.util.spec_from_file_location("wb_ref", ref)
    R = importlib.util.module_from_spec(spec)
    sys.modules["wb_ref"] = R
    spec.loader.exec_module(R)
    rng = random.Random(7)
    t, mism = 0.0, 0
    w_new = W.WindowBuilder(learn_rules=True)
    w_old = R.WindowBuilder(learn_rules=True)
    for i in range(3000):
        t += rng.expovariate(1 / 60) + (rng.random() < 0.01) * 7200
        r, lv = f"R{rng.randint(1, 15)}", rng.randint(3, 12)
        tac = (rng.choice(list(W.TACTIC_ORDINAL)),) if rng.random() < 0.1 else ()
        a = W.Alert(str(i), i, t, r, lv, tactics=tac, entities=(HOST, ("user", "u")))
        b = R.Alert(str(i), i, t, r, lv, tactics=tac, entities=(HOST, ("user", "u")))
        for (_, f1, o1), (_, f2, o2) in zip(w_new.push(a), w_old.push(b)):
            mism += (not np.array_equal(f1, f2)) or o1 != o2
    check("alert mode bit-identical to reference on 3000 random alerts", mism == 0, f"{mism} mismatches")
else:
    print("  SKIP  alert-mode identity (set WB_REF=<path to previous window_builder.py>)")

print(f"\n{'ALL PASS' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}")
sys.exit(1 if FAILED else 0)
