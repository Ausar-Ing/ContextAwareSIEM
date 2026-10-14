#!/usr/bin/env python3
"""Checks for accumulator.py (Component 8).   python3 tools/test_accumulator.py"""
import math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import accumulator as A
FAILED = []
def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  -- ' + detail) if detail else ''}")
    if not ok: FAILED.append(name)
print("accumulator")
acc = A.Accumulator(N=20, a_r=1.0, a_c=0.0, a_s=0.0)
for i in range(1000):
    R, terms, w = acc.push("h", 1000.0 + i * 0.01, "R1", 20.0, 0.0, -1, False, ())
check("1000 repeats count as 1 + ln 1000 alerts", abs(R - 20 * (1 + math.log(1000))) < 1e-6, f"{R:.2f}")
R4, _, _ = acc.push("h", 1000.0 + 9.99 + 4 * 3600, "R2", 0.0, 0.0, -1, False, ())
check("group halves after one half-life since its LAST member", abs(R4 - 20 * (1 + math.log(1000)) / 2) < 1e-3, f"{R4:.2f}")
R_late, _, _ = acc.push("h", 1000.0 + 9.99 + 25 * 3600, "R3", 0.0, 0.0, -1, False, ())
check("group older than T is dropped", R_late == 0.0)
acc2 = A.Accumulator(N=20, a_r=0.0, a_c=0.0, a_s=1.0)
Rq, _, w = acc2.push("u", 0.0, "R1", 0, 0, 99.0, True, ())
check("q for S_seq 99 on a quiet entity is 50", abs(w - 50) < 1e-6, f"{w:.2f}")
check("the same 99 from an entity with 100 effective windows scores q < 10", A.q_score(99.0, 100.0) < 10,
      f"{A.q_score(99.0, 100.0):.2f}")
acc3 = A.Accumulator(N=20, a_r=0.0, a_c=0.0, a_s=1.0)
for i in range(2000):                      # entries every second: n_e reaches 2000/20 = 100
    acc3.push("busy", float(i), f"R{i}", 0, 0, 50.0, True, ())
_, _, w3 = acc3.push("busy", 2000.0 + 4 * 3600, "Rz", 0, 0, 99.0, True, ())
check("n_e counts entries opened in the last T", w3 < 10, f"{w3:.2f}")
_, _, wq = acc2.push("u", 4 * 3600.0, "R1", 0, 0, -1, False, ())
check("window term is a decayed running maximum, not a sum", abs(wq - 25) < 1e-6, f"{wq:.2f}")
G = lambda rule, tacs: type("g", (), {"rule": rule, "tactics": set(tacs)})()
check("one rule with two tactics does not satisfy the tactic condition",
      not A.tactics_from_different_rules([G("A", ["TA0004", "TA0005"]), G("B", [])]))
check("two rules with two different tactics do",
      A.tactics_from_different_rules([G("A", ["TA0004"]), G("B", ["TA0006"])]))
check("two rules with the same single tactic do not",
      not A.tactics_from_different_rules([G("A", ["TA0004"]), G("B", ["TA0004"])]))
# end-to-end: escalation needs both groups contributing
stream = []
for i in range(200):   # baseline: low activity
    stream.append(dict(ent="h", etype="host", t=float(i * 600), rule="B", s_rule=5, s_exp=0, s_seq=50, opened=True, tactics=(), gid=None, baseline=True))
t0 = 200 * 600.0 + 3600
for i, (rule, tac) in enumerate([("X", ("TA0006",)), ("Y", ("TA0004",)), ("X", ("TA0006",)), ("Y", ("TA0004",))]):
    stream.append(dict(ent="h", etype="host", t=t0 + i, rule=rule, s_rule=60, s_exp=0, s_seq=99, opened=True, tactics=tac, gid=i % 2, baseline=False))
Rb, _ = A.run(stream, 20)
th = A.calibrate_theta(Rb)
_, nbs = A.run(stream, 20, theta=th)
check("two rules, two tactics, above theta -> one notable absorbing both queue groups",
      len(nbs) == 1 and nbs[0]["gids"] == {0, 1}, f"theta={th}, notables={[(n['gids'], n['rules']) for n in nbs]}")
print(f"\n{'ALL PASS' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}")
sys.exit(1 if FAILED else 0)
