#!/usr/bin/env python3
"""
Reproduces the measurements cited in FEEDBACK_RESPONSE.md and system_model.md
sections 4.2.3, 4.3.6 and 4.4.2.

Input : wazuh_dataset.json  (JSONL, one Wazuh alert per line)
Usage : python3 tools/doublecount_check.py [path]

The point of this script is to test whether the risk accumulator specified in
the SUBMITTED Deliverable 2 double-counts correlated alerts, and by how much,
on recorded benign data. It is not a model of the system; it isolates the
accumulator and the escalation gate.
"""
import json, sys, re, math, collections, datetime

PATH = sys.argv[1] if len(sys.argv) > 1 else "wazuh_dataset.json"
COMPLIANCE = {"sca", "rootcheck", "policy_monitoring", "ciscat"}

# Accumulator settings mirroring submitted section 4.8 (rule term only: S_exp and
# S_seq need enrichment sources and a fitted model that this sample cannot supply,
# so only w_r * S_rule is exercised. Including the other terms can only increase
# the inflation, never reduce it, since both are non-negative.)
W_R = 0.3
HALF_LIFE_S = 4 * 3600


def parse_ts(s):
    # Wazuh emits +0700, fromisoformat wants +07:00
    return datetime.datetime.fromisoformat(re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s))


def load(path):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    for r in rows:
        r["_ts"] = parse_ts(r["timestamp"])
    rows.sort(key=lambda r: r["_ts"])
    return rows


def is_compliance(r):
    return bool(set(r["rule"].get("groups", [])) & COMPLIANCE)


def s_rule(r):
    return W_R * (r["rule"]["level"] / 15 * 100)


def decay(r, t_end):
    return 2 ** (-(t_end - r["_ts"]).total_seconds() / HALF_LIFE_S)


def accum_naive(rows, t_end):
    """Submitted formula: sum P(a) over every alert."""
    return sum(s_rule(r) * decay(r, t_end) for r in rows)


def accum_saturated(rows, t_end):
    """Proposed: group by repeat key, contribute (1 + ln k) x one alert."""
    g = collections.defaultdict(list)
    for r in rows:
        g[(r["agent"]["id"], r["rule"]["id"])].append(r)
    return sum(s_rule(v[0]) * decay(v[0], t_end) * (1 + math.log(len(v))) for v in g.values())


def accum_first_only(rows, t_end):
    """Reference point: one contribution per repeat key."""
    g = {}
    for r in rows:
        g.setdefault((r["agent"]["id"], r["rule"]["id"]), r)
    return sum(s_rule(r) * decay(r, t_end) for r in g.values())


def main():
    rows = load(PATH)
    t_end = rows[-1]["_ts"]
    comp = [r for r in rows if is_compliance(r)]
    beh = [r for r in rows if not is_compliance(r)]

    print("=" * 68)
    print("SAMPLE")
    print("=" * 68)
    print(f"  alerts                 {len(rows)}")
    print(f"  span                   {(t_end - rows[0]['_ts']).total_seconds():.0f} s")
    print(f"  distinct rule ids      {len(set(r['rule']['id'] for r in rows))}")
    print(f"  agents                 {len(set(r['agent']['id'] for r in rows))}")
    print(f"  max rule.firedtimes    {max(r['rule'].get('firedtimes', 0) for r in rows)}")

    # timestamp collisions -- motivates the (timestamp, ingest_seq) ordering in 4.2.2
    coll = collections.Counter(r["timestamp"][:19] for r in rows)
    worst, n = coll.most_common(1)[0]
    print(f"  worst 1-second bucket   {n} alerts at {worst}")

    print()
    print("=" * 68)
    print("ADMISSION FILTER (system_model.md 4.2.3)")
    print("=" * 68)
    print(f"  compliance alerts      {len(comp)}  ({100*len(comp)/len(rows):.0f}% of sample)")
    if comp:
        print(f"    span                 {(comp[-1]['_ts'] - comp[0]['_ts']).total_seconds():.1f} s")
        tac = set(t for r in comp for t in r["rule"].get("mitre_tactics", []))
        tech = set(t for r in comp for t in r["rule"].get("mitre_techniques", []))
        print(f"    distinct tactics     {len(tac)}   <-- gate in submitted 4.8 required 2")
        print(f"    distinct techniques  {len(tech)}")
    print(f"  behavioural alerts     {len(beh)}")
    print(f"    distinct rule ids    {len(set(r['rule']['id'] for r in beh))}")

    print()
    print("=" * 68)
    print("ENTITY RESOLUTION (system_model.md 4.1.3)")
    print("=" * 68)
    ent = collections.Counter()
    for r in rows:
        d = r.get("data", {})
        ent["host"] += 1
        if d.get("srcuser") or d.get("dstuser"):
            ent["user"] += 1
        if d.get("srcip"):
            ent["srcip"] += 1
    for k in ("host", "user", "srcip"):
        print(f"  {k:8s} resolved for {ent[k]:3d} / {len(rows)} alerts")

    print()
    print("=" * 68)
    print("RISK ACCUMULATION  (rule term only, w_r=0.3, h=4h)")
    print("=" * 68)
    print(f"  {'population':<24s}{'naive':>10s}{'saturated':>12s}{'first-only':>12s}{'inflation':>12s}")
    for name, pop in (("all alerts", rows), ("behavioural only", beh)):
        if not pop:
            continue
        a, b, c = accum_naive(pop, t_end), accum_saturated(pop, t_end), accum_first_only(pop, t_end)
        print(f"  {name:<24s}{a:>10.1f}{b:>12.1f}{c:>12.1f}{a/c:>11.1f}x")
    if comp:
        share = accum_naive(comp, t_end) / accum_naive(rows, t_end)
        print(f"\n  compliance scan share of naive total: {100*share:.0f}%")

    print()
    print("=" * 68)
    print("COMPOSITE ALERTS (system_model.md 4.4.4)")
    print("=" * 68)
    pv = [r for r in rows if "previous_output" in r]
    print(f"  alerts carrying previous_output: {len(pv)}")
    for r in pv:
        print(f"    rule {r['rule']['id']:>6s}  groups={r['rule'].get('groups')}  "
              f"frequency={r['rule'].get('frequency')}")
    print("  NOTE: rule 533 uses previous_output for netstat diffs, not frequency")
    print("        correlation. This sample contains no frequency composites, so the")
    print("        detection signal in 4.4.4 remains UNVALIDATED.")


if __name__ == "__main__":
    main()
