#!/usr/bin/env python3
"""
Baseline readiness check for ContextAwareSIEM.

Run this after the Phase 1 collection week, then weekly during Phase 2.
It answers the four questions that decide whether the anomaly model of
Component 6 is trainable on this testbed:

  1. What is the admitted alert rate, per awake hour and per calendar day?
  2. Which entity types actually resolve, and how often?
  3. Which of the fifteen window features are populated and non-constant?
  4. How many more days of collection to reach the training-set target?

Usage:
    # month-agnostic: a baseline that crosses into October still assembles
    zcat $(ls /var/ossec/logs/alerts/*/*/ossec-alerts-*.json.gz 2>/dev/null) \
         /var/ossec/logs/alerts/alerts.json > ~/baseline_corpus.json
    python3 tools/baseline_check.py ~/baseline_corpus.json \
            --since 2026-09-11T18:00 --json provenance/gate/week1.json

--since is the collection epoch T0 -- the moment the audit policy was enabled.
Alerts before it come from a different generating process (system_model.md 6.2)
and must not be counted. Record T0 in COLLECTION_RECORD.md and pass it every
time; a gate reading taken without it is wrong in your favour.

Targets come from component6_isolation_forest.md section 3.2.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import glob as _glob
import gzip
import hashlib
import json
import os
import sys

import numpy as np

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from window_builder import (Alert, WindowBuilder, FEATURE_NAMES, parse_wazuh,
                            COMPLIANCE_GROUPS, SITE_UTC_OFFSET_H)

TARGET_WINDOWS = 8000       # section 3.2 target
FLOOR_WINDOWS = 4000        # section 3.2 floor
STRIDE = 10                 # section 3.3
DOWNTIME_GAP_MULT = 20      # a gap this many x the median awake gap = downtime
MIN_DOWNTIME_S = 1800       # ...and at least this long


def load(path):
    op = gzip.open if path.endswith(".gz") else open
    rows = []
    with op(path, "rt", errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except json.JSONDecodeError:
                continue          # truncated final line during rotation
    return rows


def detect_downtime(ts: np.ndarray):
    """Intervals where the host was almost certainly off. Derived from the
    stream itself -- no rule-ID assumptions (protocol section 2.1)."""
    if len(ts) < 10:
        return [], 0.0
    gaps = np.diff(ts)
    med = float(np.median(gaps[gaps > 0])) if (gaps > 0).any() else 1.0
    thresh = max(med * DOWNTIME_GAP_MULT, MIN_DOWNTIME_S)
    idx = np.where(gaps > thresh)[0]
    return [(float(ts[i]), float(ts[i + 1])) for i in idx], thresh


def fmt_dur(s):
    h = s / 3600.0
    return f"{h:.1f} h" if h < 48 else f"{h/24:.1f} d"


def parse_local(s):
    """ISO-ish local (site) time -> epoch seconds."""
    if s is None:
        return None
    tz = dt.timezone(dt.timedelta(hours=SITE_UTC_OFFSET_H))
    txt = s.strip().replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(txt, fmt).replace(tzinfo=tz).timestamp()
        except ValueError:
            continue
    raise SystemExit(f"could not parse time {s!r} (want YYYY-MM-DD[THH:MM])")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("corpus", nargs="?", default="baseline_corpus.json")
    ap.add_argument("--since", metavar="T0",
                    help="collection epoch, site-local (YYYY-MM-DD[THH:MM]). "
                         "Alerts before it are discarded -- see system_model 6.2")
    ap.add_argument("--until", metavar="T1", help="freeze point, site-local")
    ap.add_argument("--json", metavar="PATH", dest="json_out",
                    help="also write the headline numbers as JSON, for the "
                         "weekly series in COLLECTION_RECORD.md")
    ap.add_argument("--label", default="", help="label for the JSON record")
    ap.add_argument("--agent", metavar="IDS",
                    help="comma-separated Wazuh agent ids to KEEP (e.g. 001). "
                         "Agent 000 is the WSL manager itself and its stream is "
                         "dominated by your own sudo/lab-admin activity, which "
                         "differs systematically between Phase 2 and Phase 3 -- "
                         "counting it inflates the gate in your favour.")
    ap.add_argument("--by-agent", action="store_true",
                    help="print the per-agent alert breakdown and exit")
    args = ap.parse_args()

    path = args.corpus
    t_since = parse_local(args.since)
    t_until = parse_local(args.until)

    keep_agents = (set(x.strip() for x in args.agent.split(",") if x.strip())
                   if args.agent else None)

    rep = {"label": args.label, "agents_kept": sorted(keep_agents) if keep_agents else None,
           "checked_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
           "corpus_path": path,
           "corpus_sha256": sha256_file(path) if os.path.exists(path) else None,
           "since": args.since, "until": args.until,
           "site_utc_offset_h": SITE_UTC_OFFSET_H,
           "stride": STRIDE, "target_windows": TARGET_WINDOWS,
           "floor_windows": FLOOR_WINDOWS}

    rows = load(path)
    if not rows:
        print(f"No alerts parsed from {path}")
        return 1

    alerts = []
    for i, r in enumerate(rows):
        try:
            alerts.append(parse_wazuh(r, i))
        except (KeyError, ValueError):
            continue
    alerts.sort(key=lambda a: (a.ts, a.ingest_seq))

    by_agent = collections.Counter()
    for a in alerts:
        for t, v in a.entities:
            if t == "host":
                by_agent[v] += 1
    if args.by_agent or (keep_agents is None and len(by_agent) > 1):
        print("=" * 72)
        print("AGENTS PRESENT IN THIS CORPUS")
        print("=" * 72)
        for ag, n in by_agent.most_common():
            note = "   <- the WSL manager itself; your own sudo activity" if ag == "000" else ""
            print(f"  agent {ag:>6}  {n:8d} alerts  ({100*n/max(len(alerts),1):5.1f}%){note}")
        if keep_agents is None and len(by_agent) > 1:
            print("\n  More than one agent. Decide which belong in the baseline and pass")
            print("  --agent <ids>. Mixing agent 000 in inflates the gate: its volume comes")
            print("  from administering the lab, not from the monitored endpoint.\n")
        if args.by_agent:
            return 0

    n_raw = len(alerts)
    if keep_agents is not None:
        alerts = [a for a in alerts
                  if any(t == "host" and v in keep_agents for t, v in a.entities)]
        rep["alerts_dropped_other_agents"] = n_raw - len(alerts)
        n_raw = len(alerts)
    if t_since is not None:
        alerts = [a for a in alerts if a.ts >= t_since]
    if t_until is not None:
        alerts = [a for a in alerts if a.ts <= t_until]
    n_dropped = n_raw - len(alerts)
    if not alerts:
        print("No alerts inside the --since/--until window.")
        return 1
    if n_dropped:
        print(f"[epoch filter] discarded {n_dropped} of {n_raw} alerts outside "
              f"the collection window (pre-T0 or post-freeze)\n")
    rep["alerts_discarded_outside_window"] = n_dropped

    admitted = [a for a in alerts if a.admissible]
    ts = np.array([a.ts for a in alerts])
    span = ts[-1] - ts[0]

    down, thresh = detect_downtime(ts)
    downtime = sum(b - a for a, b in down)
    awake = span - downtime

    print("=" * 72)
    print("CORPUS")
    print("=" * 72)
    t0 = dt.datetime.fromtimestamp(ts[0], dt.timezone(dt.timedelta(hours=SITE_UTC_OFFSET_H)))
    t1 = dt.datetime.fromtimestamp(ts[-1], dt.timezone(dt.timedelta(hours=SITE_UTC_OFFSET_H)))
    print(f"  file                    {path}")
    print(f"  first alert             {t0:%Y-%m-%d %H:%M} (site local)")
    print(f"  last alert              {t1:%Y-%m-%d %H:%M} (site local)")
    print(f"  wall-clock span         {fmt_dur(span)}")
    print(f"  detected downtime       {fmt_dur(downtime)} in {len(down)} interval(s)")
    print(f"  AWAKE time              {fmt_dur(awake)}   <- the rate denominator")
    print(f"  total alerts            {len(alerts)}")
    print(f"  admitted (behavioural)  {len(admitted)}  "
          f"({100*len(admitted)/len(alerts):.1f}%)")
    print(f"  excluded (compliance)   {len(alerts)-len(admitted)}")
    print(f"  distinct rule ids       {len(set(a.rule_id for a in admitted))}")
    rep.update(first_alert=t0.isoformat(timespec="seconds"),
               last_alert=t1.isoformat(timespec="seconds"),
               wall_clock_span_h=round(span / 3600, 2),
               downtime_h=round(downtime / 3600, 2),
               awake_h=round(awake / 3600, 2),
               downtime_intervals=len(down),
               downtime_gap_threshold_s=round(thresh, 1),
               total_alerts=len(alerts), admitted_alerts=len(admitted),
               excluded_compliance=len(alerts) - len(admitted),
               distinct_rule_ids=len(set(a.rule_id for a in admitted)))
    print(f"  agents                  {len(set(e[1] for a in alerts for e in a.entities if e[0]=='host'))}")

    if down:
        print("\n  downtime intervals (gap threshold %s):" % fmt_dur(thresh))
        for a, b in down[:12]:
            la = dt.datetime.fromtimestamp(a, dt.timezone(dt.timedelta(hours=SITE_UTC_OFFSET_H)))
            print(f"    {la:%a %d %b %H:%M}  for {fmt_dur(b-a)}")
        if len(down) > 12:
            print(f"    ... and {len(down)-12} more")

    # --- entity resolution --------------------------------------------------
    print("\n" + "=" * 72)
    print("ENTITY RESOLUTION  (system_model.md 4.1.3)")
    print("=" * 72)
    ent = collections.Counter()
    for a in admitted:
        for t, _ in a.entities:
            ent[t] += 1
    for t in ("host", "user", "srcip"):
        n = ent.get(t, 0)
        pct = 100 * n / max(len(admitted), 1)
        flag = "" if pct > 5 else "   <- too rare for its own model"
        print(f"  {t:8s} {n:7d} / {len(admitted)} admitted alerts  ({pct:5.1f}%){flag}")
        rep.setdefault("entity_resolution_pct", {})[t] = round(pct, 2)

    # --- windows and features ----------------------------------------------
    wb = WindowBuilder(learn_rules=True)
    X, types = [], []
    for a in admitted:
        for e, f, scoreable in wb.push(a):
            if scoreable:
                X.append(f)
                types.append(e[0])
    X = np.array(X) if X else np.zeros((0, 15))
    types = np.array(types)

    print("\n" + "=" * 72)
    print("WINDOW FEATURES  (constant = consumes split budget, contributes nothing)")
    print("=" * 72)
    if len(X) == 0:
        print("  no scoreable windows yet")
    else:
        print(f"  {'feature':26s}{'min':>12s}{'max':>12s}{'distinct':>10s}  status")
        dead = []
        for i, nm in enumerate(FEATURE_NAMES):
            c = X[:, i]
            nd = len(np.unique(np.round(c, 6)))
            st = ""
            if c.std() < 1e-9:
                st = "CONSTANT"
                dead.append(nm)
            elif nd <= 2:
                st = "near-constant"
            print(f"  {nm:26s}{c.min():12.3f}{c.max():12.3f}{nd:10d}  {st}")
        rep["dead_features"] = dead
        rep["feature_distinct_values"] = {
            nm: int(len(np.unique(np.round(X[:, i], 6))))
            for i, nm in enumerate(FEATURE_NAMES)}
        if dead:
            print(f"\n  {len(dead)} dead feature(s): {', '.join(dead)}")
            print("  -> drop these from the model, or fix what feeds them")

    # --- the gate -----------------------------------------------------------
    print("\n" + "=" * 72)
    print("TRAINING-SET PROJECTION  (component6_isolation_forest.md 3.2)")
    print("=" * 72)
    host_windows = int((types == "host").sum()) if len(X) else 0
    pool = host_windows // STRIDE
    awake_h = max(awake / 3600.0, 1e-6)
    per_awake_h = len(admitted) / awake_h
    days_elapsed = max(span / 86400.0, 1e-6)
    print(f"  admitted alerts / awake hour     {per_awake_h:8.1f}")
    print(f"  admitted alerts / calendar day   {len(admitted)/days_elapsed:8.1f}")
    print(f"  host windows so far              {host_windows:8d}")
    print(f"  training pool at stride {STRIDE}        {pool:8d}   "
          f"(target {TARGET_WINDOWS}, floor {FLOOR_WINDOWS})")

    rep.update(admitted_per_awake_hour=round(per_awake_h, 2),
               admitted_per_calendar_day=round(len(admitted) / days_elapsed, 1),
               host_windows=host_windows, training_pool_at_stride=pool,
               windows_by_entity_type={t: int((types == t).sum())
                                       for t in set(types.tolist())} if len(X) else {})

    if pool <= 0:
        print("\n  VERDICT: not enough data yet to project. Collect longer.")
        rep["verdict"] = "INSUFFICIENT"
        _emit(rep, args.json_out)
        return 0
    rate_pool_per_day = pool / days_elapsed
    need_t = max(TARGET_WINDOWS - pool, 0) / rate_pool_per_day
    need_f = max(FLOOR_WINDOWS - pool, 0) / rate_pool_per_day
    print(f"\n  days to floor  ({FLOOR_WINDOWS})   {need_f:8.1f}")
    print(f"  days to target ({TARGET_WINDOWS})   {need_t:8.1f}")

    total_days = days_elapsed + need_t
    rep.update(days_elapsed=round(days_elapsed, 2),
               days_to_floor=round(need_f, 1), days_to_target=round(need_t, 1),
               projected_total_days=round(total_days, 1))
    print()
    if total_days <= 35:
        rep["verdict"] = "GO"
        print("  VERDICT: GO. Phase 2 as scheduled.")
    elif total_days <= 70:
        rep["verdict"] = "GO_WITH_FLOOR"
        print("  VERDICT: GO WITH THE FLOOR. Target 4,000 windows and report")
        print("           seed variance bands honestly (expect +-0.02 AUC).")
    else:
        rep["verdict"] = "STOP_AND_REDESIGN"
        print("  VERDICT: STOP AND REDESIGN. The model is not trainable on this")
        print("           testbed within the schedule. See protocol section 4 --")
        print("           widen audit policy, or cut features 8-10, or declare")
        print("           the model under-trained. Do NOT lower log_alert_level.")
    _emit(rep, args.json_out)
    return 0


def _emit(rep, path):
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, sort_keys=True)
    print(f"\n  [json] {path}")


if __name__ == "__main__":
    sys.exit(main())
