#!/usr/bin/env bash
# Look at the Wazuh alert stream -- the file the prioritisation layer actually
# reads. Run in WSL Ubuntu. Needs sudo: /var/ossec/logs is wazuh:wazuh 0750.
#
#   bash tools/watch_alerts.sh            # live tail, one line per alert
#   bash tools/watch_alerts.sh --last 20  # the last 20 alerts instead
#   bash tools/watch_alerts.sh --where    # where everything lives, and how big
#   bash tools/watch_alerts.sh --logon    # just the authentication alerts
#   bash tools/watch_alerts.sh --status   # IS COLLECTION HEALTHY RIGHT NOW?
#
# Use the live tail during Phase 0 step 4: start it, sign out, sign back in,
# and watch the logon alert arrive. Record its rule id in COLLECTION_RECORD A.4.
set -uo pipefail
A=/var/ossec/logs/alerts

fmt() {
  python3 -c '
import sys, json
for ln in sys.stdin:
    ln = ln.strip()
    if not ln:
        continue
    try:
        r = json.loads(ln)
    except Exception:
        continue
    ru = r.get("rule") or {}
    ts = (r.get("timestamp") or "")[:19]
    rid = str(ru.get("id"))
    lvl = str(ru.get("level"))
    ag = ((r.get("agent") or {}).get("name") or "?")[:16]
    desc = (ru.get("description") or "")[:62]
    grp = ",".join((ru.get("groups") or [])[:3])
    print("%-19s  id=%7s  lvl=%2s  %-16s  %-62s  [%s]"
          % (ts, rid, lvl, ag, desc, grp), flush=True)
'
}

case "${1:-}" in
  --status)
    echo "=== services (want: active x3) ==="
    systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard 2>&1 | sed 's/^/  /'
    echo
    echo "=== agents (want: 001 Active) ==="
    sudo /var/ossec/bin/agent_control -l 2>&1 | sed 's/^/  /'
    echo
    echo "=== alert flow ==="
    sudo tail -n 4000 "$A/alerts.json" 2>/dev/null | python3 -c '
import sys, json, datetime as dt, collections
now = dt.datetime.now(dt.timezone.utc)
last = None; buckets = collections.Counter()
for ln in sys.stdin:
    ln = ln.strip()
    if not ln:
        continue
    try:
        r = json.loads(ln)
    except Exception:
        continue
    t = r.get("timestamp") or ""
    if not t:
        continue
    try:
        d = dt.datetime.fromisoformat(t.replace("+0700", "+07:00"))
    except Exception:
        continue
    if last is None or d > last:
        last = d
    age = (now - d).total_seconds()
    if age <= 3600:
        buckets["1h"] += 1
    if age <= 600:
        buckets["10m"] += 1
if last is None:
    print("  NO PARSEABLE ALERTS -- collection is NOT running")
    raise SystemExit
age = (now - last).total_seconds()
print("  newest alert   %s" % last.astimezone().strftime("%Y-%m-%d %H:%M:%S %z"))
print("  age            %.0f s" % age)
print("  last 10 min    %d alerts" % buckets["10m"])
print("  last hour      %d alerts" % buckets["1h"])
print("")
if age < 900:
    print("  HEALTHY -- alerts are arriving.")
elif age < 7200:
    print("  QUIET -- nothing for %.0f min. Plausible on an idle desktop," % (age / 60))
    print("  but confirm the agent shows Active above.")
else:
    print("  STALE -- nothing for %.1f h. Manager down, agent disconnected," % (age / 3600))
    print("  or WSL was restarted. Log the gap in COLLECTION_RECORD.md C.1")
    print("  once you know the cause.")
'
    echo
    echo "=== corpus reach ==="
    printf '  rotated .gz files: %s\n' "$(sudo find "$A" -name 'ossec-alerts-*.json.gz' 2>/dev/null | wc -l)"
    sudo du -sh "$A" 2>/dev/null | sed 's/^/  alerts dir: /'
    ;;
  --where)
    echo "=== live file (today) ==="
    sudo ls -la "$A/alerts.json" "$A/alerts.log" 2>&1
    echo
    echo "=== rotated daily files -- THESE ARE THE CORPUS ==="
    sudo find "$A" -name 'ossec-alerts-*.json.gz' -printf '%TY-%Tm-%Td  %9s B  %p\n' 2>/dev/null | sort | tail -40
    n=$(sudo find "$A" -name 'ossec-alerts-*.json.gz' 2>/dev/null | wc -l)
    echo "  ($n gz files)"
    echo
    echo "=== total size of the alerts tree ==="
    sudo du -sh "$A" 2>/dev/null
    echo
    echo "=== archives (should be ABSENT - logall_json is off by design) ==="
    sudo du -sh /var/ossec/logs/archives 2>/dev/null || echo "  (none - correct)"
    echo
    echo "=== threshold: only rules at or above this level are written ==="
    sudo grep -A4 "<alerts>" /var/ossec/etc/ossec.conf 2>&1 | sed 's/^/  /'
    echo
    echo "=== agents ==="
    sudo /var/ossec/bin/agent_control -l 2>&1 | sed 's/^/  /'
    ;;
  --logon)
    n="${2:-2000}"
    echo "authentication-related alerts in the last $n lines of alerts.json:"
    sudo tail -n "$n" "$A/alerts.json" | python3 -c '
import sys, json
hits = 0
for ln in sys.stdin:
    ln = ln.strip()
    if not ln:
        continue
    try:
        r = json.loads(ln)
    except Exception:
        continue
    ru = r.get("rule") or {}
    grp = [g.lower() for g in (ru.get("groups") or [])]
    desc = ru.get("description") or ""
    blob = json.dumps(r)
    auth = any("authentication" in g for g in grp)
    ev = ("4624" in blob) or ("4625" in blob) or ("4634" in blob) or ("4688" in blob)
    if auth or ev or "logon" in desc.lower():
        hits += 1
        print("%-19s  id=%7s  lvl=%2s  %-58s  [%s]"
              % ((r.get("timestamp") or "")[:19], str(ru.get("id")),
                 str(ru.get("level")), desc[:58], ",".join(grp[:3])))
print("")
print("%d matching alert(s). Record the rule id and level in COLLECTION_RECORD A.4." % hits)
if hits == 0:
    print("None yet. Checklist, in order:")
    print("  1. manager running?   systemctl is-active wazuh-manager")
    print("  2. agent Active?      sudo /var/ossec/bin/agent_control -l")
    print("  3. Security channel?  agent ossec.log must contain: Analyzing event log: Security")
    print("  4. auditpol applied?  auditpol /get /category:Logon/Logoff")
    print("  5. retry with a FAILED logon (one wrong password): 4625 maps to a")
    print("     higher-level rule than 4624 and is the more reliable smoke test.")
'
    ;;
  --last)
    n="${2:-20}"
    sudo tail -n "$n" "$A/alerts.json" | fmt
    ;;
  *)
    echo "live tail of $A/alerts.json  (Ctrl-C to stop)"
    echo "nothing appearing is not necessarily wrong: only rules at level >= 3 are written."
    echo
    sudo tail -f -n 5 "$A/alerts.json" | fmt
    ;;
esac
