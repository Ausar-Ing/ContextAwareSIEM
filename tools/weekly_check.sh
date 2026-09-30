#!/usr/bin/env bash
# ContextAwareSIEM -- the whole weekly routine, in one place.
#
#   bash tools/weekly_check.sh wk1
#
# Run from the project root in WSL. Every step below has a trap that has already
# bitten this project once; they are all handled here so they cannot recur.
#
#   1. assemble the corpus            (sudo/glob traps -- see the build step)
#   2. refresh the offline archive    (flat-copy collision trap)
#   3. check WSL vs Windows clock     (drift corrupts every timing feature)
#   4. check disk on both sides
#   5. run the gate                   (--since and --agent are NOT optional)
#
# Log the result in COLLECTION_RECORD.md Part D.
set -uo pipefail

T0="2026-09-12T12:14"          # COLLECTION_RECORD.md A.1 -- do not change
# windows11-host. Agent 000 is excluded (D.1). The endpoint was re-enrolled on
# 27 Sep and reports as 002 from then on (Part B #2); window_builder.HOST_ALIASES
# folds 002 onto 001 so it stays one host entity. If it is ever re-enrolled
# again, add the new id HERE and in HOST_ALIASES, or the gate reads STALE.
AGENT="001,002"
LABEL="${1:-adhoc}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$HOME/baseline_corpus.json"
ARCHIVE="$HOME/baseline_archive"
A=/var/ossec/logs/alerts

s() { printf '\n\033[1m==== %s ====\033[0m\n' "$1"; }

s "1. assembling corpus"
# Two traps here, both of which have already cost a reading:
#
#  (a) The glob MUST be expanded by root. /var/ossec/logs/alerts is wazuh:wazuh
#      0750, so a glob expanded by the calling shell fails with "Permission
#      denied" even when the command itself runs under sudo.
#
#  (b) Rotated day files are NOT all .json.gz. monitord gzips a day file at the
#      midnight rollover and only if it is running then; a host that is shut
#      down overnight leaves them as plain .json indefinitely. Matching only
#      *.json.gz silently skipped the 11th, 12th and 13th of September -- 43 MB
#      of 46 MB collected -- while still exiting 0 and printing a GO verdict.
#
#      Today's dated file is a HARDLINK to alerts.json (same inode, link count
#      2), so it is skipped here and picked up once from alerts.json below.
sudo bash -c '
  A=/var/ossec/logs/alerts
  live=$(stat -c %i "$A/alerts.json" 2>/dev/null || echo 0)

  for f in $(ls -1 "$A"/*/*/ossec-alerts-*.json.gz 2>/dev/null | sort); do
    zcat -- "$f"
  done

  for f in $(ls -1 "$A"/*/*/ossec-alerts-*.json 2>/dev/null | sort); do
    ino=$(stat -c %i "$f" 2>/dev/null || echo -1)
    if [ "$ino" != "$live" ]; then
      cat -- "$f"
    fi
  done

  cat "$A/alerts.json" 2>/dev/null
' > "$CORPUS"
printf '  %s\n  %s lines, %s\n' "$CORPUS" \
  "$(wc -l < "$CORPUS")" "$(du -h "$CORPUS" | cut -f1)"
printf '  day files seen: %s\n' \
  "$(sudo bash -c 'ls -1 /var/ossec/logs/alerts/*/*/ossec-alerts-*.json* 2>/dev/null | wc -l')"

s "2. refreshing offline archive"
# Preserves YYYY/Mon/, so Oct's ossec-alerts-04 cannot collide with Sep's.
# Takes .json as well as .json.gz, for the same reason as (b) above.
sudo rsync -a --prune-empty-dirs \
     --include='*/' \
     --include='ossec-alerts-*.json' --include='ossec-alerts-*.json.gz' \
     --include='ossec-alerts-*.sum' --exclude='*' \
     "$A/" "$ARCHIVE/"
sudo chown -R "$USER:$USER" "$ARCHIVE"
printf '  %s day files archived, %s\n' \
  "$(find "$ARCHIVE" -name 'ossec-alerts-*' | wc -l)" \
  "$(du -sh "$ARCHIVE" | cut -f1)"

s "3. clock agreement (WSL is where every alert timestamp comes from)"
WSL_T=$(date +%s)
# NOT `Get-Date -UFormat %s`: on Windows PowerShell 5.1 that returns seconds
# since epoch computed against LOCAL time, so it reads exactly UTC-offset hours
# out (25200 s here) and reports a 7-hour "drift" that does not exist.
WIN_T=$(powershell.exe -NoProfile -Command \
        '[int64]([datetime]::UtcNow - [datetime]"1970-01-01").TotalSeconds' \
        2>/dev/null | tr -d '\r')
if [ -n "${WIN_T:-}" ] && [ "$WIN_T" -gt 0 ] 2>/dev/null; then
  D=$(( WSL_T > WIN_T ? WSL_T - WIN_T : WIN_T - WSL_T ))
  printf '  WSL %s / Windows %s -- drift %ss\n' \
    "$(date -d @"$WSL_T" '+%H:%M:%S')" "$(date -d @"$WIN_T" '+%H:%M:%S')" "$D"
  [ "$D" -gt 30 ] && printf '  \033[1mDRIFT > 30s -- fix with: sudo hwclock -s\033[0m\n'
else
  printf '  (could not reach Windows via interop -- check by hand)\n'
fi

s "4. disk"
df -h / | tail -1 | awk '{printf "  vhdx interior: %s used, %s avail\n", $3, $4}'
powershell.exe -NoProfile -Command \
  '"  C: {0} GB free" -f [math]::Round((Get-PSDrive C).Free/1GB,1)' 2>/dev/null | tr -d '\r'
printf '  (compact the vhdx only if C: drops below ~25 GB)\n'

s "5. gate"
mkdir -p "$ROOT/provenance/gate"
python3 "$ROOT/tools/baseline_check.py" "$CORPUS" \
        --since "$T0" --agent "$AGENT" \
        --label "$LABEL" --json "$ROOT/provenance/gate/${LABEL}.json"

s "next"
cat <<'TXT'
  - Log this reading in COLLECTION_RECORD.md Part D.
  - SANITY CHECK FIRST: does "first alert" in the CORPUS block above match your
    T0 (2026-09-12 12:14), and is the wall-clock span roughly the days elapsed
    since? If the span is minutes rather than days, the corpus assembly lost
    day files again -- the verdict below is then meaningless even though it
    reads GO.
  - DOWNTIME: this host is shut down most nights and runs ~12 h/day, so roughly
    one 10-14 h gap per day is NORMAL and needs no entry. The active-time
    correction exists for exactly those. Log in Part C.1 only:
      * a gap during hours the machine was actually in use,
      * a gap beyond ~24 h that was not a deliberate shutdown,
      * a sharp rate drop while uptime looks normal (usually a dropped agent),
      * any gap on one of the three deliberate awake nights.
  - Change nothing in the config. Tuning ideas go in Part B as proposals.
TXT
