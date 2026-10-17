#!/usr/bin/env bash
# Freeze the workstation baseline -- COLLECTION_RECORD.md Part E. Run ONCE, in WSL,
# from the project root, with T1 = a site-local (+07) minute that is already past:
#
#   bash tools/freeze_baseline.sh 2026-10-17T23:30
#
# Writes ~/baseline_frozen_<T1>.json: the host agents' alerts (001, and 002 after
# the 27 Sep re-enrollment) with T0 <= timestamp < T1, each line byte-for-byte as
# Wazuh wrote it, in assembly order. Nothing else is filtered here: admission
# (compliance groups, scan-timed FIM) stays in the analysis code, so the frozen
# file is the raw input the paper's numbers are computed from. The file is made
# read-only, copied into the offline archive, hashed, and gated with --until.
set -euo pipefail

T0="2026-09-12T12:14"          # COLLECTION_RECORD.md A.1 -- do not change
AGENT="001,002"                # weekly_check.sh / window_builder.HOST_ALIASES
T1="${1:?usage: bash tools/freeze_baseline.sh YYYY-MM-DDTHH:MM  (site-local +07, in the past)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW="$HOME/baseline_corpus.json"
STAMP="$(echo "$T1" | tr -d ':-')"
FROZEN="$HOME/baseline_frozen_${STAMP}.json"
ARCHIVE="$HOME/baseline_archive"
A=/var/ossec/logs/alerts

s() { printf '\n\033[1m==== %s ====\033[0m\n' "$1"; }

[ -e "$FROZEN" ] && { echo "$FROZEN already exists; a freeze is done once. Refusing to overwrite."; exit 1; }
t1_epoch=$(date -d "${T1/T/ } +0700" +%s) || { echo "cannot parse T1=$T1"; exit 1; }
[ "$t1_epoch" -lt "$(date +%s)" ] || { echo "T1=$T1 is not in the past; pick a minute that has already ended."; exit 1; }

s "1. assembling the raw corpus (same rules as weekly_check.sh step 1)"
sudo bash -c '
  A=/var/ossec/logs/alerts
  live=$(stat -c %i "$A/alerts.json" 2>/dev/null || echo 0)
  for f in $(ls -1 "$A"/*/*/ossec-alerts-*.json.gz 2>/dev/null | sort); do zcat -- "$f"; done
  for f in $(ls -1 "$A"/*/*/ossec-alerts-*.json 2>/dev/null | sort); do
    ino=$(stat -c %i "$f" 2>/dev/null || echo -1)
    [ "$ino" != "$live" ] && cat -- "$f"
  done
  cat "$A/alerts.json" 2>/dev/null
' > "$RAW"
printf '  %s: %s lines\n' "$RAW" "$(wc -l < "$RAW")"

s "2. refreshing the offline archive"
sudo rsync -a --prune-empty-dirs --include='*/' \
     --include='ossec-alerts-*.json' --include='ossec-alerts-*.json.gz' \
     --include='ossec-alerts-*.sum' --exclude='*' "$A/" "$ARCHIVE/"
sudo chown -R "$USER:$USER" "$ARCHIVE"
printf '  %s day files archived\n' "$(find "$ARCHIVE" -name 'ossec-alerts-*' | wc -l)"

s "3. writing the frozen corpus"
python3 - "$RAW" "$FROZEN" "$T0" "$T1" "$AGENT" <<'PY'
import sys, json, re, datetime as dt
raw, out, t0, t1, agents = sys.argv[1:6]
tz = dt.timezone(dt.timedelta(hours=7))
lo = dt.datetime.strptime(t0, "%Y-%m-%dT%H:%M").replace(tzinfo=tz).timestamp()
hi = dt.datetime.strptime(t1, "%Y-%m-%dT%H:%M").replace(tzinfo=tz).timestamp()
keep = set(agents.split(","))
n = kept = bad = other_agent = outside = 0
first = last = None
with open(raw, "rb") as fi, open(out, "xb") as fo:
    for line in fi:
        n += 1
        try:
            r = json.loads(line)
            s = r.get("timestamp") or r["@timestamp"]
            s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s.replace("Z", "+00:00"))
            ts = dt.datetime.fromisoformat(s).timestamp()
            ag = str(r["agent"]["id"])
        except Exception:
            bad += 1
            continue
        if ag not in keep:
            other_agent += 1; continue
        if not (lo <= ts < hi):
            outside += 1; continue
        fo.write(line if line.endswith(b"\n") else line + b"\n")
        kept += 1
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
f = lambda t: dt.datetime.fromtimestamp(t, tz).isoformat(timespec="seconds") if t else "-"
print(f"  raw lines {n}; kept {kept}; other agents {other_agent}; outside [T0,T1) {outside}; unparseable {bad}")
print(f"  first kept alert {f(first)}   last kept alert {f(last)}")
if kept == 0:
    sys.exit("nothing kept -- do not use this file")
PY
chmod 444 "$FROZEN"
mkdir -p "$ARCHIVE/frozen"; cp -p "$FROZEN" "$ARCHIVE/frozen/"

s "4. identity of the frozen corpus (copy into Part E)"
SHA=$(sha256sum "$FROZEN" | cut -d' ' -f1)
printf '  T1                %s +07:00\n' "$T1"
printf '  file              %s\n' "$FROZEN"
printf '  SHA-256           %s\n' "$SHA"
printf '  bytes / lines     %s / %s\n' "$(stat -c %s "$FROZEN")" "$(wc -l < "$FROZEN")"
printf '  archive copy      %s\n' "$ARCHIVE/frozen/$(basename "$FROZEN")"

s "5. freeze gate reading"
mkdir -p "$ROOT/provenance/gate"
python3 "$ROOT/tools/baseline_check.py" "$FROZEN" --since "$T0" --until "$T1" \
        --agent "$AGENT" --label freeze --json "$ROOT/provenance/gate/freeze.json"

s "next"
echo "  ./tools/collect_provenance.sh T1      (then the PowerShell one, as Administrator)"
echo "  Paste everything above to Claude for Part E, A.2, C.4 and the Part D freeze row."
