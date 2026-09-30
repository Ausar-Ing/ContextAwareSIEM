#!/usr/bin/env bash
# Environment provenance snapshot -- MANAGER SIDE (WSL2 Ubuntu).
#
# Run this THREE times, with the label as the argument:
#   ./tools/collect_provenance.sh T0       <- right after the audit-policy change
#   ./tools/collect_provenance.sh mid      <- any time you change anything
#   ./tools/collect_provenance.sh T1       <- when you freeze the baseline
#
# Everything here is something you cannot reconstruct in November.
# Output: provenance/raw/<label>_manager_<date>.txt
#
# Usage from the WSL project copy; if the repo lives on C:, run it from
# /mnt/c/Personal/UniStuff/Project/ContextAwareSIEM.
set -uo pipefail

LABEL="${1:-adhoc}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/provenance/raw/${LABEL}_manager_$(date +%Y%m%dT%H%M%S).txt"
mkdir -p "$(dirname "$OUT")"

s() { printf '\n==================== %s ====================\n' "$1"; }

{
s "SNAPSHOT"
echo "label            $LABEL"
echo "captured_at      $(date -Iseconds)"
echo "captured_at_utc  $(date -u -Iseconds)"
echo "timezone         $(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)"
echo "utc_offset_h     $(date +%z)   <- MUST match SITE_UTC_OFFSET_H in tools/window_builder.py"
echo "host             $(hostname)"
echo "kernel           $(uname -srmo)"
echo "distro           $(. /etc/os-release && echo "$PRETTY_NAME")"

s "WAZUH VERSIONS"
sudo /var/ossec/bin/wazuh-control info 2>&1
echo "--- packages ---"
dpkg -l 2>/dev/null | grep -i wazuh | awk '{print $2, $3}'
echo "--- ruleset revision ---"
grep -m1 -i "revision\|version" /var/ossec/ruleset/VERSION 2>/dev/null || \
  cat /var/ossec/ruleset/VERSION 2>/dev/null || echo "(no VERSION file)"

s "SERVICE STATE"
systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard 2>&1
systemctl is-enabled wazuh-indexer wazuh-manager wazuh-dashboard 2>&1

s "AGENTS (Active/Disconnected)"
sudo /var/ossec/bin/agent_control -l 2>&1

s "ALERT THRESHOLD AND ARCHIVES  <- the stock-Wazuh premise of the whole project"
sudo grep -A6 "<alerts>" /var/ossec/etc/ossec.conf 2>&1
sudo grep -A6 "<logall" /var/ossec/etc/ossec.conf 2>&1

s "CONFIG HASHES  (any change here is a segment boundary in the baseline)"
# `[ -f ]` runs as the CALLING user, which cannot stat inside /var/ossec/etc
# (0750). Without sudo on the test itself the hash was silently never taken.
for f in /var/ossec/etc/ossec.conf /var/ossec/etc/local_internal_options.conf \
         /var/ossec/etc/internal_options.conf; do
  sudo test -f "$f" && sudo sha256sum "$f" 2>&1
done
echo "--- local rules/decoders ---"
sudo sha256sum /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml 2>/dev/null || echo "(none)"
echo "--- shipped ruleset, aggregate ---"
sudo find /var/ossec/ruleset -name '*.xml' -type f -print0 2>/dev/null \
  | sort -z | xargs -0 sudo sha256sum 2>/dev/null | sha256sum | sed 's/-$/(aggregate of ruleset xml)/'

s "RULE IDS FOR THE AUDITED EVENTS  (record, do not assume)"
for eid in 4624 4625 4634 4688; do
  echo "--- Windows event $eid ---"
  # [a-z0-9_] missed 0955-WEF-baseline_rules.xml -- uppercase and hyphens
  sudo grep -rn "$eid" /var/ossec/ruleset/rules/ 2>/dev/null \
    | grep -oE 'rules/[A-Za-z0-9_.-]+\.xml:[0-9]+' | sort -u | head -5
  sudo grep -rn -B6 "<field name=\"win.system.eventID\">$eid</field>" \
    /var/ossec/ruleset/rules/ 2>/dev/null \
    | grep -oE '<rule id="[0-9]+" level="[0-9]+"' | sort -u | head -5
done
echo "--- rule ids seen, with levels (top 40 in today's alerts) ---"
sudo python3 - <<'PY' 2>&1
import json,collections,sys
c=collections.Counter()
try:
    for ln in open('/var/ossec/logs/alerts/alerts.json',errors='replace'):
        try: r=json.loads(ln)
        except Exception: continue
        ru=r.get('rule',{})
        c[(ru.get('id'),ru.get('level'),(ru.get('description') or '')[:48])]+=1
except FileNotFoundError:
    print('(alerts.json not present)'); sys.exit()
for (i,l,d),n in c.most_common(40):
    print(f"  {n:7d}  id={i:<8} level={l:<3} {d}")
PY

s "LOG ROTATION / CORPUS EXTENT"
sudo ls -la /var/ossec/logs/alerts/alerts.json 2>&1
echo "--- rotated daily files ---"
sudo find /var/ossec/logs/alerts -name 'ossec-alerts-*.json.gz' \
     -printf '%TY-%Tm-%Td  %10s  %p\n' 2>/dev/null | sort | tail -40
echo "--- archives (should be absent unless Phase 1 insurance is on) ---"
sudo du -sh /var/ossec/logs/archives 2>/dev/null || echo "(no archives dir)"

s "DISK  <- 50 GB free on a 90% full volume; watch this"
df -h / /var 2>&1
sudo du -sh /var/ossec/logs /var/ossec/queue /var/lib/wazuh-indexer 2>/dev/null

s "INDEXER RETENTION (ISM)"
# admin:admin is NOT the install password. Find the real one, or the check
# returns "Unauthorized" -- which also means a policy you created with the wrong
# password never existed, because curl exits 0 on an auth failure.
IPW=""
for f in "$HOME/ContextAwareSIEM/wazuh-install-files/wazuh-passwords.txt" \
         /root/wazuh-install-files/wazuh-passwords.txt; do
  sudo test -f "$f" && IPW=$(sudo awk '/indexer_username: .?admin/{f=1} f&&/indexer_password/{gsub(/.*indexer_password: .?|.$/,"");print;exit}' "$f")
  [ -n "$IPW" ] && break
done
if [ -z "$IPW" ]; then
  echo "(admin password not found automatically - check by hand with:"
  echo "   curl -sk -u admin:<pw> https://127.0.0.1:9200/_plugins/_ism/policies?pretty )"
else
  curl -sk -u "admin:$IPW" "https://127.0.0.1:9200/_plugins/_ism/policies?pretty" 2>/dev/null \
    | grep -E '"policy_id"|"min_index_age"|"index_patterns"|"state_name"|Unauthorized' | head -20
  echo "--- indices currently managed by a policy ---"
  curl -sk -u "admin:$IPW" "https://127.0.0.1:9200/_plugins/_ism/explain/wazuh-alerts-*?pretty" 2>/dev/null \
    | grep -E '"index"|"policy_id"' | head -20
fi

s "ANALYSIS TOOLCHAIN  (Isolation Forest results depend on these)"
python3 -VV 2>&1
python3 -c "import numpy,sklearn;print('numpy',numpy.__version__);print('scikit-learn',sklearn.__version__)" 2>&1 \
  || python3 -c "import numpy;print('numpy',numpy.__version__);print('scikit-learn NOT INSTALLED')" 2>&1

s "REPO STATE"
git -C "$ROOT" rev-parse HEAD 2>&1
git -C "$ROOT" status --porcelain 2>&1 | head -30
sha256sum "$ROOT/tools/window_builder.py" "$ROOT/tools/baseline_check.py" 2>&1

s "END"
} > "$OUT" 2>&1

echo "Written: $OUT"
echo
echo "NEXT: check utc_offset_h matches window_builder.py, then paste the headline"
echo "      numbers into COLLECTION_RECORD.md. Raw snapshots are gitignored."
