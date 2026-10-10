#!/usr/bin/env bash
# VM freeze watchdog -- RUNS IN WSL (manager side), as root, from cron every 10 min:
#   */10 * * * * /home/user/ContextAwareSIEM/tools/vm_watchdog.sh
#
# Why on the manager: a frozen guest that is saved and resumed never logs its
# freeze in VirtualBox (COLLECTION_RECORD.md G.4b #10). Only the manager knows
# that agent 003 went quiet. The host's own agent 002 being Active proves the
# host and manager are up, so "002 Active and 003 silent > 30 min" means the VM
# is frozen or its agent is down while it should be collecting.
#
# Writes one line per state CHANGE (alarm raised / cleared) to
#   provenance/raw/vm_watchdog.log   (gitignored; Claude can read it)
# and on a raised alarm shows a pop-up on the Windows desktop (one host process,
# only when an alarm is raised -- never periodically).
# Silence it while the VM is deliberately off:  touch ~/ContextAwareSIEM/provenance/raw/vm_watchdog.pause

set -u
REPO="/home/user/ContextAwareSIEM"
LOG="$REPO/provenance/raw/vm_watchdog.log"
STATE="/var/tmp/casiem_vm_watchdog.state"
PAUSE="$REPO/provenance/raw/vm_watchdog.pause"
LIMIT_S=1800
AC=/var/ossec/bin/agent_control

now=$(date +%s)
ts() { date -d "@$1" '+%Y-%m-%d %H:%M:%S%z'; }

[ -e "$PAUSE" ] && exit 0

host_status=$($AC -i 002 2>/dev/null | awk -F': *' '/^ *Status/{print $2; exit}')
vm_status=$($AC -i 003 2>/dev/null | awk -F': *' '/^ *Status/{print $2; exit}')
vm_ka=$($AC -i 003 2>/dev/null | awk -F': *' '/Last keep alive/{print $2; exit}')
case "$vm_ka" in ''|*[!0-9]*) vm_ka=0 ;; esac
silent=$(( now - vm_ka ))

prev=$(cat "$STATE" 2>/dev/null || echo ok)

if [ "$host_status" = "Active" ] && { [ "$vm_status" != "Active" ] || [ "$silent" -gt "$LIMIT_S" ]; }; then
  if [ "$prev" != "alarm" ]; then
    echo "alarm" > "$STATE"
    echo "$(ts "$now") ALARM vm=003 status=${vm_status:-?} last_keepalive=$(ts "$vm_ka") silent_s=$silent host002=$host_status" >> "$LOG"
    /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -WindowStyle Hidden -Command \
      "(New-Object -ComObject WScript.Shell).Popup('VM agent 003 silent since $(ts "$vm_ka"). The VM is probably frozen. Tell Claude; do not shut down yet.',0,'CASIEM VM watchdog',48)" \
      >/dev/null 2>&1 &
  fi
else
  if [ "$prev" = "alarm" ]; then
    echo "ok" > "$STATE"
    echo "$(ts "$now") CLEAR vm=003 status=${vm_status:-?} last_keepalive=$(ts "$vm_ka") host002=${host_status:-?}" >> "$LOG"
  fi
fi
exit 0
