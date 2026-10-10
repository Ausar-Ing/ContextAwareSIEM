#!/usr/bin/env bash
# VM freeze watchdog -- RUNS IN WSL (manager side), as root, from cron every 10 min:
#   */10 * * * * /bin/bash /home/user/ContextAwareSIEM/tools/vm_watchdog.sh
#
# Why on the manager: a frozen guest that is saved and resumed never logs its
# freeze in VirtualBox (COLLECTION_RECORD.md G.4b #10). Only the manager knows
# that agent 003 went quiet.
#
# Two checks, each with its own alarm state:
#   HOST  agent 002 is not Active while WSL/cron is up. Catches a dropped host
#         agent, the manager not answering, and a silent RE-ENROLLMENT under a
#         new id (as on 27 Sep, Part B #2); other Active agent ids are listed.
#         Without this check a re-enrollment would also disable the VM check.
#   VM    host 002 Active, and 003 not Active or its keep-alive > LIMIT_S old.
# A condition must hold on CONFIRM_RUNS consecutive runs (>= 10 min) before it
# alarms. That is the boot grace: after a nightly shutdown 003's keep-alive is
# from the night before until the VM has resumed and reconnected.
#
# Writes one line per state CHANGE (raised / cleared) to
#   provenance/raw/vm_watchdog.log   (gitignored; Claude can read it)
# and on a raised alarm shows one pop-up on the Windows desktop (one host
# process, only when an alarm is raised -- never periodically). Pop-up launch
# errors go to provenance/raw/vm_watchdog.popup.err.
# Silence it while the VM is deliberately off with the host on:
#   touch ~/ContextAwareSIEM/provenance/raw/vm_watchdog.pause
# (Nightly shutdowns need no pause file: the host is off, so cron is too.)

set -u
REPO="${CASIEM_REPO:-/home/user/ContextAwareSIEM}"
AC="${CASIEM_AC:-/var/ossec/bin/agent_control}"
STATE="${CASIEM_STATE:-/var/tmp/casiem_vm_watchdog.state}"
LOG="$REPO/provenance/raw/vm_watchdog.log"
ERR="$REPO/provenance/raw/vm_watchdog.popup.err"
PAUSE="$REPO/provenance/raw/vm_watchdog.pause"
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
HOST_ID=002
VM_ID=003
LIMIT_S=1800
CONFIRM_RUNS=2

now=$(date +%s)
ts() { if [ "${1:-0}" -gt 0 ] 2>/dev/null; then date -d "@$1" '+%Y-%m-%d %H:%M:%S%z'; else echo never; fi; }

[ -e "$PAUSE" ] && exit 0

popup() {   # $1 = message (no single quotes)
  [ "${CASIEM_NO_POPUP:-0}" = 1 ] && return 0
  # cron does not inherit WSL_INTEROP; without it .exe interop can fail
  if [ -z "${WSL_INTEROP:-}" ]; then
    for s in /run/WSL/*_interop; do [ -S "$s" ] && { export WSL_INTEROP="$s"; break; }; done
  fi
  "$PS" -NoProfile -WindowStyle Hidden -Command \
    "(New-Object -ComObject WScript.Shell).Popup('$1',0,'CASIEM watchdog',48)" \
    >/dev/null 2>>"$ERR" &
}

field() { awk -F': *' -v k="$2" '$0 ~ "^ *"k {print $2; exit}' <<<"$1"; }

host_info=$("$AC" -i "$HOST_ID" 2>/dev/null)
vm_info=$("$AC" -i "$VM_ID" 2>/dev/null)
host_status=$(field "$host_info" "Status")
vm_status=$(field "$vm_info" "Status")
vm_ka=$(field "$vm_info" "Last keep alive")
case "$vm_ka" in ''|*[!0-9]*) vm_ka=0 ;; esac
silent=$(( now - vm_ka ))
# Active agents other than server, host and VM: a re-enrollment shows up here
others=$("$AC" -l 2>/dev/null | grep -E ', *Active' | grep -vE "ID: *(000|$HOST_ID|$VM_ID)," \
         | sed -E 's/^ *//; s/, *IP:[^,]*//' | paste -sd ';' -)

# state: host_n host_a vm_n vm_a   (n = consecutive bad runs, a = ok|alarm)
host_n=0 host_a=ok vm_n=0 vm_a=ok
[ -r "$STATE" ] && read -r host_n host_a vm_n vm_a < "$STATE"
case "${host_n:-}" in ''|*[!0-9]*) host_n=0 ;; esac
case "${vm_n:-}"   in ''|*[!0-9]*) vm_n=0 ;; esac
[ "${host_a:-}" = alarm ] || host_a=ok
[ "${vm_a:-}" = alarm ] || vm_a=ok

# ---- HOST check
if [ "$host_status" != "Active" ]; then
  host_n=$(( host_n + 1 ))
  if [ "$host_n" -ge "$CONFIRM_RUNS" ] && [ "$host_a" != alarm ]; then
    host_a=alarm
    echo "$(ts "$now") ALARM host=$HOST_ID status=${host_status:-no-answer} other_active=[${others:-none}]" >> "$LOG"
    popup "Host agent $HOST_ID is not Active (status ${host_status:-no answer}). Other active agents: ${others:-none}. Manager down, agent dropped, or re-enrolled under a new id. The VM check is blind until this is fixed. Tell Claude."
  fi
else
  host_n=0
  if [ "$host_a" = alarm ]; then
    host_a=ok
    echo "$(ts "$now") CLEAR host=$HOST_ID status=$host_status other_active=[${others:-none}]" >> "$LOG"
  fi
fi

# ---- VM check (only meaningful while the host agent is Active)
if [ "$host_status" = "Active" ]; then
  if [ "$vm_status" != "Active" ] || [ "$silent" -gt "$LIMIT_S" ]; then
    vm_n=$(( vm_n + 1 ))
    if [ "$vm_n" -ge "$CONFIRM_RUNS" ] && [ "$vm_a" != alarm ]; then
      vm_a=alarm
      echo "$(ts "$now") ALARM vm=$VM_ID status=${vm_status:-?} last_keepalive=$(ts "$vm_ka") silent_s=$silent host$HOST_ID=$host_status" >> "$LOG"
      popup "VM agent $VM_ID silent since $(ts "$vm_ka"). The VM is probably frozen. Tell Claude; do not shut down yet."
    fi
  else
    vm_n=0
    if [ "$vm_a" = alarm ]; then
      vm_a=ok
      echo "$(ts "$now") CLEAR vm=$VM_ID status=$vm_status last_keepalive=$(ts "$vm_ka") host$HOST_ID=$host_status" >> "$LOG"
    fi
  fi
else
  vm_n=0   # cannot judge the VM; keep its alarm state as it is
fi

echo "$host_n $host_a $vm_n $vm_a" > "$STATE"
exit 0
