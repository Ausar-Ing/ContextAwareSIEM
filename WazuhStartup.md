# Wazuh Lab: Start, Stop, Verify

Operating notes for the ContextAwareSIEM testbed.
Revised 2026-09-11. Corrections against the previous version are listed at the end.

Layout:

- **Windows 11 host** — Wazuh agent (`WazuhSvc`) + Sysmon64. Daily-driver machine. Source of the benign baseline.
- **WSL2 Ubuntu 24.04** — `wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard`.
- **VM (isolated)** — Wazuh agent, attack execution target.

Project root on Windows: `C:\Personal\UniStuff\Project\ContextAwareSIEM`
Sysmon binaries: `C:\Personal\UniStuff\Project\ContextAwareSIEM\tools\sysmon`

---

## 1. Start everything

**WSL Ubuntu**, in this order — the indexer must be up before the manager, and the dashboard last:

```bash
sudo sysctl -w vm.max_map_count=262144
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-dashboard
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager
```

`vm.max_map_count` is required by the indexer (OpenSearch). **`sysctl -w` does not survive a WSL restart.** To persist it:

```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

**PowerShell as Administrator** (Windows host):

```powershell
Start-Service WazuhSvc
Get-Service WazuhSvc, *Sysmon*
```

---

## 2. Stop everything

**PowerShell as Administrator** — stop the agent first so the manager does not log a disconnect storm:

```powershell
Stop-Service WazuhSvc
```

**WSL Ubuntu** — reverse of the start order:

```bash
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
```

---

## 3. Sysmon shutdown options

`Stop-Service Sysmon64` may fail. That is expected: Sysmon installs as a service plus a kernel driver and is designed to resist being stopped.

**Recommended for this lab:**

```powershell
Stop-Service WazuhSvc
```

Sysmon keeps writing to its own event channel, but nothing is forwarded to Wazuh. This is almost always what you want — it is reversible in one command and leaves the Sysmon configuration untouched.

**To fully remove Sysmon** (PowerShell as Administrator):

```powershell
cd "C:\Personal\UniStuff\Project\ContextAwareSIEM\tools\sysmon"
.\Sysmon64.exe -u
```

If normal uninstall fails:

```powershell
.\Sysmon64.exe -u force
```

Reinstall:

```powershell
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

**Do not uninstall Sysmon during a baseline collection period.** Reinstalling changes the configuration hash and can change which events are emitted, which shifts the feature distribution mid-baseline. That breaks the assumption in `system_model.md` §6.2 that baseline and evaluation come from the same generating process.

---

## 4. Restart everything

WSL Ubuntu:

```bash
sudo sysctl -w vm.max_map_count=262144
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-dashboard
```

PowerShell as Administrator:

```powershell
Restart-Service WazuhSvc
Get-Service *Sysmon*
```

---

## 5. Auto-start

> **Read this before changing anything here.** During a baseline collection period every service must start automatically, on both sides. A service that fails to come back after a reboot produces a silent gap in the baseline, and gaps that correlate with time of day are the most damaging kind — see `component6_isolation_forest.md` §3.4.

**Enable auto-start** (the state you want while collecting):

```bash
sudo systemctl enable wazuh-indexer
sudo systemctl enable wazuh-manager
sudo systemctl enable wazuh-dashboard
```

```powershell
Set-Service WazuhSvc -StartupType Automatic
```

**`systemctl enable` is not sufficient on WSL.** A WSL2 distro does not launch when Windows boots — it starts when something first touches it. Enabling the units only means they start *once the distro does*. To make the distro come up at logon, create a scheduled task:

```powershell
$action  = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d Ubuntu -u root /bin/true"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "Start WSL Ubuntu" -Action $action -Trigger $trigger -RunLevel Highest
```

**This trigger is `-AtLogOn`, and on a 24/7 host that is a real gap.** An
unattended Windows Update reboot at 3am leaves the machine at the lock screen
with nobody logged on, so the distro never starts and the manager stays down
until you next sit at it. See `PHASE0_RUNBOOK.md` §5a for the test and the
options. Confirm after the next reboot -- one you log straight into, and one you
leave alone for five minutes -- that the manager is actually running before
assuming the baseline is intact.

**Disable auto-start** — only when deliberately pausing the lab, never during collection:

```bash
sudo systemctl disable wazuh-dashboard
sudo systemctl disable wazuh-manager
sudo systemctl disable wazuh-indexer
```

```powershell
Set-Service WazuhSvc -StartupType Manual
```

---

## 6. Verification

### 6.1 Services and agent connectivity

PowerShell:

```powershell
Get-Service WazuhSvc, *Sysmon*
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 40
```

WSL Ubuntu:

```bash
sudo /var/ossec/bin/agent_control -l          # agent list WITH Active/Disconnected status
sudo tail -n 80 /var/ossec/logs/ossec.log
```

`agent_control -l` is the better check than `manage_agents -l`: it reports connection state, not just registration.

Healthy Windows agent log lines:

```text
Connected to the server ([127.0.0.1]:1514/tcp).
Agent is now online.
Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.
Analyzing event log: 'Security'.
```

If the `Security` line is absent, the Security channel is not being collected and the audit-policy work in §7 will produce nothing.

### 6.2 Alerts are actually being written

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

Nothing appearing does not necessarily mean nothing is happening — Wazuh only writes rules at level ≥ 3 to `alerts.json`. Check the threshold:

```bash
grep -A3 "<alerts>" /var/ossec/etc/ossec.conf
```

`<log_alert_level>` defaults to 3. Leave it at 3 — the prioritisation layer is specified against the stock threshold, and lowering it weakens the claim that the design works on a default Wazuh deployment.

### 6.3 What is actually being collected

```bash
grep -B2 -A6 "<localfile>" /var/ossec/etc/ossec.conf | grep -i "location\|log_format"
```

On the Windows agent, `C:\Program Files (x86)\ossec-agent\ossec.conf` should contain `Security` and `Microsoft-Windows-Sysmon/Operational` as `eventchannel` locations.

### 6.4 Generate test events

PowerShell:

```powershell
notepad.exe
ping 8.8.8.8
whoami
```

Then check that something appears in `alerts.json`. If Sysmon is forwarding but *no alerts* result, that is expected and correct: most Sysmon rules for ordinary process creation are level 0 and never reach `alerts.json`. The fix is audit policy (§7), not lowering the alert level.

---

## 7. Audit policy (required before baseline collection)

Windows does not generate logon or process-creation events unless the advanced audit policy asks for them. Without this, the `user` and `srcip` entities never resolve and the behavioural alert rate stays near zero.

PowerShell as Administrator:

```powershell
auditpol /set /subcategory:"Logon"            /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"           /success:enable
auditpol /set /subcategory:"Special Logon"    /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

**Do not enable command-line capture.** The conventional recommendation is to
turn on `ProcessCreationIncludeCmdLine_Enabled` so 4688 events carry the full
command line. This project does not use it: none of the fifteen window features
touches alert content, so the command line is pure liability — it is the most
sensitive field in the capture and the model would never read it. If it is
already enabled, turn it off:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
```

See `baseline_collection_protocol.md` §7.2 for the full data-minimisation
argument, which matters a great deal if any machine other than your own is
monitored.

Verify:

```powershell
auditpol /get /category:"Logon/Logoff"
auditpol /get /subcategory:"Process Creation"
```

Then confirm end-to-end: log out, log back in, and check that an authentication alert appears in `alerts.json`. Which rule ID fires is worth recording rather than assuming — on the manager:

```bash
grep -rn "4624\|4625\|4688" /var/ossec/ruleset/rules/ | head -40
```

**Record the exact timestamp you enabled this** in `COLLECTION_RECORD.md` A.1 --
it is T0, and it is passed to `tools/baseline_check.py --since` on every run
thereafter. Alerts before and after come from different generating processes, so
baseline collection starts *after* this change, not before. Then take both
provenance snapshots (`tools/collect_provenance.sh T0`,
`tools/collect_provenance.ps1 -Label T0`).

---

## 8. Where the data actually lands

`alerts.json` is rotated daily. Yesterday's alerts are not in `alerts.json`:

```text
/var/ossec/logs/alerts/alerts.json              <- today, live
/var/ossec/logs/alerts/2026/Sep/ossec-alerts-10.json.gz   <- 10 September
```

A month of collection is ~30 gzipped daily files, not one file. To assemble a corpus:

```bash
# month-agnostic: a baseline that crosses into October still assembles
zcat $(ls /var/ossec/logs/alerts/*/*/ossec-alerts-*.json.gz 2>/dev/null) \
     /var/ossec/logs/alerts/alerts.json > ~/baseline_corpus.json
wc -l ~/baseline_corpus.json
```

Archives (`logall_json`, default **off**) store every event whether or not a rule matched, in `/var/ossec/logs/archives/archives.json`. The prioritisation layer does not use archives — it is specified as a layer over *alerts*. See `baseline_collection_protocol.md` §4 for the one case where enabling archives temporarily is worth the disk.

---

## 9. Corrections against the previous version

| Issue | Previous | Now |
|---|---|---|
| **File was truncated** | Opened mid-code-fence at "### 3"; sections 1 and 2 absent | Reconstructed |
| **Wrong Sysmon path** | `C:\Personal\Uni stuff\Project\Context Aware SIEM\tools\sysmon` — spaces in both folder names; that directory does not exist | `C:\Personal\UniStuff\Project\ContextAwareSIEM\tools\sysmon`, confirmed against the repo |
| `vm.max_map_count` | `sysctl -w` only | Noted that it does not persist; added `/etc/sysctl.d/99-wazuh.conf` |
| Agent status check | `manage_agents -l` (registration only) | `agent_control -l` (reports Active/Disconnected) |
| Auto-start | Presented neutrally | Warned: disabling it during collection creates time-correlated gaps. Added the WSL-does-not-start-at-boot gap and a scheduled task to fix it |
| Stop order | Not specified | Agent first, then dashboard → manager → indexer |
| Audit policy | Absent | §7 — required before baseline collection |
| Log rotation | Absent | §8 — `alerts.json` is daily; a month is 30 gz files |
| Sysmon reinstall during collection | Not mentioned | Warned against: changes the generating process mid-baseline |

Sources for the configuration claims:
[alerts — ossec.conf](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/alerts.html),
[global — ossec.conf](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html),
[Event logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html).
