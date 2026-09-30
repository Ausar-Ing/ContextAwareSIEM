# Phase 0 Runbook — do this once, today

Tick each box. Roughly one hour. Order matters: several steps are pointless if an
earlier one silently failed.

Companion to `WazuhStartup.md` (reference for each command) and
`COLLECTION_RECORD.md` (where the results go).

> **The one thing to get right:** T0 — the start of collection — is recorded at
> the **end** of this runbook, not in the middle. Everything in Phase 0 changes
> the generating process. T0 is the moment the last change is done and verified.

---

## Which shell, and from where

| Task | Where |
|---|---|
| Manager / indexer / dashboard | Ubuntu WSL terminal |
| Agent, Sysmon, audit policy, power | **PowerShell as Administrator** (Win+X → Terminal (Admin)) |
| Running repo scripts from WSL | `cd /mnt/c/Personal/UniStuff/Project/ContextAwareSIEM` |

**There is one copy of this repo and it lives on `C:`.** `~/ContextAwareSIEM`
inside WSL is where the Wazuh installer was run — it is not the repo. So from
WSL, work under `/mnt/c/...`.

Two DrvFs quirks when you do:

- The execute bit does not stick. Run `bash tools/collect_provenance.sh T0`, not
  `./tools/collect_provenance.sh T0`.
- `/mnt/c` is slow for large files. The **corpus stays in the WSL home**
  (`~/baseline_corpus.json`), never on `/mnt/c`. Only the small JSON gate records
  get written into the repo.

VS Code with the WSL remote extension is fine for all of this — its integrated
terminal is a normal Ubuntu shell.

---

## Phase 0 splits cleanly at T0 — use that if you are starting late

Steps 1, 2, 6 and 7 change nothing about the alert stream that matters, or they
change it *before* the clock starts. They can be done in one sitting and the
rest another, with no cost. Steps 3, 4, 5 and 8 belong together, because T0 is
only valid once the configuration is stable and verified.

| Can be done any time before T0 | Must be done together, ending at T0 |
|---|---|
| 1 start the lab | 3 audit policy |
| 2 verify | 4 confirm end-to-end, record rule IDs |
| 6 power (`powercfg /h off`, NIC) | 5 auto-start + the unattended-reboot test |
| 7 retention (ISM, `keep_log_days`) | 8 set T0, snapshot, open the record |

**Do not compress the right-hand column to finish tonight.** A rushed Phase 0
produces a T0 that does not correspond to a stable configuration, and that is
worse than a T0 one day later — it is the one error in this document that cannot
be detected afterwards from the data. Starting a day late costs about 3% of
collection volume and moves no deadline: the end date is pinned by Patch Tuesday
on 13 October, not by the start date.

---

## 1 ☐ Start the lab

`WazuhStartup.md` §1. Indexer → manager → dashboard, in that order.

Also make `vm.max_map_count` persist, if you have not already — `sysctl -w` does
not survive a WSL restart, and the indexer will not start without it:

```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

## 2 ☐ Verify before changing anything

`WazuhStartup.md` §6. This is a separate step, not part of step 1 — the whole
point is to establish the starting state rather than remember it.

```bash
sudo /var/ossec/bin/agent_control -l        # want: Active, not Disconnected
```
```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 40
```

**Count the channels. You should see FOUR, not three:**

```text
Analyzing event log: 'Application'.
Analyzing event log: 'Security'.                          <- audit policy lands here
Analyzing event log: 'System'.
Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.   <- often MISSING
```

`Application`, `Security` and `System` are the stock Wazuh agent defaults.
**Sysmon is not** — it has to be added to the agent's `ossec.conf` by hand, and
if nobody did, Sysmon is running and writing to its own channel while Wazuh
ignores it entirely. That matches the finding in `component6_isolation_forest.md`
that no Sysmon telemetry has ever appeared in a capture.

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "<location>"
Get-Service *Sysmon*
```

If the Sysmon channel is absent, **decide now, before T0** — adding it later is a
segment boundary that splits the baseline. Add this inside `<ossec_config>` in
`C:\Program Files (x86)\ossec-agent\ossec.conf`, then `Restart-Service WazuhSvc`
and re-check the log:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Worth knowing before you decide: most Sysmon rules sit at level 0 and never reach
`alerts.json`, so this will not transform the alert rate — the audit policy in §3
is what does that. It matters for two other reasons. The report describes Sysmon
as a telemetry source, which has to be true or be corrected; and the Phase 3
attack emulation leans on the Sysmon rules that *do* fire at level 3+. Including
it costs nothing now and is impossible to add later without restarting the
baseline.

If the `Security` line itself is absent, fix that first — same file, same
restart. Without it the audit-policy work in §3 produces nothing.

## 3 ☐ Enable audit policy

Windows does not write logon or process-creation events unless asked. Without
this the `user` and `srcip` entities never resolve and the behavioural alert rate
stays near zero.

**PowerShell as Administrator:**

```powershell
auditpol /set /subcategory:"Logon"            /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"           /success:enable
auditpol /set /subcategory:"Special Logon"    /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

Each prints `The command was successfully executed.` It takes effect immediately;
no reboot.

**Make sure command-line capture is OFF.** The conventional advice is to turn it
on. This project does not use it — none of the fifteen features touches alert
content — and 4688 command lines are the most sensitive field in the whole
capture:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
```

**Verify:**

```powershell
auditpol /get /category:"Logon/Logoff"
auditpol /get /subcategory:"Process Creation"
```

Every line you enabled should read `Success` or `Success and Failure`. If one
still says `No Auditing`, Group Policy is overriding `auditpol` — check
`secpol.msc` → Advanced Audit Policy Configuration.

## 4 ☐ Confirm end-to-end, and record the rule IDs

Ctrl+Alt+Del → **Sign out**, then sign back in. (Lock/unlock is not enough — you
want a real 4624 logon.)

**Watch `alerts.json`, not the dashboard.** The dashboard reads the indexer; the
prioritisation layer reads `alerts.json`. Those are different pipelines and only
the second one matters.

### Where the JSON actually lives

Everything is on the **manager side, in WSL** — the Windows agent forwards events
and keeps no alerts of its own. All of it needs `sudo`: `/var/ossec/logs` is
`wazuh:wazuh` mode 0750.

| Path | What it is |
|---|---|
| `/var/ossec/logs/alerts/alerts.json` | **today**, live, one JSON object per line (JSON-lines, not a JSON array) |
| `/var/ossec/logs/alerts/alerts.log` | the same alerts as plain text — easier to eyeball, not the input |
| `/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz` | every previous day. **These are the corpus** |
| `/var/ossec/logs/archives/archives.json` | every event whether or not a rule matched. Off by design — should not exist |
| `/var/ossec/logs/ossec.log` | the manager's own diagnostics. Not alert data |

`alerts.json` is rotated daily by `wazuh-monitord`, so yesterday's alerts are
**not** in it. A month of collection is ~30 gz files, not one file.

```bash
bash tools/watch_alerts.sh --where     # what exists, how big, threshold, agents
bash tools/watch_alerts.sh --last 20   # last 20 alerts, one readable line each
bash tools/watch_alerts.sh             # live tail -- use this for the test logon
```

Raw equivalents, if you would rather not use the helper:

```bash
sudo ls -la /var/ossec/logs/alerts/
sudo wc -l /var/ossec/logs/alerts/alerts.json
sudo tail -n 1 /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
sudo tail -f /var/ossec/logs/alerts/alerts.json
sudo zcat /var/ossec/logs/alerts/2026/Sep/ossec-alerts-10.json.gz | head -1 | python3 -m json.tool
```

**An empty or missing `alerts.json` is not automatically a fault.** Wazuh writes
only rules at level >= 3, and most Sysmon process-creation rules are level 0. If
nothing appears, check the threshold and the agent state before assuming
something is broken — `--where` prints both:

```bash
sudo grep -A4 "<alerts>" /var/ossec/etc/ossec.conf    # <log_alert_level>, leave at 3
sudo /var/ossec/bin/agent_control -l                  # Active, not Disconnected
```

Do not edit, truncate or delete anything under `/var/ossec/logs/alerts/` once
collection starts. Read it, copy it, never modify it.

**Record the rule id, level and description** for 4624 / 4625 / 4688 into
`COLLECTION_RECORD.md` A.4. Observed, not assumed — the docs are not evidence for
your install. To see what your ruleset maps:

```bash
sudo grep -rn "4624\|4625\|4688" /var/ossec/ruleset/rules/ | head -40
```

> **This alert's timestamp is not T0.** It is the proof the chain works. T0 is set
> in step 8.

## 5 ☐ Auto-start, both sides

`WazuhStartup.md` §5. A service that does not come back after a reboot puts a gap
in the baseline, and gaps that correlate with time of day are the damaging kind.

```bash
sudo systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard
```
```powershell
Set-Service WazuhSvc -StartupType Automatic
```

**`systemctl enable` is not sufficient on WSL** — the distro does not launch when
Windows boots. It starts when something first touches it:

```powershell
$action  = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d Ubuntu -u root /bin/true"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "Start WSL Ubuntu" -Action $action -Trigger $trigger -RunLevel Highest
```

### 5a The 3am problem — read this, it is the most likely way to lose data

That task fires **at logon**. A desktop running 24/7 will take an unattended
Windows Update reboot in the small hours and then sit at the lock screen with
nobody logged in. WSL never starts, the manager never starts, and the baseline
loses everything until you next sit down at it — a multi-hour hole at exactly the
hours that continuous uptime was supposed to buy you. It is also the kind of gap
that recurs on a monthly cadence, so the model would learn it.

`-AtStartup` does not fix it on its own: WSL distros are registered per Windows
user, so a task running as `SYSTEM` has no `Ubuntu` to start.

### The test

**Do step 6 (`powercfg /h off`) first.** With fast startup on, "shut down" is a
partial hibernate, so the machine never really boots and the test measures
nothing.

1. **Restart** the machine (Start -> Restart). A full shutdown then power-on
   works equally well.
2. **Do NOT log in. Wait five minutes at the lock screen.** This is the entire
   test -- it is the 3am update reboot with nobody sitting there. Logging straight
   in makes boot time and logon time indistinguishable and the test always
   "passes".
3. Log in, then collect three timestamps:

```powershell
# Windows: when the machine actually booted
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```
```bash
# WSL: when the distro started, and when the manager came up
uptime -s
systemctl show wazuh-manager -p ActiveEnterTimestamp
```

### Reading it -- `uptime -s` is NOT the Windows boot time

This is the trap. `uptime -s` inside WSL reports when the **WSL virtual machine**
started, not when Windows booted. If the distro only starts at logon, then
`uptime -s` and `ActiveEnterTimestamp` will both sit at your logon time and
**match each other perfectly** -- which looks like a pass and is a failure. The
Windows `LastBootUpTime` is the only valid reference point.

| Comparison | Verdict |
|---|---|
| `uptime -s` within ~2 min of `LastBootUpTime` | **PASS** -- the distro came up without a logon |
| `uptime -s` ~5+ min after `LastBootUpTime` (i.e. at your logon) | **FAIL** -- logon-gated. Go to option 1 |
| `uptime -s` fine but `ActiveEnterTimestamp` empty or much later | distro starts, manager does not. Different fault -- check `systemctl is-enabled wazuh-manager` |

One prerequisite the task relies on: systemd must be enabled in the distro, or
`systemctl enable` does nothing at boot. You are already using `systemctl`
successfully so it is almost certainly on, but confirm:

```bash
cat /etc/wsl.conf        # wants a [boot] section with systemd=true
```

**Options, best first:**

1. **Task runs whether or not you are logged on, at startup.** Register it under
   your own account with stored credentials, so it has a user context for WSL to
   resolve:

   ```powershell
   $action  = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d Ubuntu -u root /bin/true"
   $trigger = New-ScheduledTaskTrigger -AtStartup
   Register-ScheduledTask -TaskName "Start WSL Ubuntu (boot)" -Action $action -Trigger $trigger `
     -User "$env:USERDOMAIN\$env:USERNAME" -Password (Read-Host -AsSecureString "Windows password" |
       ForEach-Object { [Runtime.InteropServices.Marshal]::PtrToStringAuto(
         [Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }) -RunLevel Highest
   ```

   Then re-run the test above. If WSL still will not start without an
   interactive session, fall through to option 2.

2. **Enable automatic logon** so a session always exists after a reboot
   (`netplwiz`, uncheck "Users must enter a user name and password", or the
   `AutoAdminLogon` registry values). Combined with a lock screen on a timer this
   is a modest trade on a lab machine and it makes the `-AtLogOn` task correct.

3. **Constrain when reboots happen.** Set Windows Update active hours so restarts
   land while you are present. Weakest option — it only narrows the window, and
   a forced restart still overrides it.

Whichever you pick, keep the weekly downtime check as the backstop, and record
the choice in `COLLECTION_RECORD.md` Part B.

**Then verify by actually rebooting**, twice: once logging straight in, once
leaving it alone for five minutes first. `agent_control -l` after each.

## 6 ☐ Power — desktop

The host is a desktop (`ChassisTypes = 3`) and will run continuously. That is the
best thing that has happened to this collection plan; protocol §2 is rewritten
around it.

```powershell
# hibernate + fast startup off. Fast startup makes "shutdown" a partial
# hibernate; reboots during a month-long collection should be clean.
powercfg /h off

# confirm the idle sleep timeout really is Never (0x00000000)
powercfg /q SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Select-String "Power Setting Index"

# what sleep states the machine even has
powercfg /a
```

**Network adapter power management — do this one.** On a machine that now sits
idle overnight, Windows powering down the NIC drops the agent's connection to the
manager and produces exactly the kind of gap that §2.3 of the protocol now treats
as a fault:

Device Manager → Network adapters → your NIC → Properties → **Power Management**
→ uncheck *Allow the computer to turn off this device to save power*.

**Not applicable on this chassis:** anything about lids. `powercfg /q
SCHEME_CURRENT SUB_BUTTONS LIDACTION` returns nothing because a desktop has no
lid switch and Windows hides the setting — that is correct output, not an error,
and "Choose what closing the lid does" is absent from Control Panel for the same
reason.

**Not relevant: "Turn off hard disk after".** A spin-down timer from the
mechanical-disk era. On NVMe it does nothing meaningful, any write wakes the
device, and it cannot produce a gap in the alert stream. Leave it alone.

## 7 ☐ Retention — two separate things

### 7·0 Which drive is actually under pressure — check this first

The "~50 GB free" figure in the project notes is the **project volume**, and it
is almost certainly not where the pressure is. What fills up is whichever drive
holds the **WSL2 virtual disk** (`ext4.vhdx`), because that is where
`/var/ossec` lives — the manager, `alerts.json`, the rotated `.gz` files and the
indexer. **Confirmed on this machine 2026-09-12: `C:\Users\User\AppData\Local\wsl\{9d7f19c9-...}`
— the drive under pressure is C:.** Space on a games drive is irrelevant unless
the vhdx is moved there. Note the path: modern WSL stores distros under
`%LOCALAPPDATA%\wsl\{guid}`, *not* the older
`%LOCALAPPDATA%\Packages\CanonicalGroupLimited...`. The registry query below is
the reliable way to find it; searching for `ext4.vhdx` under `Packages` misses.

Find it, then read the free space on that drive:

```powershell
Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss |
  ForEach-Object { $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{ Distro = $p.DistributionName; Path = $p.BasePath } }

Get-PSDrive -PSProvider FileSystem |
  Select-Object Name, @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}}
```

```bash
df -h /            # what the distro sees inside the vhdx
du -sh /var/ossec/logs /var/lib/wazuh-indexer 2>/dev/null
```

**Rough sizing, so nobody deletes anything prematurely.** Rule 67027 uses
`no_full_log`, so process-creation alerts are compact. At 30k admitted
alerts/day: `alerts.json` is roughly 25 MB/day raw and 2–3 MB/day once rotated
and gzipped — under half a gigabyte for the whole 36-day collection. The indexer
is the hog at roughly 3 KB/alert, but a 14-day ISM policy caps it at a couple of
gigabytes steady-state. Even at 100k alerts/day the whole thing sits in single-
digit GB **with retention configured**.

So 50 GB is comfortable. The danger is not a full drive, it is an **unbounded
index** growing for five weeks because 7a was skipped. Configure retention, then
read the free-space line at each weekly check and act only if it actually moves.

**The gotcha that makes ordering matter: a WSL2 vhdx grows and does not shrink.**
It is a dynamically expanding disk. If the indexer balloons it to 40 GB and you
then delete every index, the vhdx keeps the 40 GB -- the space does not come back
on its own. Reclaiming it means `wsl --shutdown` followed by a `diskpart` compact
(or `Optimize-VHD`, which needs the Hyper-V module and is absent on Home), and
that is a mid-collection outage you do not want.

So retention is configured **before** volume ramps, not after it looks large.
That is today, before T0, and it is why step 7 is not last.

Recent WSL versions also offer `wsl --manage Ubuntu --set-sparse true`, which
lets the vhdx release space automatically. Check `wsl --version` first, and treat
it as a **pre-T0 change only** -- it rewrites the disk, so it is not something to
do while collecting.

**If C: turns out genuinely tight** (under roughly 30 GB free), the answer is not
deleting anything -- move the distro to the roomier drive:

```powershell
wsl --shutdown
wsl --export Ubuntu D:\ubuntu.tar
wsl --unregister Ubuntu
wsl --import Ubuntu D:\WSL\Ubuntu D:\ubuntu.tar
```

It takes a while, it resets the default user (set it again in
`/etc/wsl.conf`), and it **must happen before T0** -- mid-collection it is a
multi-hour gap and a changed environment fingerprint. Decide from the free-space
number, today.

### 7a Indexer indices (disk pressure)

The indexer is a dashboard convenience. Nothing in the pipeline reads it, so
deleting old indices is free. **~50 GB free on a 90%-full volume is not enough
for a month of unbounded indices.**

Create an ISM policy that deletes `wazuh-alerts-*` after 14 days:

```bash
curl -sk -u admin:<Pass.txt> -X PUT \
  "https://127.0.0.1:9200/_plugins/_ism/policies/wazuh_alerts_14d" \
  -H 'Content-Type: application/json' -d '{
  "policy": {
    "description": "ContextAwareSIEM: delete wazuh alert indices after 14 days",
    "default_state": "hot",
    "states": [
      {"name": "hot", "actions": [],
       "transitions": [{"state_name": "delete",
                        "conditions": {"min_index_age": "14d"}}]},
      {"name": "delete", "actions": [{"delete": {}}], "transitions": []}
    ],
    "ism_template": [{"index_patterns": ["wazuh-alerts-*"], "priority": 100}]
  }
}'
```

Password: `~/ContextAwareSIEM/wazuh-install-files/wazuh-passwords.txt` in WSL, or
`sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt`.

**`ism_template` only attaches to indices created *after* this point.** Attach it
to the ones that already exist:

```bash
curl -sk -u admin:<Pass.txt> -X POST \
  "https://127.0.0.1:9200/_plugins/_ism/add/wazuh-alerts-*" \
  -H 'Content-Type: application/json' \
  -d '{"policy_id":"wazuh_alerts_14d"}'
```

Or: Dashboard → Indexer management → Index Management → Indices → select →
Actions → Apply policy.

### 7b `alerts.json` rotation — **this one can eat your baseline**

`wazuh-monitord` rotates `alerts.json` daily into
`/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz`. Those `.gz` files
**are** the baseline corpus.

The shipped default is `monitord.keep_log_days=31`. Your collection window is
11 Sep → 17 Oct — **36 days**. Check what your install is set to:

```bash
# sudo is required -- /var/ossec/etc is wazuh:wazuh 0750. Without it you get
# "Permission denied", and with 2>/dev/null you get SILENCE, which reads exactly
# like "no such setting". Never redirect stderr on a first look at these files.
sudo grep -n "monitord" /var/ossec/etc/internal_options.conf
sudo ls -la  /var/ossec/etc/local_internal_options.conf
sudo grep -n "monitord" /var/ossec/etc/local_internal_options.conf
```

Record the shipped `keep_log_days` value you find, then override it.
`keep_log_days` = 31 (before overriding)

Raise it well past the collection window — edit `local_internal_options.conf`,
not `internal_options.conf`, because the latter is overwritten on upgrade:

```bash
echo 'monitord.keep_log_days=120' | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager

# verify both that the line landed and that the manager came back
sudo grep -n "monitord" /var/ossec/etc/local_internal_options.conf
systemctl is-active wazuh-manager
```

`local_internal_options.conf` may not exist yet; `tee -a` creates it. Restarting
the manager here is safe -- this is all pre-T0.

**Belt and braces — copy the rotated files out weekly regardless:**

```bash
sudo rsync -a --prune-empty-dirs \
     --include='*/' --include='ossec-alerts-*.json.gz' --exclude='*' \
     /var/ossec/logs/alerts/ "$HOME/baseline_archive/"
sudo chown -R "$USER:$USER" "$HOME/baseline_archive"
find "$HOME/baseline_archive" -name '*.gz' | sort
```

Three things this gets right, each of which bit an earlier version of this
command:

1. **No shell glob in the source path.** `rsync -a /var/ossec/logs/alerts/*/*/...`
   fails with "Permission denied" even under `sudo`, because the *shell* expands
   the glob before the command runs and your shell is `user`, which cannot read
   that directory. Handing rsync a single readable root and letting it recurse as
   root avoids the problem entirely.
2. **The directory structure is preserved.** Rotated files are named by
   day-of-month only, so copying them into one flat folder makes
   `2026/Oct/ossec-alerts-04.json.gz` collide with
   `2026/Sep/ossec-alerts-04.json.gz` -- and a no-clobber copy then skips the
   October file *silently*. A baseline that crosses a month boundary, as this one
   does, would lose up to half its archive with no error.
3. **`chown` after.** Anything written under `sudo` lands root-owned and you
   cannot manage it afterwards.

`rsync -a` skips unchanged files, so the weekly re-run is cheap and idempotent;
rotated `.gz` files never change once written.

Five seconds a week against losing the start of the baseline. Do it.

## 8 ☐ Set T0, snapshot, and open the record

Everything above changed the generating process. **Now** the clock starts.

1. Note the time to the next whole minute. That is T0. Write it into
   `COLLECTION_RECORD.md` A.1 in both `+07:00` and UTC.
2. Take both provenance snapshots:

```bash
cd /mnt/c/Personal/UniStuff/Project/ContextAwareSIEM
bash tools/collect_provenance.sh T0
```
```powershell
cd "C:\Personal\UniStuff\Project\ContextAwareSIEM"
powershell -ExecutionPolicy Bypass -File .\tools\collect_provenance.ps1 -Label T0
```

3. **Check three values immediately** (each one silently ruins a month):
   - `utc_offset_h` = `7.0` in both, matching `SITE_UTC_OFFSET_H` in
     `tools/window_builder.py`. This already caused one real bug.
   - `ProcessCreationIncludeCmdLine_Enabled` = 0 or unset.
   - The endpoint agent log contains `Analyzing event log: 'Security'`.
4. Transcribe the environment fingerprint into `COLLECTION_RECORD.md` A.3, the
   rule IDs into A.4, the `auditpol /get` output into A.5.
5. Log row 1 of Part B: T0, "audit policy enabled", starts segment 1.

---

## Then stop touching it

Phase 1 runs 11–18 Sep with **no configuration changes at all**. Every tuning
impulse goes into `COLLECTION_RECORD.md` Part B as a proposal, not into the
config.

Two readings:

```bash
# 14 Sep, ~72 h — early warning. A catastrophic rate leaves you 4 days to react.
# 18 Sep — the real gate.
zcat $(ls /var/ossec/logs/alerts/*/*/ossec-alerts-*.json.gz 2>/dev/null) \
     /var/ossec/logs/alerts/alerts.json > ~/baseline_corpus.json
cd /mnt/c/Personal/UniStuff/Project/ContextAwareSIEM
python3 tools/baseline_check.py ~/baseline_corpus.json \
        --since "<T0>" --label wk1 --json provenance/gate/wk1.json
```

`--since` is not optional. Without it the projection counts pre-T0 alerts and is
wrong in your favour.
