# Handoff: VM benign baseline — build, enroll, collect

*Written 2026-09-30 from the main ContextAwareSIEM design session. Self-contained:
a session picking this up needs nothing else from that conversation. When this
work is done, report back with the items in §9 and the main session continues
from there.*

---

## 0. How to work in this repo

- Project folder on Windows: `C:\Personal\UniStuff\Project\ContextAwareSIEM`.
  In WSL, `~/ContextAwareSIEM` is a **symlink** to it: one copy, no syncing.
- Claude's `device_bash` is a sandboxed Linux shell over the connected folder.
  It is **not** a Windows shell and **not** the WSL distro: it cannot run
  PowerShell, `wsl.exe`, `sudo` or anything under `/var/ossec`. The user runs
  those and pastes the output.
- Git writes from `device_bash` need `device_request_delete_permission` on the
  folder first, or git leaves a stale `.git/index.lock`.
- Credentials live in WSL `~/wazuh-setup` (`Pass.txt`,
  `wazuh-install-files.tar`). Never copy them into the repo, which is submitted.
  Never ask the user to paste them.
- Read first, in this order: `COLLECTION_RECORD.md` (Parts A, B, D.1),
  `system_model.md` §4.1.3, §4.2.3, §4.2.6.2, §6, and `baseline_collection_protocol.md` §8.

## 1. Why the VM baseline exists

Attack emulation (Phase 3, late October, two disjoint sessions A and B) runs on
a VM, never on the Windows host, which is a daily-driver machine. The anomaly
model (Isolation Forest, one per entity type) is trained on a **benign**
baseline.

**If the VM emits alerts only during attack sessions, "came from the VM" becomes
a perfect proxy for "is an attack".**
- Every VM alert gets `novel_rule_flag = 1`.
- Every VM window looks unfamiliar to the model.
- System B2 would beat B1 by recognising the machine, not the behaviour, and
  the project's headline result would be an artifact.

Two requirements follow, and both are non-negotiable:

1. **A benign VM baseline** in the training data, collected before Session A.
2. **Benign VM background during the emulation sessions**, driven the same way,
   so VM alerts labelled benign exist in the evaluation stream.

Even with a baseline, VM windows will be a small minority of host-type training
windows, and Isolation Forest scores rarity. The planned fix is **per-host
percentile calibration**: one shared host-type forest, with the calibration table
fitted per machine on that machine's own benign windows. This is a proposal from
the design session and not yet written into `system_model.md`. It sets the
volume target below.

## 2. Targets

| Quantity | Target | Why |
|---|---|---|
| Benign VM training windows at stride 10 | **≥ 1,000** | Stable per-host percentile table: the standard error at the 95th percentile is under 1 point at n = 1,000 |
| Admitted VM alerts | **≈ 10,000** | = 1,000 windows × stride 10 |
| Behavioural modes covered | boot, logon/logoff, idle, Windows Update, admin shell (cmd + PowerShell), software install, the benign workload of §6 | Coverage, not row count, is what the model needs. Withholding one mode in simulation cost up to −0.208 AUC (Patch Tuesday) |
| VM baseline end | **before Session A** (late Oct) | Not tied to the host freeze on 17 Oct. It only has to precede emulation |

Time to target depends on the VM's alert rate, which is unknown until it runs.
At 100–300 admitted alerts per VM-hour that is 30–100 VM-hours. The VM runs only
while the host is on, about 9 h/day, so budget **4–12 days**. **Measure the rate
at 48 h (§7) and re-plan from the number.**

## 3. Fixed constraints — do not change these

These are settled decisions. Changing any of them breaks the premise of the
project or the host baseline, which is **being collected right now**.

- **Do not touch the host's Wazuh agent** (agent `002`, `windows11-host`
  re-enrolled as "TestRun1"; `001` is its retired id). Do not run the Wazuh
  installer, `agent-auth` or any enrollment command on the host. **On 27 Sep the
  host agent was re-enrolled by accident and silently dropped out of the corpus
  for three days.** Run every enrollment command inside the VM only.
- **Do not edit the manager's `/var/ossec/etc/ossec.conf`, the ruleset, or
  `log_alert_level`.** Any of these is a segment boundary for the host corpus
  (COLLECTION_RECORD Part B). If manager-side networking genuinely cannot work
  without an edit, stop and record it in Part B with before/after hashes. Do not
  just do it.
- **Never lower `log_alert_level` below 3 and never enable `logall`/`logall_json`.**
  The layer prioritises what a stock Wazuh produces.
- **Wazuh agent v4.14.7** on the VM, matching the manager and host.
- **Same Sysmon binary and config as the host:** `tools/sysmon/Sysmon64.exe` +
  `tools/sysmon/sysmonconfig-export.xml`. Record the config SHA-256; the host's
  is `055FEBC6…` (COLLECTION_RECORD A.3).
- **Same audit policy as the host**, and **command-line capture OFF**
  (`ProcessCreationIncludeCmdLine_Enabled` absent or 0). The pipeline is
  content-blind by design (system_model §4.2.8).
  - Logon: Success and Failure
  - Logoff: Success
  - Special Logon: Success
  - Account Lockout: Success
  - Network Policy Server: Success and Failure
  - Process Creation: Success
  - everything else in Logon/Logoff and Detailed Tracking: No Auditing
- **Verify every audit subcategory with `auditpol /get` in an elevated shell.**
  Trap already hit on the host: `auditpol /set` in a non-elevated shell fails
  with `0x00000522`, easy to miss. Logon alerts still fire because Windows
  audits logons by default, so they do not prove the policy applied.
- **The VM agent's `ossec.conf`:** start from the host agent's
  (`C:\Program Files (x86)\ossec-agent\ossec.conf`, SHA-256 `278DBA62…`) and
  change **only** the manager `<address>` and whatever enrollment needs. Record
  the diff. It must collect the same four eventchannels: Application, Security,
  System, Microsoft-Windows-Sysmon/Operational.

## 4. Decisions this session must make (and record)

Each goes into the VM record (§8) with a date and reason. Anything that differs
between the baseline and the emulation sessions is a confound, so **every choice
here must hold unchanged through Sessions A and B**.

1. **Guest OS.** Recommended: **Windows 11 Enterprise, 90-day evaluation**
   (free from Microsoft). It shares the host's rules and decoders, so its windows
   are comparable. A 90-day licence installed in early October outlasts the
   November deadline. A Linux VM would share no rules with the host baseline, so
   every alert would be novel by construction; only choose it with a reason.
2. **Hypervisor.** The host is **Windows 11 Home**, so Hyper-V Manager is not
   available. Candidates are VirtualBox 7 or VMware Workstation Pro (free for
   personal use). Both run alongside WSL2 via the Windows Hypervisor Platform,
   more slowly. Windows 11 needs TPM 2.0 and Secure Boot: VirtualBox 7 provides
   both. The hypervisor install creates services and drivers on the **host**, so
   log it in COLLECTION_RECORD **C.2** with a timestamp. It is normal software
   installation, not a config change.
3. **Where the VM disk lives.** C: had **56.6 GB free** on 30 Sep. A 64 GB
   dynamic disk can fill it, and the documented act-now threshold is 25 GB. Use
   another drive if one exists; otherwise cap the disk at ~40 GB and watch C: in
   every weekly check.
4. **Network and isolation.** The system model says "isolated network". Trade-off:
   - Internet access means Windows Update runs, which is a behavioural mode the
     baseline needs, but less isolation.
   - A host-only network is fully isolated, but the VM has no update mode and a
     less realistic baseline.

   Recommended: NAT for internet, plus VM-side Windows Firewall outbound blocks
   to private ranges except the manager. Either way it must be **identical in
   baseline and emulation**.
5. **How the VM reaches the manager.** The manager runs inside WSL2. The host
   agent reaches it at `127.0.0.1:1514` via localhost forwarding, which does not
   help a VM. Options:
   - (a) **WSL mirrored networking** (`networkingMode=mirrored` in
     `%UserProfile%\.wslconfig`). WSL then listens on the host's interfaces. It
     needs `wsl --shutdown`, which is a short deliberate manager outage: log it in
     C.1. Check afterwards that agent `002` reconnects (`--status`).
   - (b) **`netsh interface portproxy`** from the host's VM-facing IP to the WSL
     IP, for 1514/tcp and 1515/tcp. The WSL IP changes on every boot, so this
     needs a boot-time task to refresh it. That is the same failure class as the
     3 a.m. autostart trap in `PHASE0_RUNBOOK.md`.

   Either way, add Windows Firewall inbound rules on the host for 1514/1515 on the
   VM-facing interface only. Test from the VM with
   `Test-NetConnection <host-ip> -Port 1514` before installing the agent. Check
   how enrollment is secured first:
   `sudo grep -n -A8 '<auth>' /var/ossec/etc/ossec.conf`. **Read only; do not edit.**
6. **Windows Defender on the VM.** Atomic Red Team payloads get quarantined by
   real-time protection. Whatever state is chosen (on, off, or folder exclusions)
   is set **before VM T0** and kept through both sessions. Defender behaviour is
   part of what generates alerts.
7. **When to install the emulation tooling** (Invoke-AtomicRedTeam and atomics).
   Installing it produces alerts. Recommended: install **after** the VM baseline
   ends and before Session A, and treat the install as burn-in. Executing any
   atomic before the baseline freezes contaminates it.
8. **Agent name.** Something unambiguous, for example `vm-win11-target`. Never a
   test-style name like the host's accidental "TestRun1".

## 5. Build sequence

1. Record the decisions of §4. Check host RAM (`Get-CimInstance
   Win32_ComputerSystem | Select TotalPhysicalMemory`). WSL, the indexer and a
   Windows VM together need headroom: give the VM 4–6 GB only if the host has
   at least 16 GB.
2. Install the hypervisor and log it in C.2. Create the VM, install the guest OS,
   and apply Windows updates **before** T0. The first-install update storm is not
   normal behaviour.
3. Networking per §4.5. Verify with `Test-NetConnection` from the VM.
4. In the VM (elevated): apply the audit policy, verify each subcategory with
   `auditpol /get`, and confirm command-line capture is off. Install Sysmon with
   the project config.
5. In the VM: install Wazuh agent 4.14.7 pointing at the host's VM-facing IP,
   with the agent name from §4.8. Then check on the manager:
   `sudo /var/ossec/bin/agent_control -l`. Expected: `002` **still Active**, plus
   a new id (probably `003`) Active. If `002` changed state, stop.
6. Provenance: run `tools/collect_provenance.ps1` **inside the VM**. Record the
   Sysmon config hash, the agent `ossec.conf` hash and diff, the OS build, and the
   Defender state.
7. **Take a hypervisor snapshot** of the clean, configured VM. Name it and record it.
8. Set up the benign workload (§6) and VM autostart. The VM should start
   automatically when the host is on, for example a logon task running
   `VBoxManage startvm "<name>" --type headless`.
9. **Record VM T0**, the moment the configured VM starts its baseline. Nothing
   before T0 counts.

## 6. The benign workload

Nobody uses the VM interactively, so its "normal" has to be produced
deliberately. That is acceptable **only if the same workload also runs during
Sessions A and B** as their benign background, and is documented.

A scheduled task inside the VM (for example every 20–40 minutes with jitter)
running a randomised mix:
- a local account signing out and in (logon/logoff/special-logon events);
- ordinary cmd and PowerShell commands (`dir`, `Get-Process`, `ipconfig`, file
  copies);
- opening applications (Notepad, Explorer, a browser to a fixed benign page if
  networking allows);
- occasional `winget` or software install or uninstall of a small benign package;
- idle periods.

Plus Windows Update left on its normal schedule, and reboots (the VM restarts
when the host does).

**Commit the script to the repo** (for example `tools/vm_benign_workload.ps1`)
and record its SHA-256. Changing it mid-baseline is a VM segment boundary.

## 7. Measurement

The host tooling filters to agents `001,002`, so VM alerts never enter the host
corpus. **Keep it that way.** Do not add the VM's id to `AGENT` in
`tools/weekly_check.sh`, and do not add it to `HOST_ALIASES` in
`tools/window_builder.py`: the VM is a different machine.

`weekly_check.sh` step 1 already assembles every agent into
`~/baseline_corpus.json`. For the VM, run the gate on that corpus with the VM's
id and T0:

```bash
cd ~/ContextAwareSIEM && bash tools/weekly_check.sh adhoc      # (re)assembles the corpus; its host reading is labelled adhoc
python3 tools/baseline_check.py ~/baseline_corpus.json \
        --since <VM_T0 as YYYY-MM-DDTHH:MM> --agent <vm id> \
        --label vm-48h --json provenance/gate/vm-48h.json
```

Read against §2: admitted alerts per awake hour, projected days to ~10,000
admitted alerts (host-window pool × 10), feature population (anything constant?),
and entity resolution. The workload's local account should resolve as `user`.

- **48 h after VM T0:** first rate reading. Re-plan the end date from it. If the
  rate is too low for §2 before late October, raise the workload frequency. That
  is a documented change, and the same frequency must then run in the sessions.
- **Weekly** until the end: the same command plus a mode-coverage check. Did a
  Windows Update, a reboot and an install each happen?
- **Before the VM baseline ends:** confirm ≥ 1,000 windows at stride 10, then
  record the end timestamp and the corpus SHA-256.

## 8. Record keeping

Add a new part to `COLLECTION_RECORD.md`, **"Part G — VM baseline"**, with:

- G.1 decisions of §4, dated;
- G.2 environment fingerprint: OS build, hypervisor and version, VM resources,
  agent id and name, agent version, Sysmon config hash, agent `ossec.conf` hash
  and its diff against the host's, audit policy (`auditpol /get` output),
  Defender state, network mode, snapshot name, workload script hash;
- G.3 VM T0;
- G.4 change log (VM segment boundaries);
- G.5 gate readings (48 h, weekly, final);
- G.6 VM baseline end and corpus hash.

Log host-side events in the existing parts: the hypervisor install in **C.2**, any
WSL restart in **C.1**, and — only if unavoidable — any manager config change in
**Part B**, with hashes.

## 9. Report back to the main session

When the VM is collecting and the 48 h reading is in:

1. OS, hypervisor, network mode and how the manager is reached;
2. the VM agent id and name, and confirmation that agent `002` stayed Active
   throughout;
3. VM T0, and the 48 h rate reading (admitted alerts per awake hour, projected
   date for ~10,000 admitted alerts);
4. the Defender state and the tooling-install plan (§4.6, §4.7);
5. the workload script path and hash;
6. anything that touched the host or manager config, with the record entries.

The main session then updates Deliverable 3 (`References/Deliverable3_ContextAwareSIEM.tex`):
§7 deployment view, §6.1 benign activity, §9.2 item 3 (VM baseline), and adds
per-host calibration to §4.3.4.

## 10. Dates

| When | What |
|---|---|
| by ~3 Oct | VM built, enrolled and collecting (VM T0) |
| Sat 3 Oct night | Host awake night 1: leave the host on, and the VM with it |
| T0 + 48 h | First VM rate reading; re-plan |
| Wed 7 Oct night | Host awake night 2 |
| Tue 13 Oct night | Patch Tuesday: host and VM both on overnight. The VM gets its update mode too |
| 17 Oct | **Host** baseline freeze (the VM continues) |
| before Session A (late Oct) | VM baseline end; then tooling install, burn-in, Session A |
