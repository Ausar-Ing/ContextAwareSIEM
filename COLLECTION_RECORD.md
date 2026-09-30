# Collection Record — ContextAwareSIEM

**This file is the dataset's provenance. It is the difference between a Dataset
section you can write in November and one you have to apologise for.**

Opened 2026-09-11. Append-only: never rewrite a past entry, strike it through and
add a correction. Companion to `baseline_collection_protocol.md` (what to do) and
`WazuhStartup.md` (how to run the lab).

Fill Part A **today**, before the first alert is collected. Everything else
accrues.

---

## Why this file exists

`system_model.md` §6.2 assumes baseline and evaluation data come from **the same
generating process**. That assumption is the load-bearing one in the whole
evaluation: percentile calibration is fitted on the baseline and applied at
evaluation, so if the generating process changed halfway through, the calibration
is fitted on one distribution and applied to another and every reported number is
meaningless.

Nothing in the alert stream tells you the process changed. Only this file does.

A reviewer's question you must be able to answer: *"How do you know your
baseline and evaluation data are comparable?"* The answer is Part A + Part B, or
there is no answer.

---

# PART A — The frozen record (fill today, Phase 0)

## A.1 Collection epoch

| | |
|---|---|
| **T0 — audit policy enabled** | `____-__-__ __:__ +07:00` |
| T0, UTC | `____-__-__ __:__ Z` |
| Site UTC offset used in code | `+7.0` (`SITE_UTC_OFFSET_H`, `tools/window_builder.py`) |
| **Manager/host clock agreement** | **Verified in sync 2026-09-12** — `date -Iseconds` in WSL against `Get-Date -Format o` in Windows, difference within human command-entry latency. Every `alerts.json` timestamp originates in WSL, and WSL2 is known to drift after host sleep or shutdown, so this is re-checked at each weekly reading. Fix if it drifts: `sudo hwclock -s`. |
| Phase 1 gate reading due | 14 Sep (72 h, early warning) and 18 Sep (full week) |
| Planned T1 — baseline freeze | 17 Oct 2026 |

> **T0 is a hard boundary.** Alerts written before the audit-policy change come
> from a different generating process. Pass `--since <T0>` to
> `tools/baseline_check.py` on *every* run. A gate reading taken without it
> counts pre-T0 alerts and is wrong **in your favour** — it will tell you the
> design is fine when it is not.

## A.2 Provenance snapshots

Run both, today, immediately after the audit-policy change:

```bash
# WSL Ubuntu, from the project root
./tools/collect_provenance.sh T0
```
```powershell
# PowerShell as Administrator, from the project root
.\tools\collect_provenance.ps1 -Label T0
```

| Snapshot | File | Taken |
|---|---|---|
| Manager, T0 | `provenance/raw/T0_manager_20260912T131341.txt` | 2026-09-12 13:13 |
| Manager, T0 (superseded) | `provenance/raw/T0_manager_20260912T121421.txt` — four `sudo` bugs left config hashes, rotated-file listing, log sizes and rule-ID mappings blank. Kept for the audit trail; **use the 13:13 file.** | 2026-09-12 12:14 |
| Endpoint, T0 | `provenance/raw/T0_endpoint_20260912T121433.txt` | 2026-09-12 12:14 |
| Manager, T1 | | |
| Endpoint, T1 | | |

Raw snapshots are gitignored (they contain hostnames and usernames). Before
submission, copy the redacted headline values into `provenance/redacted/`.

**Three things to check the moment the snapshots land, because each one silently
destroys a month of collection:**

1. `utc_offset_h` in both snapshots equals `SITE_UTC_OFFSET_H = 7.0`. This
   already produced one real bug — `night_fraction = 1.0` on every window of the
   September capture.
2. `ProcessCreationIncludeCmdLine_Enabled` is `0` or unset. Protocol §7.2.
3. The endpoint agent log contains `Analyzing event log: 'Security'`. Without
   that line the audit policy produces nothing and you find out in a week.

## A.3 Environment fingerprint (transcribe from the snapshots)

| Component | Version / hash | |
|---|---|---|
| Wazuh manager | `v4.14.7` (revision `rc1`); packages `4.14.7-1` | indexer, manager, dashboard all active + enabled |
| Wazuh agent (Windows) | `v4.14.7` | `WazuhSvc` Running, StartType Automatic |
| Wazuh ruleset revision | no `VERSION` file shipped | identified by the aggregate hash below instead |
| `ossec.conf` (manager) SHA-256 | `77826ff6d386feb0febf9303ae118cee91295c56d3d8ed23a24d4e76092b170f` | |
| `local_internal_options.conf` SHA-256 | `a0e810eac07245edc08bf99936f19e04e7cb246fef565f555199d2638a0aada7` | holds `monitord.keep_log_days=120` |
| `internal_options.conf` SHA-256 | `2f434217b2f894a4cf3164ef6a1f4471d9196e5ad21f19c2e21c5be97b16e26a` | stock; overwritten on upgrade |
| `ossec.conf` (agent) SHA-256 | `278DBA62057017DE3907B2F886E2FFA4FC6097AB96548267F3CAEB8CEC334B84` | |
| Shipped ruleset, aggregate SHA-256 | `a385210169b48c3d677739a3b13c0951075c0610449984943beab7d943d97c5d` | |
| Local rules/decoders | **none** | stock ruleset only |
| Sysmon version | `15.21` | service Running, Automatic |
| Sysmon config + SHA-256 | `sysmonconfig-export.xml`, `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162` | |
| Windows build | Windows 11 Home Single Language, `10.0.26200` / `25H2` | |
| WSL kernel / distro | `6.18.33.2-microsoft-standard-WSL2` / Ubuntu 24.04.4 LTS | |
| `log_alert_level` | `3` | **stock default — never lower it** |
| `logall` / `logall_json` | `no` / `no` | `/var/ossec/logs/archives` exists at 32 KB and is empty — correct state with archives off |
| Python | `3.12.3` | |
| numpy | `1.26.4` | |
| scikit-learn | **NOT INSTALLED** | not needed for the gate; required for Component 6 |
| Repo commit at T0 | `075bf155c6ed47280a3cad18b58e08e82f2d4804` | working docs still untracked at T0 |
| `tools/window_builder.py` SHA-256 | `f89e5f542ead848fbce50b642c256d5c7032859ff65f3ac1961d333aab33bbb0` | post entity-resolution fix (A.10) |
| `tools/baseline_check.py` SHA-256 | `bd54372de209b6cc1a04922ca88a1945015c1a477ed28d5d6675d09ff8cf5345` | |

## A.4 Rule IDs actually observed for the audited events

Do not cite Wazuh documentation for these. Record what fires on *your* manager.

Observed 2026-09-11 22:16–22:36 on a sign-out / sign-in and a deliberate failed
logon. Confirmed end to end: the audit policy fires, the agent forwards, the
manager writes to `alerts.json`.

| Windows event | Wazuh rule id | Level | Description |
|---|---|---|---|
| 4624 successful logon | **60118** | 3 | Windows Workstation Logon Success |
| 4624, WEF ruleset | 67022 | 3 | Non network or service local logon |
| 4624, service account | 67024 | 3 | Service logon event from non standard service account |
| 4625 failed logon | **60122** | 5 | Logon Failure - Unknown user or bad password |
| 4634 logoff | 67023 | 3 | Non service account logged off |
| 4672 special privileges | 67028 | 3 | Special privileges assigned to new logon |
| **4688 process creation** | **67027** | 3 | A process was created (`0955-WEF-baseline_rules.xml`) |

A single sign-in produced a **burst of 10 alerts across 5 rule ids within one
second** (22:34:29) — multi-rule, single-entity, exactly the shape Component 5 is
built to window. Good news for feature population.

Sysmon is also producing level ≥ 3 alerts: 92052 (lvl 4, command prompt started
by an abnormal process) and 92307 (lvl 3, service creation in registry), both
triggered by the Phase 0 work itself.

**Resolved 2026-09-11 22:5x.** The first attempt at §3 did not take — `auditpol
/get` showed `Process Creation: No Auditing` despite the command having been run.
Re-run elevated, confirmed `Success`. **The logon alerts were not evidence the
audit policy worked**: Windows 11 audits Logon success and failure by default, so
60118/60122 would have fired regardless. Verify every subcategory, never infer
from one working.

Rule **67027, level 3, "A process was created"** exists in
`0955-WEF-baseline_rules.xml` — same WEF ruleset as the 670xx logon rules, which
are demonstrably active. So `component6_isolation_forest.md`'s claim that stock
Wazuh rules pick up 4688 at level 3+ **holds**. The volume estimate stands.

Two consequences to watch at the first gate reading:

1. **Expect a lot of volume.** 4688 at level 3 on a daily-driver desktop means an
   alert per process creation. This is likely to overshoot the ~2,200/day target
   rather than undershoot it, which makes step 7's retention work load-bearing
   rather than housekeeping.
2. **67027 carries no MITRE tags** (unlike 67028, which has T1484). If the bulk
   of the new volume is 67027, features 8–10 — `distinct_technique_count`,
   `distinct_tactic_count`, `tactic_progression` — may stay at zero even after
   the audit policy change. That is the §6 feature-population check; do not
   assume the MITRE features are recovered.

## A.7 Unattended-restart behaviour — measured, PASS

Runbook §5a exists because the WSL auto-start task fires `-AtLogOn`, and a 24/7
host takes unattended Windows Update restarts in the small hours with nobody
there to log in. Measured directly on 2026-09-12:

| Event | Time | Delta from boot |
|---|---|---|
| Windows boot (`Win32_OperatingSystem.LastBootUpTime`) | 11:13:35 | — |
| WSL distro started (`uptime -s`) | 11:14:03 | +28 s |
| `wazuh-manager` active (`ActiveEnterTimestamp`) | 11:14:33 | +58 s |

Restarted with no keypress; the whole chain came up in under a minute. The
28-second figure also proves the distro was already running before a terminal was
opened — had the task not fired, `uptime -s` would report whenever the terminal
was first opened, minutes later.

**Nothing blocks an unattended boot on this machine:** BitLocker is
`FullyDecrypted` / protection Off, so there is no pre-boot PIN, and
`DisableAutomaticRestartSignOn` is unset, so Windows auto-signs-in after update
restarts specifically.

**The mechanism is not `AutoAdminLogon`** — that reads 0. The account most likely
has no password, so Windows boots straight to the desktop. The mechanism was not
pinned down and does not need to be: the *behaviour* was observed end to end, and
that is the evidence. Optional confirmation:
`net user $env:USERNAME | Select-String "Password required"`.

**Recorded as a dependency, not a certainty.** Sign-in behaviour is what makes
the `-AtLogOn` task sufficient. If a password is ever set on this account, or
auto-sign-in is turned off, the 3am gap returns silently. Do not change sign-in
behaviour during collection; if it changes anyway, the weekly downtime check in
Part D is what catches it. No move to §5a option 1 is needed.

Note on test validity: `Restart` performs a full boot even with fast startup
enabled — only `Shutdown` becomes a partial hibernate — so this result stands
regardless of whether `powercfg /h off` had been applied first.

## A.4b Audit subcategories deliberately left OFF

`Other Logon/Logoff Events` (4800/4801 workstation lock and unlock, 4778/4779 RDP
session events) is **No Auditing**, and stays that way. It is a plausible volume
widener on a daily-driver desktop, and it is exactly protocol §4's mitigation 1
if the gate comes back thin — held in reserve rather than enabled pre-emptively,
because widening now costs extra personal activity in the corpus for a volume
problem that may not exist. The 14 Sep early reading is what decides; widening
then costs three days, not a week.

Also off and staying off: Process Termination, DPAPI Activity, RPC Events, Plug
and Play, Token Right Adjusted, all IPsec modes, User/Device Claims, Group
Membership, Access Rights.

## A.5 Audit policy state at T0

Paste the `auditpol /get` output verbatim from the endpoint snapshot. Subcategories
enabled per protocol: Logon (S/F), Logoff (S), Special Logon (S), Process
Creation (S).

```
(paste)
```

## A.6 Admission policy in force

Excluded at Component 1: rule groups `sca`, `rootcheck`, `policy_monitoring`,
`ciscat`. Measured cost on the September capture: **94% of alert volume**. State
this number in the paper — it is a large exclusion and it needs the justification
from `FEEDBACK_RESPONSE.md` (SCA MITRE fields describe what a check *mitigates*,
not what an attacker did).

---

## A.8 Open items carried past T0

None of these change the generating process, so none block T0 or create a
segment boundary. Recorded so they are not lost.

| # | Item | Why it is not a blocker | Status |
|---|---|---|---|
| 1 | **`python3-numpy` not installed in WSL** | Analysis tooling, not collection. But `tools/baseline_check.py` cannot run without it, so the 14 Sep gate reading fails until it is installed. `sudo apt install -y python3-numpy`. `python3-sklearn` also needed later, for Component 6. | **☑ done 2026-09-12, numpy 1.26.4** |
| 2 | **Security event log is 20 MB** (`wevtutil gl Security`) | Retention, not generation. At the observed ~5,600 alerts/hour it is roughly two hours of buffer; if WSL is down longer than that, Windows overwrites Security events and they are lost before Wazuh reads them. `wevtutil sl Security /ms:1073741824`. Log the change in Part C, not Part B. | ☐ |
| 3 | **ISM policy `wazuh_alerts_14d` does NOT exist** | Verified 2026-09-12: `curl -sk -u admin .../_ism/policies` returns `Unauthorized`, so the 7a attempt silently failed — curl exits 0 on an auth failure and prints the error as a body. The password in `~/ContextAwareSIEM/Pass.txt` is not the indexer admin password; the authoritative copy is inside `wazuh-install-files.tar`. **Low urgency:** projected index growth is ~7 GB over the whole collection against 63.7 GB free on C:, so disk does not run out without it. The critical retention fix, `monitord.keep_log_days=120`, is already in place and is what protects the corpus itself. | **☑ done 2026-09-12** — policy created and `_ism/explain` confirms all seven existing indices are managed by it. |
| 4 | **Manager provenance snapshot has blank fields** | Four `sudo` bugs in `tools/collect_provenance.sh` (fixed 2026-09-12) left the manager `ossec.conf` SHA-256, the rotated-file listing, the log directory sizes and the rule-ID mappings empty in `T0_manager_20260912T121421.txt`. The script is read-only, so re-running it after T0 captures the same state — use the newer file for A.3 and list both in A.2. | **☑ done 2026-09-12 13:13** — all four fields captured; A.2 and A.3 transcribed. |

## A.9 Observed at T0 — volume is going to overshoot, not fall short

In the first hour of uptime after the audit policy took effect, rule **67027 "A
process was created" fired 5,644 times**. Projected at the ~12 h/day duty cycle
that is roughly **67,000 admitted alerts per day**, against a gate target of
~2,200/day for a 30-day baseline — more than an order of magnitude over.

Consequences to carry into the 14 Sep reading:

- The go/no-go gate will almost certainly return GO by a wide margin. The
  interesting numbers will be entity resolution and feature population, not
  volume.
- `Other Logon/Logoff Events`, held in reserve as protocol §4's volume widener,
  will not be needed.
- Stride-10 subsampling matters more, not less, at this volume.
- Watch instead for the opposite failure: whether the stream is now so dominated
  by 67027 (which carries no MITRE tags) that features 8–10 stay at zero.

## A.10 Entity resolution fix — analysis-time, not a segment boundary

`tools/window_builder.py` `parse_wazuh()` was rewritten 2026-09-12. This is a
Component 1 / §4.1.3 change applied when the corpus is *read*, not when it is
collected, so it is **not** a Part B entry and creates no segment boundary. The
raw alerts on disk are unchanged and any earlier corpus can simply be re-parsed.

**What was wrong.** It read only `data.srcuser` and `data.dstuser` — Linux/PAM
decoder field names, which is what the September sample had because that sample
came from agent 000. The Windows endpoint stream puts identity under
`data.win.eventdata.*`. Measured over 3,000 live alerts:

| field | count |
|---|---|
| `data.win.eventdata.subjectUserName` | 2689 |
| `data.win.eventdata.targetUserName` | 291 |
| `data.win.eventdata.user` (Sysmon) | 147 |
| `data.dstuser` | 116 |
| `data.srcuser` | 39 |
| `data.srcip` | **0** |
| `data.win.eventdata.ipAddress` | 2 |

Result: `user` resolved at 0%. Post-fix, **79.8%**.

**Three decisions embedded in the fix, each reportable:**

1. Logon-family events (4624/4625/4634/4647/4648/4672/4778/4779) take
   `targetUserName`; all others take `subjectUserName`. For a logon the account
   of interest is the one logging in; for process creation it is the one running
   the process. Choosing per event keeps "user" meaning one thing.
2. Machine accounts are excluded — `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`,
   anything ending `$`, and Windows' `-` placeholder. Admitting `SYSTEM` would
   create one enormous "user" whose behaviour is the machine's: the same failure
   mode as admitting compliance alerts at Component 1. The 20.2% of alerts with
   no user entity are these, and that is correct behaviour, not a shortfall.
3. `DOMAIN\user`, `user@domain` and case variants normalise to one id. Sysmon
   writes `ING-LEGION2021\User` where the Security channel writes `User`, and
   Windows accounts are case-insensitive; without this one person fragments into
   three entities and every per-entity window is split.

# PART B — Change log (append-only)

**Every change to any of: audit policy, Sysmon config, `ossec.conf` (either
side), ruleset, agent or manager version, `log_alert_level`, or which event
channels are collected.**

A change mid-collection creates a **segment boundary**. You then have three
options and you must pick one explicitly:

1. Discard everything before the boundary and restart the clock (safest, most
   expensive).
2. Keep both segments and report the baseline as two-segment, with a
   before/after feature-distribution comparison showing the change did not shift
   the distribution. Only defensible if you actually run that comparison.
3. Keep going and say nothing. **Not an option.** This is how a thesis gets a
   result it cannot defend.

| # | Timestamp (+07) | What changed | Why | Segment effect | Snapshot taken |
|---|---|---|---|---|---|
| 1 | **2026-09-12 12:14 +07:00** | Audit policy enabled (Logon S+F, Logoff S, Special Logon S, Process Creation S); command-line capture confirmed off. **T0 — start of collection.** | Protocol §3.2. Without it `user`/`srcip` never resolve and the behavioural rate stays near zero. | **starts segment 1** | `T0_manager_20260912T131341.txt`, `T0_endpoint_20260912T121433.txt` |
| 2 | **2026-09-27 ~11:46 +07:00** (last `001` alert 11:46:14; `002` begins the same day) | Windows endpoint **re-enrolled**: now agent `002` "TestRun1" instead of `001` "windows11-host". `001` shows Disconnected on the manager and is left registered as part of the record. | Not a planned change. Cause not yet recorded — fill in. | **Identity only, NOT a segment boundary.** Verified 2026-09-30: agent `ossec.conf` SHA-256 still `278DBA62…` (T0 value), agent version still v4.14.7, same OS. Daily counts show a clean handover (27 Sep: 322 from `001`, 2,659 from `002`; no overlap, no missing day). Handled at analysis time: `window_builder.HOST_ALIASES = {"002": "001"}` keeps one host entity; `weekly_check.sh` now keeps `--agent 001,002`. Found only because the wk3 corpus ended 3.2 days before the reading — the gate had been silently discarding `002` as "other agents". | none needed — config hashes unchanged |
| 3 | | | | | |
T0 = 12:14 GMT+7
**Planned, and therefore not a surprise:** nothing. Phase 1 and Phase 2 are
change-free by design. If you find yourself wanting to tune something, that is
the signal to write it here instead of doing it.

---

# PART C — Event log (append-only)

## C.1 Outages and unexplained gaps

Downtime from sleep is **expected and handled** (protocol §2.1) — do not log
routine overnight sleep. Log anything that is not that.

| Timestamp (+07) | Duration | What | Cause | Action taken |
|---|---|---|---|---|
| | | | | |

The weekly `baseline_check.py` run prints detected downtime intervals. Anything
longer than an overnight, or on a day you know you were using the machine, is a
service that did not restart — usually the WSL scheduled task.

## C.2 Contamination log

`component6_isolation_forest.md` §3.5: **up to ~7% attack-like windows in
training causes no measurable damage**; damage begins at 19%. So this log is not
a reason to change your behaviour — it is the evidence that lets you *state* the
contamination bound in the paper instead of hoping.

Log anything on this machine that a defender would flag: security tooling for
another course, port scanners, pentest VMs, unusual bulk downloads, cracked or
sideloaded software, remote-access sessions.

| Date | What | Rough duration | Notes |
|---|---|---|---|
| | | | |

## C.3 Uptime continuity

*(Revised twice. The host was briefly assumed to be running continuously; it is
not. It keeps its normal ~12 h/day duty cycle plus three deliberate awake
nights. Protocol §2.1.)*

**A nightly downtime interval is EXPECTED, not a fault.** `baseline_check.py`
will report roughly one 10-14 h gap per day, ending when the machine was next
switched on. Those need no C.1 entry — the active-time correction exists for
exactly them. Log in C.1 only: a gap during hours the machine was in use, a gap
beyond ~24 h that was not a deliberate shutdown, a rate drop while uptime looks
normal (usually a disconnected agent), or any gap on a deliberate awake night.

**Measured pre-collection baseline (25 Aug – 11 Sep 2026, from
Power-Troubleshooter):** 15 low-power intervals, 206.2 h off in 419.8 h wall
clock — **uptime 50.9%, 12.2 h/day**. Downtime was voluntary (nightly Start-menu
shutdown), not a lid or idle timer.

**Plan: keep the normal duty cycle, add three deliberate awake nights.**
Continuous operation was considered and rejected as impractical; measurement
(`night_coverage_note.md`) shows 3–5 nights reaches the plateau and that the
`night_fraction` drop matters more than the nights do. Record the uptime
fraction anyway — it is a reported dataset statistic, not a pass/fail gate.

| Check | When | Done | Notes |
|---|---|---|---|
| First full 24 h with zero reported downtime | after 14 Sep reading | ☐ | proves the arrangement holds |
| **Awake night 1 — a weekday** | | ☐ | 3 nights is the measured sufficient number |
| **Awake night 2 — a weekend** | | ☐ | |
| **Awake night 3 — 13/14 Oct** | 13 Oct 2026 | ☐ | Patch Tuesday; the only fixed date |
| Dirty shutdowns (6008) stopped after `powercfg /h off` | week 1 | ☐ | 6 in the 4 weeks to 11 Sep; indexer + WSL vhdx corruption risk |
| Unattended-reboot test passed (WSL starts with nobody logged in) | 2026-09-12 | ☑ | **PASS** — see A.7 |
| `night_fraction` confirmed non-constant | 14 or 18 Sep reading | ☐ | it was dead before; verify it is alive |
| **Patch Tuesday burst captured, install + reboot** | 13/14 Oct 2026 | ☐ | −0.208 AUC to miss; the only fixed date |
| Any deliberate shutdown (travel, maintenance) | | | log in C.1 |

Planned power/uptime changes go here. They alter *how much* you collect, not what
generates it, so they are **not** segment boundaries and do not belong in Part B.

## C.4 Calendar coverage achieved (fill at T1)

| | |
|---|---|
| Weekdays covered | |
| Weekend days covered | |
| Patch cycles fully inside the window | |
| Uptime fraction over the window (target ~100%) | |
| Unplanned outages: count and total hours | |
| Public holidays / travel / atypical weeks | |

---

# PART D — Gate readings

Run weekly, five minutes. Always with `--since`.

```bash
zcat $(ls /var/ossec/logs/alerts/*/*/ossec-alerts-*.json.gz 2>/dev/null) \
     /var/ossec/logs/alerts/alerts.json > ~/baseline_corpus.json
python3 tools/baseline_check.py ~/baseline_corpus.json \
        --since "<T0>" --label wkN --json provenance/gate/wkN.json
```

The `--json` files are the series you plot in the paper: rate stability over the
collection period is evidence for the same-generating-process assumption, and it
is free.

| Reading | Date | Admitted/awake h | Admitted/day | Pool @ stride 10 | Dead features | Verdict |
|---|---|---|---|---|---|---|
| 72 h early warning | 14 Sep | 383.4 | 4,033 | 909 | tech/tactic/progression | **GO** — floor 7.7 d, target 17.6 d |
| **Phase 1 gate** | 18 Sep | 469.8 | 3,918 | 2,428 | tech/tactic/progression | **GO** — floor 4.0 d, target 14.2 d (~2 Oct) |
| wk2 | | | | | | |
| wk3 | | | | | | |
| wk4 | | | | | | |
| wk5 | | | | | | |
| Freeze | 17 Oct | | | | | |

**The gate**: ≤35 projected days → GO. 35–70 → GO WITH THE FLOOR (4,000 windows,
report seed variance bands). >70 → STOP AND REDESIGN. The redesign options, in
order: widen audit policy → cut features 8–10 → declare the model under-trained.
**Never** lower `log_alert_level` or feed the layer from archives; both break the
premise that this is a prioritisation layer over stock Wazuh output.

### First real reading — 14 Sep 2026, 18:20

Corpus 48 MB / 17,613 lines, 13 day files. First alert **2026-09-12 12:14**,
matching T0 exactly; span 2.3 d; 7,649 of 16,744 discarded as pre-T0.
Clock drift 1 s. 9,092 admitted alerts, 49 distinct rule ids, agent 001 only.

**Two earlier attempts on this date were invalid and are not gate readings.**
The corpus assembly globbed only `ossec-alerts-*.json.gz`, but `monitord`
compresses a day file only if it is running at the midnight rollover — and this
host is off at midnight — so the 11th, 12th and 13th sat on disk as plain
`.json` and were silently skipped. The corpus held 8 then 25 minutes of
post-boot data, and **both runs still exited 0 and printed "VERDICT: GO"**.
Fixed in `tools/weekly_check.sh`; it now takes both extensions, skips the
hardlink of `alerts.json`, prints the day-file count, and tells the reader to
sanity-check the span before trusting the verdict.

**Downtime: 30.4 h in 2 intervals — both routine, no C.1 entry.**
Sat 12 Sep 23:36 for 10.2 h and Sun 13 Sep 21:37 for 20.2 h: the ordinary
nightly shutdowns. Awake time 23.7 h over 2.3 days, consistent with the measured
~12 h/day duty cycle.

**Rate is lower than the T0 snapshot suggested and that is the honest figure.**
4,033 admitted alerts/calendar day against a 2,200/day target — roughly 1.8×
headroom, not the 3× estimated from the 12th (a heavy Phase 0 working day) nor
the 30× briefly extrapolated from a boot storm. Target reached ~30 September,
well inside the 17 October freeze.

**Entity resolution: host 100%, user 51.1%, srcip 0%.** The 79.8% seen on 12 Sep
came from a 37-minute window; 51.1% over 2.3 days is the number to report.

## D.0 Findings from the first real reading that change the design

**1. `night_fraction` is NOT constant on real data — the drop decision needs
re-examining.** Measured here: 21 distinct values spanning the full 0–1 range.
The decision recorded in D.1 on 12 Sep rested on a simulation showing the
feature near-constant on a duty-cycled host (sd 0.117) and therefore costing
−0.019 AUC as wasted split budget. **That premise is false for this host**,
because the machine is used well into the evening and `WORK_END = 18`, so
18:00 onward counts as night and varies genuinely.

The drop may still be right, but only on the *other* leg of that experiment:
where the feature did have real variance, it was worth **+0.002** — nothing
measurable. So the honest statement is "it contributes nothing even when
populated", not "it is constant and wastes budget". **Re-test both ways on the
frozen corpus at T1**; it is an analysis-time choice and costs one extra fit.

**2. ⚠️ WITHDRAWN 2026-09-30 — this finding was a parser bug, not a property of
the data.** `parse_wazuh()` read only `rule.mitre_techniques` / `rule.mitre_tactics`,
which is the shape SCA checks use. Detection rules, which are everything the admission
filter admits, write `rule.mitre = {id, tactic, technique}` with tactic *names*.
So no admitted alert ever carried a tag as far as the pipeline could see. The
lab's own A.4 table records rule 67028 with MITRE T1484, firing on every sign-in,
which is what exposed the contradiction. Fixed and tested (`tools/test_parse_wazuh.py`).
On the September sample, 4 of 19 admitted alerts carry tags. The original text
follows for the record.

~~**2. The MITRE trio is confirmed dead on real data.**~~ `distinct_technique_count`,
`distinct_tactic_count` and `tactic_progression` are identically zero across
9,092 alerts, 49 distinct rule ids and 2.3 days. On the September sample this
could be dismissed as a small-sample artifact; it cannot now. Rule 67027
dominates the stream and carries no MITRE tags. Features 8–10 should be dropped,
and the report should say the admission filter and the available rule set leave
no MITRE signal on this testbed.

**3. The active-time correction is NOT implemented in `tools/window_builder.py`.**
`window_duration_s` reaches **73,064 s (20.3 h)** and `inter_arrival_mean_s`
reaches 3,845 s in this reading — windows spanning the overnight gaps, exactly
the artifact protocol §2.2 exists to remove. A working implementation exists as
`ActiveWindowBuilder` in `tools/night_coverage_study.py` but was never ported
into the reference feature map. **This must be ported before any modelling**, or
every timing feature carries the gap artifact.

   **DONE 2026-09-30.** Ported into `tools/window_builder.py` as an **online,
   causal** correction, where `ActiveWindowBuilder` was batch-only: a gap over
   `G = 1800 s` in the host's global stream is recorded as downtime when the next
   alert arrives, and subtracted from every window gap. Liveness is taken from
   every alert, compliance included, so a compliance scan cannot manufacture
   downtime. One refinement over the protocol's literal formula: a gap that is
   *entirely* downtime is dropped from the inter-arrival statistics, not counted
   as 0 s. Counted, it hit the 0.001 s floor and made every morning host window
   look like it held a simultaneous pair. Tests: `tools/test_active_time.py`, which
   covers matching the gate's batch intervals, causality, bit-identical wall-clock
   behaviour when disabled, and only timing features changing. The two frozen
   simulation studies are pinned to `downtime_gap_s=None` so their recorded results
   still reproduce.

**4. C: free fell 63.9 → 40.2 GB in two days.** Collection is not the cause —
the whole corpus is 48 MB and the indexer is a few hundred MB at most. Something
else consumed roughly 23 GB. Not urgent at 40 GB, but at that rate the 25 GB
compact trigger arrives in days. Worth identifying before assuming it is a
one-off (Windows Update, a game, the PQABSE work).

### Phase 1 GO/NO-GO GATE — 18 Sep 2026, 17:01. **VERDICT: GO.**

Sanity check passed: first alert **2026-09-12 12:14:04**, matching T0 exactly;
span 148.8 h = 6.2 d; 7,649 discarded as pre-T0; 932 dropped as agent 000.

| | 14 Sep | 18 Sep |
|---|---|---|
| Span | 2.3 d | 6.2 d |
| Awake / wall-clock | 23.7 h / 55.2 h | 51.7 h / 148.8 h |
| Downtime intervals | 2 | 7 |
| Admitted alerts | 9,092 | 24,289 |
| Distinct rule ids | 49 | 55 |
| Admitted / awake hour | 383.4 | 469.8 |
| **Admitted / calendar day** | **4,033** | **3,918** |
| Training pool @ stride 10 | 909 | 2,428 |
| `user` resolution | 51.1% | 45.7% |
| Days to floor / target | 7.7 / 17.6 | 4.0 / 14.2 |

**Rate stability: −2.9% across four days.** The reading the same-generating-process
assumption most needs, and it holds. Per *awake hour* rose 22% while per
*calendar day* stayed flat, which is the signature of less machine use rather
than a changed alert process.

**Uptime fell to 8.3 h/day** (51.7 awake hours over 6.2 days) against the 12.2
h/day measured pre-collection — midterm exam week, and the machine is simply
used less. Volume is unaffected because per-hour intensity rose to compensate.
Report the achieved uptime fraction in C.4 rather than the historical norm.

**Projection: target 8,000 windows around 2 October**, leaving a fortnight of
surplus collection before the 17 October freeze — which is exactly what is
wanted, since the remaining value is calendar coverage (Patch Tuesday) rather
than row count.

**Feature population over 24,289 alerts and 55 rule ids:** `night_fraction` has
25 distinct values and remains alive (see D.0 item 1); `inter_arrival_min_s` has
recovered to 48 distinct values, no longer pinned at the tie floor; the MITRE
trio is still *exactly* constant.

### Week 3 reading — 30 Sep 2026, 16:16. **VERDICT: GO.**

**A first run at 16:05 was invalid and is not a gate reading.** It kept only
agent `001`, which had stopped reporting on 27 Sep 11:46 when the endpoint was
re-enrolled as `002` (Part B #2). The corpus therefore ended 3.2 days before the
reading, and the gate still printed GO. The tools now catch this: the gate reads
STALE when kept agents lag the newest alert by more than 6 h, and `--status`
reports CORPUS AGENT SILENT. This reading keeps `--agent 001,002`, with `002`
folded onto `001` as one host.

Sanity check passed: first alert **2026-09-12 12:14**, matching T0; last alert
**2026-09-30 16:15**, minutes before the reading; span 18.2 d; 7,649 discarded
as pre-T0; only 1,073 dropped as agent 000. Corpus SHA-256 `1dac5bbb…`.

| | 14 Sep | 18 Sep | 30 Sep |
|---|---|---|---|
| Span | 2.3 d | 6.2 d | 18.2 d |
| Awake / wall-clock | 23.7 h / 55.2 h | 51.7 h / 148.8 h | 159.2 h / 436.0 h |
| Awake per calendar day | 10.3 h | 8.3 h | **8.8 h** |
| Downtime intervals | 2 | 7 | 23 |
| Admitted alerts | 9,092 | 24,289 | 61,970 |
| Excluded (compliance) | — | 9 | 511 |
| Distinct rule ids | 49 | 55 | 68 |
| Admitted / awake hour | 383.4 | 469.8 | 389.2 |
| **Admitted / calendar day** | **4,033** | **3,918** | **3,411** |
| Training pool @ stride 10 | 909 | 2,428 | **6,196** |
| `user` resolution | 51.1% | 45.7% | 50.9% |
| Days to target | 17.6 | 14.2 | **5.3 (≈ 6 Oct)** |

**Floor passed, target around 6 October**, 11 days inside the 17 October
freeze. The rate per calendar day fell 13% from 18 Sep. Per awake hour stayed in
the same 380–470 band, so the drop is lower machine use through midterms, not a
changed alert process.

**Compliance exclusions jumped from 9 to 511.** Most likely the re-enrolled
agent re-ran SCA and rootcheck from scratch, since the manager holds no stored
scan state for a new agent id. The Component 1 admission filter removed all of
it, which is exactly the case it was built for. Without it, a re-enrollment
would have injected a burst of MITRE-tagged compliance alerts into the baseline.

**Downtime: 11.5 d in 23 intervals — routine, no C.1 entry.** The researcher
reports using the machine every day through midterms, at least an hour or two a
day. The 12 intervals this reading printed are consistent with that: none
exceeds 24 h, each ends in a session, and the long ones (20.2 h on 13 Sep,
22.5 h on 15 Sep, 21.2 h + 21.1 h across 21–22 Sep) are evenings-only days, not
missing days. Full list checked the same afternoon: **all 23 are under 24 h**,
the longest is 22.5 h. The 27 Sep 11:46 → 15:23 interval (3.6 h) sits exactly between the last `001`
alert and the first `002` alert. The researcher confirms they were away from the
machine for that period, so no endpoint activity was lost and it needs no C.1
entry. From about
25 Sep the nightly gaps start between 00:00 and 04:00 rather than around 23:00,
so late-night hours are now partly covered without deliberate awake nights. The full interval list is now written
to the gate JSON (`downtime_list`, `downtime_over_24h`) so this can be audited
without re-running.

**Features over 61,970 alerts and 68 rule ids:** the MITRE trio is still
exactly constant (drop confirmed, D.1). `night_fraction` has 31 distinct values
(see D.0 item 1). `window_duration_s` reaches **82,652 s (23.0 h)**. The overnight-gap
artifact is still in every timing feature because the active-time correction is
**still not ported** (D.0 item 3). That remains the blocker before any modelling.

## D.1 Decisions the gate forces (record the answer and the date)

| Decision | Driven by | Answer | Date |
|---|---|---|---|
| **Which agents belong in the corpus** | Agent 000 is the WSL manager; its stream is PAM 5501 "Login session opened" from the researcher's own `sudo`, plus an unrelated second project's build activity (rust, circom, liboqs, openfhe) on the same WSL instance. That volume tracks how much lab work is happening — heavy during Phase 2 implementation, light during Phase 3 — a systematic difference between baseline and evaluation, which `system_model.md` §6.2 forbids. Counting it **inflates the gate in the project's favour**. | **Windows agent only, id=001.** Agent 000 excluded. Pass `--agent 001` to every `baseline_check.py` run. | 2026-09-12 |
| ~~Keep or drop~~ **DROP `night_fraction`** | **Decided 2026-09-11** on measurement (`night_coverage_note.md` §4.1): −0.019 AUC on a duty-cycled baseline, +0.002 at full night coverage. Earns its place in neither regime. Feature set becomes 14. | dropped | 2026-09-11 |
| Keep or drop features 8–10 (MITRE) | **REOPENED 2026-09-30.** The 18 Sep DROP rested on a parser bug (D.0 item 2): nested `rule.mitre` was never read. Re-measure on the real corpus with the fixed parser before deciding. Original entry follows. ~~**DROP.** Identically zero across 24,289 alerts and 55 distinct rule ids over 6.2 days — no longer dismissible as a small-sample artifact. Rule 67027 dominates and carries no MITRE tags. Report that the admission filter plus this rule set leave no MITRE signal on this testbed. | 2026-09-18 |
| Target 8,000 windows or floor 4,000 | Phase 1 gate | **Target 8,000.** Projection reaches it ~2 Oct, a fortnight inside the freeze. No need to settle for the floor or report variance bands. | 2026-09-18 |
| Per-entity-type models, or host only | Was `user` 47%, `srcip` 0% on the agent-000 sample. On the live endpoint stream `user` initially read **0%** — `parse_wazuh` only knew the Linux/PAM field names (`data.srcuser`/`dstuser`) and Windows eventchannel puts identity in `data.win.eventdata.*`. Fixed 2026-09-12; `user` now resolves at **79.8%**. `srcip` stays at 0% and that is not a bug — only 2 `ipAddress` fields in 3,000 alerts, because a standalone desktop has no network logons. | **Host + user. `srcip` declared unavailable on this deployment and reported as a stated limitation.** | 2026-09-12 |
| Downtime threshold `G` | Detector's derived threshold (20× median awake gap, floor 1800 s) resolved to 0.5 h and cleanly separated 7 routine nightly gaps from awake activity across 6.2 days. **Keep as specified.** | 2026-09-18 |
| VM benign baseline: collect, or state the assumption | Protocol §8 — **unresolved, decide before October** | | |

---

# PART E — Freeze record (fill at T1)

The baseline must be **frozen before any emulation data exists**, and the freeze
must be verifiable. Percentile calibration is fitted on this exact file; if it
changes afterwards, the calibration no longer corresponds to anything.

| | |
|---|---|
| T1 (freeze timestamp) | |
| Frozen corpus filename | |
| **SHA-256 of the frozen corpus** | |
| Bytes / line count | |
| Train / calibration split rule | (state it once, here) |
| Random seeds used | |
| `provenance/raw/T1_*` snapshots taken | ☐ manager ☐ endpoint |

After freezing, `git tag baseline-frozen` on the repo so the code that produced
the features is pinned alongside the data that is not in the repo.

---

# PART F — What the paper must report

Mapped to where each number comes from. If a row is blank in November, it is
because it was not collected — none of this is recoverable after the fact.

## F.1 Testbed description

| Report | Source |
|---|---|
| Manager / agent / ruleset versions, Sysmon version and config | A.3 |
| Windows build, WSL2 Ubuntu version | A.3 |
| Topology: one Windows 11 endpoint, WSL2 manager, isolated VM | fixed |
| `log_alert_level = 3`, archives off — i.e. **stock Wazuh** | A.3 |
| Audit policy subcategories enabled, and that command-line capture was **deliberately disabled** | A.5, §7.2 |
| Site timezone and the UTC offset used in feature computation | A.1 |

The command-line point is worth a sentence of its own, not a footnote: the
pipeline is **content-blind by construction** — the fifteen features need only
`rule_id, rule_level, mitre_tactic, mitre_technique, timestamp, entity ids`.
"We retain rule identifiers and timestamps, not log content" is true by
construction rather than by promise, and it is the sentence that makes the ethics
section short.

## F.2 Dataset characterisation

| Report | Source |
|---|---|
| Collection window T0 → T1, wall-clock span | A.1, E |
| Uptime fraction: active hours vs wall-clock hours (expect ~100%), and that rates are per *active* hour | D |
| Detected downtime intervals: count, total, threshold `G`, how derived | D, §2.1 |
| Total alerts, admitted alerts, excluded-as-compliance, with percentages | D |
| Distinct rule IDs; top-N rule ID distribution and level distribution | D, A.4 |
| Entity resolution rate per type (host / user / srcip) | D |
| Windows produced per entity type; training pool after stride-10 | D |
| Calendar coverage table | C.4 |
| Feature population table — min/max/distinct, and which are constant | D |
| Contamination bound: what was logged, as a % of training windows, against the measured 7% tolerance | C.2 |

**Aggregate statistics only.** No sample alerts containing real paths, hostnames
or usernames. The corpus is personal data from a daily-driver machine and the
repository is submitted.

## F.3 Methodology and justification

| Report | Source |
|---|---|
| Why active-time correction exists, and that it is a Component 5 design change | §2.1 |
| Why compliance alerts are excluded, and the 94% cost | A.6, FEEDBACK_RESPONSE |
| `max_samples = 4096`, with the measured psi sweep that rejects 256 | component6 §1 |
| Stride-10 subsampling, with the measurement showing it *improves* AUC | component6 §3.3 |
| Percentile calibration, with the raw-score-concentration measurement | component6 §3.6 |
| Target 8,000 / floor 4,000 from the seed-variance curve, not a rule of thumb | component6 §3.2 |
| Which features were dropped and why | D.1 |

## F.4 Threats to validity — the section that decides how the work reads

Write these as *measured and bounded*, not as apologies. Each already has a
number behind it.

| Threat | The honest framing |
|---|---|
| Single host | Measured: pooling three heterogeneous hosts changes AUC by ±0.005 against seed sd ±0.003 — no effect. The limitation is **entity diversity**, not volume or uptime, and it is stated as such. |
| Truncated night coverage | **Conditional.** The host ran at 50.9% uptime before collection and runs continuously during it *by decision*. Report the achieved uptime fraction from C.4 as evidence; if it is near 100%, nocturnal coverage is a claim you can defend. If the habit slipped, say so and lean on the active-time correction. |
| Collection period is not the machine's normal duty cycle | Running 24/7 for the baseline is a deliberate departure from the measured 12.2 h/day norm. It improves coverage but means the baseline does not represent typical workstation operation. One sentence, stated plainly — it costs nothing and pre-empts the question. |
| Baseline contamination | Bounded by C.2 against the measured 7% tolerance. |
| Daily-driver realism | Argue it as a **strength**: the alternative — a dedicated idle machine with scripted synthetic activity — is itself a validity threat that would have to be declared. |
| VM has no benign baseline | Unresolved (D.1). Either collect VM benign windows in Phase 2 or state that VM windows are scored by a host-model trained elsewhere. Do not leave it implicit. |
| Baseline/eval comparability | Part A + Part B are the evidence. This is the one that has no fallback. |
| Single measurement period | One patch cycle, one month, one season. State it. |

## F.5 Ethics and data handling

| Report | Source |
|---|---|
| Data is from the researcher's own machine — self-collected, no third-party subjects | fixed |
| Content-blind pipeline: the six fields retained, everything else unused | §7.2 |
| Command-line capture deliberately disabled | A.5 |
| Corpus excluded from the submitted repository; aggregate statistics only | `.gitignore` |
| Retention: index ISM policy, and what happens to the corpus after submission | A.3 |
| **If friends' machines are added**: written informed consent, projection to six fields at ingestion, ethics review | protocol §7.2–7.3 |

## F.6 Reproducibility artefacts

| Artefact | Where |
|---|---|
| `tools/window_builder.py` — the feature map, one implementation | repo |
| `tools/baseline_check.py` — the gate, with `--json` output | repo |
| `tools/collect_provenance.{sh,ps1}` — the environment snapshots | repo |
| Provenance snapshots, redacted | `provenance/redacted/` |
| Weekly gate JSON series | `provenance/gate/` |
| Frozen corpus SHA-256 (corpus itself withheld) | E |
| Seeds, splits, toolchain versions | E, A.3 |
| `git tag baseline-frozen` | repo |

---

## Standing rules

1. **Change nothing** during Phase 1 and Phase 2. Every tuning impulse goes in
   Part B as a proposal, not into the config.
2. **Always pass `--since`.** A reading without it is wrong in your favour.
3. **Never** lower `log_alert_level` below 3, and never feed the layer from
   `logall_json` archives. If the layer needs a non-default Wazuh to have
   anything to prioritise, that is a finding to report, not a setting to change.
4. **Do not reinstall or reconfigure Sysmon** while collecting. It changes the
   config hash and which events are emitted — a segment boundary, mid-baseline.
5. The corpus never enters git.
