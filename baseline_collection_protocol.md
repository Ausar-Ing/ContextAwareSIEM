# Baseline Collection Protocol

ContextAwareSIEM — written 2026-09-11
Companion to `component6_isolation_forest.md` (which says *how much* data) and
`WazuhStartup.md` (which says how to run the lab)

---

## 0. The headline

**Start collecting today. Do not wait for anything else to be ready** — the
baseline accrues passively while you implement Components 1–9, and it is the
only part of the project that cannot be compressed by working harder later.

Two facts about the setup change the design, and both need handling before the
first byte is collected:

1. **The machine sleeps at night.** This is not a minor operational detail. It
   systematically corrupts three of the fifteen window features and makes a
   fourth degenerate. §2 has the fix; it is a change to Component 5, not a
   change to how you run the lab.
2. **It is your daily-driver machine.** Good for baseline realism — genuinely
   varied benign activity is exactly what §3.4 of the Isolation Forest note says
   matters most. It also means your personal activity ends up in a thesis
   dataset. §5.

---

## 1. Schedule

| Phase | Dates | What happens | Gate |
|---|---|---|---|
| **0. Setup** | today, ~1 hour | Audit policy, auto-start, sleep/retention settings, verification | Test logon produces an alert |
| **1. Rate measurement** | 11 – 18 Sep | Collect and do nothing else to the config | **Go/no-go on the whole design** |
| **2. Baseline** | 18 Sep – 17 Oct | Keep collecting. Implement Components 1–9 in parallel | Includes Patch Tuesday, 13 Oct |
| **3. Emulation A + B** | late Oct | Two disjoint sessions on the VM | Session B touched once |
| **4. Evaluation, write-up** | Nov | — | — |

**Why 17 October.** The mode-coverage result says the expensive thing to miss is
periodic bulk activity that resembles an attack — bursty, multi-rule, off the
usual rhythm. On Windows the dominant one is Patch Tuesday, next on **13 October
2026**. A baseline that ends before it has never seen a patch burst, and will
rank every future patch burst at the top of the queue. September's already
passed (8 Sep), so 13 October is the first one you can catch.

**Phase 2 runs in the background.** It requires no attention beyond the weekly
check in §6. Implementation happens during it, not after it.

---

## 2. The sleep problem, and the fix

The machine is on for roughly 8–10 hours a day and asleep the rest. Three
consequences, in descending severity.

### 2.1 Downtime gaps corrupt the timing features

`T = 24 hours`, so a window built on the first alert of the morning reaches back
across the overnight gap. Its `window_duration_s` will be ~60,000 s and its
`inter_arrival_mean_s` correspondingly inflated — not because the host behaved
unusually, but because the lid was closed. `inter_arrival_min_s` is unaffected;
the other two are systematically wrong for the first window of every day.

**This is an artefact, and it is one that repeats daily**, so the model will
learn it as a legitimate mode and then have nothing left to say about genuinely
slow activity.

**Fix — measure active time, not wall-clock time.** The host being off is not the
entity being quiet; those are different facts and only the second is evidence.
Reconstruct downtime intervals from the alert stream itself and subtract them:

```
window_duration_s      := (t_last − t_first) − downtime_within_window
inter_arrival_mean_s   := mean over gaps, each gap minus any downtime inside it
```

Downtime intervals are derivable without any rule-ID assumptions: take the global
stream for that agent, and treat any gap longer than `G` as downtime, where `G`
is chosen from the observed awake-state gap distribution (§6 reports it). Agent
connect/disconnect alerts can corroborate the boundaries but should not be the
primary signal — they are not guaranteed to fire on an abrupt sleep.

This belongs in `system_model.md` §4.2.6 as part of the feature definitions, and
it is worth writing up explicitly: it is a real consequence of deploying on a
workstation rather than a server, which is a defensible thing for the report to
have noticed.

### 2.2 `night_fraction` becomes degenerate

If the host is never awake at night, every baseline window has
`night_fraction ≈ 0`. The feature carries no information during training — and
worse, if anything at evaluation time *does* land outside working hours, it takes
a value the model has never seen and is flagged anomalous for a reason unrelated
to attack behaviour. That would inflate your results with a false signal.

Two honest options, decided after §6 reports the observed range:

- **Drop the feature**, stating why. Preferred — a constant feature is worse than
  an absent one, because it still consumes split budget (see
  `component6_isolation_forest.md` §2.2).
- **Keep it and constrain the emulation** to the same hours of day as the
  baseline, so both distributions are equally truncated. Weaker, because it
  removes a degree of freedom from the attack scenarios.

This is the same feature-population check that already found five constant
features on the September capture. Run it; do not assume.

### 2.3 Reduced calendar coverage

Nightly scheduled tasks, Windows Update, and backups either do not run or run
bunched at the next wake. The baseline therefore under-represents scheduled bulk
activity — which is precisely the `nightly` and `patchday` category that the
mode-coverage experiment showed to be expensive to miss.

**Mitigation, in order of preference:**

1. **Leave it awake for two or three full 24-hour stretches** during Phase 2 —
   one weekday, one weekend, and the night of 13/14 October. That is enough to
   put nocturnal modes in the baseline without running the machine continuously
   for a month. Set a calendar reminder; this is the single highest-value
   manual action in the whole protocol.
2. Set the power plan to sleep only the display, not the system, on those nights.
3. If neither is possible, report the truncation as a stated limitation in §6.5
   of the system model and drop `night_fraction`.

---

## 3. Phase 0 — setup, today

Work through these in order. Each one is a thing that silently ruins a month of
collection if skipped.

**1. Verify the current state.** You mentioned disabling some settings; rather
than trying to remember which, run the verification in `WazuhStartup.md` §6 and
let it tell you. Specifically check that the agent log shows
`Analyzing event log: 'Security'` — if that line is missing, §7 will produce
nothing.

**2. Enable audit policy** — `WazuhStartup.md` §7. Confirm end-to-end with a
logout/login before moving on. **Record the timestamp.** Collection starts after
this, not before: alerts from before the change come from a different generating
process and must not be mixed into the baseline.

**3. Enable auto-start on both sides**, including the WSL scheduled task —
`WazuhStartup.md` §5. `systemctl enable` alone is not enough.

**4. Power settings.** Sleep is acceptable (§2 handles it); *hibernate and
shutdown* are worse because WSL has to cold-start. Disable hybrid sleep. Confirm
the manager is running after the first natural sleep/wake cycle.

**5. Index retention.** The project volume has roughly 50 GB free. Set an ISM
policy to delete `wazuh-alerts-*` indices older than 14 days — the prioritisation
layer reads `alerts.json` and its rotated `.gz` files, not the indexer, so the
indices are a dashboard convenience and nothing depends on them.

**6. Keep the corpus out of git.** Add to `.gitignore`:

```
baseline_corpus*.json
*.json.gz
```

See §5 for why.

---

## 4. Phase 1 — the 72-hour rate measurement

Collect for one calendar week (≈ 60–70 awake hours). Change nothing during it.
Then:

```bash
zcat /var/ossec/logs/alerts/2026/Sep/ossec-alerts-*.json.gz \
     /var/ossec/logs/alerts/alerts.json > ~/baseline_corpus.json
python3 tools/baseline_check.py ~/baseline_corpus.json
```

`baseline_check.py` reports the four numbers that decide everything: admitted
alert rate per awake hour, entity resolution rate per type, which of the fifteen
features are populated, and the projected days-to-target.

### The gate

The target is **8,000 training windows after stride-10 subsampling**, floor 4,000.
Roughly 65,000 admitted alerts for the target, 33,000 for the floor.

| Projected days to 8,000 windows | Verdict |
|---|---|
| ≤ 35 days | **Go.** Phase 2 as scheduled |
| 35–70 days | **Go with the floor.** Target 4,000 windows and report the seed variance honestly |
| > 70 days | **Stop and redesign.** See below |

If the projection exceeds ~70 days, the anomaly model is not trainable on this
testbed within the schedule, and the response is a design change, not more
patience. Options in order of preference:

1. **Widen what is collected** — add Object Access or PowerShell Script Block
   auditing. More audit policy, still stock Wazuh rules.
2. **Reduce the feature set** — features 8–10 (the MITRE ones) first, which
   lowers the dimensionality and therefore the sample requirement.
3. **Declare the limitation and report the model as under-trained**, with the
   variance bands that go with it. Unattractive but honest, and better than a
   headline number with ±0.04 of seed noise under it.

**What not to do:** lowering `log_alert_level` below 3, or enabling
`logall_json` and treating archives as the input. Both break the project's own
premise — that this is a prioritisation layer over the alerts a stock Wazuh
produces. If the layer needs a non-default Wazuh to have anything to prioritise,
that is a finding worth reporting, not a configuration to quietly apply.

**One exception on archives.** Enabling `logall_json` *for Phase 1 only* is worth
considering as insurance: if the rate comes back too low, you can re-derive what
a wider rule set would have produced without re-collecting a week. Archives grow
fast — check the size daily and turn it off at the end of Phase 1 regardless of
the outcome.

---

## 5. Daily-driver machine: two consequences

**Realism — the good half.** A real workstation produces exactly the multi-modal
benign activity the mode-coverage experiment says is worth having: interactive
logons, browsing, development tools, updates, scheduled jobs. A dedicated idle
lab machine would have needed scripted synthetic activity, which is itself a
threat to validity that has to be declared. You have the better setup.

**Your own activity becomes research data.** The corpus will contain process
names, command lines (4688 with command-line inclusion is explicitly enabled),
logon times, and network destinations from your normal use. Before Phase 2:

- Keep the corpus out of git (§3 step 6). The repository is submitted; the corpus
  should not be in it.
- Report aggregate statistics only — rates, distributions, feature summaries —
  not sample alerts containing real paths or hostnames.
- If the dataset is ever shared or published, it needs scrubbing first, and that
  is easier to plan now than to retrofit.

**Contamination.** A daily-driver machine is a plausible route for Risk 1 — a
security tool run for another course, an unusual download, anything that looks
like attack activity. The measured tolerance is wide (no damage up to ~7% of
training windows), so this is a note to keep a rough log of anything unusual you
do during Phase 2, not a reason to change machines.

---

## 6. While Phase 2 runs

Weekly, five minutes:

```bash
python3 tools/baseline_check.py ~/baseline_corpus.json
```

Watch three things:

- **Gaps.** The script lists detected downtime intervals. An unexpected multi-day
  gap means a service did not restart — fix it and note the gap.
- **Rate stability.** A rate that drops sharply usually means the agent
  disconnected rather than that you were less active.
- **Feature population.** If `distinct_tactic_count` is still zero after the audit
  policy change, the MITRE features are not recoverable on this testbed and
  should be dropped from the design rather than carried.

And once: **the awake nights.** One weekday, one weekend, and 13/14 October.

---

## 7. Additional machines

Two friends' machines are available. Measured before recommending: the simulator
was rebuilt with three *heterogeneous* hosts — different mixtures of normal
behaviour modes, as three real people's machines would have — and the model was
trained on one host alone versus all three pooled, evaluating on the first host.

| Own machine baseline | Own only | + 2 friends, own calibration | + 2 friends, pooled calibration |
|---|---|---|---|
| 5 days (284 windows) | 0.951 | 0.945 | 0.945 |
| 10 days (713) | 0.944 | 0.946 | 0.946 |
| 20 days (1,362) | 0.947 | 0.950 | 0.950 |
| 40 days (2,750) | 0.947 | 0.952 | 0.952 |

**Pooling makes essentially no difference.** The spread is ±0.005 against a seed
standard deviation of ±0.003, and with a thin own-baseline it is slightly
*negative*. Per-host versus pooled calibration is identical to three decimals.

*(These error bars are narrower than those in `component6_isolation_forest.md`
§3.2 by construction: that experiment resampled which windows you happened to
collect, this one holds the baseline fixed and varies only the forest seed. They
answer different questions and should not be compared directly.)*

So the friends' machines are **not** the answer to the volume problem. They are
still worth having, for three reasons that have nothing to do with volume:

1. **Entity diversity — the real win.** The design specifies per-entity-type
   models for host, user and source IP. On one machine that is a population of
   one host and, currently, 47% user resolution and 0% source IP. Three machines
   with six accounts makes per-entity-type modelling an honest proposition
   rather than a formality.
2. **Uptime coverage.** If either friend's machine is a desktop that stays on,
   it contributes the night and weekend windows yours never will — directly
   addressing §2.3, which the mode-coverage experiment identified as the
   expensive gap. **Ask which of the two is a desktop before deciding anything
   else.**
3. **Redundancy.** A month of collection on a single laptop is a single point of
   failure.

### 7.1 The blocker

The manager runs on WSL2 at `127.0.0.1`. Friends' machines cannot reach it.
Options, worst to best:

- Exposing the manager port from a personal laptop — no.
- Agents buffer and flush when on the same network — fragile, and creates
  bursty artificial arrival patterns that corrupt the timing features.
- **A manager on a machine that is always up and reachable.** This is the ask in
  §8 of `supervisor_meeting_brief.md`.

Without a reachable manager, additional machines are not practical, and the
benefits above are not worth improvising for.

### 7.2 Consent and data minimisation

Installing an endpoint agent with process-creation auditing on someone else's
personal computer captures what they run, when they log on, and where they
connect. For a thesis dataset, about identifiable people. This needs written
informed consent at minimum, and quite possibly institutional ethics review —
see the first item of the supervisor brief.

**One fact makes this much easier, and it is worth stating in the system model
as a design property: the prioritisation layer is content-blind.** None of the
fifteen window features touches alert content. The whole pipeline needs only:

```
rule_id, rule_level, mitre_tactic, mitre_technique, timestamp, entity identifiers
```

No process names, no command lines, no file paths, no URLs, no `full_log`.

Three consequences:

- **Turn off command-line capture** (`ProcessCreationIncludeCmdLine_Enabled`) on
  every machine, not just the friends'. The model does not use it, and 4688
  command lines are the single most sensitive field in the capture. It was in
  `WazuhStartup.md` §7 because it is the conventional recommendation; for this
  project it is a pure liability.
- **Drop the rest at ingestion.** Component 1 preserves the raw alert for audit
  (§4.1.1); for the friends' machines, project to the six fields above at
  collection time and never store the rest.
- **Say this in the consent form and in the report.** "We retain rule
  identifiers and timestamps, not log content" is a much easier sentence to
  defend than anything involving command lines, and it is true by construction
  rather than by promise.

### 7.3 If you do go ahead

- Same agent version, same Sysmon config, same audit policy on all three, or the
  same-generating-process assumption of §6.2 breaks across hosts.
- Written consent naming what is collected, how long it is kept, who sees it, and
  how to withdraw.
- Corpus never enters git; friends' data never leaves the manager.
- Emulation runs only on your VM. The friends' machines contribute baseline only,
  so the model is trained on three hosts and evaluated on one — realistic for a
  fleet deployment, but state it.

---

## 8. What this does not cover

The VM needs its own benign baseline. Entities are per-agent but the anomaly
model is per entity *type*, so windows from the VM and from the Windows host feed
the same host-type model. If the VM only ever appears during emulation, every VM
window is an attack window and the model has no idea what a normal VM looks like.

Either collect benign VM activity during Phase 2 as well, or decide explicitly
that the VM is scored by a model trained on the Windows host and state the
assumption. This is a genuine open question and worth raising with the
supervisor alongside the ones already in `system_model.md` §9.2.
