# Supervisor Meeting Brief

ContextAwareSIEM — Anawin Suwannapha, Worathun Termjitcharoen
Prepared 2026-09-11, for the first discussion of the Deliverable 2 feedback

---

## How to run the meeting

Four feedback comments were received and all four are answered — three as
accepted defects, one confirmed by measurement. That part is reporting, not
discussion, and should take five minutes. **The meeting's value is in the four
decisions in §2 and the resource asks in §3**, because those have deadlines
attached and the resource asks in particular need lead time.

Order the conversation: ethics question first (longest lead time), then
resources, then the design decisions. The feedback recap can go last — if it
gets cut for time, nothing is lost, because it is written up in
`FEEDBACK_RESPONSE.md`.

---

## 1. Feedback: what was done (five minutes)

| Comment | Response |
|---|---|
| Focus the Temporal Context Window Builder | §4 restructured around it. Writing it out formally exposed an undefined case: an alert resolving to several entities produced several anomaly scores with no rule for combining them |
| Distinguish alert / context / risk state | New §3.2. The exercise exposed a naming collision — "Static Context Enrichment" held no state and was not context; renamed |
| Isolation Forest underspecified | §4.3 rewritten from a measured study rather than from argument. The study **overturned one of my own specified values** — see below |
| Risk accumulation may double-count | **Confirmed by measurement.** The submitted accumulator inflates entity risk 20× on ten minutes of benign data, and the safeguard written to prevent exactly that does not work |

Two results worth mentioning aloud because they are the ones a reviewer will
press on:

**The double-counting question had a concrete answer.** 93% of the risk total on
the recorded capture came from a single 23-second CIS compliance scan. The
two-tactic escalation gate was supposed to stop that; the scan carries 13
distinct MITRE tactics, so it clears the gate six times over. The gate was
defeated by precisely the traffic it was written to stop.

**The Isolation Forest specification contained a value that would have sunk the
result.** `max_samples = 256` came from the original paper's default. Measured,
the method at that setting scores AUC 0.926 — *below* the trivial comparator
added as a sanity check (0.965). At the corrected value it scores 0.991. Had the
project been built on the submitted specification, the conclusion would have been
"the machine-learning method does not beat a simple baseline", and that
conclusion would have been an artefact of one hyperparameter.

---

## 2. Decisions needed

### 2.1 Is excluding compliance alerts acceptable?

SCA, rootcheck and policy-monitoring rules report scan state, not behaviour, and
their MITRE fields describe what a check *mitigates* rather than what anyone did.
Excluding them removes the 20× inflation. It also removes **94%** of the alert
volume in the recorded sample, which sharpens the training-data problem
considerably.

*Recommendation:* exclude. The alternative — admit them as activity but strip
their MITRE fields — preserves volume by filling the baseline with a periodic
artefact.

### 2.2 Is a B0–B3 ablation the expected form of evaluation?

Or is a comparison against a published method required? The ablation isolates the
contribution of temporal context, which is the project's actual claim.
Reimplementing a published baseline is a materially larger undertaking and would
come out of implementation time.

### 2.3 What would supervisor-provided ground truth look like?

This gates the emulation phase, so it is the most schedule-sensitive of the four.
The distinction that matters is host-based versus network-based: CICIDS2017 and
UNSW-NB15 are network flow records, not Wazuh alerts, and consuming them would
mean either discarding the Sysmon endpoint telemetry the whole design rests on or
abandoning the Wazuh-specific claim. Host-based labelled data, or any capture
replayable through a Wazuh agent, would be usable directly.

### 2.4 Should a comparator that might beat the ML method be reported?

The study added two sanity baselines. One of them — robust Mahalanobis — beats
Isolation Forest at the wrongly-specified hyperparameter and loses at the
corrected one. It may well win on real data, which is less well-behaved than
simulated data.

*Recommendation:* report it either way. A project that measured the thing and
reported it honestly is stronger than one that did not look. Worth confirming
that this is how the department sees it too, before committing to it in the
report.

---

## 3. Resource asks

Ranked by value, with the measurement that justifies each. All are small.

### 3.1 Guidance on research ethics — ask first

Two friends have offered their personal machines for data collection. That means
installing an endpoint monitoring agent on identifiable people's computers and
retaining the result as a thesis dataset.

**The question for the supervisor:** does this require institutional ethics
review, and if so, what is the process and how long does it take? This is asked
first because approval lead time, if it is needed at all, is the only thing here
that cannot be compressed — and the collection window closes in mid-October.

Worth stating in the same breath, because it changes the answer: **the design is
content-blind.** None of the fifteen window features touches alert content — the
pipeline needs rule identifiers, severity, MITRE tags, timestamps and entity
identifiers, and nothing else. Command-line capture will be disabled on every
machine, and everything but those six fields dropped at ingestion. The retained
data is closer to "which detection rules fired and when" than to "what this
person did".

### 3.2 One always-on machine to run an agent on

**The single highest-value technical ask.** A spare lab PC or workstation that
stays powered on, doing whatever it normally does.

*Why:* the mode-coverage experiment found that a normal behaviour mode missing
from the baseline costs more than any hyperparameter — omitting one periodic
bursty mode dropped ranking AUC from 0.992 to 0.784. The modes most expensive to
miss are the nocturnal ones: scheduled tasks, updates, backups. The project's
only monitored machine is a laptop that sleeps at night, so those modes are
systematically absent. One always-on machine fixes this in a way that no amount
of additional daytime collection can.

It does not need to be fast, idle, or dedicated. It needs to be *on*.

### 3.3 A small VM to host the Wazuh manager

Modest: 4 vCPU, 8–16 GB RAM (the indexer is the memory consumer), 200 GB disk.

*Why, three reasons:*

- **Reachability.** The manager currently runs on WSL2 at `127.0.0.1`. Additional
  agents cannot reach it, so the offered machines cannot actually be used without
  this.
- **Disk.** The project volume has ~50 GB free. A 30-day collection with indexer
  retention will not fit comfortably.
- **Single point of failure.** A month of collection currently lives on one
  laptop.

If only one of §3.2 and §3.3 is available, take §3.2 — the coverage problem is
the one the measurements say is expensive.

### 3.4 Host-based labelled data, if the department has any

Restating 2.3 as a resource rather than a question: a previous student's Wazuh
capture, a lab exercise capture, or any host-based labelled corpus would reduce
or remove the need for adversary emulation, which is currently two sessions of
work in late October.

### 3.5 Explicitly not needed: compute

Worth saying, unprompted. The anomaly model fits in 0.6 seconds on two cores;
the entire parameter study ran in minutes on a laptop. No GPU, no cluster, no
compute allocation. The constraint is data collection, and it was measured rather
than assumed.

---

## 4. Status and schedule

| Phase | Dates | State |
|---|---|---|
| Setup: audit policy, auto-start, retention | 11 Sep | starting now |
| Rate measurement — **go/no-go on the design** | 11–18 Sep | |
| Baseline collection, implementation in parallel | 18 Sep – 17 Oct | |
| Emulation sessions A and B | late Oct | depends on 2.3 |
| Evaluation and write-up | Nov | |

Baseline collection is passive, so implementation of Components 1–9 happens
during it rather than after it. The end date of 17 October is set by Patch
Tuesday on 13 October — the first one available, since September's was the 8th,
and a baseline containing no patch burst will rank every future patch burst at
the top of the queue.

**The one number that could change everything** is the admitted alert rate,
measured on 18 September. If it comes back below roughly 700/day, the anomaly
model is not trainable on this testbed within the schedule and the design changes
rather than the timeline. Options in that case are prepared and documented; worth
flagging now so it is not a surprise.

---

## 5. Open item not yet resolved

The VM used for attack emulation needs its own benign baseline. Entities are
per-agent, but the anomaly model is per entity *type*, so VM windows and Windows
host windows feed the same host-type model. If the VM only ever appears during
emulation, every VM window is an attack window and the model has never seen a
normal VM.

Either benign VM activity is collected during the baseline period too, or the VM
is scored by a model trained on the Windows host and the assumption is stated.
Leaning towards the first; worth a minute of the supervisor's opinion.

---

## Supporting documents

| File | Contents |
|---|---|
| `FEEDBACK_RESPONSE.md` | Full response to the four comments, with measurements |
| `system_model.md` | Revision 2; §11 is a changelog against the submitted version |
| `component6_isolation_forest.md` | The Isolation Forest study, the ψ correction, data requirements |
| `baseline_collection_protocol.md` | Phase 0–4 plan, the sleep-gap problem, the multi-host analysis |
| `WazuhStartup.md` | Lab operating notes |
| `tools/` | Reference feature map, the study, the readiness check |
