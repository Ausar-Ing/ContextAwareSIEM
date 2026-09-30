# System Model: Context-Aware Alert Prioritization for Wazuh

Deliverable 2 — System Model
Anawin Suwannapha, Worathun Termjitcharoen

*Revision 3, 2026-09-30. Revision 3 brings the model into line with eighteen days
of baseline measurement on the testbed (12–30 September 2026); its changes are
listed in Section 11.1. Revision 2's changes against the submitted version are in
Section 11.2 and argued in `FEEDBACK_RESPONSE.md`. Measurements cited as
"COLLECTION_RECORD" are logged, with dates and corpus hashes, in
`COLLECTION_RECORD.md`.*

## 1. Purpose and Scope of This Document

This document specifies the system model for the context-aware alert prioritization layer proposed in Deliverable 1. It defines the architecture, the responsibilities of each component, the state each holds, the scoring model, and the evaluation protocol by which the system will be assessed.

The system is a **prioritization layer**, not a detector. It consumes alerts that Wazuh has already produced and re-orders them. It does not add detection rules, modify Wazuh decoders, or attempt to identify threats Wazuh did not flag. An alert Wazuh never raises is outside the system boundary.

The centre of the design is Component 5, the Temporal Context Window Builder. Section 4.2 specifies it in full; the remaining components are specified at the level of detail needed to make Component 5 implementable and measurable.

## 2. Design Requirement

The governing requirement for this system model is:

> The system must derive context **across a batch of logs over time within a single stream**, not from an alert considered in isolation.

This is a deliberate narrowing. Correlation across heterogeneous log sources is a different problem, and it is excluded. The system reasons about a sequence of alerts belonging to the same entity, ordered in time.

This requirement is what distinguishes the design from a conventional enrichment pipeline. Enrichment answers "what do we know about the entities in this alert?" using static lookups. It is stateless: the same alert always produces the same enrichment. The requirement above demands a **stateful** component whose output for an alert depends on the alerts that preceded it.

### 2.1 Why single-alert scoring is insufficient

Consider two alerts, identical in every field: Wazuh rule 60122 (`Logon Failure - Unknown user or bad password`, Windows event 4625), same host, same user, same rule level.

- In the first case, it is the only alert for that user in six hours — a mistyped password.
- In the second case, it is the fortieth such alert in ninety seconds, followed by rule 60118 (`Windows Workstation Logon Success`, event 4624).

A stateless pipeline assigns both the same priority. The second is a successful password-guessing attack. (Both rule ids were verified on the testbed's own manager, not taken from documentation; COLLECTION_RECORD A.4.) No amount of static enrichment — asset criticality, CVSS, threat intelligence — distinguishes them, because the difference is not in the alert, it is in the sequence. Temporal context is therefore not an accuracy refinement; it is the only mechanism that separates these cases at all.

### 2.2 Positioning against related work

Two forms of "context" appear in the literature and the distinction matters for this design:

| Form | Definition | Representative work |
|---|---|---|
| Entity-attribute context | Static attributes of the entities named in an alert | Risk-based alerting, [ref9] |
| Temporal-sequence context | The window of preceding events for the same entity | DEEPCASE [ref15], AlertPro [ref5] |

DEEPCASE [ref15] establishes that a fixed window of preceding events on the same device carries sufficient signal to classify the current event, and that operators can triage clusters of such windows rather than individual events. AlertPro [ref5] reports that context features derived from alert sequences outperform features taken from raw alert fields alone. This system model adopts temporal-sequence context as its primary signal and treats entity-attribute context as a secondary modifier.

**A note on terminology.** The submitted revision of this document used "context" for both forms, naming Component 4 "Static Context Enrichment" and its output `S_ctx`. Component 4 holds no state and belongs entirely to alert state (Section 3.2); calling its output "context" conflicted with the temporal sense that is the subject of the design requirement. Throughout this revision, **"context" means temporal context only**. Component 4 is renamed *Entity Attribute Enrichment* and its output `S_exp` (exposure).

### 2.3 Log Sources and Log Types in Scope

Wazuh's `log_format` setting, declared per source in the `localfile` block of `ossec.conf`, tells the log collector how to parse a source. Supported values include `eventchannel`, `syslog`, `json`, `audit`, `journald`, `multi-line`, `command` and `full_command`.

This is an **ingestion-time** concern only. Once the collector has read a record and `analysisd` has decoded it against the ruleset, every source converges on a single unified alert structure written to `alerts.json`. The prioritization layer sits downstream of that convergence and therefore consumes one format regardless of origin. Adding a log source does not require a new pipeline branch; it requires only that the source has a decoder.

The sources in scope, classified by the type of record each carries:

| Source | `log_format` | Log type | Content |
|---|---|---|---|
| Windows Security channel | `eventchannel` | Security audit log | Logon and logoff, privilege use, account management |
| Sysmon/Operational channel | `eventchannel` | Endpoint (host) telemetry | Process creation, network connections, image loads, registry activity |
| Linux `auditd` on the VM, if enabled | `audit` | Security audit log | Syscall and file-access auditing |
| Wazuh agent `ossec.log` | n/a | Application log | Agent health only; not an analysis input |
| Wazuh file integrity monitoring (`syscheck`) | n/a (agent module) | Integrity-state report | Registry and file changes. Scheduled-scan results are **excluded** (Section 4.2.3); on this testbed every FIM alert observed was scheduled |

The analytical inputs to this system are therefore **security audit logs and endpoint telemetry**, not application logs. The distinction matters for the argument in Section 2.1: audit and endpoint records describe discrete, attributable actions by a subject upon an object, which is what makes per-entity sequencing meaningful in the first place. Application logs describe internal program state and do not decompose into subject-action-object in the same way.

Wazuh also emits alerts that are neither of these — configuration assessment (SCA), rootcheck and policy-monitoring output, and integrity-monitoring results produced by a scheduled scan. These are **excluded** by the admission policy in Section 4.2.3, for reasons given there.

*Measured stream composition.* Over 18.2 days of normal use, the admitted stream holds 60,692 alerts from 68 distinct rules, dominated by rule 67027 (`A process was created`, event 4688). Its rate is 3,411 admitted alerts per calendar day, or about 390 per awake hour (COLLECTION_RECORD Part D).

### 2.4 Correlation and Anomaly Scoring

Correlation and anomaly scoring are distinct operations, and this design contains both. The terms are frequently conflated, so they are separated here explicitly.

**Correlation** answers *which alerts belong together*. It is a grouping operation whose output is a set of related alerts.

**Anomaly scoring** answers *how unusual is this group*. It is a scoring operation whose output is a number.

Correlation is logically prior: there is nothing to score until something has been grouped.

| Operation | Component | Mechanism |
|---|---|---|
| Correlation (window level) | 5 | Entity-and-time grouping: alerts sharing an entity within lookback `T` form one context |
| Anomaly scoring | 6 | Isolation Forest over the correlated window's feature vector |
| Correlation (incident level) | 8 | Decaying risk accumulation per entity, gated on multi-tactic spread |

Component 5 performs attribute-based correlation, the simplest and most robust family: alerts are related if they concern the same entity within a bounded interval. Component 8 escalates a correlated group to an incident. Component 6 evaluates a group but does not form one.

**Relationship to Wazuh's native correlation.** Wazuh already performs rule-level correlation through composite rule options: `frequency` combined with `timeframe`, `if_matched_sid`, `if_group`, `if_level`, and field constraints such as `same_source_ip` and `same_user`. Baseline system B0 therefore already contains correlation, and this project does not claim to introduce it.

The proposed distinction is that Wazuh's correlation is **authored**, while the correlation in Components 5 and 8 is **derived**. Authored correlation requires an analyst to anticipate a pattern and encode it as a rule with a fixed threshold; it detects only what someone thought to write down. Derived correlation forms a window mechanically for every alert regardless of pattern, and what counts as unusual within that window is learned from observed data rather than declared in advance. Stating this contrast is necessary rather than optional: without it, a reviewer may reasonably ask what the layer offers over a `frequency`-based rule.

One consequence of Wazuh's authored correlation is handled in Section 4.4.4: a composite rule emits an alert *summarising* alerts that are themselves in the stream, and both must not be counted as independent evidence.

## 3. Architecture and State

### 3.1 Component overview

```text
                    Wazuh Manager (alerts.json)
                              |
                              v
                    [1] Alert Ingestion
                        + admission filter
                              |
                              v
                    [2] Normalization
                              |
                              v
                    [3] Entity Resolution
                              |
              +---------------+---------------+
              |                               |
              v                               v
    [4] Entity Attribute            [5] TEMPORAL CONTEXT
        Enrichment                      WINDOW BUILDER
     (asset, vuln, TI)              (last N alerts / entity)
              |                               |
              |                               v
              |                     [6] Sequence Anomaly
              |                          Scoring
              |                               |
              +---------------+---------------+
                              v
                    [7] Hybrid Priority Scoring
                              |
                              v
                    [8] Entity Risk Accumulation
                              |
                              v
                    [9] Ranked Queue + Explanation
                              |
                              v
                       Analyst Interface
```

Components 1–4 are stateless per alert. Components 5, 6 and 8 hold state and are where the design requirement of Section 2 is satisfied.

### 3.2 State model

The system holds three kinds of state. They differ in what they are keyed by, how many of them exist, and how they behave over time. Conflating them is the most common source of confusion when reading a pipeline of this shape, so they are separated here before any component is specified.

| | **Alert state** | **Context state** | **Risk state** |
|---|---|---|---|
| Question answered | What happened? | What surrounds it? | How much does this entity worry me? |
| Key | `alert_id` | `(entity_ref, t)` | `entity_ref` |
| Cardinality | one per admitted alert | one per (alert × resolved entity) | one per active entity |
| Time behaviour | frozen at ingestion | slides; bounded by `N` and `T` | decays; half-life `h` |
| Mutability | immutable, append-only | recomputed on each arrival | updated on each arrival |
| Produced by | Components 1–4 | Component 5 | Component 8 |
| Consumed by | Components 5, 7 | Components 6, 7 | Component 9 |
| Scoring term | `S_rule`, `S_exp` | `S_seq` | `R_e` |
| Storage | `NormalizedAlert` | `WindowVector` (a view) | `EntityRisk` |

**Alert state** is everything derivable from one alert without reference to any other: the normalized fields of Section 4.1.2 and the entity attributes of Section 4.1.4. It is stateless in the operational sense — the same alert always yields the same alert state — and immutable once written.

**Context state** is the ordered window of alerts for one entity and the feature vector derived from it. It is the subject of the design requirement and the substance of Section 4.2.

**Risk state** is the decaying accumulation per entity. It is the only state whose scope is unbounded in time.

Three properties follow, and each is relied on later:

1. **Context state is a pure function of alert state.** A window is a *view* over the immutable alert log, not independent storage. Nothing is lost by discarding it and nothing is gained by persisting it beyond the current computation.

2. **Risk state is also a pure function of alert state**, because the decay in Section 4.4 is closed-form: `R_e(t)` depends only on which alerts occurred and when, not on the order in which the accumulator happened to be updated. This is a design constraint, not an observation — an accumulator with path-dependent behaviour (a cap applied online, say) would forfeit property 3.

3. Therefore **every state layer is reconstructible by replaying the alert log.** This is what makes the B0–B3 ablation of Section 6.3 possible: each system variant is produced by replaying one immutable corpus under different scoring configurations, with no re-collection.

### 3.3 Parameters are not state

The fitted Isolation Forest, its baseline calibration table, the tuned values of `N`, `T`, `h`, `θ` and the scoring weights, the downtime threshold `G` (Section 4.2.6.2) and the host alias table (Section 4.1.3) are **frozen parameters**, not runtime state. They are fitted once, versioned, and held constant across the evaluation.

The distinction is load-bearing rather than pedantic. Risk 2 of Section 6.2 — evaluating on training data — is precisely the requirement that parameters must never be refitted from state belonging to the evaluation period. Keeping parameters in their own category makes that requirement checkable: a parameter file has a version and a fitting date, and the evaluation records which one it used.

## 4. Component Specification

**Note on parameter values.** Every numeric parameter in this section and in Section 6 — window size `N`, lookback `T`, decay half-life `h`, escalation threshold `θ`, label tolerance `δ`, saturation behaviour, the Isolation Forest hyperparameters, and the scoring weights — is a **provisional estimate**, stated so that the model is concrete and implementable. Each will be re-derived from observed alert-stream behaviour, and the sensitivity of results to each is reported in the evaluation. They are starting points, not findings.

*Revision 3.* Four values are now measured rather than estimated, and are marked **(measured)** where they appear: the downtime threshold `G = 1800 s`, `max_samples = 4096`, the training stride `s = 10`, and the training-volume target of 8,000 windows (floor 4,000). The last three come from a simulation study (`component6_isolation_forest.md`), `G` from the live corpus. All other values remain provisional.

### 4.1 Supporting pipeline (Components 1–4, 9)

These components exist to make Component 5 possible and Component 5's output actionable. They are specified to that level and no further.

#### 4.1.1 Component 1 — Alert Ingestion and Admission

Reads Wazuh alerts from `/var/ossec/logs/alerts/alerts.json` (or the Indexer API). Preserves the original alert unmodified for audit and reprocessing. Assigns an internal monotonic **ingestion sequence number** so that ordering is well defined when timestamps collide — a real case, not a hypothetical one (Section 4.2.2).

Applies the admission filter of Section 4.2.3. Non-admitted alerts are retained in the raw store but do not enter any window, are not scored, and do not contribute to risk.

**Output:** raw alert + ingestion metadata + admission flag.

#### 4.1.2 Component 2 — Normalization

Projects the Wazuh alert onto a fixed internal schema. Only fields the prioritization layer actually consumes are retained.

| Field | Source | Notes |
|---|---|---|
| `alert_id` | Wazuh `id` | |
| `ingest_seq` | Component 1 | Monotonic; breaks timestamp ties |
| `timestamp` | Wazuh `timestamp` | Converted to UTC |
| `rule_id` | `rule.id` | |
| `rule_level` | `rule.level` | Integer 0–15 |
| `rule_groups` | `rule.groups` | Drives admission (Section 4.2.3) |
| `rule_description` | `rule.description` | For analyst display |
| `firedtimes` | `rule.firedtimes` | Manager-global repeat counter; see Section 4.4.2 |
| `mitre_technique` | `rule.mitre.id` (detection rules); `rule.mitre_techniques` (SCA) | May be absent; list-valued; both shapes read |
| `mitre_tactic` | `rule.mitre.tactic` (detection rules, tactic **names**); `rule.mitre_tactics` (SCA, tactic **ids**) | May be absent; list-valued; normalised to ATT&CK tactic ids |
| `agent_id`, `agent_name` | `agent.*` | Raw id retained; host identity via the alias table, Section 4.1.3 |
| `src_ip`, `dst_ip` | `data.srcip`, `data.win.eventdata.ipAddress` | May be absent |
| `user` | `data.win.eventdata.{targetUserName, subjectUserName, user}`, `data.{dstuser, srcuser}` | May be absent; selection and normalisation in Section 4.1.3 |
| `syscheck_mode` | `syscheck.mode` | FIM alerts only; drives admission (Section 4.2.3) |
| `process`, `parent_process` | Sysmon-derived | May be absent |
| `previous_output` | top-level, when present | Composite-alert detection (Section 4.4.4) |

Absent fields are recorded as explicitly null rather than defaulted, so that downstream components can distinguish "not applicable" from "zero".

**Wazuh writes MITRE ATT&CK tags in two shapes, and both must be read.** Detection rules — everything the admission policy admits — write a nested `rule.mitre` object whose `tactic` list holds tactic *names*. SCA checks write flat `rule.mitre_techniques` and `rule.mitre_tactics` lists holding *ids*. An earlier reference implementation read only the flat shape, and so saw no tag on any admitted alert. That produced a false finding that the MITRE-dependent features were constant (withdrawn; COLLECTION_RECORD D.0 item 2). Tactics are normalised to ids so that the two shapes count alike and the ordinal of Section 4.2.6.1 applies to both.

#### 4.1.3 Component 3 — Entity Resolution

Determines which entities the alert concerns. An entity is the unit over which temporal context accumulates.

Entity types in the model: **host** and **user**. Source IP was specified in earlier revisions and is **not available on this testbed** (below).

An alert may map to several entities and will then contribute to each of their windows. Where an entity cannot be resolved, the alert still flows through the pipeline but contributes only to the windows of the entities it does resolve.

**Measured resolution rates** over 60,692 admitted alerts, 12–30 September 2026:

| Entity type | Resolved | Decision |
|---|---|---|
| host | 100% | Modelled |
| user | 50.9% | Modelled |
| source IP | 0% (2 `ipAddress` fields in the first 3,000 alerts) | **Dropped** from the model on this testbed |

*Source IP is absent by construction, not by fault.* A standalone desktop produces no network logons, so the Windows Security channel never carries a remote address. The three-entity design is therefore a **two-entity design on this testbed**. This is stated as a limitation of the deployment, not of the method; a networked deployment would populate it.

*User selection.* Windows eventchannel alerts carry identity under `data.win.eventdata.*`, not in the Linux/PAM fields `data.srcuser`/`data.dstuser`. For logon-family events (4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779) the target account is the entity. For all other events the subject account is. Machine and service identities (`SYSTEM`, `LOCAL SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, accounts ending in `$`, and `-`) are not users and are not resolved. `DOMAIN\user`, `user@domain` and case variants normalise to one identifier. The unresolved 49% is almost entirely these machine identities, correctly excluded.

*Host identity is the machine, not the agent id.* Wazuh keys an agent by the id in its enrollment key, so re-enrolling a machine gives it a new id. On this testbed the endpoint was re-enrolled on 27 September and reappeared as agent `002`. Its configuration hash and agent version were unchanged (COLLECTION_RECORD Part B #2). A frozen **host alias table** maps agent ids onto machines, `{002 → 001}`, so one machine remains one entity. Without it, every host window would have been split at the re-enrollment.

#### 4.1.4 Component 4 — Entity Attribute Enrichment

*Renamed from "Static Context Enrichment"; output renamed `S_ctx` → `S_exp`. See Section 2.2.*

Attaches attributes that do not depend on alert history. Contributes to **alert state**, not context state.

| Source | Attributes | Availability in lab |
|---|---|---|
| Asset inventory (manually authored) | criticality, environment, role | Synthetic, authored for the testbed |
| Wazuh Vulnerability Detector | open CVE count, max CVSS | Native |
| Threat intelligence (AbuseIPDB / local list) | IP reputation | External or offline list |

**Design note.** The testbed contains a small number of hosts and one human user. Attributes that depend on organizational structure — department, business role, peer-group deviation — cannot be meaningfully populated and are **excluded from the implemented system**. Including them in the model while stubbing them in the implementation would make the evaluation dishonest. The asset inventory is authored deliberately as a synthetic but documented artifact of the testbed, and its contents are reported alongside results.

**Output:** `S_exp(a) ∈ [0,100]`.

#### 4.1.5 Component 9 — Ranked Queue and Explanation

Emits the prioritized alert list and, for each entry, the evidence behind its score:

- the three highest-contributing terms of `P(a)`;
- the window features that most influenced `S_seq`, by the attribution method of Section 4.3.5, together with the entity whose window produced the maximum (Section 4.2.7);
- the alerts contributing to `R_e` when the entry is a risk notable, grouped by repeat group rather than listed individually;
- the *incident* the notable belongs to, after the cross-entity deduplication of Section 4.4.5.

Explanation is a functional requirement, not presentation. An analyst who cannot see why an alert was promoted cannot act on the promotion.

---

### 4.2 Component 5 — Temporal Context Window Builder

**This is the core component of the system model.** Everything before it prepares its input; everything after it consumes its output.

#### 4.2.1 Window semantics

Let `A` be the ordered sequence of admitted alerts. For an alert `a` and an entity `e ∈ entities(a)`, the window is

> `W(e, a) = ` the last `N` elements of
> `{ x ∈ A : e ∈ entities(x), time(a) − T < time(x) ≤ time(a) }`,
> ordered by `(timestamp, ingest_seq)`.

Three things this definition settles that the submitted version left open:

**The window includes `a` itself.** The vector describes the entity's situation *as of* `a`, not the situation `a` walked into. `window_size`, `burst_ratio` and `inter_arrival_min_s` all depend on this and would be off by one alert otherwise. This differs from DEEPCASE [ref15], which builds context from strictly preceding events and classifies the current event against that context; the difference is noted because the two designs are otherwise closely related.

**The bound is a conjunction, not a choice.** A window is simultaneously count-bounded (`≤ N`) and time-bounded (`> t − T`). Whichever binds first, binds. A quiet entity yields a short window covering the full `T`; a noisy entity yields `N` alerts covering seconds.

**Windows are per `(alert, entity)`, not per alert.** An alert resolving to both a host and a user produces two windows and two feature vectors. Section 4.2.7 specifies how they combine.

Parameters: `N = 20` alerts, `T = 24` hours (provisional; both tuned during evaluation with sensitivity reported).

#### 4.2.2 Ordering and tie-breaking

Wazuh timestamps carry millisecond resolution, and collisions occur in ordinary operation: in the sample recorded on 2026-09-05, 100 alerts share the second `15:02:59`, and even among the alerts that survive the admission policy below, six share `15:06:25`. Ordering by timestamp alone is therefore not well defined, and several features (`rule_level_trend`, `tactic_progression`, `inter_arrival_min_s`) depend on order.

Windows are ordered by the pair `(timestamp, ingest_seq)`, where `ingest_seq` is the monotonic counter assigned in Component 1. This makes ordering total and reproducible across replays, which Section 3.2 property 3 requires.

Alerts with an inter-arrival gap of exactly zero after tie-breaking contribute a floor value of 1 ms to `inter_arrival_min_s`, so that the feature remains defined without a special case.

#### 4.2.3 Admission policy

Not every Wazuh alert is a behavioural event, and admitting the ones that are not corrupts the window features rather than merely diluting them.

**Excluded:**

1. alerts whose `rule.groups` intersects `{sca, rootcheck, policy_monitoring, ciscat}`;
2. *(Revision 3)* integrity-monitoring alerts produced by a **scheduled scan**, `syscheck.mode = scheduled`. Registry rules that lack the field are treated as scheduled, because Windows registry monitoring is scan-only.

*Reason.* These rules report configuration-assessment and policy-scan state. They fire in bulk on a schedule, they are not attributable to a subject acting on an object, and — critically — the MITRE fields they carry describe *what the check mitigates*, not what anyone did. Three window features (`distinct_tactic_count`, `distinct_technique_count`, `tactic_progression`) read those fields as behavioural evidence, and would be reading them wrongly.

*Measured justification.* In the 300-alert sample of 5 September, 281 of 300 alerts (94%) came from a single CIS benchmark scan lasting 23 seconds. Those 281 alerts carry **13 distinct MITRE tactics and 93 distinct techniques**. Under the submitted design a single benign configuration scan would therefore have produced saturated windows with maximal tactic diversity, and would have cleared the two-tactic escalation gate of Section 4.4.3 by a factor of six.

*Cost of the exclusion, stated plainly.* It removed 94% of the alert volume in that sample, leaving 19 behavioural alerts in 596 seconds. **That figure was a property of a 300-alert sample dominated by one scan, not of the testbed.** Measured over 18.2 days of normal use, the whole admission policy removes 1,789 of 62,481 alerts, 2.9%: 511 compliance alerts and 1,278 scheduled-scan FIM alerts. The re-enrollment of 27 September caused a full SCA and rootcheck re-scan under the new agent id, and the filter absorbed all of it. That event is the case the filter exists for.

*Why scheduled-scan FIM is excluded.* A scheduled syscheck result carries the time the scan ran, not the time the change happened. Measured: 1,190 registry FIM alerts fell into **four distinct minutes**, up to 392 in one minute. The timing features would read each scan as a burst of activity that never occurred. Real-time and who-data FIM alerts keep near-change timestamps and remain admitted; none was observed on this testbed. The objection is to the timestamp, not to the content, which is why the criterion is `syscheck.mode` rather than a rule list.

**Admitted but flagged:** alerts from the `ossec` group reporting agent and manager state (rules 502, 533 and similar). These are behavioural in form but describe the monitoring infrastructure rather than the monitored system. They are admitted so that windows reflect what actually occurred, and their contribution is reported separately in the feature-importance analysis so that a result driven by them is visible rather than hidden.

#### 4.2.4 State representation and eviction

Per entity, the builder maintains:

- a bounded deque of at most `N` alert references, ordered as in Section 4.2.2;
- the timestamp of the most recent alert, for expiry.

The window itself is a view over alert state (Section 3.2 property 1); the deque holds references, not copies.

**Eviction.** An alert leaves the deque when either it is displaced by the `N+1`-th arrival, or its age exceeds `T`. An *entity* is evicted from the builder after `2T` of inactivity. Note that entity eviction from the **builder** is independent of eviction from the **risk accumulator**: risk decays with half-life `h`, which may exceed `T`, so an entity with no recent alerts can hold non-negligible risk state while holding no context state. The two structures are keyed alike and expire differently, and treating them as one structure would be an error.

**Memory bound.** `O(|E| · N)` alert references for `|E|` active entities, plus `O(|E|)` risk records. For a testbed with tens of entities this is negligible; the bound is stated because it is what makes the claim of real-time operation checkable rather than asserted.

**Cost.** Feature computation is `O(N)` per `(alert, entity)` pair; deque maintenance is `O(1)` amortised. At the busiest minute observed in the baseline (1,217 admitted alerts, about 20 alerts/s, at a start-up burst), with two entity types and `N = 20`, this is roughly 800 feature operations per second. The active-time correction (Section 4.2.6.2) adds `O(k)` per window for `k` downtime intervals inside the lookback. On this host `k` is at most a few per day.

#### 4.2.5 Cold start and burn-in

Two distinct situations, handled differently.

**Cold start (an entity is new).** Windows with `window_size < 3` are not scored. `S_seq` is set to 50 — the baseline median percentile under the calibration of Section 4.3.4 — and the alert is flagged **unscored**. The flag is surfaced in Component 9 so an analyst sees "no temporal evidence available" rather than inferring "normal". Several features (`rule_level_trend`, `tactic_progression`, `inter_arrival_*`) are undefined on windows this short; the threshold of 3 is the minimum at which a trend has meaning.

**Burn-in (the evaluation period is new).** Distinct from cold start and addressed in Section 6.2: windows early in the evaluation period reach back into baseline alerts, which is realistic and should not be prevented, but the first `T` of the evaluation period is excluded from metric computation.

#### 4.2.6 The feature map

The builder computes `φ(W) ∈ ℝ¹⁵`; the anomaly model of Section 4.3 consumes **14** of them. Every feature is computed from the Wazuh alert stream alone, and none requires a data source the testbed does not have. This is a deliberate constraint: it makes the component reproducible by anyone with a Wazuh deployment.

| # | Feature | Definition | Rationale | Model input |
|---|---|---|---|---|
| 1 | `window_size` | `\|W\|`, alerts actually present (≤ N) | Sparse vs. saturated | yes |
| 2 | `window_duration_s` | **active** time from first to last alert (Section 4.2.6.2) | Burst vs. slow activity | yes |
| 3 | `distinct_rule_count` | `\|{rule_id}\|` over `W` | Varied vs. one repeating rule | yes |
| 4 | `repeat_ratio` | count of modal `rule_id` ÷ `window_size` | High = repetitive noise | yes |
| 5 | `rule_level_max` | `max rule_level` | | yes |
| 6 | `rule_level_mean` | arithmetic mean of `rule_level` | | yes |
| 7 | `rule_level_trend` | OLS slope of `rule_level` on position | Escalation signal | yes |
| 8 | `distinct_technique_count` | `\|{mitre_technique}\|`, union over list-valued fields | | yes |
| 9 | `distinct_tactic_count` | `\|{mitre_tactic}\|`, union over list-valued fields | Multi-stage indicator | yes |
| 10 | `tactic_progression` | Spearman ρ between position and tactic ordinal (Section 4.2.6.1) | Multi-step attack signal | yes |
| 11 | `inter_arrival_mean_s` | mean successive **active** gap; gaps wholly inside downtime omitted (Section 4.2.6.2) | | yes |
| 12 | `inter_arrival_min_s` | min successive **active** gap, floored at 1 ms; same omission | Automation signal | yes |
| 13 | `burst_ratio` | alerts within 60 s of `a` ÷ `window_size` | | yes |
| 14 | `novel_rule_flag` | 1 if `rule_id` unseen for this entity during baseline, else 0 | Novelty | yes |
| 15 | `night_fraction` | fraction of `W` outside 09:00–18:00 site-local time | | **no** — see below |

Features 2, 11 and 12 are heavy-tailed by construction and are `log1p`-transformed before model fitting (Section 4.3.3). The table above defines the raw feature; the transform belongs to the model, not the feature.

**Population on the baseline (measured).** Every feature varies over the 18-day corpus; none is constant. `novel_rule_flag` is binary by definition, and its two values are its full range, not a defect.

**Features 8–10 and MITRE coverage (measured).** 9.4% of admitted alerts carry an ATT&CK tag before the scheduled-FIM exclusion, and about 7.7% after it. Across windows, `distinct_technique_count` reaches 9, `distinct_tactic_count` reaches 8, and `tactic_progression` spans the full range −1 to +1. The tags on this **benign** baseline cover most of the kill chain. The single most frequent is T1570 *Lateral Tool Transfer*, 1,039 alerts from Sysmon rule 92217, on a standalone desktop that has nothing to move laterally to. After it come T1105 *Ingress Tool Transfer* (software downloads), T1543.003 (service creation), and T1059 (command and PowerShell execution). **On a developer workstation, the presence of a tag, or of several tactics, does not separate attack from normal.** This is the empirical case for the design's premise: whether a window is unusual must be learned against a baseline, not read off rule metadata. Features 8–10 stay in the model precisely because they vary on benign data, so the forest can learn what normal tag diversity looks like. Whether they contribute is shown by the attribution of Section 4.3.5, not assumed.

**`night_fraction` is computed but not a model input.** A simulation study found it worth −0.019 AUC on a duty-cycled baseline and +0.002 at full night coverage (`night_coverage_note.md`). The original argument for dropping it was that it would be near-constant on a host shut down at night. That argument does not hold here: the host is used into the evening, so the feature takes 31 distinct values. The honest statement is narrower: it contributed nothing measurable even where populated. Inclusion is re-tested on the Session A tuning set (Section 6.2) as an ordinary feature-selection decision, and the result is reported either way.

##### 4.2.6.1 Technique selection and tactic ordering

Two of the window features depend on MITRE ATT&CK mappings, which requires deciding in advance which techniques the system tracks and how tactics are ordered. Both decisions are made **before any data is collected**, so that feature selection cannot be influenced by results.

**Technique selection.** Candidate techniques are drawn from the public Wazuh ruleset at a pinned release tag, applying two criteria:

1. the technique is referenced by at least ten distinct rules in the Windows or Sysmon rule groups;
2. the technique is associated with host-based intrusion activity in the MITRE ATT&CK Enterprise matrix.

The resulting list, the ruleset version, and the date of inspection are recorded in the report. This procedure follows the a priori selection method used for the web-application domain in [ref17], transposed to host telemetry.

Rule groups excluded by the admission policy of Section 4.2.3 are excluded from this count, so that a technique referenced only by compliance checks does not enter the tracked set.

**Tactic ordering.** Each tracked technique is mapped to its ATT&CK tactic, and each tactic is assigned an ordinal position approximating adversary progression: Reconnaissance (1), Resource Development (2), Initial Access (3), Execution (4), Persistence (5), Privilege Escalation (6), Defense Evasion (7), Credential Access (8), Discovery (9), Lateral Movement (10), Collection (11), Command and Control (12), Exfiltration (13), Impact (14).

**`tactic_progression`** is the Spearman rank correlation between an alert's position in the window and the ordinal of its tactic, computed over those alerts in the window that carry a tactic mapping. It is defined as 0 when fewer than three such alerts are present. A value near +1 indicates activity advancing through the kill chain within the window; a value near 0 indicates unordered or repetitive activity.

Where an alert carries several tactics, the lowest ordinal is used, on the reasoning that the earliest stage represented is the more conservative attribution.

**Stated limitation.** ATT&CK tactics are not strictly sequential — Defense Evasion and Discovery recur throughout an intrusion rather than occupying a fixed stage. The ordinal scale is therefore a heuristic, not a claim about adversary behaviour, and `tactic_progression` should be read as a weak ordering signal. The baseline sharpens this: benign windows already take 1,380 distinct values across the whole range, largely from which tagged rules happen to fire in which order. An attack chain has to stand out against that spread. The feature is one of fourteen inputs, and its individual contribution is visible in the feature-importance analysis.

##### 4.2.6.2 Active-time correction

The testbed host is a desktop on a duty cycle: it is shut down most nights and was awake 8.8 hours per calendar day across the baseline. With `T = 24 h`, the first windows of each morning reach back across the overnight shutdown. Uncorrected, `window_duration_s` reached 82,652 s (23 h) and `inter_arrival_mean_s` 20,125 s. Those values came from the host being off, not from anything any entity did. Because the artefact repeats daily, the model would learn it as a normal mode and then have nothing left to say about genuinely slow activity. **The host being off is not the entity being quiet, and only the second is evidence.**

*Downtime detection.* A gap longer than `G` in a host's **global** alert stream is taken as the host being off. The global stream is every alert from that host, of any entity, *including alerts the admission policy excludes*, because a compliance scan still proves the machine was on. `G = 1800 s` **(measured)**. The gate's data-derived threshold (20 × the median gap, floor 1800 s) resolved to this value on the live corpus, and it cleanly separated 23 nightly shutdowns from awake activity over 18 days. It is frozen as a parameter rather than re-derived online, so the feature map does not drift with the data.

*Detection is online and causal.* A downtime interval is recognised when the first alert after it arrives. It can therefore only affect windows computed from that alert onward, so no information from the future enters any feature. The online intervals are identical to those found by batch analysis of the same stream (`tools/test_active_time.py`).

*Definitions.* For successive alerts `x_i, x_{i+1}` in `W`, with `D(x_i, x_{i+1})` the detected downtime between them:

> active gap `g_i = time(x_{i+1}) − time(x_i) − D(x_i, x_{i+1})`
>
> `window_duration_s = Σ g_i`
>
> `inter_arrival_mean_s`, `inter_arrival_min_s` = mean and minimum of `max(g_i, 1 ms)` over gaps **not wholly inside downtime**

The omission in the last line is deliberate. For the host entity, the overnight gap *is* the detected interval, so its active length is exactly zero. Counted, it would sit at the 1 ms floor and make every morning window look as if it held two simultaneous alerts, which is the automation signature of feature 12. A gap that lies entirely within downtime is not an observation of the entity at all. A window whose only gap is downtime has duration 0 and inter-arrival features 0, the same convention as a one-alert window.

*Effect on the corpus.* After correction, 23 intervals are subtracted, the longest window falls from 82,652 s to 31,370 s, and the longest mean gap from 20,125 s to 6,443 s. Windows that remain long are legitimate. Either the user was quiet while the machine kept producing system alerts, or an idle machine produced an alert just often enough never to cross `G`. That second case sets the method's resolution: an idle host that goes longer than `G` without an alert is read as off. The deliberate awake nights of the collection plan are the ground truth for testing it.

*Scope.* Downtime is taken from the host of the current alert. This is exact on a single-host testbed. A user whose window spans several hosts would need the union of those hosts' uptime, which is out of scope while one host is monitored.

*Why this is worth reporting.* It is a consequence of deploying on a workstation rather than a server. A prioritisation layer on a real endpoint must distinguish "the host was off" from "the entity was quiet", and an evaluation run only on always-on infrastructure would never encounter the problem.

#### 4.2.7 Combining per-entity windows

Component 5 produces one vector per `(alert, entity)` pair; Component 7 consumes one score per alert. The reduction is

> `S_seq(a) = max_{e ∈ entities(a)} S_seq(a, e)`, with `argmax` recorded.

**Maximum, not mean.** An alert that is unremarkable in the context of its host but highly unusual in the context of the user account should be promoted; averaging across entities — particularly when one of them has a sparse or cold-start window scored at the median — would suppress exactly the case the design exists to catch.

The `argmax` entity is carried into the explanation, so the analyst is told *which* entity's history drove the promotion. Without it the score is uninterpretable when an alert resolves to several entities.

Unscored windows (Section 4.2.5) do not participate in the maximum unless every window for the alert is unscored, in which case the alert is itself flagged unscored.

#### 4.2.8 What the window deliberately does not capture

Stated so that these read as decisions rather than oversights:

- **Cross-entity structure.** Excluded by the design requirement of Section 2. A window concerns one entity; relationships *between* entities are not modelled.
- **Causal lineage.** Sysmon supplies parent-child process relationships, and the window does not use them. A window is a time-ordered sequence, not a process tree. Using lineage would be a different and larger design.
- **Alert content.** `full_log`, command lines and file paths are not featurised. Doing so would make the component depend on decoder-specific fields and would break the reproducibility constraint stated above. The consequence is worth stating as a property: **the pipeline is content-blind.** It needs only `rule_id`, `rule_level`, `rule_groups`, MITRE tags, timestamp, entity identifiers and `syscheck.mode`, and never process names, command lines, paths or URLs. Command-line capture for process creation is accordingly left **off** on the testbed. "We retain rule identifiers and timestamps, not log content" is then true by construction rather than by promise, which matters for collecting a baseline on a machine in daily personal use.
- **Alert volume across entities.** A host generating alerts about many distinct users is not distinguished from one generating the same volume about a single user, except insofar as the per-user windows differ.

**Output:** `window_vector(a, e) = φ(W(e,a))`, plus the window's alert references for explanation.

---

### 4.3 Component 6 — Sequence Anomaly Scoring

Converts the window vector into a scalar anomaly score `S_seq ∈ [0,100]`.

This component scores the correlated window produced by Component 5; it does not itself determine which alerts are related. The separation is deliberate — correlation is a structural decision that should remain inspectable, while scoring is where the learned model belongs.

#### 4.3.1 Method and why

**Isolation Forest**, fitted unsupervised on window vectors collected during a benign baseline period.

- **Unsupervised.** Labels are unavailable at training time and expensive to obtain. Isolation Forest requires none.
- **Precedent.** Isolation Forest is the established choice for this role in the alert-triage literature, appearing in the comparison table of AlertPro [ref5].
- **Cost.** Training and inference are cheap enough for real-time operation on a desktop-scale testbed (measured: 0.6 s to fit at ψ = 4096 on 50,000 rows, two cores).
- **Rejected: deep sequence models.** DEEPCASE's attention-based encoder-decoder [ref15] is more expressive, but requires a volume of event data the testbed will not produce and would not be trainable within the project schedule.
- **Rejected: supervised classification.** Requires labels for training, not merely for evaluation, and would overfit the specific emulated techniques.

This component is the answer to a gap in the Deliverable 1 pipeline: the weighted scoring model consumes a `behavior_anomaly_score` as an input without specifying what produces it. Component 6 produces it.

#### 4.3.2 Model scope

**One model per entity type** (host, user), not one global model.

Window vectors for different entity types are drawn from different distributions. A host window mixes every account's activity and is dense; a user window holds only that account's actions and is sparser. A single forest would have to treat "sparse window" as anomalous and as normal simultaneously, and would resolve that by whichever entity type dominated the training set.

*Measured volume per type.* The host model is comfortably fed: 6,069 training windows at stride 10 on 30 September, reaching the 8,000 target around 6 October. **The user model is not.** User windows are about half as frequent, giving roughly 3,100 at stride 10 on 30 September, below the 4,000 floor. At the observed rate the user pool passes the floor around 6 October and reaches roughly 5,900 by the 17 October freeze, short of the target.

*Consequence.* The user model is fitted under the floor regime of Section 4.3.6: seed-variance bands are reported with every user-model result, and B2's user-entity contribution is read against them. If the user pool at freeze is below the floor, the fallback applies: a single model with entity type one-hot encoded. Which was used is reported with the results.

#### 4.3.3 Training data construction

**Autocorrelation is the controlling problem.** Consecutive alerts on one entity produce windows that overlap in `N−1` of their `N` alerts. The number of training rows therefore overstates the number of independent observations by roughly a factor of `N`. Choosing `max_samples` against an uncorrected row count would be a silent error.

Two controls:

1. Training windows are subsampled at stride `s = N/2 = 10` **(measured)**, so adjacent training rows share at most half their alerts.
2. Effective sample size is reported alongside raw row count.

Striding is not only housekeeping. In simulation, the same 40-day baseline scored ranking AUC 0.981 at stride 1 (117k rows) and 0.993 at stride 20 (5.9k rows). Discarding 95% of the rows *improved* the model, because de-duplication gives quiet periods their proportionate weight against dense bursts. Stride 20 is checked alongside 10.

**Preprocessing.** Isolation Forest chooses split points uniformly between the minimum and maximum of a feature *within each node*, so a heavy tail draws split points away from the dense region where the decision actually matters. Features 2, 11 and 12 (`window_duration_s`, `inter_arrival_mean_s`, `inter_arrival_min_s`) are `log1p`-transformed. `tactic_progression ∈ [−1,1]` and `novel_rule_flag ∈ {0,1}` are used as-is. No standardisation is applied — with the tails handled, it would not change axis-parallel split behaviour.

#### 4.3.4 Hyperparameters and score calibration

| Parameter | Value | Justification |
|---|---|---|
| `n_estimators` | 200 | Above the point where cross-seed score variance stabilises for low-dimensional data; cost negligible here |
| `max_samples` (ψ) | **4096** **(measured)**; `min(4096, n)` if a pool is smaller | See below. Revision 2 specified 256 |
| `max_features` | 1.0 | All 14 model features available at each split |
| `contamination` | **not used** | It sets a decision threshold only. This design ranks rather than thresholds; setting it would import an unjustified prior about the attack rate. `score_samples` is consumed directly |
| `random_state` | fixed; 10 seeds reported | Results reported as mean ± sd over seeds. At the target volume the seed spread is small (simulation: ±0.003 AUC at n = 8,000); under the floor it is not (±0.037 at n = 1,000), which is why the user model reports bands |

**Why ψ = 4096, not 256 (Revision 3).** Revision 2 chose ψ = 256 from the original Isolation Forest paper's swamping-and-masking argument. That argument assumes anomalies form a *dense cluster* in feature space, and the assumption was not checked. Here attack windows are a diffuse minority. Measured in simulation at n = 8,000 over 10 seeds, ranking AUC was:

| Model | AUC |
|---|---|
| ψ = n | 0.996 |
| **ψ = 4096** | **0.991** |
| Mahalanobis comparator | 0.965 |
| ψ = 1024 | 0.958 |
| ψ = 256 | 0.926 |
| max\|z\| comparator (B2′) | 0.753 |

At ψ = 256 the forest falls below a simple Mahalanobis comparator. The project would then have concluded that the machine-learning method does not earn its place, as an artefact of one hyperparameter. A hypothesis that baseline contamination would reverse the ordering was tested and refuted: large ψ wins at every contamination level. ψ = 4096 rather than ψ = n because the model grows with ψ: 13.7 MB and 0.6 s to fit at 4096, against 75 MB and 2.5 s at n, for +0.005 AUC. Hardware is not a constraint at either setting.

**Score calibration.** Isolation Forest's native output is the path-length statistic `s(x, ψ) = 2^(−E[h(x)] / c(ψ))`, whose values for real data concentrate tightly around 0.5. Rescaling that range linearly onto `[0,100]` would place nearly every window between roughly 45 and 55 — so `w_s · S_seq` would be near-constant across alerts and the weight `w_s` would be doing almost no work whatever its value. The B2-vs-B1 comparison of Section 6.3 would then measure close to nothing, for a reason unrelated to whether temporal context is useful.

The mapping is therefore **percentile calibration against the frozen baseline**:

> `S_seq = 100 · F̂_baseline( s(φ(W)) )`

where `F̂_baseline` is the empirical CDF of raw scores over the baseline training windows, stored as a lookup table with linear interpolation between knots.

Three consequences:

- `S_seq` is uniform on `[0,100]` over baseline data by construction, so it is commensurate with `S_rule` and `S_exp` and the weights of Section 4.3.7 become interpretable.
- The transform is monotone, so within-model ranking is unchanged.
- The CDF table is fitted on baseline data only and frozen with the model. It is a **parameter** under Section 3.3, and falls under the Risk 2 control of Section 6.2.

#### 4.3.5 Attribution

Component 9 promises the window features that most influenced `S_seq`. Isolation Forest provides no native attribution, so the method is specified here rather than assumed.

**Leave-one-feature-out re-scoring.** For each feature `j`, recompute the score with `φ_j` replaced by its baseline median, and report the resulting drop in `S_seq`. The three largest drops are surfaced. Cost is 14 re-scores of 200 trees per explained alert, which is negligible and incurred only for alerts an analyst actually opens.

`shap.TreeExplainer` supports `IsolationForest` and was considered. Leave-one-out is preferred: it is simpler to describe in the report, adds no dependency, and its output ("the score falls by 31 points if burst_ratio were typical") is directly interpretable to an analyst.

#### 4.3.6 Sanity comparator and the volume risk

**Comparator.** A trivial baseline is fitted alongside: the aggregate robust z-score `max_j |z_j|`, with `z_j` computed against the baseline median and MAD of feature `j`. If Isolation Forest does not beat this on nDCG, the forest is not contributing and the honest finding is to report that. The cost is near zero and it pre-empts the obvious question of why a forest is warranted at all.

**Volume — measured, and resolved for the host model.** Revision 2 carried training volume as the project's leading risk: the 300-alert sample yielded 19 admitted alerts in 596 seconds. It was measured in the first week as required. The admitted rate on normal use is 3,411 alerts per calendar day. The Phase 1 go/no-go gate on 18 September returned GO against a target of **8,000 training windows at stride 10, floor 4,000 (measured)**. Those figures come from the variance argument above: below about 2,000 windows, the seed noise exceeds the B2 − B1 effect the project exists to measure. The host pool stood at 6,069 on 30 September. The residual volume risk is the user model (Section 4.3.2).

The volume-driven fallbacks of Revision 2 are therefore not applied. In particular, features 8–10 are *not* dropped (Section 4.2.6).

---

### 4.4 Component 7 — Hybrid Priority Scoring, and Component 8 — Risk Accumulation

#### 4.4.1 Component 7 — per-alert priority

```text
P(a) = w_r · S_rule(a)      [alert state]
     + w_c · S_exp(a)       [alert state]
     + w_s · S_seq(a)       [context state]
```

where

- `S_rule` = Wazuh rule level normalized to [0,100] (`level/15 × 100`)
- `S_exp`  = entity attribute score from Component 4
- `S_seq`  = sequence anomaly score from Component 6, reduced across entities per Section 4.2.7

The bracketed annotations are not decoration: they record that `P(a)` spans two state layers, and that only its third term carries temporal information. The B1→B2 ablation of Section 6.3 is exactly the addition of that term.

**On the weights.** Fixed weights asserted without justification are the most common weakness in risk-scoring designs. This project addresses them explicitly by:

1. Reporting results under a documented default (`w_r = 0.3, w_c = 0.2, w_s = 0.5`);
2. Performing a sensitivity analysis over the weight simplex and reporting how ranking quality varies;
3. Reporting the weights that maximize nDCG on the tuning set, as an upper bound, while making clear these are fitted and not proposed as general values.

The percentile calibration of Section 4.3.4 is what makes these weights meaningful: without it the three terms would not be on comparable scales and `w_s` would be uninterpretable.

The scoring function remains linear and inspectable. Each term's contribution to a given alert's score can be displayed to the analyst.

#### 4.4.2 Component 8 — accumulation without double counting

Maintains a decaying risk total per entity, so that a sustained campaign of individually unremarkable alerts becomes visible.

The submitted version of this document accumulated `P(a)` over every alert:

```text
R_e(t) = Σ  P(a_i) · 2^(−(t − t_i)/h)          [SUPERSEDED]
```

Applied to the recorded 300-alert sample this yields `R_host = 2609.9`, of which **93% comes from a single 23-second benign compliance scan**. Deduplicating to one contribution per rule gives 130.5 — a factor of **20** between the two. The formula was measuring how many alerts occurred, not how much they meant.

Three distinct double-counting mechanisms are present, and they need different remedies.

**Mechanism 1 — repeat inflation.** Identical alerts each contribute in full. *Remedy:* group by repeat key `(entity, rule_id)` and saturate concavely — a group of `k` alerts contributes `(1 + ln k)` times a single alert's value rather than `k` times. The first occurrence of a rule is the informative one; the hundredth carries almost nothing. Wazuh's `rule.firedtimes` is a manager-global counter rather than a per-entity one, so the layer maintains its own per-entity count; `firedtimes` is retained in the schema for cross-checking, not as the source of `k`.

**Mechanism 2 — window evidence charged per alert.** This is the structural case and it survives the admission filter. `S_seq` is a property of a *set* of alerts, but `P(a)` is per-alert and the accumulator sums over alerts — so a window that is anomalous **once** is charged up to `N` times as it slides. *Remedy:* the window term does not accumulate. It enters as a **decayed running maximum**.

**Mechanism 3 — cross-entity fan-out.** Section 4.4.5.

The revised accumulator:

```text
R_e(t) =   Σ      (w_r·S_rule(g) + w_c·S_exp(g)) · (1 + ln k_g) · 2^(−(t − t_g)/h)
        g ∈ groups(e)

        +  w_s ·   max        S_seq(a,e) · 2^(−(t − t_a)/h)
                a ∈ alerts(e)
                t − t_a < T
```

where `groups(e)` are the repeat groups for entity `e`, `k_g` the group's alert count, and `S_rule(g)`, `S_exp(g)`, `t_g` those of the group's first member.

The **point term** accumulates deduplicated alert-local evidence. The **window term** is bounded by the single most anomalous window observed within the lookback, rather than growing with the number of alerts that happened to fall inside it.

*Why a running maximum rather than non-overlapping windows at stride `N`.* A stride-based scheme would wait for `N` alerts before registering an anomalous burst, which defeats the purpose in exactly the brute-force case of Section 2.1. The maximum responds on the first anomalous window and is monotone-bounded, which is what makes the threshold `θ` interpretable rather than dependent on alert volume.

Half-life `h = 4 hours` (provisional).

*Verification note.* Both remedies were checked against the 300-alert sample of 5 September. On the full 300 alerts, saturation alone reduces `R_host` from 2609.9 to 303.3; after the admission filter of Section 4.2.3, 19 alerts remain and saturation reduces 178.2 to 146.6 — still a factor of 1.9 against first-occurrence-only accounting. **The admission filter does not subsume the saturation fix**; both are required.

#### 4.4.3 Escalation gate

An entity is escalated to a **risk notable** when all three hold:

1. `R_e(t) > θ`;
2. the contributing alerts span at least two distinct MITRE tactics;
3. the contributing alerts span at least two distinct **repeat groups**.

Condition 3 is new. The submitted document claimed condition 2 alone "suppresses the common failure mode of accumulation models, in which one noisy repeating rule alone crosses the threshold." Measured against the 300-alert sample of 5 September, it does not: the 281 compliance-scan alerts carry 13 distinct tactics, clearing a two-tactic gate by a factor of six and a half. One rule that carries twelve technique mappings is one piece of evidence, not twelve, and condition 3 is what encodes that.

Condition 2 is retained rather than replaced, because the two conditions fail differently: condition 2 catches a single multi-tactic rule firing repeatedly, condition 3 catches a single rule carrying many tactics. Neither implies the other.

**Revision 3: condition 2 is weak on this testbed, measured.** Benign activity carries ATT&CK tags on about 8% of admitted alerts (Section 4.2.6). Several common benign rules each carry two or three tactics on their own: 92307 (service creation), 92219 (DLL search-order), 67028 (special privileges at every sign-in), 92058. **A single benign alert therefore satisfies "at least two tactics".** Condition 3 is also easily met by ordinary activity, which routinely involves several rules. In practice, on a developer workstation the gate reduces to the threshold `θ`.

Proposed tightening, to be evaluated rather than asserted: count tactics per contributing **rule**, and require the union of tactics to span at least two tactics contributed by *different* rules. One rule, however many tactics it carries, then cannot satisfy condition 2 alone. The pass rate of benign entities under both the current and the tightened condition is measured on the frozen baseline before either is relied on. The measurement is reported whichever way it falls (Section 9.2).

This mechanism follows the risk-based alerting model used in commercial SIEM practice, adapted to Wazuh.

#### 4.4.4 Wazuh composite alerts

Wazuh's `frequency` and `if_matched_sid` rules emit a composite alert *summarising* alerts that are themselves present in the stream. Treating the composite and its constituents as independent evidence is double counting by construction.

*Handling.* The composite **replaces** its constituents in the accumulator; constituents still enter windows, because Component 5 needs the raw sequence to compute timing and repetition features.

*Detection, and its current uncertainty.* Candidate signals are the presence of `previous_output` and the rule's `if_matched_sid` lineage. **This has not been verified against data.** The 300-alert sample of 5 September contains two alerts carrying `previous_output`, but both are rule 533 netstat diffs — a different use of the same field — and the sample contains no authentication or brute-force activity of the kind that produces frequency composites. The detection method must be validated against a stream that actually contains them before the implementation relies on it. The frozen 18-day baseline (68 distinct admitted rules) is the first stream large enough to check for `frequency`-type composites; that check precedes implementation of this rule. Carried as a risk in Section 10.

#### 4.4.5 Cross-entity deduplication

An alert resolving to host and user contributes to two risk totals. This is not double counting within an entity, but it produces three notables for one incident and makes totals incomparable across entity types.

Two rules:

- `R_e` values are comparable **within an entity type only**. The ranked queue does not interleave host risk with user risk on a common scale.
- Notables sharing contributing alert IDs above a threshold fraction are collapsed into one **incident** at Component 9, with the highest-scoring entity designated primary and the others listed as also-implicated.

## 5. Data Model

```text
RawAlert          -- as emitted by Wazuh, immutable; retained even when not admitted
NormalizedAlert   -- Section 4.1.2 schema + admission flag        [alert state]
DowntimeInterval  -- (host, start, end), detected online          [derived from alert state]
EntityRef         -- (type, identifier)
WindowVector      -- (alert_id, entity_ref, features{...}, N, T)  [context state, a view]
ScoredAlert       -- (alert_id, S_rule, S_exp, S_seq, argmax_entity, P, explanation[])
RepeatGroup       -- (entity_ref, rule_id, k, first_alert_id, first_ts)
EntityRisk        -- (entity_ref, R_point, R_window, R, groups[], notable_flag)
Incident          -- (primary_entity, implicated_entities[], contributing_alert_ids[])
ModelArtifact     -- (entity_type, forest, cdf_table, feature_transform, feature_list, fit_date, version)
FeatureMapConfig  -- (N, T, G, host_alias_table, admission_policy, version)
```

`ModelArtifact` and `FeatureMapConfig` are **parameters**, not state (Section 3.3), and are versioned separately so that every reported result names the artifacts it used. `DowntimeInterval` is a pure function of the alert log, like context state, so the replay property of Section 3.2 is preserved.

Stores are kept separate so that scoring logic can be revised and the full alert history re-scored without re-collection. Re-scoring capability is required for the ablation in Section 6.3, and Section 3.2 property 3 establishes why it holds.

## 6. Evaluation Design

The evaluation determines whether temporal context improves prioritization over Wazuh's native ranking. It is specified here because it constrains the implementation.

### 6.1 Ground truth by adversary emulation

Wazuh alerts carry no labels. Labels are generated by controlled attack execution:

1. Benign activity is the host's normal use under its ordinary duty cycle, not a continuously running workload. The evaluation stream therefore contains the same start-up bursts and overnight gaps as the baseline.
2. Attack techniques are executed from a manifest recording `(technique_id, target_host, start_time, end_time)`.
3. An alert is labelled positive if it falls within `[start − δ, end + δ]` on the target host, with `δ = 60 s`.
4. All other alerts are labelled negative.

This follows the MITRE ATT&CK evaluation methodology applied to Wazuh in [ref12]. Labelling by time window is imperfect — a benign alert inside the window is mislabelled — and the error rate is estimated by manual inspection of a sample and reported.

Labelling applies to admitted alerts only; non-admitted alerts are neither ranked nor scored and are excluded from metric computation.

### 6.2 Data partitioning and contamination control

Four risks threaten the validity of the measurement. They are separated because they have different causes and different remedies, and only the third is leakage in the usual sense.

**Risk 1 — a contaminated baseline.** The anomaly model in Component 6 is trained on windows drawn from a benign baseline period. If that period contains attack activity — an emulation run started early, or genuine malicious activity on a personal machine — the model learns that activity as normal and will subsequently rank it low. This is the most likely failure in a small testbed and the least visible.

*Controls.* No emulation is executed during the baseline period. The baseline is collected on the isolated VM and the monitored host under normal use only. Before training, the highest-scoring baseline windows under a provisional model are manually inspected, and the inspection is reported.

**Risk 2 — evaluating on training data.** If Component 6 is trained on data that includes the evaluation period, the reported ranking quality is circular.

*Control.* A strict temporal split. The baseline period precedes the evaluation period; the anomaly model **and its calibration table** are fitted on baseline windows only and frozen before evaluation begins. Neither is refitted on evaluation data. The frozen artifact is versioned (Section 5) and its version reported with every result.

**Risk 3 — tuning on the test set.** This is the leakage that most threatens this project, because the system model commits to tuning `N`, `T`, `h`, `θ` and the scoring weights, and to reporting the weights that maximise nDCG. Selecting parameters on the same data used for the headline result inflates that result.

*Control.* Emulation is executed in two disjoint sessions using the same technique manifest. Session A is the tuning set: all parameter selection, weight fitting and sensitivity analysis are performed on it. Session B is held out, touched once, and is the source of every reported comparison between B0–B3. Where a fitted-weight upper bound is reported, it is labelled as fitted on Session A and evaluated on Session B.

**Risk 4 — insufficient independent training windows.** New in this revision, arising from Section 4.3.3 and 4.3.6. Window overlap means the number of training rows overstates independent observations by roughly `N`, and the admission filter of Section 4.2.3 removes the bulk of the alert volume the testbed produces at rest.

*Control.* Admitted alert rate and effective sample size are measured at the start of baseline collection, not at the end. If the effective sample size is inadequate, the fallbacks of Section 4.3.6 are applied and reported — reducing the feature set is preferable to reporting a model fitted on too few independent windows.

*Status (Revision 3).* Measured weekly since 14 September. Host: GO, target reached around 6 October. User: below the floor on 30 September, expected between floor and target at freeze (Section 4.3.2).

**A note on windows that span the split.** A window built for an alert early in the evaluation period may reach back into baseline alerts. This is *not* leakage and should not be prevented: in deployment an attack always begins against a background of prior benign activity, so a window reaching backwards is the realistic case, and truncating it would make evaluation conditions differ from operating conditions. The one artefact worth handling is that the first few alerts of the evaluation period have windows composed almost entirely of baseline activity. A burn-in of `T` is therefore excluded from metric computation, and the exclusion is stated with the results.

### 6.3 Systems compared (ablation)

| System | Description | Isolates |
|---|---|---|
| B0 | Wazuh rule level only | Baseline |
| B1 | B0 + entity attributes (`S_exp`) | Value of enrichment |
| B2 | B1 + sequence anomaly (`S_seq`) | **Value of temporal context** |
| B3 | B2 + entity accumulation | Value of cross-alert aggregation |
| B2′ | B1 + robust z-score in place of Isolation Forest | Whether the forest earns its place |

B2 versus B1 is the measurement the project exists to make. B2′ is the sanity comparator of Section 4.3.6; it is reported whatever the outcome.

### 6.4 Metrics

Prioritization is a ranking problem and is measured with ranking metrics, not classification metrics:

- **nDCG@k** for k ∈ {10, 20, 50} — primary metric
- **Precision@k** — proportion of top-k that are attack alerts
- **Technique coverage@k** — fraction of executed techniques represented in the top k, capturing whether an analyst with a fixed budget sees each distinct attack
- **MRR** — rank of the first true positive
- **Alert volume reduction** — alerts an analyst can skip at fixed recall

All are reported as mean ± sd over the 10 model seeds of Section 4.3.4, so that a difference between systems can be read against the variance of a single system.

### 6.5 Threats to validity

- Emulated attacks are noisier and more concentrated than real intrusions; absolute scores will be optimistic.
- A single benign user generates less diverse background activity than an organization, understating false positives.
- Techniques are drawn from a public catalogue that Wazuh rules may be specifically tuned to detect.
- The admission filter of Section 4.2.3 removes 2.9% of the testbed's alert volume (measured). Results describe ranking quality over behavioural alerts; the filter's effect is reported separately as a descriptive statistic.
- **One host, two entity types.** Source IP is unavailable on a standalone desktop (Section 4.1.3). Per-entity-type modelling is exercised for host and user only.
- **Duty cycle.** The baseline reflects a desktop awake 8.8 hours per calendar day, not an always-on server. Overnight gaps are removed from the timing features by the active-time correction (Section 4.2.6.2). Night-time activity is represented only by the evening use, which already runs past midnight on most days, and by three deliberate awake nights, one of them on Patch Tuesday.
- **Start-up bursts dominate the baseline.** 34% of admitted alerts arrive within 15 minutes of the host coming on, or of activity resuming after a gap longer than `G`. That is about 4% of awake time. The model therefore learns dense multi-rule bursts as normal. An attack burst on this host must differ from a start-up burst in *what* fires, not merely in how densely it fires.
- **The baseline spans an examination period** in which machine use fell (8.3 hours per day in week 1, against 12.2 before collection began). Per-awake-hour alert intensity stayed in the same band, which indicates less use rather than a different generating process. The achieved uptime is reported rather than the historical norm.
- **Collection gaps are logged.** Agent re-enrollment on 27 September changed the endpoint's agent id without changing its configuration; it is handled by the host alias table and recorded as an identity change (Section 4.1.3).

These are stated in the results rather than left for the reader to infer.

## 7. Deployment View

```text
Windows 11 Host                     VM (isolated network)
+---------------------+             +---------------------+
| Wazuh Agent         |             | Wazuh Agent         |
| Sysmon64            |             | Attack execution    |
+---------------------+             +---------------------+
          |                                   |
          +------------------+----------------+
                             v
                   WSL2 Ubuntu 24.04
        +--------------------------------------+
        | wazuh-manager / indexer / dashboard  |
        | prioritization layer (Components 1-9) |
        +--------------------------------------+
```

Attack execution is confined to the VM. The host is not a target of emulated techniques.

## 8. Assumptions and Exclusions

**Assumptions**

- Wazuh raises an alert for the activity of interest; undetected activity is out of scope.
- Alert timestamps are consistent enough for ordering within a stream, with `ingest_seq` breaking ties (Section 4.2.2).
- A benign baseline period of sufficient length is available before evaluation. Tested, not assumed: sufficient for the host model, marginal for the user model (Sections 4.3.2, 4.3.6).
- The Wazuh field mapping of Section 4.1.2 matches what the deployed manager actually writes. Verified against recorded alerts, not documentation, after one mapping error was found (Section 4.1.2); covered by regression tests.

**Exclusions, with reasons**

| Excluded | Reason |
|---|---|
| Cross-source correlation | Out of the stated design requirement (Section 2) |
| Graph neural network | Agreed with the supervisor and dropped: the testbed's entity graph is too small for message passing to be meaningful, and the project focuses on machine-learning methods |
| Organizational context (department, peer group) | Not populatable in a testbed with one user |
| Configuration-assessment alerts (SCA, rootcheck, policy monitoring) | Not behavioural events; their MITRE fields describe mitigations, not actions (Section 4.2.3) |
| Process lineage as a window feature | A window is a time-ordered sequence, not a process tree (Section 4.2.8) |
| Source IP as an entity type | 0% resolution on a standalone desktop; no network logons occur (Section 4.1.3) |
| Scheduled-scan integrity-monitoring alerts | Timestamp is scan time, not change time (Section 4.2.3) |
| `night_fraction` as a model input | No measurable contribution; re-tested on Session A (Section 4.2.6) |
| Alert content (command lines, paths, `full_log`) | The pipeline is content-blind by design (Section 4.2.8) |
| Analyst feedback loops / learning-to-defer | Requires sustained analyst interaction unavailable in this project |
| Automated response | Prioritization layer only |

## 9. Design Questions

### 9.1 Resolved

**Graph neural network.** Agreed with the supervisor: the GNN component is dropped and the project focuses on machine-learning methods. This supersedes scope item 4 of Deliverable 1, which committed to applying a GNN over an alert graph. The final report must state the change and its justification explicitly rather than omitting the item silently, since the earlier scope is on record.

**Per-entity score reduction.** An alert resolving to several entities produces several `S_seq` values; the submitted document did not say how they combine. Resolved as maximum with `argmax` recorded (Section 4.2.7).

**Excluding configuration-assessment alerts** (Revision 2, question 1). Resolved: excluded, the recommended option. The volume cost Revision 2 feared came from a 300-alert sample dominated by one scan. Measured over 18 days, the whole admission policy removes 2.9% (Section 4.2.3).

**Training volume.** Resolved for the host model by measurement: the Phase 1 gate returned GO on 18 September (Section 4.3.6). The user model remains open, below.

**MITRE-dependent features 8–10.** Kept. An apparent finding that they were constant was a parser error, withdrawn. With the mapping corrected they vary on benign data (Section 4.2.6).

### 9.2 Outstanding

Listed in the order they block work.

1. **Escalation gate condition 2** (Section 4.4.3). On this testbed one benign alert can satisfy "at least two tactics". The tightened per-rule condition is proposed. Both are measured for benign pass rate on the frozen baseline, and the choice is made on Session A. Needed before Component 8 is implemented.

2. **User-model volume** (Section 4.3.2). If the user pool at freeze is between floor and target, the plan is per-type models with seed-variance bands on the user model. If it is below the floor, a single model with entity type encoded. Confirmation of that rule is wanted before the freeze, so it cannot be chosen after seeing results.

3. **VM benign baseline** (collection protocol §8). The attack VM contributes alerts during emulation. Either a benign baseline is collected for it, or the assumption that its benign stream resembles the host's is stated. To be decided before emulation begins in late October.

4. **What form would supervisor-provided ground truth take?** The answer determines whether adversary emulation is needed at all, so it gates the emulation phase. The distinction that matters is host-based versus network-based data. A public IDS benchmark such as CICIDS2017 or UNSW-NB15 consists of network flow records rather than Wazuh alerts, and could not be consumed by this system without either replaying traffic through a network sensor — which discards the Sysmon endpoint telemetry the design depends on — or abandoning the Wazuh-specific claim entirely. Host-based labelled data, or a lab capture that can be replayed through a Wazuh agent, would be usable directly. Emulation remains the fallback and is assumed until this is settled.

5. **Is the B0–B3 ablation the expected form of evaluation,** or is a comparison against a published method required? The ablation isolates the contribution of temporal context, which is the project's claim; a comparison against published work would require reimplementing a baseline from the literature and is a materially larger undertaking.

6. **Should B2′ be reported as a full ablation arm?** (Section 4.3.6.) The robust z-score comparator tests whether Isolation Forest earns its place. Reporting it is more honest and nearly free, but risks a result in which the trivial method wins and the machine-learning contribution is weakened on paper. Recommendation: report it regardless. In simulation at ψ = 4096 the forest leads the comparator clearly (Section 4.3.4), so the risk is smaller than Revision 2 supposed.

7. **Is a synthetic asset inventory acceptable** as the source of asset criticality, given that no authentic inventory exists for a testbed?

## 10. Schedule and Risks

| Phase | Dates | Output | Status |
|---|---|---|---|
| 0 Setup | 11–12 Sep 2026 | Audit policy, retention, T0 = 12 Sep 12:14 | Done |
| 1 Rate measurement | 12–18 Sep | Go/no-go on the whole design | **GO** (18 Sep) |
| 2 Baseline collection, and implementation of Components 1–9 | 18 Sep – 17 Oct | Frozen corpus (T1 = 17 Oct, after Patch Tuesday 13 Oct); working layer | In progress |
| 3 Emulation, two disjoint sessions | late Oct | Manifest + labelled corpus, split into tuning and held-out sets | — |
| 4 Evaluation, ablation, write-up | Nov | Results; implementation due about one week before the end of November | — |

Phase 2 is passive collection; implementation happens during it, not after it.

| Risk | Impact | Mitigation | Status |
|---|---|---|---|
| Insufficient admitted alert volume | Anomaly model untrainable | Measured weekly from week 1 (Section 4.3.6) | **Resolved for host**; user model marginal, Section 4.3.2 |
| User model below training floor | Wide seed variance on user-entity results | Floor regime with variance bands; single-model fallback (Section 4.3.2) | Open |
| Baseline contaminated by attack activity | Anomaly model learns attacks as normal | No emulation during baseline; contamination log; manual inspection of top-scoring baseline windows (Section 6.2) | Controlled |
| Parameters tuned on the reported test set | Headline results inflated | Two disjoint emulation sessions; Session B touched once (Section 6.2) | Controlled |
| Too few positive alerts | Ranking metrics unstable | Increase technique count and repetitions; report confidence intervals | Open |
| Benign MITRE tags are common | Tag-based gate conditions pass on benign activity | Measure gate pass rates on the frozen baseline; per-rule tactic condition (Section 4.4.3) | Open, **measured** |
| Composite-alert detection unvalidated | Composite and constituents both counted (Section 4.4.4) | Check the frozen baseline for frequency composites before implementation | Open |
| Class imbalance | Metrics dominated by negatives | Ranking metrics throughout | Controlled |
| Entity types resolve too rarely | Per-type models unfittable | Measured (Section 4.1.3) | **Realised** for source IP: dropped |
| Idle host misread as off (`G` too low) | Awake-but-idle time removed from timing features | Awake nights provide ground truth for `G` (Section 4.2.6.2) | Open; tested after 3 Oct |
| Collection agent silently changes identity or disconnects | Corpus silently stops growing while the gate reports healthy | Gate reports STALE and the status check reports a silent corpus agent within hours; host alias table (Section 4.1.3) | **Occurred** 27 Sep; handled, tooling now detects it |
| Field-mapping error in the parser | A feature silently constant or wrong | Mapping verified against recorded alerts; regression tests | **Occurred** (MITRE, Section 4.1.2); fixed |

## 11. Changelog

### 11.1 Revision 3 (2026-09-30) — measurement from the first 18 days of baseline collection

Every change below is driven by measurement on the testbed, logged in `COLLECTION_RECORD.md` with date and corpus hash, or by a simulation study cited in place.

| Section | Change | Driven by |
|---|---|---|
| 2.1 | Motivating example moved to Windows logon rules verified on the testbed (60122 → 60118) | The SSH example cannot occur on a standalone Windows desktop |
| 2.3 | Scheduled-scan FIM added to exclusions; measured stream composition | Measurement |
| 3.3, 5 | `G` and the host alias table are frozen parameters; `DowntimeInterval`, `FeatureMapConfig` added | Sections 4.1.3, 4.2.6.2 |
| 4 | Four parameters marked measured | Simulation study; live corpus |
| 4.1.2 | Both Wazuh MITRE shapes read; tactics normalised; user and `syscheck.mode` sources specified | Parser error found and fixed |
| 4.1.3 | **Two entity types.** Source IP dropped (0%); user selection rules; host identity via alias table | Measured resolution; re-enrollment on 27 Sep |
| 4.2.3 | Scheduled-scan FIM excluded; admission cost re-measured at 2.9% (was 94% on the sample) | 1,190 registry alerts in four minutes |
| 4.2.4 | Cost bound restated at the observed peak | Measurement |
| 4.2.6 | 14 model inputs; `night_fraction` excluded with a corrected rationale; features 8–10 kept; benign MITRE coverage reported | Measurement |
| 4.2.6.2 | **New.** Active-time correction: online, causal downtime detection; revised definitions of features 2, 11, 12 | Overnight gaps measured at up to 23 h |
| 4.2.8 | Content-blind property stated | Design property; ethics of personal-machine collection |
| 4.3.2 | Per-type volume measured; user model below floor | Measurement |
| 4.3.3 | Stride measured to improve the model, not only de-correlate | Simulation study |
| 4.3.4 | **ψ = 256 → 4096**, with the measured comparison | Simulation study; 256 rested on an unchecked assumption |
| 4.3.6 | Volume risk resolved for host by the Phase 1 gate | Measurement |
| 4.4.3 | Condition 2 shown weak; per-rule tightening proposed for measurement | Benign MITRE coverage |
| 4.4.5 | Two entity types | Section 4.1.3 |
| 6.1, 6.2, 6.5 | Duty-cycled benign activity; Risk 4 status; six threats added | Measurement |
| 8, 9, 10 | Assumptions, exclusions, questions, schedule and risks brought in line | All of the above |

Unchanged in Revision 3: the design requirement (Section 2), the state model (Section 3.2), window semantics (Section 4.2.1), the accumulator (Section 4.4.2), the evaluation methodology (Sections 6.1–6.4), and the deployment view (Section 7).

### 11.2 Revision 2 (2026-09-10) — against the submitted version

Prompted by supervisor comments on Deliverable 2. Argued in full in `FEEDBACK_RESPONSE.md`; measurements reproduced by `tools/doublecount_check.py`.

| Section | Change | Prompted by |
|---|---|---|
| 2.2 | Terminology note; "context" now means temporal context only | Comment 2 |
| 3.2 | **New.** State model: alert / context / risk, with the replay property | Comment 2 |
| 3.3 | **New.** Parameters distinguished from state | Comment 2 |
| 4.1 | Components 1–4 and 9 condensed into a supporting section | Comment 1 |
| 4.1.1 | Admission filter added; ingestion sequence number made load-bearing | Comment 4 |
| 4.1.3 | Entity resolution rates flagged as unmeasured | Comment 4 |
| 4.1.4 | Component 4 renamed *Entity Attribute Enrichment*; `S_ctx` → `S_exp` | Comment 2 |
| 4.2 | **Rewritten and expanded** as the core of the document: formal window semantics, tie-breaking, admission policy, eviction, memory and cost bounds, cold start, full feature definitions, per-entity reduction, stated non-goals | Comment 1 |
| 4.2.7 | **New.** Per-entity `S_seq` reduction — previously undefined | Comment 1 |
| 4.3 | **Rewritten.** Full Isolation Forest specification: model scope, autocorrelation control, preprocessing, hyperparameters with justification, percentile calibration, attribution method, sanity comparator, volume risk | Comment 3 |
| 4.4.2 | **Rewritten.** Split accumulator: saturating point term + running-maximum window term | Comment 4 |
| 4.4.3 | Escalation gate corrected — repeat-group condition added | Comment 4 |
| 4.4.4 | **New.** Wazuh composite alerts, flagged as unvalidated | Comment 4 |
| 4.4.5 | **New.** Cross-entity deduplication | Comment 4 |
| 5 | `RepeatGroup`, `Incident`, `ModelArtifact` added | Comments 2, 4 |
| 6.2 | Risk 4 added (independent training windows) | Comment 3 |
| 6.3 | B2′ arm added | Comment 3 |
| 6.4 | Metrics reported over 10 seeds | Comment 3 |
| 6.5 | Threat added regarding the admission filter | Comment 4 |
| 8 | Two exclusions added with reasons | Comments 1, 4 |
| 9 | Two questions resolved, two added | Comments 1, 3, 4 |
| 10 | Risk table revised; three risks added or promoted | Comments 3, 4 |

Unchanged: the design requirement (Section 2), the correlation/anomaly distinction (Section 2.4), the evaluation methodology (Section 6.1, 6.3), and the deployment view (Section 7).
