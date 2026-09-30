# System Model: Context-Aware Alert Prioritization for Wazuh

Deliverable 2 — System Model
Anawin Suwannapha, Worathun Termjitcharoen

*Revision 2, 2026-09-10. Changes against the submitted version are listed in
Section 11 and argued in `FEEDBACK_RESPONSE.md`.*

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

Consider two alerts, identical in every field: Wazuh rule 5710 (`sshd: attempt to login using a non-existent user`), same host, same rule level.

- In the first case, it is the only alert on that host in six hours.
- In the second case, it is the fortieth such alert in ninety seconds, followed by rule 5715 (`successful sshd authentication`).

A stateless pipeline assigns both the same priority. The second is a successful brute force. No amount of static enrichment — asset criticality, CVSS, threat intelligence — distinguishes them, because the difference is not in the alert, it is in the sequence. Temporal context is therefore not an accuracy refinement; it is the only mechanism that separates these cases at all.

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

The analytical inputs to this system are therefore **security audit logs and endpoint telemetry**, not application logs. The distinction matters for the argument in Section 2.1: audit and endpoint records describe discrete, attributable actions by a subject upon an object, which is what makes per-entity sequencing meaningful in the first place. Application logs describe internal program state and do not decompose into subject-action-object in the same way.

Wazuh also emits alerts that are neither of these — configuration assessment (SCA), rootcheck and policy-monitoring output. These are **excluded** by the admission policy in Section 4.2.3, for reasons given there.

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

The fitted Isolation Forest, its baseline calibration table, and the tuned values of `N`, `T`, `h`, `θ` and the scoring weights are **frozen parameters**, not runtime state. They are fitted once, versioned, and held constant across the evaluation.

The distinction is load-bearing rather than pedantic. Risk 2 of Section 6.2 — evaluating on training data — is precisely the requirement that parameters must never be refitted from state belonging to the evaluation period. Keeping parameters in their own category makes that requirement checkable: a parameter file has a version and a fitting date, and the evaluation records which one it used.

## 4. Component Specification

**Note on parameter values.** Every numeric parameter in this section and in Section 6 — window size `N`, lookback `T`, decay half-life `h`, escalation threshold `θ`, label tolerance `δ`, saturation behaviour, the Isolation Forest hyperparameters, and the scoring weights — is a **provisional estimate**, stated so that the model is concrete and implementable. None is derived from measurement. Each will be re-derived from observed alert-stream behaviour during the baseline collection phase, and the sensitivity of results to each is reported in the evaluation. They are starting points, not findings.

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
| `mitre_technique` | `rule.mitre_techniques` | May be absent; list-valued |
| `mitre_tactic` | `rule.mitre_tactics` | May be absent; list-valued |
| `agent_id`, `agent_name` | `agent.*` | |
| `src_ip`, `dst_ip` | decoder-dependent | May be absent |
| `user` | decoder-dependent | May be absent |
| `process`, `parent_process` | Sysmon-derived | May be absent |
| `previous_output` | top-level, when present | Composite-alert detection (Section 4.4.4) |

Absent fields are recorded as explicitly null rather than defaulted, so that downstream components can distinguish "not applicable" from "zero".

#### 4.1.3 Component 3 — Entity Resolution

Determines which entities the alert concerns. An entity is the unit over which temporal context accumulates.

Entity types in scope: **host** (Wazuh agent), **user**, **source IP**.

An alert may map to several entities and will then contribute to each of their windows. Where an entity cannot be resolved, the alert still flows through the pipeline but contributes only to the windows of the entities it does resolve.

**Resolution rates must be measured before the design leans on them.** In the 300-alert sample recorded on 2026-09-05, host resolved for 300 alerts, user for 9, and source IP for none. That sample contains no network-facing activity and is not representative, but it establishes that a three-entity model cannot simply be assumed to be populated. Per-type resolution rate is reported from the baseline collection, and an entity type that resolves for a negligible fraction of alerts is dropped from the model rather than carried as an unpopulated branch.

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

**Windows are per `(alert, entity)`, not per alert.** An alert resolving to three entities produces three windows and three feature vectors. Section 4.2.7 specifies how they combine.

Parameters: `N = 20` alerts, `T = 24` hours (provisional; both tuned during evaluation with sensitivity reported).

#### 4.2.2 Ordering and tie-breaking

Wazuh timestamps carry millisecond resolution, and collisions occur in ordinary operation: in the sample recorded on 2026-09-05, 100 alerts share the second `15:02:59`, and even among the alerts that survive the admission policy below, six share `15:06:25`. Ordering by timestamp alone is therefore not well defined, and several features (`rule_level_trend`, `tactic_progression`, `inter_arrival_min_s`) depend on order.

Windows are ordered by the pair `(timestamp, ingest_seq)`, where `ingest_seq` is the monotonic counter assigned in Component 1. This makes ordering total and reproducible across replays, which Section 3.2 property 3 requires.

Alerts with an inter-arrival gap of exactly zero after tie-breaking contribute a floor value of 1 ms to `inter_arrival_min_s`, so that the feature remains defined without a special case.

#### 4.2.3 Admission policy

Not every Wazuh alert is a behavioural event, and admitting the ones that are not corrupts the window features rather than merely diluting them.

**Excluded:** alerts whose `rule.groups` intersects `{sca, rootcheck, policy_monitoring, ciscat}`.

*Reason.* These rules report configuration-assessment and policy-scan state. They fire in bulk on a schedule, they are not attributable to a subject acting on an object, and — critically — the MITRE fields they carry describe *what the check mitigates*, not what anyone did. Three window features (`distinct_tactic_count`, `distinct_technique_count`, `tactic_progression`) read those fields as behavioural evidence, and would be reading them wrongly.

*Measured justification.* In the recorded sample, 281 of 300 alerts (94%) came from a single CIS benchmark scan lasting 23 seconds. Those 281 alerts carry **13 distinct MITRE tactics and 93 distinct techniques**. Under the submitted design a single benign configuration scan would therefore have produced saturated windows with maximal tactic diversity, and would have cleared the two-tactic escalation gate of Section 4.4.3 by a factor of six.

*Cost of the exclusion, stated plainly.* It removes 94% of the alert volume in that sample, leaving 19 behavioural alerts in 596 seconds. This sharpens the training-volume risk of Section 4.3.6 considerably and is the subject of an open question in Section 9.2.

**Admitted but flagged:** alerts from the `ossec` group reporting agent and manager state (rules 502, 533 and similar). These are behavioural in form but describe the monitoring infrastructure rather than the monitored system. They are admitted so that windows reflect what actually occurred, and their contribution is reported separately in the feature-importance analysis so that a result driven by them is visible rather than hidden.

#### 4.2.4 State representation and eviction

Per entity, the builder maintains:

- a bounded deque of at most `N` alert references, ordered as in Section 4.2.2;
- the timestamp of the most recent alert, for expiry.

The window itself is a view over alert state (Section 3.2 property 1); the deque holds references, not copies.

**Eviction.** An alert leaves the deque when either it is displaced by the `N+1`-th arrival, or its age exceeds `T`. An *entity* is evicted from the builder after `2T` of inactivity. Note that entity eviction from the **builder** is independent of eviction from the **risk accumulator**: risk decays with half-life `h`, which may exceed `T`, so an entity with no recent alerts can hold non-negligible risk state while holding no context state. The two structures are keyed alike and expire differently, and treating them as one structure would be an error.

**Memory bound.** `O(|E| · N)` alert references for `|E|` active entities, plus `O(|E|)` risk records. For a testbed with tens of entities this is negligible; the bound is stated because it is what makes the claim of real-time operation checkable rather than asserted.

**Cost.** Feature computation is `O(N)` per `(alert, entity)` pair; deque maintenance is `O(1)` amortised. At the peak arrival rate observed in the recorded sample (281 alerts in 23 s ≈ 12 alerts/s), with three entity types and `N = 20`, this is roughly 720 feature operations per second.

#### 4.2.5 Cold start and burn-in

Two distinct situations, handled differently.

**Cold start (an entity is new).** Windows with `window_size < 3` are not scored. `S_seq` is set to 50 — the baseline median percentile under the calibration of Section 4.3.4 — and the alert is flagged **unscored**. The flag is surfaced in Component 9 so an analyst sees "no temporal evidence available" rather than inferring "normal". Several features (`rule_level_trend`, `tactic_progression`, `inter_arrival_*`) are undefined on windows this short; the threshold of 3 is the minimum at which a trend has meaning.

**Burn-in (the evaluation period is new).** Distinct from cold start and addressed in Section 6.2: windows early in the evaluation period reach back into baseline alerts, which is realistic and should not be prevented, but the first `T` of the evaluation period is excluded from metric computation.

#### 4.2.6 The feature map

`φ(W) ∈ ℝ¹⁵`. Every feature is computed from the Wazuh alert stream alone; none requires a data source the testbed does not have. This is a deliberate constraint — it makes the component reproducible by anyone with a Wazuh deployment.

| # | Feature | Definition | Rationale |
|---|---|---|---|
| 1 | `window_size` | `\|W\|`, alerts actually present (≤ N) | Sparse vs. saturated |
| 2 | `window_duration_s` | `time(last) − time(first)` | Burst vs. slow activity |
| 3 | `distinct_rule_count` | `\|{rule_id}\|` over `W` | Varied vs. one repeating rule |
| 4 | `repeat_ratio` | count of modal `rule_id` ÷ `window_size` | High = repetitive noise |
| 5 | `rule_level_max` | `max rule_level` | |
| 6 | `rule_level_mean` | arithmetic mean of `rule_level` | |
| 7 | `rule_level_trend` | OLS slope of `rule_level` on position | Escalation signal |
| 8 | `distinct_technique_count` | `\|{mitre_technique}\|`, union over list-valued fields | |
| 9 | `distinct_tactic_count` | `\|{mitre_tactic}\|`, union over list-valued fields | Multi-stage indicator |
| 10 | `tactic_progression` | Spearman ρ between position and tactic ordinal (Section 4.2.6.1) | Multi-step attack signal |
| 11 | `inter_arrival_mean_s` | mean successive gap | |
| 12 | `inter_arrival_min_s` | min successive gap, floored at 1 ms | Automation signal |
| 13 | `burst_ratio` | alerts within 60 s of `a` ÷ `window_size` | |
| 14 | `novel_rule_flag` | 1 if `rule_id` unseen for this entity during baseline, else 0 | Novelty |
| 15 | `night_fraction` | fraction of `W` outside working hours | |

Features 2, 11 and 12 are heavy-tailed by construction and are `log1p`-transformed before model fitting (Section 4.3.3). The table above defines the raw feature; the transform belongs to the model, not the feature.

Features 8, 9 and 10 depend on MITRE mappings, which Wazuh populates unevenly. Their coverage is measured during baseline collection, and Section 10 carries the fallback if coverage is too sparse to support them.

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

**Stated limitation.** ATT&CK tactics are not strictly sequential — Defense Evasion and Discovery recur throughout an intrusion rather than occupying a fixed stage. The ordinal scale is therefore a heuristic, not a claim about adversary behaviour, and `tactic_progression` should be read as a weak ordering signal. It is reported as one feature among fifteen, and its individual contribution is visible in the feature-importance analysis.

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
- **Alert content.** `full_log`, command lines and file paths are not featurised. Doing so would make the component depend on decoder-specific fields and would break the reproducibility constraint stated above.
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
- **Cost.** Training and inference are cheap enough for real-time operation on a laptop-scale testbed.
- **Rejected: deep sequence models.** DEEPCASE's attention-based encoder-decoder [ref15] is more expressive, but requires a volume of event data the testbed will not produce and would not be trainable within the project schedule.
- **Rejected: supervised classification.** Requires labels for training, not merely for evaluation, and would overfit the specific emulated techniques.

This component is the answer to a gap in the Deliverable 1 pipeline: the weighted scoring model consumes a `behavior_anomaly_score` as an input without specifying what produces it. Component 6 produces it.

#### 4.3.2 Model scope

**One model per entity type** (host, user, source IP), not one global model.

Window vectors for a source IP and for a host are drawn from different distributions — a source IP typically appears in sparse, network-facing windows, a host in dense mixed ones. A single forest would have to treat "sparse window" as anomalous and as normal simultaneously, and would resolve that by whichever entity type dominated the training set.

*Fallback.* If per-type volume proves insufficient (Section 4.3.6), a single model is fitted with entity type one-hot encoded. Which was used is reported with the results.

#### 4.3.3 Training data construction

**Autocorrelation is the controlling problem.** Consecutive alerts on one entity produce windows that overlap in `N−1` of their `N` alerts. The number of training rows therefore overstates the number of independent observations by roughly a factor of `N`. Choosing `max_samples` against an uncorrected row count would be a silent error.

Two controls:

1. Training windows are subsampled at stride `s = N/2 = 10`, so adjacent training rows share at most half their alerts.
2. Effective sample size is reported alongside raw row count.

**Preprocessing.** Isolation Forest chooses split points uniformly between the minimum and maximum of a feature *within each node*, so a heavy tail draws split points away from the dense region where the decision actually matters. Features 2, 11 and 12 (`window_duration_s`, `inter_arrival_mean_s`, `inter_arrival_min_s`) are `log1p`-transformed. `tactic_progression ∈ [−1,1]` and `novel_rule_flag ∈ {0,1}` are used as-is. No standardisation is applied — with the tails handled, it would not change axis-parallel split behaviour.

#### 4.3.4 Hyperparameters and score calibration

| Parameter | Value | Justification |
|---|---|---|
| `n_estimators` | 200 | Above the point where cross-seed score variance stabilises for low-dimensional data; cost negligible here |
| `max_samples` (ψ) | 256 | The subsample size from the original method. Resistance to swamping and masking *depends* on ψ being small; raising it toward `n` degrades detection of **clustered** anomalies — which is exactly this setting, since attack windows arrive in clusters |
| `max_features` | 1.0 | All 15 features available at each split |
| `contamination` | **not used** | It sets a decision threshold only. This design ranks rather than thresholds; setting it would import an unjustified prior about the attack rate. `score_samples` is consumed directly |
| `random_state` | fixed; 10 seeds reported | ψ = 256 subsampling makes a single fit visibly seed-dependent. Results reported as mean ± sd over seeds |

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

**Leave-one-feature-out re-scoring.** For each feature `j`, recompute the score with `φ_j` replaced by its baseline median, and report the resulting drop in `S_seq`. The three largest drops are surfaced. Cost is 15 re-scores of 200 trees per explained alert, which is negligible and incurred only for alerts an analyst actually opens.

`shap.TreeExplainer` supports `IsolationForest` and was considered. Leave-one-out is preferred: it is simpler to describe in the report, adds no dependency, and its output ("the score falls by 31 points if burst_ratio were typical") is directly interpretable to an analyst.

#### 4.3.6 Sanity comparator and the volume risk

**Comparator.** A trivial baseline is fitted alongside: the aggregate robust z-score `max_j |z_j|`, with `z_j` computed against the baseline median and MAD of feature `j`. If Isolation Forest does not beat this on nDCG, the forest is not contributing and the honest finding is to report that. The cost is near zero and it pre-empts the obvious question of why a forest is warranted at all.

**Volume risk.** A 15-dimensional model at ψ = 256 needs on the order of low thousands of *independent* windows; at stride 10 that implies tens of thousands of admitted alerts in the baseline period. The recorded sample yields 19 admitted alerts in 596 seconds, most of them one-off installation activity that will not recur.

This must be **measured in week 1, not assumed.** If the admitted alert rate on a realistic workload is a few per hour, the anomaly model is not trainable and the project needs to know before implementation, not after. Fallbacks, in order of preference: lengthen the baseline period; reduce the feature set (features 8–10, the MITRE-dependent ones, are the least reliably populated and go first); drive scripted benign activity to raise the rate. Carried as a risk in Section 10.

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

*Verification note.* Both remedies were checked against the recorded sample. On the full 300 alerts, saturation alone reduces `R_host` from 2609.9 to 303.3; after the admission filter of Section 4.2.3, 19 alerts remain and saturation reduces 178.2 to 146.6 — still a factor of 1.9 against first-occurrence-only accounting. **The admission filter does not subsume the saturation fix**; both are required.

#### 4.4.3 Escalation gate

An entity is escalated to a **risk notable** when all three hold:

1. `R_e(t) > θ`;
2. the contributing alerts span at least two distinct MITRE tactics;
3. the contributing alerts span at least two distinct **repeat groups**.

Condition 3 is new. The submitted document claimed condition 2 alone "suppresses the common failure mode of accumulation models, in which one noisy repeating rule alone crosses the threshold." Measured against the recorded sample, it does not: the 281 compliance-scan alerts carry 13 distinct tactics, clearing a two-tactic gate by a factor of six and a half. One rule that carries twelve technique mappings is one piece of evidence, not twelve, and condition 3 is what encodes that.

Condition 2 is retained rather than replaced, because the two conditions fail differently: condition 2 catches a single multi-tactic rule firing repeatedly, condition 3 catches a single rule carrying many tactics. Neither implies the other.

This mechanism follows the risk-based alerting model used in commercial SIEM practice, adapted to Wazuh.

#### 4.4.4 Wazuh composite alerts

Wazuh's `frequency` and `if_matched_sid` rules emit a composite alert *summarising* alerts that are themselves present in the stream. Treating the composite and its constituents as independent evidence is double counting by construction.

*Handling.* The composite **replaces** its constituents in the accumulator; constituents still enter windows, because Component 5 needs the raw sequence to compute timing and repetition features.

*Detection, and its current uncertainty.* Candidate signals are the presence of `previous_output` and the rule's `if_matched_sid` lineage. **This has not been verified against data.** The recorded sample contains two alerts carrying `previous_output`, but both are rule 533 netstat diffs — a different use of the same field — and the sample contains no authentication or brute-force activity of the kind that produces frequency composites. The detection method must be validated against a stream that actually contains them before the implementation relies on it. Carried as a risk in Section 10.

#### 4.4.5 Cross-entity deduplication

An alert resolving to host, user and source IP contributes to three risk totals. This is not double counting within an entity, but it produces three notables for one incident and makes totals incomparable across entity types.

Two rules:

- `R_e` values are comparable **within an entity type only**. The ranked queue does not interleave host risk with source-IP risk on a common scale.
- Notables sharing contributing alert IDs above a threshold fraction are collapsed into one **incident** at Component 9, with the highest-scoring entity designated primary and the others listed as also-implicated.

## 5. Data Model

```text
RawAlert          -- as emitted by Wazuh, immutable; retained even when not admitted
NormalizedAlert   -- Section 4.1.2 schema + admission flag        [alert state]
EntityRef         -- (type, identifier)
WindowVector      -- (alert_id, entity_ref, features{...}, N, T)  [context state, a view]
ScoredAlert       -- (alert_id, S_rule, S_exp, S_seq, argmax_entity, P, explanation[])
RepeatGroup       -- (entity_ref, rule_id, k, first_alert_id, first_ts)
EntityRisk        -- (entity_ref, R_point, R_window, R, groups[], notable_flag)
Incident          -- (primary_entity, implicated_entities[], contributing_alert_ids[])
ModelArtifact     -- (entity_type, forest, cdf_table, feature_transform, fit_date, version)
```

`ModelArtifact` is a **parameter**, not state (Section 3.3), and is versioned separately so that every reported result names the artifact it used.

Stores are kept separate so that scoring logic can be revised and the full alert history re-scored without re-collection. Re-scoring capability is required for the ablation in Section 6.3, and Section 3.2 property 3 establishes why it holds.

## 6. Evaluation Design

The evaluation determines whether temporal context improves prioritization over Wazuh's native ranking. It is specified here because it constrains the implementation.

### 6.1 Ground truth by adversary emulation

Wazuh alerts carry no labels. Labels are generated by controlled attack execution:

1. Benign activity runs continuously on the testbed to produce background alerts.
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
- The admission filter of Section 4.2.3 removes the majority of the testbed's alert volume. Results describe ranking quality over behavioural alerts and do not speak to the volume-reduction benefit of the filter itself, which is reported separately as a descriptive statistic.

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
- A benign baseline period of sufficient length is available before evaluation — an assumption Section 4.3.6 requires to be tested rather than assumed.

**Exclusions, with reasons**

| Excluded | Reason |
|---|---|
| Cross-source correlation | Out of the stated design requirement (Section 2) |
| Graph neural network | Agreed with the supervisor and dropped: the testbed's entity graph is too small for message passing to be meaningful, and the project focuses on machine-learning methods |
| Organizational context (department, peer group) | Not populatable in a testbed with one user |
| Configuration-assessment alerts (SCA, rootcheck, policy monitoring) | Not behavioural events; their MITRE fields describe mitigations, not actions (Section 4.2.3) |
| Process lineage as a window feature | A window is a time-ordered sequence, not a process tree (Section 4.2.8) |
| Analyst feedback loops / learning-to-defer | Requires sustained analyst interaction unavailable in this project |
| Automated response | Prioritization layer only |

## 9. Design Questions

### 9.1 Resolved

**Graph neural network.** Agreed with the supervisor: the GNN component is dropped and the project focuses on machine-learning methods. This supersedes scope item 4 of Deliverable 1, which committed to applying a GNN over an alert graph. The final report must state the change and its justification explicitly rather than omitting the item silently, since the earlier scope is on record.

**Per-entity score reduction.** An alert resolving to several entities produces several `S_seq` values; the submitted document did not say how they combine. Resolved as maximum with `argmax` recorded (Section 4.2.7).

### 9.2 Outstanding

Listed in the order they block work.

1. **Is excluding configuration-assessment alerts acceptable?** (Section 4.2.3.) It is the change that removes the measured 20× risk inflation and it is defensible on its own terms. But it removes 94% of the alert volume in the recorded sample, sharpening the training-volume risk of Section 4.3.6. The alternative is to admit these alerts as activity while stripping their MITRE fields — preserving volume at the cost of filling the baseline with a periodic artifact. Recommendation: exclude. Confirmation is wanted before baseline collection begins.

2. **What form would supervisor-provided ground truth take?** The answer determines whether adversary emulation is needed at all, so it gates the week 3–4 phase. The distinction that matters is host-based versus network-based data. A public IDS benchmark such as CICIDS2017 or UNSW-NB15 consists of network flow records rather than Wazuh alerts, and could not be consumed by this system without either replaying traffic through a network sensor — which discards the Sysmon endpoint telemetry the design depends on — or abandoning the Wazuh-specific claim entirely. Host-based labelled data, or a lab capture that can be replayed through a Wazuh agent, would be usable directly. Emulation remains the fallback and is assumed until this is settled.

3. **Is the B0–B3 ablation the expected form of evaluation,** or is a comparison against a published method required? The ablation isolates the contribution of temporal context, which is the project's claim; a comparison against published work would require reimplementing a baseline from the literature and is a materially larger undertaking.

4. **Should B2′ be reported as a full ablation arm?** (Section 4.3.6.) The robust z-score comparator tests whether Isolation Forest earns its place. Reporting it is more honest and nearly free, but risks a result in which the trivial method wins and the machine-learning contribution is weakened on paper. Recommendation: report it regardless.

5. **Is a synthetic asset inventory acceptable** as the source of asset criticality, given that no authentic inventory exists for a testbed?

## 10. Schedule and Risks

| Phase | Weeks | Output |
|---|---|---|
| System model, VM build, baseline collection begins | 1–2 | This document; telemetry recording; **admitted-alert-rate measurement** |
| Emulation runs (two disjoint sessions), labelled dataset | 3–4 | Manifest + labelled alert corpus, split into tuning and held-out sets |
| Implement Components 1–9 | 5–7 | Working prioritization layer |
| Evaluation and ablation | 8–9 | Results |
| Write-up | 10–11 | Final report |

| Risk | Impact | Mitigation |
|---|---|---|
| **Insufficient admitted alert volume** | Anomaly model untrainable; the project's central measurement cannot be made | Measure admitted rate and effective sample size in week 1 (Section 4.3.6); fallbacks are longer baseline, reduced feature set, scripted benign activity |
| Baseline contaminated by attack activity | Anomaly model learns attacks as normal | No emulation during baseline; manual inspection of top-scoring baseline windows (Section 6.2) |
| Parameters tuned on the reported test set | Headline results inflated | Two disjoint emulation sessions; Session B touched once (Section 6.2) |
| Too few positive alerts | Ranking metrics unstable | Increase technique count and repetitions; report confidence intervals |
| Sparse MITRE mapping in admitted rules | Features 8–10 degrade | Measure coverage early; these features are first to be dropped under Section 4.3.6 |
| **Composite-alert detection unvalidated** | Composite and constituents both counted (Section 4.4.4) | Validate the detection signal against a stream containing frequency-rule activity before implementation |
| Class imbalance | Metrics dominated by negatives | Use ranking metrics throughout, as specified |
| Entity types resolve too rarely to model | Per-type models unfittable | Measure resolution rate per type during baseline (Section 4.1.3); drop or merge types, or fall back to a single model with entity type encoded |

## 11. Changelog Against the Submitted Version

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
