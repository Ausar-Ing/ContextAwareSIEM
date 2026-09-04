# System Model: Context-Aware Alert Prioritization for Wazuh

Deliverable 2 — System Model
Anawin Suwannapha, Worathun Termjitcharoen

## 1. Purpose and Scope of This Document

This document specifies the system model for the context-aware alert prioritization layer proposed in Deliverable 1. It defines the architecture, the responsibilities of each component, the data produced at each stage, the scoring model, and the evaluation protocol by which the system will be assessed.

The system is a **prioritization layer**, not a detector. It consumes alerts that Wazuh has already produced and re-orders them. It does not add detection rules, modify Wazuh decoders, or attempt to identify threats Wazuh did not flag. An alert Wazuh never raises is outside the system boundary.

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
| Entity-enrichment context | Static attributes of the entities named in an alert | Risk-based alerting, [ref9] |
| Temporal-sequence context | The window of preceding events for the same entity | DEEPCASE [ref15], AlertPro [ref5] |

DEEPCASE [ref15] establishes that a fixed window of preceding events on the same device carries sufficient signal to classify the current event, and that operators can triage clusters of such windows rather than individual events. AlertPro [ref5] reports that context features derived from alert sequences outperform features taken from raw alert fields alone. This system model adopts temporal-sequence context as its primary signal and treats entity-enrichment context as a secondary modifier.

## 3. Architecture Overview

```text
                    Wazuh Manager (alerts.json)
                              |
                              v
                    [1] Alert Ingestion
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
    [4] Static Context              [5] Temporal Context
        Enrichment                      Window Builder
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

Components [1]-[4] are stateless per alert. Components [5], [6] and [8] hold state and are where the design requirement of Section 2 is satisfied.

## 4. Component Specification

### 4.1 Component 1 — Alert Ingestion

Reads Wazuh alerts from `/var/ossec/logs/alerts/alerts.json` (or the Indexer API). Preserves the original alert unmodified for audit and reprocessing. Assigns an internal monotonic sequence number so that ordering is well defined even when timestamps collide.

**Output:** raw alert + ingestion metadata.

### 4.2 Component 2 — Normalization

Projects the Wazuh alert onto a fixed internal schema. Only fields the prioritization layer actually consumes are retained.

| Field | Source | Notes |
|---|---|---|
| `alert_id` | Wazuh `id` | |
| `timestamp` | Wazuh `timestamp` | Converted to UTC |
| `rule_id` | `rule.id` | |
| `rule_level` | `rule.level` | Integer 0-15 |
| `rule_description` | `rule.description` | For analyst display |
| `mitre_technique` | `rule.mitre.id` | May be absent |
| `mitre_tactic` | `rule.mitre.tactic` | May be absent |
| `agent_id`, `agent_name` | `agent.*` | |
| `src_ip`, `dst_ip` | decoder-dependent | May be absent |
| `user` | decoder-dependent | May be absent |
| `process`, `parent_process` | Sysmon-derived | May be absent |

Absent fields are recorded as explicitly null rather than defaulted, so that downstream components can distinguish "not applicable" from "zero".

### 4.3 Component 3 — Entity Resolution

Determines which entities the alert concerns. An entity is the unit over which temporal context accumulates.

Entity types in scope: **host** (Wazuh agent), **user**, **source IP**.

An alert may map to several entities and will then contribute to each of their windows. Where an entity cannot be resolved, the alert still flows through the pipeline but contributes only to the windows of the entities it does resolve.

### 4.4 Component 4 — Static Context Enrichment

Attaches attributes that do not depend on alert history.

| Source | Attributes | Availability in lab |
|---|---|---|
| Asset inventory (manually authored) | criticality, environment, role | Synthetic, authored for the testbed |
| Wazuh Vulnerability Detector | open CVE count, max CVSS | Native |
| Threat intelligence (AbuseIPDB / local list) | IP reputation | External or offline list |

**Design note.** The testbed contains a small number of hosts and one human user. Attributes that depend on organizational structure — department, business role, peer-group deviation — cannot be meaningfully populated and are **excluded from the implemented system**. Including them in the model while stubbing them in the implementation would make the evaluation dishonest. The asset inventory is authored deliberately as a synthetic but documented artifact of the testbed, and its contents are reported alongside results.

### 4.5 Component 5 — Temporal Context Window Builder

**This is the core component of the system model.**

For each incoming alert `a` and each entity `e` it resolves to, the builder retrieves the preceding `N` alerts for `e` within a maximum lookback `T`, and encodes that window as a feature vector.

Parameters: `N = 20` alerts, `T = 24` hours (initial values; both are tuned during evaluation and the sensitivity of results to them is reported).

Window feature vector:

| Feature | Description | Rationale |
|---|---|---|
| `window_size` | Alerts actually present (≤ N) | Distinguishes sparse from saturated windows |
| `window_duration_s` | Time span of the window | Burst vs. slow activity |
| `distinct_rule_count` | Unique `rule_id` values | Varied activity vs. one repeating rule |
| `repeat_ratio` | Count of most frequent rule ÷ window_size | High = repetitive noise |
| `rule_level_max` | Maximum level in window | |
| `rule_level_mean` | Mean level in window | |
| `rule_level_trend` | Slope of level over window | Escalation signal |
| `distinct_technique_count` | Unique MITRE techniques | |
| `distinct_tactic_count` | Unique MITRE tactics | Multi-stage indicator |
| `tactic_advance` | Whether tactics progress along kill-chain order | Multi-step attack signal |
| `inter_arrival_mean_s` | Mean gap between alerts | |
| `inter_arrival_min_s` | Minimum gap | Automation signal |
| `burst_ratio` | Alerts in last 60 s ÷ window_size | |
| `novel_rule_flag` | Rule unseen for this entity during baseline | Novelty |
| `night_fraction` | Fraction of window outside working hours | |

Every feature is computed from the Wazuh alert stream alone. No feature requires a data source the testbed does not have. This is a deliberate constraint: it makes the component reproducible by anyone with a Wazuh deployment.

**Output:** `window_vector(a, e)`.

### 4.6 Component 6 — Sequence Anomaly Scoring

Converts the window vector into a scalar anomaly score `S_seq ∈ [0,100]`.

**Method:** Isolation Forest, trained unsupervised on window vectors collected during a benign baseline period.

Justification for this choice over the alternatives:

- **Unsupervised.** Labels are unavailable at training time and expensive to obtain. Isolation Forest requires none.
- **Precedent.** Isolation Forest is the established choice for this role in the alert-triage literature, appearing in the comparison table of AlertPro [ref5].
- **Cost.** Training and inference are cheap enough for real-time operation on a laptop-scale testbed.
- **Rejected: deep sequence models.** DEEPCASE's attention-based encoder-decoder [ref15] is more expressive, but requires a volume of event data the testbed will not produce and would not be trainable within the project schedule.
- **Rejected: supervised classification.** Requires labels for training, not merely for evaluation, and would overfit the specific emulated techniques.

This component is the answer to a gap in the Deliverable 1 pipeline: the weighted scoring model consumes a `behavior_anomaly_score` as an input without specifying what produces it. Component 6 produces it.

### 4.7 Component 7 — Hybrid Priority Scoring

Combines the transparent and learned signals into a single priority.

```text
P(a) = w_r * S_rule(a)
     + w_c * S_ctx(a)
     + w_s * S_seq(a)
```

where

- `S_rule` = Wazuh rule level normalized to [0,100] (level/15 × 100)
- `S_ctx`  = static context score from Component 4
- `S_seq`  = sequence anomaly score from Component 6

**On the weights.** Fixed weights asserted without justification are the most common weakness in risk-scoring designs. This project addresses them explicitly by:

1. Reporting results under a documented default (`w_r = 0.3, w_c = 0.2, w_s = 0.5`);
2. Performing a sensitivity analysis over the weight simplex and reporting how ranking quality varies;
3. Reporting the weights that maximize nDCG on the emulation set, as an upper bound, while making clear these are fitted and not proposed as general values.

The scoring function remains linear and inspectable. Each term's contribution to a given alert's score can be displayed to the analyst.

### 4.8 Component 8 — Entity Risk Accumulation

Maintains a decaying risk total per entity, so that a sustained campaign of individually unremarkable alerts becomes visible.

```text
R_e(t) = Σ  P(a_i) * 2^(-(t - t_i) / h)
        i ∈ alerts(e)
```

with half-life `h = 4 hours` (tuned).

An entity is escalated to a **risk notable** when both hold:

1. `R_e(t) > θ` for threshold `θ`;
2. the contributing alerts span at least two distinct MITRE tactics.

The second condition suppresses the common failure mode of accumulation models, in which one noisy repeating rule alone crosses the threshold. This mechanism follows the risk-based alerting model used in commercial SIEM practice, adapted to Wazuh.

### 4.9 Component 9 — Ranked Queue and Explanation

Emits the prioritized alert list and, for each entry, the evidence behind its score:

- the three highest-contributing terms of `P(a)`;
- the window features that most influenced `S_seq`;
- the alerts contributing to `R_e` when the entry is a risk notable.

Explanation is a functional requirement, not presentation. An analyst who cannot see why an alert was promoted cannot act on the promotion.

## 5. Data Model

```text
RawAlert          -- as emitted by Wazuh, immutable
NormalizedAlert   -- Section 4.2 schema
EntityRef         -- (type, identifier)
WindowVector      -- (alert_id, entity_ref, features{...}, N, T)
ScoredAlert       -- (alert_id, S_rule, S_ctx, S_seq, P, explanation[])
EntityRisk        -- (entity_ref, R, contributing_alert_ids[], notable_flag)
```

Stores are kept separate so that scoring logic can be revised and the full alert history re-scored without re-collection. Re-scoring capability is required for the ablation in Section 6.

## 6. Evaluation Design

The evaluation determines whether temporal context improves prioritization over Wazuh's native ranking. It is specified here because it constrains the implementation.

### 6.1 Ground truth by adversary emulation

Wazuh alerts carry no labels. Labels are generated by controlled attack execution:

1. Benign activity runs continuously on the testbed to produce background alerts.
2. Attack techniques are executed from a manifest recording `(technique_id, target_host, start_time, end_time)`.
3. An alert is labelled positive if it falls within `[start - δ, end + δ]` on the target host, with `δ = 60 s`.
4. All other alerts are labelled negative.

This follows the MITRE ATT&CK evaluation methodology applied to Wazuh in [ref12]. Labelling by time window is imperfect — a benign alert inside the window is mislabelled — and the error rate is estimated by manual inspection of a sample and reported.

### 6.2 Systems compared (ablation)

| System | Description | Isolates |
|---|---|---|
| B0 | Wazuh rule level only | Baseline |
| B1 | B0 + static context (`S_ctx`) | Value of enrichment |
| B2 | B1 + sequence anomaly (`S_seq`) | **Value of temporal context** |
| B3 | B2 + entity accumulation | Value of cross-alert aggregation |

B2 versus B1 is the measurement the project exists to make.

### 6.3 Metrics

Prioritization is a ranking problem and is measured with ranking metrics, not classification metrics:

- **nDCG@k** for k ∈ {10, 20, 50} — primary metric
- **Precision@k** — proportion of top-k that are attack alerts
- **Technique coverage@k** — fraction of executed techniques represented in the top k, capturing whether an analyst with a fixed budget sees each distinct attack
- **MRR** — rank of the first true positive
- **Alert volume reduction** — alerts an analyst can skip at fixed recall

### 6.4 Threats to validity

- Emulated attacks are noisier and more concentrated than real intrusions; absolute scores will be optimistic.
- A single benign user generates less diverse background activity than an organization, understating false positives.
- Techniques are drawn from a public catalogue that Wazuh rules may be specifically tuned to detect.

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
        +-------------------------------------+
        | wazuh-manager / indexer / dashboard |
        | prioritization layer (Components 1-9)|
        +-------------------------------------+
```

Attack execution is confined to the VM. The host is not a target of emulated techniques.

## 8. Assumptions and Exclusions

**Assumptions**

- Wazuh raises an alert for the activity of interest; undetected activity is out of scope.
- Alert timestamps are consistent enough for ordering within a stream.
- A benign baseline period of sufficient length is available before evaluation.

**Exclusions, with reasons**

| Excluded | Reason |
|---|---|
| Cross-source correlation | Out of the stated design requirement (Section 2) |
| Graph neural network | The testbed's entity graph is too small for message passing to be meaningful; see Section 9 |
| Organizational context (department, peer group) | Not populatable in a testbed with one user |
| Analyst feedback loops / learning-to-defer | Requires sustained analyst interaction unavailable in this project |
| Automated response | Prioritization layer only |

## 9. Open Design Questions

Questions requiring supervisor input, in priority order:

1. **Does excluding the graph neural network conflict with Deliverable 1?** Deliverable 1's scope commits to applying a GNN over an alert graph, while this system model argues the testbed cannot support one meaningfully. This must be resolved before implementation begins.
2. **Is emulation-derived ground truth acceptable** as the evaluation basis, or is a public labelled dataset expected in addition?
3. **Is the ablation (B0-B3) the expected form of evaluation,** or is a comparison against a published method required?
4. **Is the synthetic asset inventory acceptable,** given that asset criticality cannot be authentic in a testbed?

## 10. Schedule and Risks

| Phase | Weeks | Output |
|---|---|---|
| System model, VM build, baseline collection begins | 1-2 | This document; telemetry recording |
| Emulation runs, labelled dataset | 3-4 | Manifest + labelled alert corpus |
| Implement Components 1-9 | 5-7 | Working prioritization layer |
| Evaluation and ablation | 8-9 | Results |
| Write-up | 10-11 | Final report |

| Risk | Impact | Mitigation |
|---|---|---|
| Insufficient benign baseline | Anomaly model untrainable | Begin continuous collection in week 1, before implementation |
| Too few positive alerts | Ranking metrics unstable | Increase technique count and repetitions; report confidence intervals |
| Sparse MITRE mapping in Wazuh rules | Tactic-based features degrade | Measure coverage early; fall back to rule-ID features |
| Class imbalance | Metrics dominated by negatives | Use ranking metrics throughout, as specified |
