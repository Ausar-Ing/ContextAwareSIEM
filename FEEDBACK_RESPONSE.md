# Response to Deliverable 2 Feedback

Context-Aware Alert Prioritization for Wazuh
Anawin Suwannapha, Worathun Termjitcharoen
Prepared 2026-09-10 — not yet discussed with the supervisor

---

## Summary

Four comments were received. Three are accepted as defects and corrected in the
revised system model. One — the double-counting question — was tested against
recorded alert data rather than answered in the abstract, and the answer is
**yes, severely**: the accumulator as submitted inflates entity risk by a factor
of 20 on ten minutes of ordinary benign activity, and the safeguard written into
Section 4.8 to prevent exactly that failure does not work.

| # | Comment | Status | Where |
|---|---|---|---|
| 1 | Focus on the Temporal Context Window Builder | Accepted — §4 restructured around it (new §4.2) | [A](#a-comment-1) |
| 2 | Distinguish alert / context / risk state | Accepted — new §3.2/3.3, plus a naming fix | [B](#b-comment-2) |
| 3 | Isolation Forest underspecified | Accepted — submitted §4.6 rewritten as §4.3 | [C](#c-comment-3) |
| 4 | Risk accumulation may double-count | **Confirmed by measurement** — submitted §4.8 rewritten as §4.4.2–4.4.5 | [D](#d-comment-4) |

Two questions for the supervisor are raised at the end. They are consequences of
the above, not new scope.

**Measurement basis.** All figures below come from `wazuh_dataset.json` in the
project repository: 300 alerts, one agent, 596 seconds, captured 2026-09-05 from
the WSL2 manager on a freshly provisioned Ubuntu 24.04 install. It is a small and
unrepresentative sample and is used only to demonstrate that the failures are
reachable, not to estimate their magnitude in operation. The script is
`tools/doublecount_check.py`.

---

## A. Comment 1

> *The most interesting concept is "Temporal Context Window Builder". Try
> focusing this part.*

Accepted. The submitted document gave nine components roughly equal weight,
which made the window builder look like one stage among many rather than the
thing the project is about. Section 4 is restructured:

```
4.1  Supporting pipeline (C1–C4, C9)          condensed to ~1 page
4.2  The Temporal Context Window Builder      the substance of the document
     4.2.1  Window semantics — formal definition
     4.2.2  Construction policy and tie-breaking
     4.2.3  Admission policy — what may enter a window
     4.2.4  State representation, eviction, memory bound
     4.2.5  Cold start and burn-in
     4.2.6  The feature map — all 15 features defined
     4.2.7  Combining per-entity windows into one score
     4.2.8  What the window deliberately does not capture
4.3  Scoring over windows (C6, C7)
4.4  Accumulation over windows (C8)
```

Writing 4.2 out properly surfaced four things the submitted version left
undefined. They are listed here because they are the substance of the accepted
comment, not incidental edits.

**A.1 — Whether the window includes the triggering alert.** It does. The vector
describes the entity's situation *as of* alert `a`, including `a`. This was never
stated, and `window_size`, `burst_ratio` and `inter_arrival_min_s` all depend on
it. Note this differs from DEEPCASE [ref15], which builds context from strictly
preceding events and classifies the current event against it.

**A.2 — Ordering under identical timestamps.** Wazuh timestamps have millisecond
resolution and collisions occur in practice: in the recorded sample 100 alerts
share the second `15:02:59`, and even among admitted behavioural alerts six share
`15:06:25`. Windows are now ordered by
`(timestamp, ingestion_sequence)`, tying the window definition to the monotonic
counter Component 1 already assigns.

**A.3 — How per-entity scores combine into a per-alert score.** *This was a hole,
not an omission of detail.* Component 5 produces one window vector per
`(alert, entity)` pair, so an alert resolving to three entities produces three
vectors and three values of `S_seq`. Component 7 consumes a single `S_seq(a)`.
The submitted document never says how the three become one. Resolved as

> `S_seq(a) = max_e S_seq(a, e)`, with `argmax_e` recorded for explanation.

Maximum rather than mean: an alert that is unremarkable for its host but highly
unusual for the user account should be promoted, and averaging over entities with
sparse windows would suppress exactly that case.

**A.4 — Cost.** Feature computation is `O(N)` per `(alert, entity)` pair and
window maintenance is `O(1)` amortised; memory is `O(|E| · N)` alert references
for `|E|` active entities. At the peak arrival rate observed in the sample
(281 alerts in 23 s ≈ 12/s) with three entity types and `N = 20` this is
roughly 720 feature operations per second. Real-time operation is not in
question and the document now says so rather than leaving a reader to wonder.

---

## B. Comment 2

> *Clearly distinguish alert state, context state and risk state.*

Accepted, and it exposed a naming collision that was actively causing the
confusion.

### B.1 The naming problem

Component 4 is called **Static Context Enrichment** and its output `S_ctx`. It
holds no state at all — it is a stateless lookup of attributes of the entities
named in a single alert, and it belongs entirely to alert state. Meanwhile the
actual context state lives in Component 5. Two unrelated things were both called
"context", one of them wrongly.

Renamed in the revision:

| Was | Now | Reason |
|---|---|---|
| Component 4, "Static Context Enrichment" | **Entity Attribute Enrichment** | It enriches; it does not build context |
| `S_ctx` | `S_exp` (exposure) | Frees "context" for the temporal sense only |

"Context" now refers to one thing in the document: the temporal window.

### B.2 The three layers

| | **Alert state** | **Context state** | **Risk state** |
|---|---|---|---|
| Question | What happened? | What surrounds it? | How much does this entity worry me? |
| Key | `alert_id` | `(entity_ref, t)` | `entity_ref` |
| Cardinality | one per alert | one per (alert × resolved entity) | one per entity |
| Time behaviour | frozen at ingestion | slides — bounded by `N` and `T` | decays — half-life `h` |
| Mutability | immutable, append-only | recomputed per arrival | updated per arrival |
| Produced by | C1–C4 | C5 | C8 |
| Consumed by | C5, C7 | C6, C7 | C9 |
| Scoring term | `S_rule`, `S_exp` | `S_seq` | `R_e` |

Three properties are stated explicitly in the revision because they carry weight
later:

1. **Context state is a pure function of alert state.** A window is a *view* over
   the immutable alert log, not independent storage. Nothing is lost by
   discarding it.
2. **Risk state is also a pure function of alert state**, because the decay is
   closed-form: `R_e(t)` depends only on the alerts and their timestamps, not on
   the order in which the accumulator happened to be updated.
3. Consequently **every state layer is reconstructible by replaying the alert
   log**, which is what makes the B0–B3 ablation in Section 6.3 possible at all.
   The submitted document asserted re-scoring capability in Section 5 without
   establishing why it holds.

### B.3 A fourth thing that is not state

The fitted Isolation Forest and its calibration table are **frozen parameters**,
not runtime state. Keeping them in a separate category matters because it is
exactly where the contamination risks of Section 6.2 live: Risk 2 (evaluating on
training data) is the statement that parameters must not be refitted from
evaluation-period state. The revised document separates *state* (rebuilt by
replay) from *parameters* (fitted once, frozen, versioned).

---

## C. Comment 3

> *Isolation Forest is currently underspecified.*

Accepted without reservation. The submitted Section 4.6 justified the *choice* of
Isolation Forest at length and specified the *method* not at all — no
hyperparameters, no preprocessing, no training protocol, and no definition of how
a forest output becomes a number on `[0,100]`.

### C.1 The specification gap that mattered most

`S_rule` and `S_exp` are on `[0,100]` by construction. `S_seq` was declared to be
on `[0,100]` with no mapping given. Isolation Forest's native output is a
path-length statistic `s(x, ψ) = 2^(−E[h(x)] / c(ψ))` whose values for real data
concentrate tightly around 0.5. Rescaling that interval linearly onto `[0,100]`
would place almost every window between roughly 45 and 55 — so `w_s · S_seq`
would be near-constant across alerts, and the weight `w_s = 0.5` would be doing
almost no work no matter what value it took. **The B2-vs-B1 comparison the whole
project exists to make would have measured close to nothing, for a reason that
has nothing to do with whether temporal context is useful.**

Fixed by percentile calibration against the frozen baseline:

> `S_seq = 100 · F̂_baseline( s(φ(W)) )`

where `F̂_baseline` is the empirical CDF of raw scores over the baseline training
windows. Three consequences: `S_seq` is uniform on `[0,100]` over baseline data
by construction, so it is genuinely commensurate with the other two terms and the
weights become interpretable; the transform is monotone, so within-model ranking
is unchanged; and the CDF table is fitted on baseline only and frozen with the
model, so it falls under the Risk 2 control already specified.

### C.2 The rest of the specification

**Model scope.** One forest per entity type (host / user / source IP), not one
global forest. Window vectors for a source IP and for a host come from different
distributions, and a single model would have to treat "sparse window" as
anomalous and normal at the same time. Fallback if per-type volume is
insufficient: one model with entity type one-hot encoded, stated in the results.

**Training-sample autocorrelation.** Consecutive alerts on one entity produce
windows overlapping in `N−1` of `N` alerts, so the row count overstates the
independent sample count by roughly `N`. Training windows are subsampled at
stride `s = N/2 = 10`, and effective sample size is reported next to row count.
Choosing `max_samples` against an uncorrected `n` would have been a silent error.

**Preprocessing.** Isolation Forest splits uniformly between the min and max of a
feature within each node, so heavy-tailed features starve the dense region of
split points. `window_duration_s`, `inter_arrival_mean_s` and
`inter_arrival_min_s` are `log1p`-transformed. No standardisation (it would not
change axis-parallel split behaviour once the tails are handled).

**Hyperparameters** — provisional under the Section 4 parameter note:

| Parameter | Value | Justification |
|---|---|---|
| `n_estimators` | 200 | Above the point where cross-seed score variance stabilises; cost negligible at this scale |
| `max_samples` (ψ) | 256 | The subsample size from the original method. Resistance to swamping and masking *depends* on ψ being small; raising it toward `n` degrades detection of *clustered* anomalies, which is precisely this setting — attack windows arrive in clusters |
| `max_features` | 1.0 | All 15 features available per split |
| `contamination` | **not used** | It only sets a decision threshold. This design ranks, it does not threshold; setting it would import an unjustified prior about the attack rate. `score_samples` is consumed directly |
| `random_state` | fixed, 10 seeds reported | ψ = 256 subsampling makes a single fit visibly seed-dependent; results reported as mean ± sd |

**Attribution.** Component 9 promises "the window features that most influenced
`S_seq`". Isolation Forest has no native attribution, so the promise was
unfunded. Specified: leave-one-feature-out re-scoring — recompute with feature
`j` replaced by its baseline median, report the drop. 15 features × 200 trees is
cheap. `shap.TreeExplainer` supports `IsolationForest` and was considered;
leave-one-out is preferred as easier to defend and dependency-free.

**Cold start.** Windows with `window_size < 3` are not scored. `S_seq` is set to
50 (the baseline median percentile) and the alert is flagged *unscored*, so an
analyst sees "no temporal evidence available" rather than inferring "normal".

**Sanity comparator.** A trivial baseline is added: aggregate robust z-score
(`max_j |z_j|` against baseline median and MAD). If the forest does not beat it
on nDCG, the forest is not contributing and the honest result is to report that.
This costs almost nothing and pre-empts the obvious question of why a forest at
all.

### C.3 A feasibility risk this exposed

Specifying the training protocol forced the question of how much training data
exists. With compliance rules excluded (see D.2), the recorded sample yields
**19 behavioural alerts in 596 seconds**, most of them one-off installation
activity that will not recur. A 15-dimensional model at ψ = 256 needs on the
order of low thousands of *independent* windows; at stride 10 that implies tens
of thousands of behavioural alerts in the baseline period.

This is now a tracked risk with stated fallbacks — lengthen the baseline period,
reduce the feature set (the three MITRE-dependent features are the least reliably
populated and go first), or drive scripted benign activity to raise the rate.
**It should be measured in week 1, not assumed.** If the behavioural alert rate
on a real workload is a few per hour, the anomaly model is not trainable and the
project needs to know that before implementation begins, not after.

---

## D. Comment 4

> *Is it possible that risk accumulation may double-count correlated alerts?*

**Yes.** Five distinct mechanisms, of which the first two were measured on
recorded data and the third is a demonstrated failure of a safeguard the
submitted document already claimed to have.

### D.1 The measurement

Applying the submitted formula from Section 4.8 to the recorded sample — rule
term only, `w_r = 0.3`, `h = 4 h`, evaluated at the end of the capture:

| Accumulator | `R_host` | vs. naive |
|---|---|---|
| **As submitted** (sum over every alert) | **2609.9** | — |
| Log-saturated by repeat group | 303.3 | 8.6× lower |
| First occurrence per rule only | 130.5 | **20.0× lower** |

**93% of the total comes from a single CIS benchmark compliance scan** that
completed in 23 seconds and produced 281 of the 300 alerts. Ten minutes of a
clean Ubuntu install, no attacker, no user activity beyond package installation.

This is not a corner case reached by adversarial input. It is what the formula
does to the most ordinary thing a Wazuh install does on first boot.

### D.2 M1 — Repeat inflation

Identical alerts each contribute their full `P(a)`. 300 alerts, 13 distinct
rules, one host.

*Fix.* Group by repeat key `(entity, rule_id)` and apply a concave saturation:
a group of `k` alerts contributes `P̄ · (1 + ln k)` rather than `P̄ · k`. The
first occurrence of a rule is the informative one; the 104th SCA check carries
almost no additional information. Wazuh supplies `rule.firedtimes` directly, but
it is manager-global rather than per-entity, so the layer maintains its own
per-entity counter — the discrepancy is noted in the revision rather than
papered over.

*Residual after the compliance filter below:* 19 behavioural alerts still show
1.9× inflation from repeats alone (178.2 naive vs 95.5 first-only). **The
compliance filter alone does not fix this**; saturation is needed independently.

### D.3 M2 — The multi-tactic gate does not work

Submitted Section 4.8 states that requiring two distinct MITRE tactics
"suppresses the common failure mode of accumulation models, in which one noisy
repeating rule alone crosses the threshold."

Measured: the 281 compliance-scan alerts carry **13 distinct MITRE tactics and
93 distinct techniques**.

A single benign configuration scan clears a two-tactic gate by a factor of six
and a half. The gate is defeated by precisely the traffic it was written to stop.

The cause is that SCA and rootcheck rules carry `mitre_techniques` describing
*what the check mitigates*, not what an attacker did. Three window features —
`distinct_tactic_count`, `distinct_technique_count`, `tactic_progression` — read
these as behavioural evidence. They are not.

*Fix, two parts.*

1. **Admission filter at Component 1.** Alerts whose `rule.groups` intersect
   `{sca, rootcheck, policy_monitoring, ciscat}` are excluded from the
   prioritisation layer. They are periodic scan output, not behavioural events,
   and per-entity sequencing over them is meaningless. The exclusion is
   documented and its effect on alert volume reported. *This is the change that
   removes the 20× case.*
2. **Gate counts repeat groups, not raw tactics.** Escalation requires
   contributing alerts spanning at least two distinct *repeat groups* as well as
   two tactics. One alert carrying twelve techniques is one piece of evidence,
   not twelve.

### D.4 M3 — Window evidence charged once per alert *(the structural answer)*

This is the sharpest form of the supervisor's question and it survives both fixes
above.

`S_seq` is a property of a **set** of alerts — the window. But `P(a)` is computed
per alert, and `R_e` sums `P` over alerts. A window that is anomalous **once**
contributes its anomaly up to `N` times as it slides. With `N = 20`, a single
anomalous burst is charged to the risk total twenty times over.

*Fix.* Split the accumulator so the two kinds of evidence accumulate differently:

```
R_e(t) =  Σ    (w_r·S_rule(g) + w_c·S_exp(g)) · (1 + ln k_g) · 2^(−(t−t_g)/h)     [point]
       g ∈ groups(e)

       +  w_s · max      S_seq(a,e) · 2^(−(t−t_a)/h)                             [window]
                a ∈ alerts(e)
                t−t_a < T
```

The point term accumulates deduplicated alert-local evidence. The window term is
a **decayed running maximum, not a sum** — so the total window contribution over
a lookback is bounded by the single most anomalous window observed, rather than
growing with how many alerts happened to fall inside it.

Maximum rather than stride-based non-overlapping windows: it responds
immediately instead of waiting for a full stride of `N` alerts, and it is
monotone-bounded, which makes the threshold `θ` interpretable.

### D.5 M4 — Entity fan-out

An alert resolving to host, user and source IP adds to three risk totals. This is
not double counting *within* an entity, but it produces three notables for one
incident and makes totals incomparable across entity types.

*Fix.* State explicitly that `R_e` is comparable within an entity type only, and
deduplicate at Component 9: notables sharing contributing alert IDs above a
threshold collapse to one incident, highest-scoring entity as primary.

*Caveat from the data:* in the recorded sample, entity resolution yields host for
300/300 alerts, user for 9/300, and **source IP for none**. The three-entity
model is currently aspirational. Resolution rates per entity type should be
measured during baseline collection before the design leans on them — if source
IP almost never resolves on this testbed, that entity type should be dropped from
the model rather than carried as an unpopulated branch.

### D.6 M5 — Wazuh composite alerts

Wazuh's own `frequency` / `if_matched_sid` rules emit a composite alert
*summarising* constituent alerts, and both appear in `alerts.json`. Counting the
composite and its constituents as independent evidence is double counting by
definition.

**Not observed in the recorded sample** — the two alerts carrying
`previous_output` are rule 533 netstat diffs, not frequency composites. The
sample contains no authentication or brute-force activity, which is where
composites typically arise. Flagged as a mechanism to handle and to **verify
against a stream that does contain such activity** before the implementation
relies on the detection method.

*Proposed handling.* The composite replaces its constituents in the accumulator;
constituents still enter windows, because the window builder needs the raw
sequence.

---

## E. Questions for the supervisor

Both follow from the above rather than opening new scope.

**E.1 — Is excluding compliance and configuration-assessment alerts acceptable?**
It is the change that removes the 20× inflation and it is defensible on its own
terms — SCA output is periodic scan state, not attributable behaviour. But it
removes 94% of the alert volume in the recorded sample, which sharpens the
training-data feasibility risk in C.3 considerably. The alternative is to keep
these alerts as activity while stripping their MITRE fields, which preserves
volume at the cost of filling the baseline with a periodic artifact. The
recommendation is exclusion; confirmation would be useful before baseline
collection begins.

**E.2 — Should the sanity comparator in C.2 be reported as a fifth ablation
arm?** The robust z-score baseline tests whether Isolation Forest earns its
place. Reporting it is more honest and costs almost nothing, but it risks a
result where the trivial method wins and the ML contribution of the project is
weakened on paper. The recommendation is to report it regardless.

The three outstanding questions from submitted Section 9.2 — supervisor-provided
ground truth, whether B0–B3 is the expected evaluation form, and whether a
synthetic asset inventory is acceptable — remain open and unchanged.

---

## F. What changed in `system_model.md`

| Section | Change |
|---|---|
| 3.2 | **New.** State model: alert / context / risk, plus frozen parameters |
| 4.1 | C1–C4 and C9 condensed; C4 renamed, `S_ctx` → `S_exp`; admission filter added to C1 |
| 4.2 | **Rewritten and expanded.** The window builder as the core of the document |
| 4.3 | C6 rewritten — full Isolation Forest specification and percentile calibration |
| 4.4 | C8 rewritten — split accumulator, repeat-group saturation, corrected gate |
| 6.2 | Risk 4 added: training-data volume |
| 9.2 | Two questions added (E.1, E.2) |
| 10 | Risk table: alert-volume risk added, MITRE-sparsity risk restated |
| 11 | **New.** Changelog against the submitted version |

Unchanged: the design requirement (§2), the correlation/anomaly distinction
(§2.4), the evaluation design (§6), and the exclusions (§8).
