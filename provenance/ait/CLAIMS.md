# Claims from the locked run (AIT-ADS test scenarios)

Decided 2026-11-04 by Anawin, after reading the outputs of the one locked run (tag `freeze-2026-11-04`, commit
`b7857b0`, outputs in `provenance/ait/test/`, committed `05e4122`). Every claim below follows a rule fixed in
`PREREGISTRATION.md` before the run (Sections 4-6 and 9). Wins and losses are both recorded; the paper and the
slides use only the wording allowed here. Unit throughout: the 10 non-scan attack stage occurrences (online
password cracking, user change, sudo escalation) of fox, santos, wardbeck and wilson; measure: the rank of the
first queue item holding each stage (seeded systems: mean over 10 seeds; lower = earlier).

## 1. Confirmatory tests (recorded baselines: the headline)

| Test (family) | Result | Verdict | Allowed wording |
|---|---|---|---|
| B2 vs host rarity B0_host (primary) | B2 earlier 6, later 4; p = 0.846, Holm 0.846 | **not significant** | No improvement claimed. Report the counts, the within-host AUC (Section 3) and the calibration split; state that AIT-ADS cannot separate temporal context from host rarity, and that host rarity is strong on AIT-ADS because every attack lands on its least active host, not as a general property of attacks. |
| B2 vs level rarity B0_rank (primary) | B2 earlier 7, later 3; p = 0.049, **Holm 0.098** | **not significant** (smaller p had to be < 0.025) | Counts only: "B2 placed 7 of 10 stages earlier than level rarity; the difference is not significant after correction." Never "significant", "marginal" or "nearly". |
| B2 vs risk-based alerting B_RBA (published-work) | **B_RBA earlier 9, later 1; p = 0.006** | **significant, against the method** | **"Risk-based alerting (Uetz et al.) ranks attack stages earlier than the method."** Stated plainly in the abstract, results and conclusion. |

Calibration split (reported beside the primary tests): only wilson's two stages are on a host calibrated mainly
against its own baseline (n_h >= n0); the other 8 are on hosts dominated by the pooled distribution, which largely
test host rarity (Deliverable 3, Statistical Analysis). Own-baseline hosts: B2 vs B0_host 1 / 1, vs B0_rank 1 / 1
(n = 2); pooled-dominated hosts: vs B0_host 5 / 3 (p = 0.641), vs B0_rank 6 / 2 (p = 0.055), vs B0 8 / 0 (p = 0.008).
So the test of the window score as specified rests on two stage occurrences: too few to say anything.

## 2. No-reconnaissance condition (Section 5a)

| Test | Result | Verdict | Allowed wording |
|---|---|---|---|
| B2 vs B_RBA, scan alerts removed | B_RBA earlier 7, later 3; p = 0.131 | **not significant** | "Without reconnaissance, no difference between the method and risk-based alerting was found." No robustness claim. |

Aggregate change, allowed only together with the test result above (Section 9.2): removing reconnaissance lowered
B_RBA's alpha-nDCG@20 from 0.676 to 0.299 (-56%) and its MRR from 0.425 to 0.106, and B2's alpha-nDCG@20 from
0.327 to 0.210 (-36%), MRR 0.134 to 0.114. Level rarity fell 61%, host rarity 1%. Never "robust" or "more robust".

## 3. Descriptive comparisons (Section 9)

- **9.1 Within-host AUC, B2 vs B_RBA:** B2 higher on 1 of 4 eligible hosts in the recorded run (wilson 0.940 vs
  0.882) and on 1 of 4 without reconnaissance: verdict **mixed, no statement**; the per-host table is reported.
  Against the rarity baselines (Section 5 secondary measure): B2 0.583 (fox), 0.953 (santos), 0.887 (wardbeck),
  0.940 (wilson); host rarity 0.500 by construction; level rarity 0.486-0.544; B_RBA 0.902, 0.988, 0.961, 0.882.
  Allowed: "within a host, the window score separates attack from benign alerts on all four eligible hosts
  (AUC 0.58-0.95), where host and level rarity are at chance; risk-based alerting does so better on three of them."
- **9.3 B3 vs B_RBA:** B3 earlier 1 / 9 later (recorded), 3 / 7 (no reconnaissance). Counts and aggregates only;
  never that the accumulator outperforms risk-based alerting.
- **9.4 Labels:** only the wording of Section 9.4 ("the detector is fitted on the alert stream without alert labels
  and, in the headline condition, without removing the attack alerts it contains"; weights and parameters "selected
  once, on four labelled tuning scenarios, and frozen", the same as B_RBA's weights). Never "label-free",
  "requires no labels" or "unsupervised" for the method as a whole; no transfer claim.

## 4. Secondary family (exploratory; counts and p-values, never "confirmed")

| Comparison | Recorded: B2 earlier / other earlier (tied); p; Holm | No reconnaissance |
|---|---|---|
| B2 vs B0 (Wazuh rule level) | 9 / 1; 0.010; 0.107 | 9 / 1; 0.004; 0.043 |
| B2 vs B1 | 8 / 2; 0.027; 0.219 | 8 / 2; 0.037; 0.260 |
| B2 vs B2' (robust z-score) | 7 / 3; 0.695; 1.000 | 3 / 7; 0.322; 1.000 |
| B2 vs B2_nov (novelty alone) | 9 / 1; 0.014; 0.123 | 5 / 5; 0.846; 1.000 |
| B2 vs B2_seq (without novelty) | 8 / 2; 0.432; 1.000 | 8 / 2; 0.010; 0.078 |
| B2 vs B2_alert (5-alert window) | 6 / 4; 0.160; 0.801 | 3 / 7; 0.131; 0.750 |
| B2 vs B2_max (no size correction) | **10 / 0; 0.002; 0.023** | 8 / 1 (1); 0.008; 0.070 |
| B2 vs B2_pooled (pooled calibration) | 2 / 8; 0.010; 0.107 | **1 / 9; 0.004; 0.043** |
| B2 vs B2_notime (no timing features) | 3 / 7; 0.695; 1.000 | **10 / 0; 0.002; 0.023** |
| B3 vs B2 | 2 / 5 (3); 0.656; 1.000 | 0 / 3 (7); 0.250; 1.000 |
| B3 vs B3_bestgrp (no promotion) | 0 / 6 (4); 0.031; 0.219 | 0 / 4 (6); 0.125; 0.750 |
| B3 vs B3_noabs (no absorption) | 6 / 0 (4); 0.031; 0.219 | 1 / 0 (9); 1.000; 1.000 |

- **The forest does not earn its place** (B2 vs B2' not significant): the robust z-score is reported as an equal
  alternative and the result is credited to the window representation, not to the Isolation Forest (Section 6).
- **Against Wazuh's own rule level (B0):** B2 reaches the first item of 9 of 10 stages earlier in both runs; B0 puts
  0 of 10 non-scan stages in the top 20, B2 6.4 of 10 (recorded) and 7.5 of 10 (no reconnaissance). Allowed:
  "compared with Wazuh's rule-level ordering, the layer placed 9 of 10 attack stages earlier (exploratory)".
- **Per-host calibration does not improve ranking:** pooled calibration placed 8 (recorded) and 9 (no
  reconnaissance) of 10 stages earlier than the specified per-host calibration. Stated plainly (Section 7 item 13).
- The size correction (pi) is the one component with a Holm-adjusted p below 0.05 in the headline run; timing
  features only in the no-reconnaissance run. Both exploratory.
- "B2 vs B1 isolates temporal context" is not used: with the tuned weights the comparison changes all four weights.

Aggregates (recorded): alpha-nDCG@20 B_RBA 0.676, B3 0.412, B2_pooled 0.429, B2 0.327, B0_host 0.332, B0_rank 0.289,
B0 0.233; stages in the top 20: B_RBA 10/10, B2_pooled 8, B0_host 7, B2 6.4, B0_rank 2, B0 0.

## 5. Santos: recorded (headline) beside oracle-cleaned

alpha-nDCG@20 recorded / cleaned: B2 0.499 / 0.390, B_RBA 0.725 / 0.718, B0_host 0.567 / 0.567, B2_pooled 0.550 /
0.535. Removing the designed exfiltration from the stream before the attack (Section 9.4 (c)) made B2's ranks later
(user change 4.0 -> 9.2, sudo escalation 10.8 -> 14.3, cracking 6.3 -> 12.8). Allowed: the two results side by side,
"evidence from one scenario"; no general claim of tolerance to contamination, and no explanation stated as fact.
(`provenance/ait/posthoc_2026-11-04.txt`, section 3.)

## 6. Post-hoc observations (not pre-registered; listed in DEVIATIONS.md; descriptive, no p-values)

Source: `tools/ait_posthoc.py` on the frozen outputs, `provenance/ait/posthoc_2026-11-04.txt`.

- **B2_pooled vs B_RBA:** B2_pooled earlier on 2 of 10 stages (recorded) and **8 of 10 without reconnaissance**
  (alpha-nDCG@20 0.357 vs 0.299, MRR 0.276 vs 0.106). B2_pooled vs host rarity: 8 of 10 earlier in both runs.
  Allowed only as: "a post-hoc look at the pre-registered pooled-calibration ablation suggests that ... ; this
  comparison was not part of the protocol and needs confirmation on new data." Never as the method's result, and
  B2_pooled is not substituted for B2. Its within-host AUC equals B2's (0.841 / 0.820): calibration changes only how
  hosts are ordered against each other, so part of its gain may be host rarity re-entering the score.
- **Where B2 loses:** sudo escalation is reached late (ranks 65.4 fox, 10.8 santos, 26.6 wardbeck, 45.7 wilson;
  B_RBA 1-3). The per-host calibration check shows benign windows of `internal_share` above S_seq 99 in 67% (fox),
  100% (santos) and 27% (wilson) of cases, against about 1% expected: that host's evaluation behaviour departs from
  its baseline. Stated as an observation in the discussion, not as a proven cause.

## 7. Positioning against other published work (design and evaluation, not ranking performance)

Only risk-based alerting (Uetz et al.) is compared in numbers, and it wins. No published method other than it has
been run here, so no ranking advantage over any of them is claimed. What can be claimed, as properties:

- **No analyst during operation, no alert labels to fit the detector.** AlertPro, learning to defer, PACT/STRAL and
  AACT learn from analyst feedback while running; DEEPCASE needs analysts to label its clusters; Smart-SIEM trains on
  46,454 labelled events. Wording per Section 9.4 (weights selected once on four labelled tuning scenarios).
- **Works on Wazuh's own alert stream and fields**, without HTTP telemetry (Smart-SIEM), an XDR incident model
  (GUIDE-based work) or an asset inventory (exposure weight 0 on AIT-ADS).
- **Context learned from each host's own baseline** instead of hypotheses fixed in advance (risk-based alerting).
  A design difference; on AIT-ADS the hand-designed hypotheses ranked better.
- **Evaluation:** all eight AIT-ADS scenarios under a tuning/test split and claims fixed in advance, one locked
  run, stage-level ranking, an independent reproduction and code review; Uetz et al. use one AIT-ADS scenario
  (russellmitchell, a tuning scenario here) with alert-level AUROC. To our knowledge this is the first evaluation
  of risk-based alerting on held-out AIT-ADS scenarios, with a reimplementation that reproduces 23 of 26 of its
  published per-module values exactly (`provenance/ait/rba_fidelity.txt`).
- **A finding about the published method:** its ranking on AIT-ADS depends on the reconnaissance alerts
  (alpha-nDCG@20 0.676 -> 0.299 without them); the corresponding first-item test is not significant (Section 2).
- Not claimable: better ranking than any published method; robustness; "label-free"/"unsupervised" for the whole
  method; transfer to other environments; lower compute cost than B_RBA (not timed on the same machine, Section 9.5).

## 8. Planned figures (all from the frozen outputs)

1. Stages in the top 20 per system (B0, B0_rank, B0_host, B2, B2_pooled, B3, B_RBA), recorded and no reconnaissance.
2. Within-host AUC per eligible host: B2, B_RBA, host rarity, level rarity.
3. alpha-nDCG@20 recorded vs no reconnaissance per system, captioned with the non-significant test.
4. First-item rank per stage (B0_host, B_RBA, B2, B2_pooled), with B2_pooled marked as an ablation and its comparison
   with B_RBA marked post hoc.
