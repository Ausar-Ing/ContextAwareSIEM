# Pre-registration of the locked test run (AIT-ADS)

Drafted 2026-10-25, before any test-scenario result of the tuned method exists. The
test scenarios were read once, untuned, for the preliminary check (Deliverable 3,
Table V); nothing since. This document fixes what the locked run does and what may be
claimed from it. It is frozen by tagging the commit that resolves Section 7.

Revised 2026-10-27: Section 7 closed by decisions taken by the student while the supervisor was
unavailable (the planned meeting was cancelled). The pre-decision version is at git tag
`checkpoint-2026-10-27-before-decisions` and in
`References/checkpoints/2026-10-27_before_provisional_decisions/`.

Revised 2026-10-29: the supervisor reviewed the questions. He accepted AIT-ADS as the corpus,
provided its constraints and assumptions (the designed contamination among them) are listed in the
paper; asked that the test compare with published work where possible and otherwise rely on
ablation; and left the design decisions to the student, to be judged as a whole at submission.
The decisions of 27-28 October, previously marked provisional, are therefore the student's
decisions and stand unless changed here before the freeze tag.

## 1. Data

| File | SHA-256 |
|---|---|
| `data/ait_ads/ait_ads.zip` | `9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9` |
| `data/ait_ads/labels.csv` | `633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0` |

Test scenarios: **fox, santos, wardbeck, wilson**, fixed before tuning (two large, two
small, one with exfiltration in each half). Tuning scenarios (harrison, russellmitchell,
shaw, wheeler) are not re-run as part of this protocol.

## 2. Method under test

The configuration at the freeze tag, with the defaults of `tools/seq_scoring.py` and
`tools/ait_eval.py`:
- calibration: `shrink`, n0 = 100;
- sequence entities: `host`;
- group score: `pi`, lambda = 8;
- priority: (1 - w) * sequence term + w * 100 * nu(g), with w = 0.2 and nu(g) = 1 when a member's
  host window flags its rule as novel; rule and exposure weights 0, i.e. weights
  (rule, exposure, sequence, novelty) = (0, 0, 0.8, 0.2) (Q1/Q8; selected on the
  tuning set by `tools/ait_weight_lab.py`, `provenance/ait/weight_lab_verdict.txt`);
- admission: configuration-assessment groups and, from 2026-10-28, vulnerability-detector results excluded (`tools/window_builder.py`, `EXCLUDED_GROUPS`; Q16); scheduled file-integrity results and duplicate Suricata ingestions excluded;
- entries N = 20, delta = 60 s;
- Delta = 24 h (repeat-group gap);
- Component 8: half-life h = 1 h, theta at the 99.9th baseline percentile, contribution floor 10%, lambda = 4, weights (0.3, 0.2, 0.5);
- window expiry T = 24 h;
- all tuned on the tuning set on 2026-10-25 and 2026-10-27 (`provenance/ait/param_lab_verdict.txt`, `provenance/ait/window_T_verdict.txt`, `provenance/ait/weight_lab_verdict.txt`);
- the risk-based alerting comparator B_RBA with the configuration in `tools/rba_config.json`, fixed on the tuning set (`tools/ait_rba_tune.py`, `provenance/ait/rba_tune_report.txt`);
- seeds 0-9.

No environment override is set, except `CONTEXTSIEM_DROP_LABELS` in the no-reconnaissance run (Section 5a). `ait_eval.py` records the configuration in each
scenario's `meta`; the report must show it unchanged.

## 3. Runs

`tools/ait_locked_run.sh` performs, in order:
1. it verifies the checksums above, that the working tree is clean at the freeze tag and that `tools/rba_config.json` exists;
2. it runs `ait_eval.py --allow-test --seeds 10 --recorded` on the four test scenarios: baselines as recorded, the designed exfiltration in santos included (**the headline**, decision on Q4);
3. it runs santos again with the oracle-cleaned baseline (its labelled exfiltration alerts removed from training), reported beside the headline;
4. it runs the four test scenarios once more with recorded baselines and the reconnaissance alerts removed from the whole stream (`CONTEXTSIEM_DROP_LABELS=service_scan,dirb,wpscan`), every system configured as for the headline (**the no-reconnaissance condition**, Section 5a);
5. it runs `ait_report.py` and `ait_holm.py` on the headline run and on the no-reconnaissance run, and `ait_report.py` on the cleaned santos run;
6. it writes everything under `provenance/ait/test/`. It refuses to start if scipy is missing, since the Wilcoxon tests would otherwise return nan.

`bash tools/ait_locked_run.sh --dry-run [seeds]` (added 2026-10-31) performs the same steps on the tuning
scenarios, without `--allow-test`, into `provenance/ait/dryrun/`, to test the script's mechanics before the
freeze. Its numbers are tuning-set numbers and are never reported as results.

The tuning scenarios were tuned with oracle-cleaned baselines (harrison cleaned; the other three
tuning scenarios have no labelled attack alerts before their first attack step). Harrison's
recorded run (`provenance/ait/eval_harrison_recorded_report.txt`) is the tuning-set evidence for
the recorded condition.

The run happens once. A crash is fixed and the run repeated from scratch. Any other
repeat, and any change of code or parameters after seeing a test number, is a deviation
and is reported as such (Section 8).

## 4. Primary analysis

**Unit:** non-scan attack stage occurrences, keyed (scenario, stage); "about ten" across
the four scenarios. Measure: the first-item rank of each occurrence in the repeat-group
queue (average ranks for ties); seeded systems enter by their mean rank over 10 seeds.

**Primary comparisons:** B2 vs B0_host (host rarity) and B2 vs B0_rank (level rarity):
number of occurrences where B2 is earlier / later / tied, and the two-sided Wilcoxon
signed-rank p.

**Comparison with published work (decided 2026-10-29):** B2 vs B_RBA, the risk-based alerting
comparator after Uetz et al. (2026), forms a family of its own: one test, two-sided Wilcoxon at
0.05, no correction. It was moved out of the secondary family because the supervisor asked that
the test compare with published work; on the tuning set B_RBA places the first item of 7 of 9
non-scan stages earlier than B2 (p = 0.023), so this comparison is expected to go against the
method and is reported whatever its outcome.

**Families and correction (decision on Q3, revised 2026-10-29):** Holm step-down within the
**primary family** (the 2 comparisons above; confirmatory), the **published-work family** (1
comparison) and, separately, within the **secondary family** (exploratory), as implemented in
`tools/ait_holm.py`:

| Secondary comparison |
|---|
| B2 vs B0 |
| B2 vs B1 |
| B2 vs B2' |
| B2 vs B2_nov |
| B2 vs B2_seq (the sequence term without the novelty term) |
| B2 vs B2_alert |
| B2 vs B2_max |
| B2 vs B2_pooled (per-host credibility calibration replaced by pooled calibration; added 2026-10-31) |
| B2 vs B2_notime (forests without the three timing features; added 2026-10-31) |
| B3 vs B2 |
| B3 vs B3_bestgrp |
| B3 vs B3_noabs |

**What this permits (stated now, so it cannot be bent later).** In the primary family the
smaller p must be below 0.05/2 = 0.025 and the larger below 0.05. The exact two-sided Wilcoxon p
for n pairs is:

| n | all one side | one loss at the smallest rank | two losses | three losses |
|---|---|---|---|---|
| 9 | 0.0039 | 0.0078 | 0.020 | 0.055 |
| 10 | 0.0020 | 0.0039 | 0.0098 | 0.027 |

So with about ten occurrences a primary comparison can be significant with up to two losses at
the smallest rank differences. Anything less is reported as a direction with counts, never as a
significant improvement. Secondary comparisons (12, smallest threshold 0.0042) are exploratory
whatever their p.

## 5. Secondary measures (reported, not tested)

- alpha-nDCG@{10, 20, 50} with seed SD;
- MRR of non-scan stages;
- stage coverage@20 (non-scan and scan separately);
- macro-AUC;
- within-host AUC (hosts with >= 5 attack and >= 5 benign alerts);
- robustness: binary grades, grades (2,1,1), alpha = 1;
- per-day alpha-nDCG@20 and MRR;
- the calibration split (stages on hosts with n_h >= n0 vs the rest);
- the per-host calibration check;
- B3 incident measures: incidents, benign incidents, time to first attack notable, stages per notable.

## 5a. No-reconnaissance condition (pre-registered 2026-10-29)

**Disclosure.** This condition was added after the tuning-set comparison with B_RBA was known: on
the tuning set, removing the reconnaissance alerts lowered B_RBA's alpha-nDCG@20 from 0.792 to
0.322 and B2's from 0.526 to 0.437, while the paired first-item ranks split 4 (B2 earlier) to 5
(p = 0.73). It is added before any test scenario has been read and is reported as a secondary
condition, never as the headline.

**Rationale.** An attacker who skips noisy scanning produces none of the service, directory and
WordPress scan alerts that every AIT-ADS attack begins with. The condition asks whether a ranking
depends on that reconnaissance.

**Analysis.** The same unit and measure as Section 4 (non-scan stage occurrences, first-item
rank). One test: B2 vs B_RBA, two-sided Wilcoxon at 0.05. All other comparisons in the
`ait_holm.py` output of this run, and all secondary measures of Section 5, are reported
descriptively beside the headline values.

## 6. Claims allowed

- **"Temporal context improves on host rarity"** only if B2 vs B0_host is significant after Holm in the primary family. Otherwise the paper reports the counts, the within-host AUC (host rarity is 0.5 there by construction) and the calibration split, and states that AIT-ADS cannot separate the two. In both cases the paper states that host rarity is strong on AIT-ADS because of how the dataset is built (every attack lands on its least active host), not as a general property of attacks (decision on Q2).
- **"Temporal context improves on level rarity"** only if B2 vs B0_rank is significant after Holm in the primary family.
- **Comparison with published work:** "the method ranks attack stages earlier than risk-based alerting" only if B2 vs B_RBA is significant in B2's favour; "risk-based alerting ranks them earlier" if it is significant in B_RBA's favour; otherwise the counts are reported and no difference is claimed.
- **No-reconnaissance condition:** "without reconnaissance the method ranks attack stages earlier than risk-based alerting" only if B2 vs B_RBA is significant in B2's favour in that run. A drop in B_RBA's aggregate measures alone does not license a robustness claim.
- **Secondary comparisons** (including static severity, B0) are reported with counts and p-values and labelled exploratory; none is stated as a confirmed improvement.
- **"The forest earns its place"** only if B2 vs B2' is significant after Holm in the secondary family. Otherwise the robust z-score is reported as an equal alternative and the result is credited to the window representation, not to the forest (decision on Q6); the method itself is not changed after the run.
- **Santos:** the recorded result is the headline; the cleaned result is reported beside it.
- **Tuning-set numbers** are never presented as results.

## 7. Decisions before the freeze (closed 2026-10-27/28; status confirmed 2026-10-29)

1. Novelty term: **adopted** (w = 0.2; Q1). Weights with the novelty term were searched (286 configurations); rule and exposure weights stay 0, and the rule and exposure scores are still shown to the analyst in every item's explanation (Q8).
2. Santos headline: **recorded**; cleaned reported beside it (Q4).
3. Holm: **primary family (2) and secondary family (11) corrected separately** (Q3).
4. Grades (Table VI): **confirmed** (Q5). Every event label that occurs among the Wazuh alerts of the eight scenarios has a grade: service, directory and WordPress scans, online password cracking, user change, sudo escalation and DNS exfiltration.
5. Workstation analysis: run before the test run (done 2026-10-25, `provenance/workstation/`).
6. Forest vs robust z-score: pre-committed claim as in Section 6 (Q6).
7. Tie rule and first-item veto: **accepted** as written in Deliverable 3, Sec. IV-C (Q7).
8. Risk-based alerting comparator B_RBA: **added** to the secondary family, configuration fixed on the tuning set (Q9). It outperforms the method on the tuning set; **the method is kept as specified** (decided 2026-10-27). Tuning-set numbers: `References/Results_Tuning_2026-10-27.pdf`.
9. Presentation decisions Q10-Q17 (2026-10-28): entries kept with the 5-alert ablation arm; notable ranking fixed; role-based exposure, the scenario split and the corpus division accepted as stated limitations; workstation drift discussed, refitting as future work; vulnerability-detector results excluded at admission; AIT-ADS kept.
10. Robustness to quieter attacks: **pre-registered** on 2026-10-29 as the no-reconnaissance condition (Section 5a), with the disclosure stated there.
11. B_RBA moved from the secondary family to a published-work family of one test (2026-10-29), following the supervisor's request to compare with published work.
12. Fidelity of B_RBA: checked against the numbers Uetz et al. publish for russellmitchell, a tuning scenario (`provenance/ait/rba_fidelity.txt`).
13. Two ablation arms added to the secondary family on 2026-10-31, so that every component claimed as a contribution has one: B2_pooled (the same forests, every host calibrated against the pooled held-out distribution only) and B2_notime (forests refitted without window duration and the mean and minimum inter-arrival times). They were added because of what the paper claims, before their tuning-set results were seen. On the tuning set B2_pooled is preferred by the objective but rejected by the protocol's calibration guard (`provenance/ait/calib_guard_pooled.txt`); the method is unchanged.
14. The accumulator's window-surprise correction is checked on the workstation's hold-out week (`tools/ws_qcheck.py`), against a criterion fixed in the script before its first run; it is not part of the locked run.

## 8. Deviations

Any departure from this document is listed in `provenance/ait/test/DEVIATIONS.md` with
its reason and the date, before the results are written up.
