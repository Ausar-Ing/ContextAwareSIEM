# Pre-registration of the locked test run (AIT-ADS)

Drafted 2026-10-25, before any test-scenario result of the tuned method exists. The
test scenarios were read once, untuned, for the preliminary check (Deliverable 3,
Table V); nothing since. This document fixes what the locked run does and what may be
claimed from it. It is frozen by tagging the commit that resolves Section 7.

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
- weights (0, 0, 1);
- entries N = 20, delta = 60 s;
- Delta = 24 h (repeat-group gap);
- Component 8: half-life h = 1 h, theta at the 99.9th baseline percentile, contribution floor 10%, lambda = 4, weights (0.3, 0.2, 0.5);
- window expiry T = 24 h;
- all tuned on the tuning set on 2026-10-25 (`provenance/ait/param_lab_verdict.txt`, `provenance/ait/window_T_verdict.txt`);
- seeds 0-9.

No environment override is set. `ait_eval.py` records the configuration in each
scenario's `meta`; the report must show it unchanged.

## 3. Runs

`tools/ait_locked_run.sh` performs, in order:
1. it verifies the checksums above and that the working tree is clean at the freeze tag;
2. it runs `ait_eval.py --allow-test --seeds 10` on the four test scenarios with oracle-cleaned baselines (the tuning convention);
3. it runs santos again with `--recorded` (its designed exfiltration stays in the baseline);
4. it runs `ait_report.py` and `ait_holm.py` on each;
5. it writes everything under `provenance/ait/test/`.

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

**Family and correction (as Deliverable 3 states):** Holm step-down over the whole
family: the 2 primary comparisons and the 9 secondary ones in `tools/ait_holm.py`:

| Secondary comparison |
|---|
| B2 vs B0 |
| B2 vs B1 |
| B2 vs B2' |
| B2 vs B2_nov |
| B2 vs B2_alert |
| B2 vs B2_max |
| B3 vs B2 |
| B3 vs B3_bestgrp |
| B3 vs B3_noabs |

If the novelty term is adopted (Section 7), "B2 vs B2_max" stays and "B2_nov+" becomes B2;
the family size does not change.

**What this permits (stated now, so it cannot be bent later).** With 11 comparisons the
smallest Holm threshold is 0.05/11 = 0.0045. The exact Wilcoxon p for n pairs all
favouring one side is 2/2^n:

| n | all one side | one loss at the smallest rank | two losses |
|---|---|---|---|
| 9 | 0.0039 | 0.0078 | 0.020 |
| 10 | 0.0020 | 0.0039 | 0.0098 |

So a primary comparison can be significant only if B2 wins essentially every stage.
Anything less is reported as a direction with counts, never as a significant
improvement.

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

## 6. Claims allowed

- **"Temporal context improves on static severity"** only if B2 vs B0 is significant after Holm. Otherwise: "B2 placed k of n stages earlier than severity".
- **"Temporal context improves on host rarity"** only if B2 vs B0_host is significant after Holm. Otherwise the paper reports the counts, the within-host AUC (host rarity is 0.5 there by construction) and the calibration split, and states that AIT-ADS cannot separate the two.
- **"The forest earns its place"** only if B2 vs B2' is significant after Holm. Otherwise the robust z-score is reported as an equal alternative.
- **Santos:** both the cleaned and the recorded results are reported. Which one is the headline is decided before the run (Section 7).
- **Tuning-set numbers** are never presented as results.

## 7. Open before the freeze (decided by the supervisor, then this section is closed)

1. Novelty term (`B2_nov+`, w = 0.2): method or arm.
2. Santos headline: recorded or cleaned.
3. Family for Holm: whole family (as written) or the 2 primary comparisons only, with the secondary family corrected separately. The power consequence is in Section 4: under the primary-only family the threshold for the smaller p is 0.025, which n = 10 meets with up to two losses at the smallest ranks.
4. Grades (Table VI) confirmed.
5. Whether to run the workstation false-promotion analysis before or after the test run. It does not touch the test scenarios.

## 8. Deviations

Any departure from this document is listed in `provenance/ait/test/DEVIATIONS.md` with
its reason and the date, before the results are written up.
