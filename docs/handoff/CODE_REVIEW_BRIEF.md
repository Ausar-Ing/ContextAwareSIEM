# Brief: review of the evaluation code against the paper

*Self-contained. You need the repository, the submission draft
`References/Deliverable3_ContextAwareSIEM_submission.tex` (or its PDF) and the pre-registration
`provenance/ait/PREREGISTRATION.md`. Report back with the items in Section 6.*

## 1. What this is and why

The paper defines exactly how systems are built, scored and compared. The code must do exactly
that, because the test run happens once and cannot be repeated after a bug is found. One silent
bug has already been caught this way: without scipy, the Wilcoxon test returned `nan` and every
corrected p-value printed as 1.000 with no error.

Your job is to read the code beside the paper and list every place where they disagree, where the
code does something the paper does not say, or where you cannot tell. You are a reviewer, not a
fixer: **do not commit changes to `main`.** Put proposed fixes on a branch, `review/<your-name>`, or
just describe them.

## 2. The one rule you must not break

**Never run anything on the test scenarios: fox, santos, wardbeck, wilson.** Never pass
`--allow-test` and never run `tools/ait_locked_run.sh`. Reading the code that handles them is fine.
For any run, use only harrison, russellmitchell, shaw and wheeler, or small synthetic inputs you
build yourself.

## 3. Files in scope

| File | What it does |
|---|---|
| `tools/window_builder.py` (~650 lines) | parsing, admission (Phase 1), entities (Phase 2), entries and windows (Phase 3) |
| `tools/seq_scoring.py` (~230) | forests, stride, per-host cap, held-out calibration with shrinkage (Phase 4-5) |
| `tools/accumulator.py` (~190) | risk accumulation and notables (Phase 7) |
| `tools/rba.py` (~220) | the comparator B_RBA (Uetz et al.) |
| `tools/eval_metrics.py` (~190) | grades, alpha-nDCG, first-item ranks, MRR, AUCs, paired test |
| `tools/ait_eval.py` (~410) | runs every system per scenario and seed; baseline/evaluation split; queue groups |
| `tools/ait_holm.py`, `tools/ait_report.py` | comparison families, Holm correction, report |
| `tools/ait_locked_run.sh` | the one-shot test run (read only) |

The paper sections to keep open: Proposed System (Phases 1-7), Experiment Design (Datasets,
Systems Compared, Evaluation Protocol, Metrics, Statistical Analysis, Parameter Selection), and
PREREGISTRATION.md Sections 2-6.

## 4. Checklist

For each item write **OK**, **MISMATCH**, or **UNCLEAR**, with `file:line` and one sentence.

**A. No leakage from the evaluation period** (most important)
- [ ] The baseline is every alert before the scenario's first attack step (from `labels.csv`),
      and nothing at or after it is used to fit forests, calibration tables, `θ`, the baseline
      rule set `B` (novelty flag), B0_host's host shares, B0_rank's level percentiles, or any
      B_RBA normalizer.
- [ ] B_RBA windows look only into the past (no future alerts) when used in the evaluation.
- [ ] `--recorded` keeps the labelled exfiltration alerts in the baseline; the default
      (cleaned) removes them from training only, never from the evaluation stream.
- [ ] Event labels are used only for scoring the ranking, never as an input to any system.
- [ ] `--allow-test` is required for every test scenario, and nothing else reads them.

**B. Admission and windows (Phases 1-3)**
- [ ] Excluded groups: `sca`, `rootcheck`, `policy_monitoring`, `ciscat`, `vulnerability-detector`;
      scheduled file-integrity alerts; the duplicate Suricata copy (`fast.log`).
- [ ] Suricata alerts use the signature id as rule identity.
- [ ] Entries: same rule, gap at most `δ` = 60 s, never rejoined after a longer gap;
      window = last `N` = 20 entries, expiry `T` = 24 h; scoreable only if the entries hold at least 3 alerts.
- [ ] The 14 model features match the feature table (definitions, log transforms on features 2, 11, 12, 13;
      feature 15 not a model input). Active-time correction is off for AIT-ADS.

**C. Model and calibration (Phases 4-5)**
- [ ] One forest per entity type; `t` = 200 trees; `ψ` = min(4096, n); fitted only with at least 200 windows.
- [ ] Training = every 10th window per entity, each host capped at an equal share; the rest held out.
- [ ] Calibration uses held-out windows only: `w_h F_host + (1 - w_h) F_pooled`, `w_h = n_h/(n_h + 100)`.
- [ ] Each seed is an independent replica (forest and calibration); metrics are per seed, never on
      seed-averaged scores.
- [ ] Priority B2 = 0.8 x sequence term + 0.2 x 100 x novelty flag; sequence term from the host window only;
      windows with fewer than 3 alerts get 50.

**D. Queue and accumulator (Phases 6-7)**
- [ ] Repeat groups: same host and rule, gap at most `Δ` = 24 h.
- [ ] Group score `π(g) = -log10(1 - u^k)` with the maximum member score `u`; capped at `λ` = 8 in the
      priority; uncapped where the paper says so.
- [ ] Accumulator: `(1 + ln k)` group term, decayed running maximum of `q`, half-life 1 h, weights
      (0.3, 0.2, 0.5), threshold at the 99.9th baseline percentile, the three escalation conditions,
      10 % contribution floor, notables absorb their groups.

**E. Metrics and statistics**
- [ ] Grades: user change, sudo escalation, exfiltration = 3; online password cracking = 2;
      service, directory and WordPress scans = 1; benign = 0. An item's grade is its highest member grade.
- [ ] alpha-nDCG: alpha = 0.5, gain `g_s (1 - α)^c`, discount `log2(i + 1)`, greedy ideal ordering.
- [ ] Ties broken by average rank (matters for B0).
- [ ] First-item rank per non-scan stage occurrence, keyed (scenario, stage); seeded systems enter the
      paired test by their mean rank over seeds. What happens if a stage is missing in some seed?
- [ ] Wilcoxon two-sided; what happens to zero differences and to tied differences; check the p-values
      against the exact table in PREREGISTRATION.md Section 4 (e.g. 9 pairs all one way gives 0.0039).
- [ ] Families: primary (B2 vs B0_host, B2 vs B0_rank), published-work (B2 vs B_RBA, no correction),
      secondary (the other 10); Holm step-down within each family only.

## 5. How to check, not just read

- Run the unit tests: `for t in test_parse_wazuh test_entries test_eval_metrics test_accumulator test_active_time; do python3 tools/$t.py; done`.
- For the metrics, build tiny inputs by hand (three items, two stages, one tie) and compute
  alpha-nDCG, first-item ranks and MRR on paper; compare with `eval_metrics.py`. Add any such case
  you write as a new test on your branch.
- For the paired test, feed `paired_ranks` known differences and compare with scipy directly and
  with the exact table.
- For leakage, add a temporary print of the latest timestamp each fitting step sees and compare
  it with the attack start; remove it afterwards (branch only).

## 6. Report back

One file, `CODE_REVIEW.md`, sent back or pushed on `review/<your-name>`:
1. The commit hash you reviewed.
2. The checklist with OK / MISMATCH / UNCLEAR, `file:line` and one sentence each.
3. For each MISMATCH: what the paper says, what the code does, and whether it could change a
   reported number (yes / no / unsure).
4. Anything the code does that the paper never mentions.
5. Any test you added and its result.

Severity first: anything in section A, or anything that changes a metric or a p-value, goes at the
top. Questions go to Anawin.
