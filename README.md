# Context-aware alert prioritization for Wazuh

A prioritization layer on top of Wazuh. It does not create new detections. It re-orders the alerts Wazuh
has already raised, using context derived across time within the alert stream: each entity's recent
activity is a window of 15 features, scored by an Isolation Forest trained without labels and calibrated
per host. The analyst queue holds repeat groups and risk notables. The paper is
`References/Deliverable3_ContextAwareSIEM_submission.tex`.

This README explains how to reproduce the paper's results on your own machine. You can run everything with
one command (Section 4) or one step at a time (Section 5). Lab operation (starting Wazuh, Sysmon, the agent)
is in `docs/LAB_OPERATIONS.md`.

## 1. What "training" and "test" mean here

There is no separate training command. Every evaluation run first fits the models (one Isolation Forest per
entity type, its per-host calibration and the accumulator thresholds) on the alerts **before the first attack
step** of each AIT-ADS scenario, without labels. It then freezes them and ranks the alerts of the attack
period. Labels are used only to score the ranking.

The eight AIT-ADS scenarios are split in two:

| Set | Scenarios | Used for |
|---|---|---|
| Tuning set | harrison, russellmitchell, shaw, wheeler | choosing every parameter: priority weights, the B_RBA comparator's configuration, the workstation thresholds |
| Test set | fox, santos, wardbeck, wilson | the reported results; run once, after the freeze |

The test set was run exactly once, on 3 Nov 2026, at git tag `freeze-2026-11-04`, under a pre-registered
protocol (`provenance/ait/PREREGISTRATION.md`). Its outputs are in `provenance/ait/test/`. Departures from
the protocol are in `provenance/ait/DEVIATIONS.md` and the claims allowed by the outcome in
`provenance/ait/CLAIMS.md`. Re-running the test set now is a reproduction of that run, not a new result.
`reproduce.sh` (Section 4) writes only to `reproduce/` and never overwrites the recorded outputs.

## 2. Requirements

- Linux, or WSL2 on Windows (the recorded runs used Ubuntu 24.04 on WSL2), with `bash`, `git`, `unzip` and `sha256sum`.
- Python 3.12 (3.11 also works) and the exact library versions in `tools/requirements-ait.txt`: numpy
  2.4.4, scikit-learn 1.8.0, scipy 1.17.1. With other versions the seeded forests can differ, so the
  numbers can differ beyond the last digit.
- At least 4 GB free memory and about 5 GB free disk (parse and forest caches are about 100 MB per scenario).

Setup, once:

```bash
git clone https://github.com/ausar-ing/ContextAwareSIEM.git && cd ContextAwareSIEM
sudo apt install -y python3-venv unzip            # Ubuntu, if missing
python3 -m venv ~/.venvs/csiem                    # keep the environment outside the repository
source ~/.venvs/csiem/bin/activate                # in every new terminal
python -m pip install -r tools/requirements-ait.txt
```

## 3. Data

The AIT Alert Data Set is public but not in git (it is large and separately licensed). Put three files in
`data/ait_ads/`:

| File | Source | SHA-256 |
|---|---|---|
| `ait_ads.zip` | Zenodo record 8263181 (AIT Alert Data Set) | `9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9` |
| `labels.csv` | same Zenodo record | `633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0` |
| `alerts_csv.zip` | GitHub `ait-aecid/alert-data-set`, commit `ce927dd`, file `alerts_csv/alerts_csv.zip` | `2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3` |

```bash
mkdir -p data/ait_ads          # copy the three files in; the check step verifies the hashes and unzips alerts_csv.zip
```

The workstation corpus (`data/workstation/baseline_frozen_20261017T2315.json`), used for the paper's
false-promotion results on a real machine, is **not distributed**: it is the alert log of the author's
personal computer. Without it, the one step that needs it (`tuning-workstation`) is skipped. Its recorded
outputs are in `provenance/workstation/`.

## 4. Run everything

```bash
bash reproduce.sh all
```

This runs, in order: the checks, every tuning-set step, every test-set step, and two comparisons with the
recorded results. It takes about 2 to 2.5 hours (see the times in Section 5). Results are in `reproduce/tuning/`
and `reproduce/test/`, and the comparisons in `reproduce/tuning/COMPARISON.txt` and
`reproduce/test/COMPARISON.txt`. A log with timestamps is in `reproduce/RUN_LOG.txt`.

The two halves can also be run on their own:

```bash
bash reproduce.sh tuning       # checks + the tuning set (about 1.5 h)
bash reproduce.sh test         # checks + the test set (about 40 min)
```

## 5. Run the steps separately

Every step is also a command: `bash reproduce.sh <step> [<step> ...]`. `bash reproduce.sh help` lists them.
Steps that read another step's caches say so and refuse to start if they are missing.
`--seeds N` overrides the number of forest seeds (the paper uses 5 on the tuning set and 10 on the test set).
Fewer seeds are fine for a quick test of the mechanics, but then the comparison reports differences.

| Step | What it does | Calls | Output (in `reproduce/`) | Time* |
|---|---|---|---|---|
| `check` | environment, library versions, data hashes, unit tests, Holm smoke test | `tools/test_*.py`, `ait_holm.py` | `RUN_LOG.txt` | 1 min |
| **Tuning set** | | | `tuning/` | |
| `tuning-eval` | all systems (B0 ... B3) and ablation arms, 4 tuning scenarios | `ait_eval.py`, `ait_report.py`, `ait_holm.py` | `eval_tuning_set_self_{report,holm}.txt` | 20 min |
| `tuning-norecon` | the same without reconnaissance alerts | same | `eval_tuning_set_noscans_self_*` | 10 min |
| `tuning-weights` | forest caches, then the priority-weight search (286 weightings) | `ait_param_lab.py`, `ait_weight_lab.py` | `weight_lab_verdict_self.txt` | 12 min |
| `tuning-rba` | B_RBA module and weight selection | `ait_rba_tune.py` | `rba_config_self.json`, `rba_tune_report_self.txt` | 9 min |
| `tuning-variety` | variety as a fifth priority term (not adopted) | `ait_weight_lab.py --variety` | `weight_lab_variety_verdict_self.txt` | 1 min |
| `tuning-calib` | calibration guard for the pooled-calibration arm | `ait_calib_guard.py` | `calib_guard_pooled_self.txt` | 6 min |
| `tuning-thresholds` | workstation load thresholds, fixed on the tuning set | `ait_thresholds.py` | `ws_thresholds_self.json` | 6 min |
| `tuning-workstation` | workstation false promotion and window-surprise check (skipped without the private corpus) | `ws_eval.py`, `ws_qcheck.py` | `ws_eval_self.json`, `ws_qcheck_self.json` | 5 min |
| `tuning-compare` | compares `reproduce/tuning/` with the recorded tuning results | `compare_rerun.py` | `COMPARISON.txt` | <1 min |
| **Test set** | | | `test/` | |
| `test-recorded` | the headline: 4 test scenarios, recorded baselines | `ait_eval.py --allow-test --recorded` | `test_recorded_{a,b}.json` | 26 min |
| `test-cleaned` | santos with its exfiltration removed from the baseline | `ait_eval.py --allow-test` | `test_santos_cleaned.json` | 3 min |
| `test-norecon` | the 4 test scenarios without reconnaissance alerts | `ait_eval.py --allow-test --recorded` | `test_norecon_{a,b}.json` | 11 min |
| `test-format` | merges the parts; reports, Holm tests, descriptive comparisons, the paper's LaTeX tables | `ait_locked_format.sh` | `test_*_report.txt`, `test_*_holm.txt`, `test_descriptive.txt`, `results_tables.tex` | <1 min |
| `test-compare` | compares `reproduce/test/` with the locked run in `provenance/ait/test/` | (in `reproduce.sh`) | `COMPARISON.txt` | <1 min |
| `clean` | deletes `reproduce/` (outputs and caches) | | | |

\* Approximate. The test steps, `tuning-eval` and `tuning-norecon` were measured in a reproduction on 17 Nov on a 2-core,
8 GB Linux machine. The other tuning steps are from the author's rerun on 1 Nov (16 cores, WSL2). A slower
machine takes longer.

Examples:

```bash
bash reproduce.sh check                                     # setup and data only
bash reproduce.sh tuning-eval tuning-compare                # only the main tuning-set table
bash reproduce.sh test-recorded test-cleaned test-norecon   # the three test-set evaluations ...
bash reproduce.sh test-format test-compare                  # ... then the reports and the comparison
```

`reproduce.sh` contains no method code. It calls the frozen scripts in `tools/` with the arguments the
paper's runs used (`tools/rerun_tuning_self.sh` for the tuning set, `tools/ait_locked_run.sh` for the
test set), so each step can also be run by hand from those two scripts. If you do that, run from an empty
scratch directory: the scripts write caches to the current directory, and the caches are not tied to a
code version. `reproduce.sh` empties its cache folders whenever the code in `tools/` changes.

## 6. Reading the comparisons

Each compared item is marked `IDENTICAL` (every value equal), `LAST DIGIT` (within one unit of the last
printed digit) or `DIFFERENT`. With the pinned library versions and the default seeds, expect:

- **Test set:** every file `IDENTICAL` except `results_tables.tex`, which differs in one table caption:
  the contaminated-scenario caption was reworded on 4 Nov, after the run, and no number changed. A
  reproduction on 17 Nov, even with newer libraries (numpy 2.5.3, scikit-learn 1.9.1, scipy 1.18.1), matched
  every other file exactly. JSON values can differ in the 16th digit between two runs of the same code (a Python set's iteration order
  inside the MRR mean), which shows as `IDENTICAL (float noise < 1e-12)`.
- **Tuning set:** items 3 to 7 (weight search, B_RBA, variety, calibration guard, workstation thresholds)
  `IDENTICAL`; items 8 and 9 `MISSING` without the workstation corpus. Items 1 and 2 (all systems, and
  no reconnaissance) show `DIFFERENT`, for two documented reasons, neither of them a reproduction failure:
  - **B2_nov was redefined on 3 Nov, before the freeze** (code review; `PREREGISTRATION.md` Section 7,
    item 15): it is now B2's own novelty term. The saved tuning references were made before that change.
    As a result, the B2_nov rows differ, and so does the comparison B2 vs B2_nov. Because that comparison
    sits in the secondary Holm family, the Holm-adjusted p-values of the other secondary comparisons
    shift slightly too (e.g. B2 vs B2_pooled 0.141 -> 0.156). Their counts and raw p-values stay
    identical, and every other system's row is identical. The reports also end with a "data checks"
    section, added the same day.
  - **Item 2's paired tests are compared with a file from 27 Oct** (`B2 vs B0` and `B2 vs B1`,
    0.043 -> 0.047). On 29 Oct B_RBA moved to its own Holm family, which changed the adjusted p-values.
- **Other library versions:** α-nDCG and MRR should agree within the seed standard deviation printed
  beside them (the `±` value), and the paired counts (earlier / later / tied) should be identical.

## 7. Where the paper's numbers come from

| Paper | Recorded file |
|---|---|
| Test-set results, all systems, paired tests with Holm correction | `provenance/ait/test/test_recorded_report.txt`, `test_recorded_holm.txt` |
| Contaminated scenario (santos), recorded vs cleaned baseline | `provenance/ait/test/test_santos_cleaned_report.txt` |
| No-reconnaissance condition | `provenance/ait/test/test_norecon_report.txt`, `test_norecon_holm.txt` |
| Descriptive comparisons | `provenance/ait/test/test_descriptive.txt` |
| Result tables (LaTeX) | `provenance/ait/test/results_tables.tex` |
| Tuning-set results, weight search, B_RBA selection | `provenance/ait/rerun_self/`, `provenance/ait/weight_lab_verdict.txt`, `provenance/ait/rba_tune_report.txt` |
| Workstation false promotion, window-surprise check | `provenance/workstation/ws_eval.json`, `ws_qcheck.json` |
| Run record of the locked run (commit, versions, machine) | `provenance/ait/test/RUN_RECORD.txt`, `pip_freeze.txt` |

## 8. Repository layout

```
tools/            all method and evaluation code, frozen at the tag (later additions only format the
                  locked-run outputs into the paper's tables and figures); the core is window_builder.py
                  (admission, entities, windows), seq_scoring.py (Isolation Forest, calibration),
                  accumulator.py (risk accumulation) and ait_eval.py (queue, systems, evaluation)
reproduce.sh      the reproduction entry point described above
provenance/       recorded outputs, pre-registration, deviations, claims, environment snapshots
References/       the paper (LaTeX) and the earlier deliverables
docs/             lab operations, handoff briefs, the locked-run checklist
figures/          architecture figure
data/             datasets, not in git (Section 3)
```
