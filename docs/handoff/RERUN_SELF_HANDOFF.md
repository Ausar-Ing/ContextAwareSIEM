# Handoff: rerun the tuning-set results on your machine (`_self`)

*Self-contained: a session picking this up needs nothing else. Written 2026-11-01. Schedule slot: Mon 2 Nov
(`SCHEDULE.md`). Report back with the items in Section 7.*

## 0. What this is

Every tuning-set number in the paper and in `References/Results_Tuning_2026-10-27.pdf` was produced in a
cloud workspace. This step reruns all of them **on your machine, in your environment**, so that you have run
them yourself at least once before they go into the paper. One command does everything and then compares
each result with the saved file. Every output carries a `_self` suffix and goes to
`provenance/ait/rerun_self/`.

Tuning scenarios only (harrison, russellmitchell, shaw, wheeler). It never touches a test scenario and is
not the locked run.

## 1. Before you start

- Ubuntu WSL, in the repo: `cd ~/ContextAwareSIEM`, and the environment active:
  `source ~/.venvs/csiem/bin/activate` (or your `csiem` alias). Set up in `docs/handoff/ENV_SETUP_HANDOFF.md`.
- `git pull` (or confirm `git status -sb` shows you are level with GitHub), so `tools/rerun_tuning_self.sh`
  and `tools/compare_rerun.py` exist and `tools/ait_param_lab.py` has the 1 Nov fix (it did not parse before).
- Data present: `data/ait_ads/` (as for the dry run) and `data/workstation/baseline_frozen_20261017T2315.json`
  (without it, steps 7-9 are skipped, not failed).
- Time: about **1.5-2.5 hours** on 2 cores. Disk: about 1 GB of caches in `~/csiem_rerun` (wiped at the
  start of each run, safe to delete afterwards). Memory: about 3 GB (two evaluations run in parallel).
- Leave the terminal open (or use `tmux`, Section 5): closing it stops the run.

## 2. The command

```bash
cd ~/ContextAwareSIEM && source ~/.venvs/csiem/bin/activate
bash tools/rerun_tuning_self.sh 2>&1 | tee /tmp/rerun_self.log
```

Progress, from a second terminal: `cat provenance/ait/rerun_self/RUN_LOG_self.txt`.
Step 1-2 (the two evaluations) is the long part; the remaining steps take minutes each.

If the run is interrupted after steps 1-2 finished, continue without redoing them:
`bash tools/rerun_tuning_self.sh --resume`. Without `--resume`, the script always starts clean.

## 3. What it reruns

| # | Result | Saved counterpart |
|---|---|---|
| 1 | All systems, 5 seeds (method, baselines, B_RBA, every ablation arm) | `provenance/ait/eval_tuning_set_ablations_1031_report.txt`, `_holm.txt` (also checked against the 27 Oct run) |
| 2 | No-reconnaissance condition | `provenance/ait/eval_tuning_set_noscans_report.txt`, `_holm.txt` |
| 3 | Priority-weight search (286 weightings) | `provenance/ait/weight_lab_verdict.txt` |
| 4 | B_RBA module and weight selection | `tools/rba_config.json`, `provenance/ait/rba_tune_report.txt` |
| 5 | Variety as a fifth term (not adopted) | `provenance/ait/weight_lab_variety_verdict.txt` |
| 6 | Calibration guard for B2_pooled | `provenance/ait/calib_guard_pooled.txt` |
| 7 | Workstation load thresholds | `provenance/workstation/ws_thresholds.json` |
| 8 | Workstation false promotion | `provenance/workstation/ws_eval.json` |
| 9 | Window-surprise check | `provenance/workstation/ws_qcheck.json` |

The committed configuration (`tools/rba_config.json`) is never overwritten: step 4 writes `rba_config_self.json`.

## 4. Outputs (28 files in `provenance/ait/rerun_self/`)

| File(s) | What |
|---|---|
| `COMPARISON_self.txt` | **Read this first**: every item marked IDENTICAL, LAST DIGIT, DIFFERENT or MISSING |
| `RUN_RECORD_self.txt` | commit, start and end time, Python and library versions, whether the workstation steps ran |
| `RUN_LOG_self.txt`, `pip_freeze_self.txt` | progress log; exact package list |
| `eval_tuning_set_self.json`, `_report.txt`, `_holm.txt`, `.out` | step 1 |
| `eval_tuning_set_noscans_self.json`, `_report.txt`, `_holm.txt`, `.out` | step 2 |
| `param_lab_self.json`, `.out`; `weight_lab_self.json`, `weight_lab_verdict_self.txt` | step 3 |
| `rba_config_self.json`, `rba_tune_self.json`, `rba_tune_report_self.txt` | step 4 |
| `weight_lab_variety_self.json`, `weight_lab_variety_verdict_self.txt` | step 5 |
| `calib_guard_pooled_self.txt` | step 6 |
| `ws_thresholds_self.json`, `.out`; `ws_eval_self.json`, `ws_eval_self_log.txt`; `ws_qcheck_self.json`, `.out` | steps 7-9 |

## 5. Reading the comparison

- **IDENTICAL**: every compared number equal. Expected for almost everything: your dry run already matched
  the cloud run exactly with the same pinned versions.
- **LAST DIGIT**: differences of one unit in the last printed digit. Acceptable; note it.
- **DIFFERENT**: a changed count ("earlier / later / tied", notables, a selected configuration) or a larger
  difference. Do not change anything; report it (Section 7). Most likely causes: a package version differs
  (`pip_freeze_self.txt` vs `tools/requirements-ait.txt`), or the code changed since the saved file.
- **MISSING**: a step did not produce its file; its `.out` file says why.
- Known exception: item 9 (window-surprise check) was saved from a run with newer library versions; a
  LAST DIGIT there is expected and fine.

Running in the background so a closed terminal does not stop it:
`tmux new -s rerun` -> run the command -> detach with Ctrl-b then d -> later `tmux attach -t rerun`.

## 6. After the run

Commit and push the outputs as the record that you ran them:
```bash
git add provenance/ait/rerun_self && git commit -m "Rerun of the tuning-set results on own machine (_self)" && git push
```
Then delete the caches if you want the space back: `rm -rf ~/csiem_rerun`.

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `numpy / scikit-learn / scipy missing` | activate the environment (Section 1) |
| `a CONTEXTSIEM_* variable is set` | `unset` the variable named in the message |
| checksum `FAILED` | wrong data file; see `provenance/ait/README.md` Section 1 |
| `alerts_csv missing` | `unzip data/ait_ads/alerts_csv.zip -d data/ait_ads/alerts_csv` |
| `Killed` or `MemoryError` | raise `memory=` in `C:\Users\<you>\.wslconfig`, `wsl --shutdown`, rerun |
| a step fails | its `.out` file in `provenance/ait/rerun_self/` has the traceback; paste it |
| run interrupted | `--resume` if steps 1-2 had finished (`RUN_LOG_self.txt` shows "1-2 done"); otherwise rerun the command |
| `SyntaxError` in `ait_param_lab.py` | you are on a commit before the 1 Nov fix: `git pull` |

## 8. Report back

1. `COMPARISON_self.txt` (paste it whole).
2. `RUN_RECORD_self.txt`.
3. Any DIFFERENT or MISSING item with its `.out` file.
4. Whether the commit is pushed.
