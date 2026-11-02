# Brief: independent reproduction of the AIT-ADS tuning-set results

*Self-contained. You need the repository and this file, nothing else. Report back with the
items in Section 7.*

> **Second round (2 Nov), if you already did this once.** Your first run used a commit from before
> 1 Nov: it still had the `ait_param_lab.py` syntax error (fixed in `a98e4a1`, the same fix you made)
> and probably not the two ablation arms added on 31 Oct (B2_pooled, B2_notime). Please run again:
> 1. `git pull` (or a fresh clone) so that `git log -1` shows commit `11f06da` or later on `main`.
>    Do not edit any code this time; if something fails, report it.
> 2. **Delete the old caches**: `rm -rf ~/repro` and start in a new, empty scratch directory. The
>    cache files (`evalcache_*`, `plabrows_*`, `plabfit_*`, `rbacache_*`) are named without the code
>    version, so old ones would be loaded silently and the rerun would test the old code.
> 3. Run steps 1-7 again and compare with the files in the table, which now point to
>    `provenance/ait/rerun_self/` (Anawin's own rerun at `fd672aa`; the evaluation code has not changed
>    since). The older `eval_tuning_set_*holm.txt` files are from 27 Oct, before B_RBA moved to its
>    own published-work family; that, not your run, caused the Holm difference you reported.
> 4. Send everything in Section 7, including the commit hash, `pip freeze`, the data hashes and
>    your output `.txt` files (`ev_report.txt`, `ev_holm.txt`, and the no-reconnaissance ones).

## 1. What this is and why

The paper's tuning-set numbers (method B2, the comparator B_RBA, the ablation arms, the
weight search, the no-reconnaissance condition) were produced by scripts in `tools/` and saved
in `provenance/ait/`. Your job is to rerun those scripts on a clean machine from a fresh clone
and check that you get the same numbers. A second person reproducing them is the evidence that
they do not depend on one machine, one cache or one undocumented step.

You are checking, not improving. If something differs or fails, record it; do not change code
to make it match.

## 2. The one rule you must not break

**Never run anything on the test scenarios: fox, santos, wardbeck, wilson.**
- Never pass `--allow-test` to any script.
- Never run `tools/ait_locked_run.sh`.
- Only the four tuning scenarios appear below: harrison, russellmitchell, shaw, wheeler.

The test scenarios are read exactly once, in a pre-registered run
(`provenance/ait/PREREGISTRATION.md`). Running them early, even by accident, contaminates the
whole evaluation. If a command ever asks for `--allow-test`, stop and ask.

## 3. Setup

Linux or WSL, 2+ CPU cores, about 10 GB free disk.

```bash
git clone <repo URL> ContextAwareSIEM && cd ContextAwareSIEM
git log -1 --format='%h %s'            # record this commit hash
python3 --version                       # 3.11 is what the saved results used
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -r tools/requirements-ait.txt   # numpy 2.4.4, scikit-learn 1.8.0, scipy 1.17.1
python3 -m pip freeze > /tmp/pip_freeze.txt
```

With exactly these versions the seeded numbers should match to every digit. Other versions
may differ in the last digits; record which you used.

## 4. Data (public, not in git)

Put three files in `data/ait_ads/` and check their hashes:

| File | Where to get it | SHA-256 |
|---|---|---|
| `ait_ads.zip` | Zenodo record 8263181 (AIT Alert Data Set) | `9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9` |
| `labels.csv` | same Zenodo record | `633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0` |
| `alerts_csv.zip` | GitHub `ait-aecid/alert-data-set`, commit `ce927dd`, file `alerts_csv/alerts_csv.zip` | `2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3` |

```bash
mkdir -p data/ait_ads   # copy the three files in, then:
sha256sum data/ait_ads/ait_ads.zip data/ait_ads/labels.csv data/ait_ads/alerts_csv.zip
unzip -q data/ait_ads/alerts_csv.zip -d data/ait_ads/alerts_csv
```

A hash mismatch means a different version of the dataset: stop and report it. Never commit
anything under `data/`.

## 5. Runs

The scripts write cache files (`evalcache_*`, `plabrows_*`, `plabfit_*`, `rbacache_*`) to the
current directory, so work in a scratch directory outside the repo and use absolute paths:

```bash
R=$(pwd); D=$R/data/ait_ads; C=$D/alerts_csv; T=$R/tools; P=$R/provenance/ait
mkdir -p ~/repro && cd ~/repro
TUNE="harrison russellmitchell wheeler shaw"
```

Run in this order (runtimes on 2 cores). Keep every output file.

| # | Command | Compare with | Time |
|---|---|---|---|
| 1 | `python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json ev.json --scenarios $TUNE --seeds 5` | (creates caches; compared in step 2) | ~15 min |
| 2 | `python3 $T/ait_report.py $T ev.json > ev_report.txt` and `python3 $T/ait_holm.py $T ev.json > ev_holm.txt` | `$P/rerun_self/eval_tuning_set_self_report.txt`, `$P/rerun_self/eval_tuning_set_self_holm.txt` | <1 min |
| 3 | `python3 $T/ait_param_lab.py $T $P/host_roles.json pl.json --seeds 5 --variants delta86400` | (creates forest caches for step 4) | ~15 min |
| 4 | `python3 $T/ait_weight_lab.py $T $P/host_roles.json weight_lab.json --seeds 5` | `$P/weight_lab_verdict.txt` (selected weights 0, 0, 0.8, 0.2) | ~1 min |
| 5 | `python3 $T/ait_rba_tune.py $T rba_config_repro.json rba_tune.json` | `$T/rba_config.json`, `$P/rba_tune_report.txt` | ~10 min |
| 6 | `CONTEXTSIEM_DROP_LABELS=service_scan,dirb,wpscan python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json evnr.json --scenarios $TUNE --seeds 5`, then `ait_report.py` and `ait_holm.py` on `evnr.json` | `$P/rerun_self/eval_tuning_set_noscans_self_report.txt`, `$P/rerun_self/eval_tuning_set_noscans_self_holm.txt` | ~15 min |
| 7 | `cd $R && for t in test_parse_wazuh test_entries test_eval_metrics test_accumulator test_active_time; do python3 $T/$t.py || echo "FAILED $t"; done; cd ~/repro` | all pass | <1 min |

Notes:
- In step 5, write the configuration to `rba_config_repro.json`, **not** to `tools/rba_config.json`,
  so the committed configuration is never overwritten.
- `ait_holm.py` refuses to run without scipy. That is deliberate: without it the Wilcoxon p-values
  were silently `nan`.
- Optional, if time allows: the comparator fidelity check (`provenance/ait/README.md`, last table
  row) against Uetz et al.; expected result 23 of 26 values exact at two decimals.

Not in scope: the workstation runs (`ws_eval.py`, `ait_thresholds.py`). They use a private corpus
that is not shared.

## 6. How to compare

```bash
diff <(sed 's/[[:space:]]\+/ /g' ev_report.txt) <(sed 's/[[:space:]]\+/ /g' $P/rerun_self/eval_tuning_set_self_report.txt)
```
and the same for the Holm and no-reconnaissance files.

- **Same library versions:** every number should be identical. Any difference is a finding.
- **Different versions:** each alpha-nDCG and MRR should agree within the seed standard deviation
  printed beside it (the `±` value), and every paired count (`earlier / later / tied`) should be
  identical. Anything outside that is a finding.

## 7. Report back

One file, `REPRO_REPORT.md`, sent back or pushed on a branch named `repro/<your-name>` (not `main`):
1. Commit hash, Python version, the `pip freeze` output, OS and core count.
2. The three data hashes as you computed them.
3. Per step: ran OK / failed (paste the error) / runtime.
4. Per compared file: identical, within tolerance, or different (paste the differing lines).
5. Anything you had to work out that this brief did not say: a missing step, a path, a package.
   Those are bugs in the documentation and are as useful as numeric differences.

Do not include any cache or data files. Questions go to Anawin.
