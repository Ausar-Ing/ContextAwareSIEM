# Handoff: Python environment on your machine (WSL) + dry run

*Self-contained: a session picking this up needs nothing else. Written 2026-10-31. Report back with the
items in Section 6. Schedule: environment working Sun 1 Nov, dry run green Mon 2 Nov (`SCHEDULE.md`).*

## 0. How to work on this

- Project folder on Windows: `C:\Personal\UniStuff\Project\ContextAwareSIEM`; in WSL (Ubuntu 24.04),
  `~/ContextAwareSIEM` is a symlink to it (one copy, no syncing).
- Claude's `device_bash` is NOT WSL: it cannot run `apt`, `sudo`, `wsl.exe` or the WSL Python. You run the
  commands below in **Ubuntu WSL** and paste the output.
- Never paste passwords or the contents of `~/wazuh-setup` into the chat. `sudo` asks for your WSL password; type it in WSL only.
- Claude commits locally; nothing reaches GitHub until you `git push`.

## 1. Goal and "done"

The locked test run (Thu 5 Nov) must run on your machine with numpy, scikit-learn and scipy. Done when:
1. `python3 -c "import numpy, sklearn, scipy"` works inside the environment;
2. the five unit tests pass;
3. the Holm smoke test reproduces the saved file **exactly** (Section 3, step 8);
4. `bash tools/ait_locked_run.sh --dry-run 2` finishes and writes `provenance/ait/dryrun/RUN_RECORD.txt`.

Why it matters: without scipy, the Wilcoxon tests once returned `nan` silently and every comparison printed
"not significant". The scripts now stop instead, but only a working environment lets the run happen at all.

## 2. Versions

The saved results used Python 3.11, numpy 2.4.4, scikit-learn 1.8.0, scipy 1.17.1 (`tools/requirements-ait.txt`).
Ubuntu 24.04 ships Python 3.12; these exact versions have wheels for 3.12, so use the system Python 3.12.
A run on Python 3.13 with newer libraries already reproduced the saved numbers to three decimals, so
3.12 is fine.

## 3. Steps (in Ubuntu WSL)

```bash
# 1. go to the repo and make sure it is current
cd ~/ContextAwareSIEM && git status -sb && git log -1 --oneline

# 2. check Python (expect 3.12.x)
python3 --version

# 3. venv support (24.04 blocks system-wide pip installs, so a virtual environment is required)
sudo apt update && sudo apt install -y python3-venv python3-pip

# 4. create the environment OUTSIDE the repo (the repo lives on the Windows drive: a venv there is slow
#    and breaks on NTFS permissions)
python3 -m venv ~/.venvs/csiem

# 5. activate it (needed in EVERY new terminal before running project scripts)
source ~/.venvs/csiem/bin/activate

# 6. install the pinned versions
python -m pip install --upgrade pip
python -m pip install -r tools/requirements-ait.txt

# 7. verify
python -c "import sys, numpy, sklearn, scipy; print(sys.version.split()[0], numpy.__version__, sklearn.__version__, scipy.__version__)"
for t in test_parse_wazuh test_entries test_eval_metrics test_accumulator test_active_time; do python tools/$t.py >/dev/null 2>&1 && echo "PASS $t" || echo "FAIL $t"; done

# 8. scipy smoke test: must print nothing (identical to the saved file)
python tools/ait_holm.py tools provenance/ait/eval_tuning_set_ablations_1031.json | diff - provenance/ait/eval_tuning_set_ablations_1031_holm.txt

# 9. dry run of the locked test run on the TUNING scenarios (2 seeds; about 40-90 min)
bash tools/ait_locked_run.sh --dry-run 2 2>&1 | tee /tmp/dryrun.log
cat provenance/ait/dryrun/RUN_RECORD.txt
grep -l Traceback provenance/ait/dryrun/*.out || echo "no tracebacks"
```

Optional convenience: `echo 'alias csiem="source ~/.venvs/csiem/bin/activate && cd ~/ContextAwareSIEM"' >> ~/.bashrc`,
then `csiem` in a new terminal.

## 4. After the dry run

- The dry run overwrites `provenance/ait/dryrun/` (tracked files). **Commit it** as the record that your
  environment works, then push:
  `git add provenance/ait/dryrun && git commit -m "Dry run on own machine (env check)" && git push`.
  The real run refuses to start with uncommitted changes under `tools/`, `provenance/ait/` or `References/`,
  so do not leave them uncommitted before Thu 5 Nov.
- The scripts leave cache files `evalcache_*.pkl` (~100 MB each) in the repo root. They are gitignored
  (`*.pkl`) and safe to delete; delete them if you change code before the freeze.
- Expected numbers: the dry-run reports should match `provenance/ait/dryrun/*_report.txt` from the 31 Oct
  commit (`git diff` after the run). Identical, or differences only in the last digit, is fine. A changed
  paired count ("earlier / later / tied") is not: report it.

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `error: externally-managed-environment` | pip run outside the venv | `source ~/.venvs/csiem/bin/activate`, then rerun |
| `The virtual environment was not created successfully because ensurepip is not available` | venv package missing | `sudo apt install -y python3.12-venv`, delete `~/.venvs/csiem`, redo step 4 |
| pip tries to compile numpy / scipy from source (long output, compiler errors) | no wheel for your Python version | check `python3 --version`; must be 3.11 or 3.12. If not, ask for the `uv` route: `uv venv --python 3.11` |
| pip cannot connect / SSL errors | network or proxy | check internet in WSL (`curl -I https://pypi.org`); VPN off; retry |
| `ModuleNotFoundError: sklearn` or "scipy missing" when running a script | venv not active in this terminal | step 5 |
| Holm smoke test prints differences | scipy version differs | `pip show scipy`; reinstall from `tools/requirements-ait.txt` |
| A unit test fails | environment or code problem | paste the failing test's full output |
| Dry run stops with `Killed` or `MemoryError` | WSL memory limit (two runs in parallel need ~3 GB) | raise `memory=` in `C:\Users\<you>\.wslconfig`, `wsl --shutdown`, retry |
| `data/ait_ads/...: FAILED` (checksum) | wrong or missing data file | see `provenance/ait/README.md` Section 1 for the files and hashes |
| `CONTEXTSIEM_* override set` | an environment variable from an experiment is set | `env | grep CONTEXTSIEM`, then `unset <NAME>` |
| Very slow | running on the Windows drive through WSL | expected; let it run |

## 6. Report back

1. Output of step 7 (versions, unit tests).
2. Whether step 8 printed anything.
3. `RUN_RECORD.txt` contents, and whether any `.out` file contains a traceback.
4. Runtime of the dry run.
5. Whether the dry-run commit is pushed.
