# Locked run: checklist, crash procedure and deviations template

For the one run of `tools/ait_locked_run.sh` on the test scenarios (`provenance/ait/PREREGISTRATION.md`
Section 3). Written 2026-11-03 from the locked-run audit (`docs/handoff/LOCKED_RUN_AUDIT_BRIEF.md`).
The script itself refuses to start on a dirty tree, a HEAD other than the tag, an existing
`provenance/ait/test/`, a wrong data or label hash, other library versions, a `CONTEXTSIEM_*` or
`DUMP_DIR` variable, or missing scipy; the checklist covers what the script cannot check.

## 1. Before freeze day

1. Every accepted fix is committed and pushed; the code review is closed (no open finding that
   could change a number).
2. Dry run at that commit, in `tmux` (about 40-50 min; it now re-parses every scenario because it
   deletes the parse caches): `bash tools/ait_locked_run.sh --dry-run 2`. It must end with
   `done: provenance/ait/dryrun`, and the folder must contain `test_descriptive.txt`,
   `results_tables.tex`, `pip_freeze.txt` and a `RUN_RECORD.txt` ending in `finished ...`.
3. **Commit the dry run**: `git add provenance/ait/dryrun && git commit -m "Dry run at the freeze commit"`.
   The dry run rewrites tracked files; without this commit the locked run stops with "dirty tree".

## 2. Freeze day, in order

1. Laptop on mains power. Windows: sleep "Never" when plugged in; pause Windows Update.
2. New WSL terminal, repository root, the Python environment with `tools/requirements-ait.txt`
   installed.
3. `free -g; nproc; df -h .`: at least about 4 GB free memory (two evaluations run in parallel; the
   audit's estimate, not measured on the test set) and at least 2 GB free disk.
4. `git status` clean, `git log -1` is the commit with the committed dry run.
5. `ls provenance/ait/test` says "No such file or directory".
6. Tag and publish: `git tag -a freeze-2026-11-05 -m "Freeze"`, then
   `git push origin main freeze-2026-11-05 checkpoint-2026-10-27-before-decisions`
   (the pre-registration cites the checkpoint tag; it is not on GitHub yet).
7. `tmux new -s locked`, then inside it:
   `bash tools/ait_locked_run.sh freeze-2026-11-05 2>&1 | tee ~/locked_run_console.txt; echo "exit ${PIPESTATUS[0]}"`
8. Detach (Ctrl-b, then d). While it runs, look only at `ls provenance/ait/test` and
   `cat provenance/ait/test/RUN_RECORD.txt`; do not open the `.out` or JSON files (they hold test numbers).
9. At the end, `tmux attach -t locked` shows `done: provenance/ait/test` and `exit 0`, and
   `RUN_RECORD.txt` ends with `finished ...`.
10. `git add provenance/ait/test && git commit -m "Locked run"` and push. Check nothing was left out
    with `git status --ignored provenance/ait/test` (keep the console log outside the repo or name it `.txt`).

## 3. Crash procedure

First, in every case, read only the error, not the numbers:
`grep -h -A40 Traceback provenance/ait/test/*.out`, or the terminal for step 5. Change nothing but
the cause of the crash. The script stops the other evaluation job by itself.

| Failure | What to do | `DEVIATIONS.md` entry |
|---|---|---|
| An evaluation step (2-4) fails, including `Killed` (out of memory) | `pgrep -af ait_eval.py` must print nothing. `mv provenance/ait/test provenance/ait/test_crash1` (its `.out` logs are kept by `.gitignore`). Fix the cause (memory: `.wslconfig` and `wsl --shutdown`; code: the smallest fix). Write the entry in `provenance/ait/DEVIATIONS.md`. Commit `test_crash1/`, `DEVIATIONS.md` and any fix together, tag `freeze-2026-11-05-r1`, push, and start again at section 2 step 7 with the new tag. | Crash in step N, error summary, fix and commit, new tag. **Test data read again: yes.** Test numbers seen: none, or which lines. |
| Step 5 fails (`ait_report`, `ait_holm`, `ait_descriptive`, `make_result_tables`, or "a pre-registered comparison is missing") | Do **not** rerun the evaluation. `sha256sum provenance/ait/test/*_a.json provenance/ait/test/*_b.json provenance/ait/test/test_santos_cleaned.json > ~/eval_json.sha256`. Fix the cause, commit. `bash tools/ait_locked_format.sh provenance/ait/test ""`. `sha256sum -c ~/eval_json.sha256` must pass. `echo "step 5 rerun $(date -Iseconds), see DEVIATIONS.md" >> provenance/ait/test/RUN_RECORD.txt`. A `make_result_tables` mismatch means two code paths disagree on a statistic: report it, do not edit numbers by hand; `ait_holm.py` is the reference. | Formatting failure, fix and commit. **Test data read again: no.** Evaluation JSON unchanged (hashes before and after). Outputs affected: reports and tables only. |
| Terminal closed, WSL or Windows shut down, power lost, disk full | Treat as the first row: the processes are gone and files may be half-written. Remove the external cause first. | As the first row, with the external cause. |
| Laptop slept and resumed | Nothing, if the run finishes. | One line: timings in `meta.seconds` are inflated. |

## 4. `DEVIATIONS.md` template

Create `provenance/ait/DEVIATIONS.md` (outside `provenance/ait/test/`: the run refuses to start while
that folder exists) from this, even when there is nothing to report:

```markdown
# Deviations from provenance/ait/PREREGISTRATION.md (locked run)

Freeze tag: <tag> (commit <hash>). Runs started: <n>. Final run: <tag>, started <time>, finished <time>.

None. / Entries below.

## D1: <short title>
- Date and time:
- Decided by: <name>; consulted: <names or none>
- Pre-registration text departed from: <section, sentence>
- What happened:
- Why this action:
- Change made: <files>; commit <before> -> <after>; new tag <tag or none>
- Test data read again: yes / no (scenarios; total number of reads so far)
- Test numbers seen before the change: none / <which file and lines>
- Outputs affected: <files>; evaluation JSON identical? <sha256 before / after>
- Record kept at: <e.g. provenance/ait/test_crash1/>
- Effect on the claims of Section 6: none / <which>
```
