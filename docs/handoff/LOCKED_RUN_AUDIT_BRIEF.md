# Brief: audit of the locked test run, and its checklist

*Self-contained. You need the repository and the AIT-ADS data set up as in
`docs/handoff/REPRODUCTION_BRIEF.md` Sections 3-4 (only if you do the optional runs in Section 5).
Report back with the items in Section 6.*

## 1. What this is and why

The paper's results come from one run of `tools/ait_locked_run.sh` on the four test scenarios.
Anawin runs it himself, on his own machine (WSL), at the freeze tag on **Thu 5 Nov**; it takes about
2-3 hours. It can be done only once: anything that goes wrong in it, or is changed after it, has to be
reported in the paper as a deviation (`provenance/ait/PREREGISTRATION.md` Section 8).

Your job is to find out, before the freeze, what can go wrong in that run, whether the script
catches it, and what Anawin should do if it happens. You produce a pre-flight checklist, a crash
procedure and a template for `DEVIATIONS.md`. You do not run the locked run.

## 2. The one rule you must not break

**Never run anything on the test scenarios: fox, santos, wardbeck, wilson.** Never run
`tools/ait_locked_run.sh` without `--dry-run`, and never pass `--allow-test`. Reading the code that
handles test scenarios is fine. The dry run (`--dry-run`) uses tuning scenarios only and is safe;
run it only in your own clone, because it deletes and rewrites `provenance/ait/dryrun/`, and do not
commit its output.

## 3. Files in scope

| File | Why |
|---|---|
| `tools/ait_locked_run.sh` | the run itself: checks, steps, output |
| `tools/ait_eval.py` | the `--allow-test` guard, `load()` (inputs and the `evalcache_*.pkl` cache), seeds |
| `tools/ait_report.py`, `tools/ait_holm.py`, `tools/ait_descriptive.py`, `tools/make_result_tables.py` | the steps after the evaluation; they only read the JSON outputs (check that) |
| `provenance/ait/PREREGISTRATION.md` | Section 3 (what the run does; "a crash is fixed and the run repeated from scratch"), Section 8 (deviations), Section 9 |
| `provenance/ait/dryrun/` | the committed dry run on Anawin's machine, with `pip_freeze.txt` and `RUN_RECORD.txt` |

## 4. Questions to answer

For each: **OK**, **GAP** or **UNCLEAR**, with `file:line` and one sentence. For each GAP, propose
the smallest fix.

**A. Inputs.** List every file the run reads. Which are hash-checked, which are covered by the
clean-tree check, which by neither? Are the Python and library versions checked or recorded?

**B. Caches.** `ait_eval.py` caches the parsed scenario as `evalcache_<scenario>_<rec|clean>_sid1.pkl`
in the current directory, keyed by scenario and baseline condition only. When could a cache made by
older code, or from other data, be used silently: in the locked run, in the dry run, in a tuning
rerun after a code fix? What should the checklist say about it?

**C. Failures.** For each case: what happens, what is left on disk, can the script be started
again, and does a restart read test data a second time?
1. one of the two parallel evaluation jobs of a step crashes (is the other job still running after
   the script exits?);
2. a crash after `provenance/ait/test/test_recorded.json` has been written (the script then refuses
   to start: reconcile this with PREREGISTRATION Section 3, "repeated from scratch");
3. a crash in one of the formatting steps (`ait_report.py`, `ait_holm.py`, `ait_descriptive.py`,
   `make_result_tables.py`);
4. the laptop sleeps, WSL shuts down, the disk fills up, or the terminal is closed during the run.

**D. Clean tree and environment.** The clean-tree check covers `tools`, `provenance/ait` and
`References` only, and the script rejects `CONTEXTSIEM_*` variables. Can anything outside those
change a result (other environment variables, thread counts, files outside those paths)?

**E. Determinism.** Would a repeat with the same code, data and library versions give identical
numbers? This decides whether "repeat from scratch" after a crash is harmless. See Section 5.

**F. Record.** `RUN_RECORD.txt` holds the tag, the commit and the finish time. What else should be
recorded so the run can be audited later (start time, duration, data hashes, `pip freeze`, Python
version, machine)?

**G. After the run.** What exactly should be committed (outputs, `.out` logs), and what must not
(caches, data)?

Already known, confirm and propose the fix (they may be fixed by the time you read this):
- `data/ait_ads/alerts_csv/<scenario>_alerts.txt` supplies every alert's event label (`ait_eval.py`
  `load()`), but the run checks only the hashes of `ait_ads.zip` and `labels.csv`.
- The committed dry run (`provenance/ait/dryrun/RUN_RECORD.txt`, commit `6707f61`) predates the
  last two changes to the script (`make_result_tables.py`, `ait_descriptive.py`), so the script as it
  stands has not been dry-run end to end on Anawin's machine.

## 5. Optional runs (tuning scenarios only)

If you have the data set up (about 40 minutes each, 2 cores):
1. `bash tools/ait_locked_run.sh --dry-run 2` in your clone, at the current `main`: does every step
   finish?
2. Move `provenance/ait/dryrun` aside, run it again (keep the caches), and compare the two with
   `diff -r`: identical apart from the timestamp in `RUN_RECORD.txt`?
3. Delete `evalcache_*.pkl`, run a third time, compare again: identical?

Record library versions with `pip freeze`. Do not commit the output.

## 6. Report back

One file, `LOCKED_RUN_AUDIT.md`, sent to Anawin or pushed on a branch `audit/<your-name>` (not `main`):
1. The commit you audited.
2. Answers to A-G (OK / GAP / UNCLEAR, `file:line`, one sentence each), GAPs first.
3. **Pre-flight checklist** for Thu 5: at most 15 items, each a command to run or a thing to check,
   in order, from "machine plugged in" to "start the run".
4. **Crash procedure:** a table, one row per failure in C: what Anawin does, and what goes into
   `DEVIATIONS.md`.
5. **`DEVIATIONS.md` template:** the fields each entry needs (date, what departed from the
   pre-registration, why, which outputs it affects, whether test data was read again, who decided).
6. Proposed script changes as a diff on your branch, smallest first. Anawin decides which go in.
7. The results of Section 5, if you ran it.

**Deadline: Wed 4 Nov, 18:00.** Fixes have to land before the freeze on Thu 5; after it, every
change is a deviation. Questions go to Anawin.
