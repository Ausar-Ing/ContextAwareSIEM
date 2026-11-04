# Deviations from provenance/ait/PREREGISTRATION.md (locked run)

Freeze tag: freeze-2026-11-04 (commit b7857b0f9ad6a0cd37c668975d7c69116d12efb4). Runs started: 1.
Final run: freeze-2026-11-04, started 2026-11-03T20:14:59+07:00, finished 2026-11-03T20:42:21+07:00
(`provenance/ait/test/RUN_RECORD.txt`).

None. The run started once, passed every check of `tools/ait_locked_run.sh`, and finished with exit 0. No test
scenario was read before it. No code, parameter or configuration changed after the tag.

Note (not a deviation): the tag name carries the planned freeze date, 4 November; the tag was created and the
run made on 3 November, as the timestamps above and the tag record show. The pre-registration does not fix the date.

## Post-hoc analyses (after the run; not part of the protocol)

Listed so that no post-hoc number can be mistaken for a pre-registered result. None changes code, parameters or a
pre-registered result, and none re-reads a test scenario: each reads only the frozen outputs in
`provenance/ait/test/`.

- P1 (2026-11-04): `tools/ait_posthoc.py` -> `provenance/ait/posthoc_2026-11-04.txt`. First-item ranks per stage;
  paired counts without a test for B2_pooled vs B_RBA, vs B0_host and vs B0 (comparisons the protocol does not
  contain); santos recorded beside cleaned in numbers. Decided by Anawin, run by Claude in a separate container
  (numpy 2.5.3; the script only averages and counts stored ranks). Reported as post hoc in
  `provenance/ait/CLAIMS.md` Section 6.
