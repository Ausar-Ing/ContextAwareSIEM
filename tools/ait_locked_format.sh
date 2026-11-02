#!/usr/bin/env bash
# Step 5 of the locked run (provenance/ait/PREREGISTRATION.md Section 3): merge the evaluation outputs,
# then the reports, Holm corrections, descriptive comparisons (Section 9) and the paper's result tables.
# Called by tools/ait_locked_run.sh. It reads only the JSON written by the evaluation steps, never the
# data, so after a crash in this step it can be rerun alone (record that in DEVIATIONS.md):
#
# usage: bash tools/ait_locked_format.sh <out-dir> [label-note]
#        e.g. bash tools/ait_locked_format.sh provenance/ait/test ""
#
# Stops if any pre-registered comparison is "not available": Holm would then divide by a smaller
# family without saying so.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"; cd "$ROOT"
OUT="${1:?usage: ait_locked_format.sh <out-dir> [label-note]}"; NOTE="${2:-}"; T=tools
for f in test_recorded_a test_recorded_b test_santos_cleaned test_norecon_a test_norecon_b; do
    [ -s "$OUT/$f.json" ] || { echo "$OUT/$f.json missing or empty: the evaluation did not finish"; exit 1; }
done

python3 - "$OUT" <<'PY'
import json, sys
o = sys.argv[1]
for name in ("recorded", "norecon"):
    R = {}
    for part in ("a", "b"):
        R.update(json.load(open(f"{o}/test_{name}_{part}.json")))
    json.dump(R, open(f"{o}/test_{name}.json", "w"), indent=1)
PY
python3 $T/ait_report.py $T "$OUT/test_recorded.json" > "$OUT/test_recorded_report.txt"
python3 $T/ait_holm.py $T "$OUT/test_recorded.json" > "$OUT/test_recorded_holm.txt"
python3 $T/ait_report.py $T "$OUT/test_santos_cleaned.json" > "$OUT/test_santos_cleaned_report.txt"
python3 $T/ait_report.py $T "$OUT/test_norecon.json" > "$OUT/test_norecon_report.txt"
python3 $T/ait_holm.py $T "$OUT/test_norecon.json" > "$OUT/test_norecon_holm.txt"
if grep -H "not available" "$OUT/test_recorded_holm.txt" "$OUT/test_norecon_holm.txt"; then
    echo "a pre-registered comparison is missing (above): its Holm family would shrink silently"; exit 1
fi
# descriptive comparisons pre-registered 2026-11-02 (PREREGISTRATION.md Section 9); formatting only
python3 $T/ait_descriptive.py $T "$OUT/test_recorded.json" "$OUT/test_norecon.json" > "$OUT/test_descriptive.txt"
# the paper's result tables, generated from the outputs above (added 2026-11-01)
python3 $T/make_result_tables.py $T "$OUT/test_recorded.json" "$OUT/results_tables.tex" \
    --norecon "$OUT/test_norecon.json" --cleaned "$OUT/test_santos_cleaned.json" --label-note "$NOTE"
echo "formatted: $OUT"
