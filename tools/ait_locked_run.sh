#!/usr/bin/env bash
# Locked test run of the AIT-ADS protocol (provenance/ait/PREREGISTRATION.md).
# Run ONCE, from the repository root, at the freeze tag, after Section 7 of the
# pre-registration is closed. Refuses to run with a dirty tree, a wrong data checksum
# or any CONTEXTSIEM_* override in the environment.
#
# usage: bash tools/ait_locked_run.sh <freeze-tag>
set -euo pipefail
TAG="${1:?usage: ait_locked_run.sh <freeze-tag>}"
ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT"
D=data/ait_ads; T=tools; P=provenance/ait; OUT=$P/test
C="$D/alerts_csv"

[ -z "$(git status --porcelain -- tools provenance/ait References)" ] || { echo "dirty tree"; exit 1; }
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$TAG^{commit}")" ] || { echo "HEAD is not $TAG"; exit 1; }
env | grep -q '^CONTEXTSIEM_' && { echo "CONTEXTSIEM_* override set"; exit 1; }
echo "9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9  $D/ait_ads.zip" | sha256sum -c -
echo "633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0  $D/labels.csv" | sha256sum -c -
[ -e "$OUT/test_cleaned.json" ] && { echo "$OUT/test_cleaned.json exists: the locked run has already happened"; exit 1; }
mkdir -p "$OUT"

python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_cleaned_a.json" \
    --scenarios fox santos --seeds 10 --allow-test > "$OUT/test_cleaned_a.out" 2>&1 &
python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_cleaned_b.json" \
    --scenarios wardbeck wilson --seeds 10 --allow-test > "$OUT/test_cleaned_b.out" 2>&1 &
wait
python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_santos_recorded.json" \
    --scenarios santos --seeds 10 --allow-test --recorded > "$OUT/test_santos_recorded.out" 2>&1

python3 - "$OUT" <<'EOF'
import json, sys
o = sys.argv[1]; R = {}
for p in ("test_cleaned_a.json", "test_cleaned_b.json"):
    R.update(json.load(open(f"{o}/{p}")))
json.dump(R, open(f"{o}/test_cleaned.json", "w"), indent=1)
EOF
python3 $T/ait_report.py $T "$OUT/test_cleaned.json" > "$OUT/test_cleaned_report.txt"
python3 $T/ait_holm.py $T "$OUT/test_cleaned.json" > "$OUT/test_cleaned_holm.txt"
python3 $T/ait_report.py $T "$OUT/test_santos_recorded.json" > "$OUT/test_santos_recorded_report.txt"
echo "freeze tag $TAG, commit $(git rev-parse HEAD), finished $(date -Iseconds)" > "$OUT/RUN_RECORD.txt"
echo "done: $OUT"
