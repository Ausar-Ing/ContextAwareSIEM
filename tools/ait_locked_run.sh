#!/usr/bin/env bash
# Locked test run of the AIT-ADS protocol (provenance/ait/PREREGISTRATION.md).
# Run ONCE, from the repository root, at the freeze tag, after Section 7 of the
# pre-registration is closed. Refuses to run with a dirty tree, a wrong data checksum
# or any CONTEXTSIEM_* override in the environment.
#
# Headline (decision on Q4, 2026-10-27): recorded baselines, as a deployment would
# see them. Santos is run again with its designed exfiltration removed from the baseline
# (oracle-cleaned) and reported beside the headline. The four test scenarios are then run once more
# without the reconnaissance alerts (pre-registered 2026-10-29, PREREGISTRATION.md Section 5a).
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
python3 -c "import scipy.stats" || { echo "scipy missing: the Wilcoxon tests would return nan"; exit 1; }
[ -f "$T/rba_config.json" ] || { echo "$T/rba_config.json missing (B_RBA configuration)"; exit 1; }
[ -e "$OUT/test_recorded.json" ] && { echo "$OUT/test_recorded.json exists: the locked run has already happened"; exit 1; }
mkdir -p "$OUT"

python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_recorded_a.json" \
    --scenarios fox santos --seeds 10 --allow-test --recorded > "$OUT/test_recorded_a.out" 2>&1 &
python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_recorded_b.json" \
    --scenarios wardbeck wilson --seeds 10 --allow-test --recorded > "$OUT/test_recorded_b.out" 2>&1 &
wait
python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_santos_cleaned.json" \
    --scenarios santos --seeds 10 --allow-test > "$OUT/test_santos_cleaned.out" 2>&1

NR=service_scan,dirb,wpscan
CONTEXTSIEM_DROP_LABELS=$NR python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_norecon_a.json" \
    --scenarios fox santos --seeds 10 --allow-test --recorded > "$OUT/test_norecon_a.out" 2>&1 &
CONTEXTSIEM_DROP_LABELS=$NR python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_norecon_b.json" \
    --scenarios wardbeck wilson --seeds 10 --allow-test --recorded > "$OUT/test_norecon_b.out" 2>&1 &
wait

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
echo "freeze tag $TAG, commit $(git rev-parse HEAD), finished $(date -Iseconds)" > "$OUT/RUN_RECORD.txt"
echo "done: $OUT"
