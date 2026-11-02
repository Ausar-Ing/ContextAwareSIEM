#!/usr/bin/env bash
# Locked test run of the AIT-ADS protocol (provenance/ait/PREREGISTRATION.md).
# Run ONCE, from the repository root, at the freeze tag, after Section 7 of the
# pre-registration is closed. Before starting, follow docs/LOCKED_RUN_CHECKLIST.md.
#
# Refuses to run with: a dirty tree or HEAD other than the tag; an existing output directory (a run
# has already started: follow the crash procedure in the checklist); a wrong checksum of the data or
# of the per-alert event-label files; library versions other than tools/requirements-ait.txt; any
# CONTEXTSIEM_* or DUMP_DIR variable in the environment; missing scipy or B_RBA configuration.
#
# Headline (decision on Q4, 2026-10-27): recorded baselines, as a deployment would
# see them. Santos is run again with its designed exfiltration removed from the baseline
# (oracle-cleaned) and reported beside the headline. The four test scenarios are then run once more
# without the reconnaissance alerts (pre-registered 2026-10-29, PREREGISTRATION.md Section 5a).
# Merging and formatting (step 5) are in tools/ait_locked_format.sh, which reads only the output
# JSON and can be rerun alone after a crash in a formatting step.
#
# usage: bash tools/ait_locked_run.sh <freeze-tag>
#        bash tools/ait_locked_run.sh --dry-run [seeds]
#
# --dry-run (added 2026-10-31) runs every step below on the TUNING scenarios instead (harrison and
# shaw, wheeler and russellmitchell, recorded baselines; harrison in place of santos for the cleaned
# run), without --allow-test, writing to provenance/ait/dryrun/ and skipping only the git-state checks
# and the existing-output check. It tests the script's mechanics; its numbers are tuning-set numbers
# and are never results.
#
# 2026-11-02, after the locked-run audit (docs/handoff/LOCKED_RUN_AUDIT_BRIEF.md): a failed evaluation
# job stops the other; parse caches are deleted before the first evaluation; event-label files are
# hash-checked; any existing output directory stops the run; library versions are checked and
# recorded; RUN_RECORD.txt is written at the start and completed at the end; formatting moved to
# tools/ait_locked_format.sh with a check that no pre-registered comparison is missing.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"; cd "$ROOT"
D=data/ait_ads; T=tools; P=provenance/ait
C="$D/alerts_csv"
START=$(date -Iseconds)
if [ "${1:-}" = "--dry-run" ]; then
    DRY=1; SEEDS="${2:-2}"; OUT=$P/dryrun; ALLOW=""
    SA="harrison shaw"; SB="wheeler russellmitchell"; SCLEAN=harrison
    MODE="DRY RUN on tuning scenarios ($SEEDS seeds)"
else
    DRY=0; TAG="${1:?usage: ait_locked_run.sh <freeze-tag> | --dry-run [seeds]}"
    SEEDS=10; OUT=$P/test; ALLOW="--allow-test"
    SA="fox santos"; SB="wardbeck wilson"; SCLEAN=santos
    MODE="LOCKED RUN, freeze tag $TAG"
    # first, so that leftovers of an earlier start are named as such and not reported as a dirty tree
    [ ! -e "$OUT" ] || { echo "$OUT exists: a locked run has already started. Do not delete it: follow the crash procedure in docs/LOCKED_RUN_CHECKLIST.md"; exit 1; }
    [ -z "$(git status --porcelain -- tools provenance/ait References)" ] || { echo "dirty tree"; exit 1; }
    [ "$(git rev-parse HEAD)" = "$(git rev-parse "$TAG^{commit}")" ] || { echo "HEAD is not $TAG"; exit 1; }
fi
# no result-changing override in the environment (compgen + grep without -q: no SIGPIPE under pipefail)
if compgen -e | grep -E '^(CONTEXTSIEM_.*|DUMP_DIR)$'; then echo "override variable(s) above are set: unset them"; exit 1; fi
echo "9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9  $D/ait_ads.zip" | sha256sum -c -
echo "633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0  $D/labels.csv" | sha256sum -c -
# the per-alert event labels (alerts_csv/<scenario>_alerts.txt); an alert without a match counts as benign
sha256sum -c --quiet "$P/alerts_csv.sha256" || { echo "event-label files differ from $P/alerts_csv.sha256"; exit 1; }
python3 - "$T/requirements-ait.txt" <<'PY'
import sys, importlib.metadata as md
bad = []
for line in open(sys.argv[1]):
    line = line.split("#")[0].strip()
    if "==" not in line:
        continue
    name, want = (x.strip() for x in line.split("=="))
    try:
        have = md.version(name)
    except md.PackageNotFoundError:
        have = "missing"
    if have != want:
        bad.append(f"{name} {have} (pinned {want})")
if bad:
    sys.exit("library versions differ from tools/requirements-ait.txt: " + "; ".join(bad))
PY
python3 -c "import scipy.stats" || { echo "scipy missing: the Wilcoxon tests would return nan"; exit 1; }
[ -f "$T/rba_config.json" ] || { echo "$T/rba_config.json missing (B_RBA configuration)"; exit 1; }

[ "$DRY" = 1 ] && rm -rf "$OUT"
mkdir -p "$OUT"
python3 -m pip freeze > "$OUT/pip_freeze.txt" 2>/dev/null || echo "pip freeze failed" > "$OUT/pip_freeze.txt"
{ echo "$MODE"
  echo "commit $(git rev-parse HEAD 2>/dev/null || echo none)"
  echo "started $START"
  python3 -c "import sys, numpy, sklearn, scipy; print('python', sys.version.split()[0], 'numpy', numpy.__version__, 'scikit-learn', sklearn.__version__, 'scipy', scipy.__version__)"
  echo "machine $(uname -srm), $(nproc) cores, $(free -g 2>/dev/null | awk '/^Mem:/ {print $2 " GB memory"}')"
  echo "checks passed: $([ "$DRY" = 1 ] && echo 'environment, data and label hashes, library versions, scipy, B_RBA configuration (git checks skipped: dry run)' || echo 'clean tree at tag, no earlier output, environment, data and label hashes, library versions, scipy, B_RBA configuration')"
} > "$OUT/RUN_RECORD.txt"

# every scenario is parsed by the code at this commit: no cached parse from older code or other data
rm -f evalcache_*.pkl
# a failed evaluation job stops the other one (without this it would keep writing to $OUT)
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_recorded_a.json" \
    --scenarios $SA --seeds $SEEDS $ALLOW --recorded > "$OUT/test_recorded_a.out" 2>&1 &
python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_recorded_b.json" \
    --scenarios $SB --seeds $SEEDS $ALLOW --recorded > "$OUT/test_recorded_b.out" 2>&1 &
wait -n; wait -n   # the first failure, in either job, stops the script (set -e) and the trap stops the other
python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_santos_cleaned.json" \
    --scenarios $SCLEAN --seeds $SEEDS $ALLOW > "$OUT/test_santos_cleaned.out" 2>&1

NR=service_scan,dirb,wpscan
CONTEXTSIEM_DROP_LABELS=$NR python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_norecon_a.json" \
    --scenarios $SA --seeds $SEEDS $ALLOW --recorded > "$OUT/test_norecon_a.out" 2>&1 &
CONTEXTSIEM_DROP_LABELS=$NR python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv "$C" $T $P/host_roles.json "$OUT/test_norecon_b.json" \
    --scenarios $SB --seeds $SEEDS $ALLOW --recorded > "$OUT/test_norecon_b.out" 2>&1 &
wait -n; wait -n
echo "evaluation finished $(date -Iseconds)" >> "$OUT/RUN_RECORD.txt"

# step 5: merge, reports, Holm, descriptive comparisons, result tables (reads only the JSON above)
if [ "$DRY" = 1 ]; then NOTE="dry run on the tuning set, not results"; else NOTE=""; fi
bash $T/ait_locked_format.sh "$OUT" "$NOTE"
echo "finished $(date -Iseconds)" >> "$OUT/RUN_RECORD.txt"
echo "done: $OUT"
