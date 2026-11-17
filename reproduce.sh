#!/usr/bin/env bash
# Reproduce the paper's AIT-ADS results: one command for everything, or one step at a time.
# See README.md for setup, data, run times and how to read the comparisons.
#
#   bash reproduce.sh all                 check + tuning set + test set (everything)
#   bash reproduce.sh tuning              check + all tuning-set steps + comparison
#   bash reproduce.sh test                check + all test-set steps + comparison
#   bash reproduce.sh <step> [<step> ...] single steps, in the order given (list: bash reproduce.sh help)
#   options:  --seeds N   (default: 5 on the tuning set, 10 on the test set, as in the paper)
#
# This script only calls the frozen scripts in tools/ with the arguments the paper's runs used
# (tools/rerun_tuning_self.sh for the tuning set, tools/ait_locked_run.sh for the test set). It writes
# only to reproduce/ (or $CSIEM_OUT) and never changes tools/, provenance/ or References/.
# Added 2026-11-17, after the locked run; it does not change any result.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$ROOT"
T="$ROOT/tools"; D="$ROOT/data/ait_ads"; C="$D/alerts_csv"
P="$ROOT/provenance/ait"; PW="$ROOT/provenance/workstation"
WSC="$ROOT/data/workstation/baseline_frozen_20261017T2315.json"
BASE="${CSIEM_OUT:-$ROOT/reproduce}"
TO="$BASE/tuning"; TW="$BASE/work_tuning"      # tuning outputs / caches
XO="$BASE/test";   XW="$BASE/work_test"        # test outputs / caches
TUNE="harrison russellmitchell shaw wheeler"
NR=service_scan,dirb,wpscan                    # the no-reconnaissance condition

TUNING_STEPS="tuning-eval tuning-norecon tuning-weights tuning-rba tuning-variety tuning-calib tuning-thresholds tuning-workstation tuning-compare"
TEST_STEPS="test-recorded test-cleaned test-norecon test-format test-compare"

usage() {
    cat <<EOF
usage: bash reproduce.sh <all | tuning | test | step ...> [--seeds N]

groups
  all                 check, then every tuning step, then every test step
  tuning              check + ${TUNING_STEPS// /, }
  test                check + ${TEST_STEPS// /, }

single steps (outputs in reproduce/tuning or reproduce/test)
  check               environment, library versions, data hashes, unit tests, Holm smoke test
  tuning-eval         all systems and ablations on the 4 tuning scenarios          (Table: tuning results)
  tuning-norecon      the same without reconnaissance alerts
  tuning-weights      forest caches + priority-weight search (286 weightings)    needs tuning-eval
  tuning-rba          B_RBA module and weight selection                          needs tuning-eval
  tuning-variety      variety as a fifth priority term (not adopted)             needs tuning-weights
  tuning-calib        calibration guard for the pooled-calibration arm           needs tuning-eval
  tuning-thresholds   workstation load thresholds, fixed on the tuning set       needs tuning-eval
  tuning-workstation  workstation false promotion + window-surprise check        needs the private corpus
  tuning-compare      compare reproduce/tuning with the saved tuning results
  test-recorded       the headline: 4 test scenarios, recorded baselines
  test-cleaned        santos with its exfiltration removed from the baseline
  test-norecon        the 4 test scenarios without reconnaissance alerts
  test-format         merge, reports, Holm, descriptive comparisons, LaTeX tables needs the three above
  test-compare        compare reproduce/test with the locked run (provenance/ait/test)
  clean               delete reproduce/ (outputs and caches)
EOF
}

# ---------------------------------------------------------------- arguments
[ $# -gt 0 ] || { usage; exit 1; }
STEPS=(); SEEDS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --seeds) SEEDS="${2:?--seeds needs a number}"; shift 2 ;;
        -h|--help|help) usage; exit 0 ;;
        all) STEPS+=(check $TUNING_STEPS $TEST_STEPS); shift ;;
        tuning) STEPS+=(check $TUNING_STEPS); shift ;;
        test) STEPS+=(check $TEST_STEPS); shift ;;
        *) STEPS+=("$1"); shift ;;
    esac
done
for s in "${STEPS[@]}"; do
    case " check clean $TUNING_STEPS $TEST_STEPS " in *" $s "*) ;; *) echo "unknown step: $s (bash reproduce.sh help)"; exit 1 ;; esac
done
S_TUNE="${SEEDS:-5}"; S_TEST="${SEEDS:-10}"

# ---------------------------------------------------------------- helpers
mkdir -p "$BASE"
LOG="$BASE/RUN_LOG.txt"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
die() { echo "ERROR: $*" | tee -a "$LOG"; exit 1; }
commit() { git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "no git"; }

# a work directory holds parse and forest caches; they are named without a code version, so the
# directory is emptied whenever the code in tools/ is not the code that wrote them
prep_work() {
    local w="$1" stamp
    stamp=$(cat "$T"/*.py | sha256sum | cut -c1-16)
    if [ -d "$w" ] && [ "$(cat "$w/.code" 2>/dev/null)" != "$stamp" ]; then rm -rf "$w"; fi
    mkdir -p "$w"; echo "$stamp" > "$w/.code"
}
need() { ls "$1"/$2 >/dev/null 2>&1 || die "$3"; }
ait_eval() {   # ait_eval <work dir> <out json> <log> <args...>
    local w="$1" out="$2" lg="$3"; shift 3
    ( cd "$w" && python3 "$T/ait_eval.py" "$D/ait_ads.zip" "$D/labels.csv" "$C" "$T" "$P/host_roles.json" "$out" "$@" ) > "$lg" 2>&1 \
        || { tail -n 20 "$lg"; die "ait_eval.py failed, see $lg"; }
}
record() {     # one line per finished step, with the environment, in RUN_RECORD.txt of that output folder
    echo "$(date -Iseconds)  $1  seeds $2  commit $(commit)  $(python3 -c 'import sys, numpy, sklearn, scipy; print("python", sys.version.split()[0], "numpy", numpy.__version__, "scikit-learn", sklearn.__version__, "scipy", scipy.__version__)')" >> "$3/RUN_RECORD.txt"
}

# ---------------------------------------------------------------- check
step_check() {
    log "check: environment"
    if compgen -e | grep -E '^(CONTEXTSIEM_.*|DUMP_DIR)$'; then die "the variable(s) above change results: unset them"; fi
    for c in python3 sha256sum unzip; do command -v $c >/dev/null || die "$c not found"; done
    python3 -c "import numpy, sklearn, scipy.stats" 2>/dev/null \
        || die "numpy / scikit-learn / scipy missing: activate the environment (README, Setup)"
    python3 - "$T/requirements-ait.txt" <<'PY' | tee -a "$LOG"
import sys, importlib.metadata as md
bad = []
for line in open(sys.argv[1]):
    line = line.split("#")[0].strip()
    if "==" in line:
        name, want = (x.strip() for x in line.split("=="))
        try:
            have = md.version(name)
        except md.PackageNotFoundError:
            have = "missing"
        if have != want:
            bad.append(f"{name} {have} (paper: {want})")
print("  library versions: " + ("as in the paper" if not bad else
      "DIFFERENT: " + "; ".join(bad) + " -- seeded numbers can then differ from the saved ones"))
PY
    log "check: data"
    for f in ait_ads.zip labels.csv; do [ -f "$D/$f" ] || die "$D/$f missing (README, Data)"; done
    echo "9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9  $D/ait_ads.zip" | sha256sum -c --quiet - \
        || die "ait_ads.zip is not the version the paper used"
    echo "633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0  $D/labels.csv" | sha256sum -c --quiet - \
        || die "labels.csv is not the version the paper used"
    if [ ! -d "$C" ]; then
        [ -f "$D/alerts_csv.zip" ] || die "$D/alerts_csv.zip missing (README, Data)"
        echo "2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3  $D/alerts_csv.zip" | sha256sum -c --quiet - \
            || die "alerts_csv.zip is not the version the paper used"
        unzip -q "$D/alerts_csv.zip" -d "$C"
        # some copies of the archive contain a top-level alerts_csv/ folder
        if [ -d "$C/alerts_csv" ]; then mv "$C/alerts_csv"/* "$C"/ && rmdir "$C/alerts_csv"; fi
    fi
    sha256sum -c --quiet "$P/alerts_csv.sha256" || die "per-alert label files differ from provenance/ait/alerts_csv.sha256"
    if [ -f "$WSC" ]; then log "  workstation corpus found: workstation steps will run"
    else log "  workstation corpus not present (private): tuning-workstation will be skipped"; fi
    log "check: unit tests"
    for t in test_parse_wazuh test_entries test_eval_metrics test_accumulator test_active_time; do
        python3 "$T/$t.py" > "$BASE/$t.out" 2>&1 || { tail -n 20 "$BASE/$t.out"; die "unit test $t failed"; }
        echo "  PASS $t"
    done
    log "check: Holm smoke test (statistics code against a saved file)"
    python3 "$T/ait_holm.py" "$T" "$P/eval_tuning_set_ablations_1031.json" | diff -q - "$P/eval_tuning_set_ablations_1031_holm.txt" >/dev/null \
        && echo "  PASS identical to provenance/ait/eval_tuning_set_ablations_1031_holm.txt" \
        || die "ait_holm.py output differs from the saved file (scipy version?)"
    log "check passed"
}

# ---------------------------------------------------------------- tuning set (tools/rerun_tuning_self.sh, steps 1-9)
step_tuning-eval() {
    mkdir -p "$TO"; prep_work "$TW"
    log "tuning-eval: 4 tuning scenarios, $S_TUNE seeds"
    ait_eval "$TW" "$TO/eval_tuning_set_self.json" "$TO/eval_tuning_set_self.out" --scenarios $TUNE --seeds "$S_TUNE"
    python3 "$T/ait_report.py" "$T" "$TO/eval_tuning_set_self.json" > "$TO/eval_tuning_set_self_report.txt"
    python3 "$T/ait_holm.py" "$T" "$TO/eval_tuning_set_self.json" > "$TO/eval_tuning_set_self_holm.txt"
    record tuning-eval "$S_TUNE" "$TO"
}
step_tuning-norecon() {
    mkdir -p "$TO"; prep_work "$TW/norecon"
    log "tuning-norecon: 4 tuning scenarios without $NR, $S_TUNE seeds"
    CONTEXTSIEM_DROP_LABELS=$NR ait_eval "$TW/norecon" "$TO/eval_tuning_set_noscans_self.json" "$TO/eval_tuning_set_noscans_self.out" \
        --scenarios $TUNE --seeds "$S_TUNE"
    python3 "$T/ait_report.py" "$T" "$TO/eval_tuning_set_noscans_self.json" > "$TO/eval_tuning_set_noscans_self_report.txt"
    python3 "$T/ait_holm.py" "$T" "$TO/eval_tuning_set_noscans_self.json" > "$TO/eval_tuning_set_noscans_self_holm.txt"
    record tuning-norecon "$S_TUNE" "$TO"
}
tuning_caches() { prep_work "$TW"; need "$TW" "evalcache_*_clean_sid1.pkl" "run tuning-eval first (its caches are read by this step)"; }
step_tuning-weights() {
    tuning_caches; log "tuning-weights: forest caches, then the weight search"
    ( cd "$TW" && python3 "$T/ait_param_lab.py" "$T" "$P/host_roles.json" "$TO/param_lab_self.json" --seeds "$S_TUNE" --variants delta86400 ) \
        > "$TO/param_lab_self.out" 2>&1 || die "ait_param_lab.py failed, see $TO/param_lab_self.out"
    ( cd "$TW" && python3 "$T/ait_weight_lab.py" "$T" "$P/host_roles.json" "$TO/weight_lab_self.json" --seeds "$S_TUNE" ) \
        > "$TO/weight_lab_verdict_self.txt" 2>&1 || die "ait_weight_lab.py failed, see $TO/weight_lab_verdict_self.txt"
    record tuning-weights "$S_TUNE" "$TO"
}
step_tuning-rba() {
    tuning_caches; log "tuning-rba: B_RBA selection (writes reproduce/tuning/rba_config_self.json, never tools/rba_config.json)"
    ( cd "$TW" && python3 "$T/ait_rba_tune.py" "$T" "$TO/rba_config_self.json" "$TO/rba_tune_self.json" ) \
        > "$TO/rba_tune_report_self.txt" 2>&1 || die "ait_rba_tune.py failed, see $TO/rba_tune_report_self.txt"
    record tuning-rba - "$TO"
}
step_tuning-variety() {
    tuning_caches; log "tuning-variety: variety as a fifth term"
    ( cd "$TW" && python3 "$T/ait_weight_lab.py" "$T" "$P/host_roles.json" "$TO/weight_lab_variety_self.json" --seeds "$S_TUNE" --variety variety_1d_triangle ) \
        > "$TO/weight_lab_variety_verdict_self.txt" 2>&1 || die "ait_weight_lab.py --variety failed, see $TO/weight_lab_variety_verdict_self.txt"
    record tuning-variety "$S_TUNE" "$TO"
}
step_tuning-calib() {
    tuning_caches; log "tuning-calib: calibration guard for B2_pooled"
    ( cd "$TW" && python3 "$T/ait_calib_guard.py" "$T" $TUNE ) > "$TO/calib_guard_pooled_self.txt" 2>&1 \
        || die "ait_calib_guard.py failed, see $TO/calib_guard_pooled_self.txt"
    record tuning-calib - "$TO"
}
step_tuning-thresholds() {
    tuning_caches; log "tuning-thresholds: workstation load thresholds from the tuning set"
    ( cd "$TW" && python3 "$T/ait_thresholds.py" "$T" "$P/host_roles.json" "$TO/ws_thresholds_self.json" --seeds "$S_TUNE" ) \
        > "$TO/ws_thresholds_self.out" 2>&1 || die "ait_thresholds.py failed, see $TO/ws_thresholds_self.out"
    record tuning-thresholds "$S_TUNE" "$TO"
}
step_tuning-workstation() {
    mkdir -p "$TO"
    if [ ! -f "$WSC" ]; then log "tuning-workstation: skipped (private workstation corpus not present; saved outputs in provenance/workstation/)"; return 0; fi
    [ -f "$TO/ws_thresholds_self.json" ] || die "run tuning-thresholds first"
    prep_work "$TW"; log "tuning-workstation: false promotion and window-surprise check (5 seeds, as in the paper)"
    ( cd "$TW" && python3 "$T/ws_eval.py" "$T" "$WSC" "$TO/ws_thresholds_self.json" "$TO/ws_eval_self.json" --seeds 5 ) \
        > "$TO/ws_eval_self_log.txt" 2>&1 || die "ws_eval.py failed, see $TO/ws_eval_self_log.txt"
    ( cd "$TW" && python3 "$T/ws_qcheck.py" "$T" "$WSC" "$TO/ws_qcheck_self.json" --seeds 5 ) \
        > "$TO/ws_qcheck_self.out" 2>&1 || die "ws_qcheck.py failed, see $TO/ws_qcheck_self.out"
    record tuning-workstation 5 "$TO"
}
step_tuning-compare() {
    [ -d "$TO" ] || die "nothing to compare: run tuning steps first"
    log "tuning-compare: reproduce/tuning vs the saved tuning-set results"
    python3 "$T/compare_rerun.py" "$TO" "$P" "$PW" "$T/rba_config.json" | tee "$TO/COMPARISON.txt" || true
    echo "(README, 'Reading the comparisons', lists the expected non-identical items)"
}

# ---------------------------------------------------------------- test set (tools/ait_locked_run.sh, same arguments)
step_test-recorded() {
    mkdir -p "$XO"; prep_work "$XW"
    log "test-recorded: fox santos | wardbeck wilson, recorded baselines, $S_TEST seeds"
    ait_eval "$XW" "$XO/test_recorded_a.json" "$XO/test_recorded_a.out" --scenarios fox santos --seeds "$S_TEST" --allow-test --recorded
    ait_eval "$XW" "$XO/test_recorded_b.json" "$XO/test_recorded_b.out" --scenarios wardbeck wilson --seeds "$S_TEST" --allow-test --recorded
    record test-recorded "$S_TEST" "$XO"
}
step_test-cleaned() {
    mkdir -p "$XO"; prep_work "$XW"
    log "test-cleaned: santos, oracle-cleaned baseline, $S_TEST seeds"
    ait_eval "$XW" "$XO/test_santos_cleaned.json" "$XO/test_santos_cleaned.out" --scenarios santos --seeds "$S_TEST" --allow-test
    record test-cleaned "$S_TEST" "$XO"
}
step_test-norecon() {
    mkdir -p "$XO"; prep_work "$XW"
    log "test-norecon: the 4 test scenarios without $NR, $S_TEST seeds"
    CONTEXTSIEM_DROP_LABELS=$NR ait_eval "$XW" "$XO/test_norecon_a.json" "$XO/test_norecon_a.out" --scenarios fox santos --seeds "$S_TEST" --allow-test --recorded
    CONTEXTSIEM_DROP_LABELS=$NR ait_eval "$XW" "$XO/test_norecon_b.json" "$XO/test_norecon_b.out" --scenarios wardbeck wilson --seeds "$S_TEST" --allow-test --recorded
    record test-norecon "$S_TEST" "$XO"
}
step_test-format() {
    log "test-format: merge, reports, Holm, descriptive comparisons, result tables"
    bash "$T/ait_locked_format.sh" "$XO" "" >> "$LOG" 2>&1 || die "tools/ait_locked_format.sh failed (see $LOG)"
    record test-format - "$XO"
}
step_test-compare() {
    [ -d "$XO" ] || die "nothing to compare: run test steps first"
    log "test-compare: reproduce/test vs the locked run (provenance/ait/test)"
    python3 - "$XO" "$P/test" <<'PY' | tee "$XO/COMPARISON.txt"
import json, math, os, re, sys
mine, saved = sys.argv[1:3]
TIMING = re.compile(r"\(\d+s\)|scores \d+s|\d+s\):|seconds|^\[")
NUM = re.compile(r"-?\d+\.\d+|-?\d+")
rows = []

def text(name):
    a, b = os.path.join(mine, name), os.path.join(saved, name)
    if not os.path.exists(a):
        return rows.append((name, "MISSING", ["not produced: run the step that writes it"]))
    la = [" ".join(l.split()) for l in open(a) if not TIMING.search(l)]
    lb = [" ".join(l.split()) for l in open(b) if not TIMING.search(l)]
    if la == lb:
        return rows.append((name, "IDENTICAL", []))
    if len(la) == len(lb):     # same lines, numbers within one unit of the last printed digit?
        worst, diffs = 0.0, []
        for x, y in zip(la, lb):
            if x != y:
                nx, ny = NUM.findall(x), NUM.findall(y)
                if NUM.sub("#", x) != NUM.sub("#", y) or len(nx) != len(ny):
                    worst = math.inf
                for p, q in zip(nx, ny):
                    if p != q:
                        unit = 10 ** -max(len(p.partition(".")[2]), len(q.partition(".")[2]))
                        worst = max(worst, abs(float(p) - float(q)) / unit)
                diffs.append(f"saved: {y}\n          yours: {x}")
        return rows.append((name, "LAST DIGIT" if worst <= 1 else "DIFFERENT", diffs[:4]))
    rows.append((name, "DIFFERENT", [f"{len(la)} lines vs {len(lb)} saved"]))

def leaves(o, p=""):
    if isinstance(o, dict):
        for k, v in o.items():
            if k != "seconds":
                yield from leaves(v, f"{p}/{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaves(v, f"{p}[{i}]")
    else:
        yield p, o

def js(name):
    a, b = os.path.join(mine, name), os.path.join(saved, name)
    if not os.path.exists(a):
        return rows.append((name, "MISSING", ["not produced: run the step that writes it"]))
    A, B = dict(leaves(json.load(open(a)))), dict(leaves(json.load(open(b))))
    if A.keys() != B.keys():
        return rows.append((name, "DIFFERENT", [f"fields differ, e.g. {sorted(A.keys() ^ B.keys())[:3]} (a different --seeds?)"]))
    worst, diffs = 0.0, []
    for k in B:
        x, y = A[k], B[k]
        if x == y or (isinstance(x, float) and isinstance(y, float) and math.isnan(x) and math.isnan(y)):
            continue
        if isinstance(x, (int, float)) and isinstance(y, (int, float)) and not isinstance(x, bool):
            worst = max(worst, abs(x - y))
        else:
            worst = math.inf
        diffs.append(f"{k}: saved {y}, yours {x}")
    v = "IDENTICAL" if worst == 0 else ("IDENTICAL (float noise < 1e-12)" if worst < 1e-12 else "DIFFERENT")
    rows.append((name, v, [] if v.startswith("IDENTICAL") else [f"{len(diffs)} values differ, largest {worst:.3g}"] + diffs[:4]))

for f in ["test_recorded.json", "test_santos_cleaned.json", "test_norecon.json"]:
    js(f)
for f in ["test_recorded_report.txt", "test_recorded_holm.txt", "test_santos_cleaned_report.txt",
          "test_norecon_report.txt", "test_norecon_holm.txt", "test_descriptive.txt", "results_tables.tex"]:
    text(f)
print("Comparison of reproduce/test with the locked run (provenance/ait/test)")
print("IDENTICAL = every value equal; LAST DIGIT = within one unit of the last printed digit; DIFFERENT = look at it\n")
for n, v, d in rows:
    print(f"{n:34s} {v}")
    for x in d:
        print("          " + x)
ok = sum(v.startswith("IDENTICAL") or v == "LAST DIGIT" for _, v, _ in rows)
print(f"\n{ok} of {len(rows)} files identical or within the last digit")
PY
}

# ---------------------------------------------------------------- run
step_clean() { log "clean: removing $BASE"; rm -rf "$BASE"; }

log "reproduce.sh ${STEPS[*]} (commit $(commit), seeds: tuning $S_TUNE, test $S_TEST)"
START=$SECONDS
for s in "${STEPS[@]}"; do
    "step_$s"
    [ "$s" = clean ] && exit 0
done
log "done in $(( (SECONDS - START) / 60 )) min; outputs in $BASE"
