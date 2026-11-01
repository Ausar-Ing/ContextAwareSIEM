#!/usr/bin/env bash
# Rerun every tuning-set result on YOUR machine, in one command, and compare it with the saved files.
# Outputs: provenance/ait/rerun_self/*_self.*  plus COMPARISON_self.txt and RUN_RECORD_self.txt.
# Tuning scenarios only (harrison, russellmitchell, shaw, wheeler); never touches a test scenario.
#
# What it reruns (saved counterpart in brackets):
#   1  all systems, 5 seeds                    [provenance/ait/eval_tuning_set_ablations_1031_report.txt, _holm.txt]
#   2  no-reconnaissance condition             [provenance/ait/eval_tuning_set_noscans_report.txt, _holm.txt]
#   3  priority-weight search (286 weightings) [provenance/ait/weight_lab_verdict.txt]
#   4  B_RBA module and weight selection       [tools/rba_config.json, provenance/ait/rba_tune_report.txt]
#   5  variety as a fifth term (not adopted)   [provenance/ait/weight_lab_variety_verdict.txt]
#   6  calibration guard for B2_pooled         [provenance/ait/calib_guard_pooled.txt]
#   7  workstation load thresholds             [provenance/workstation/ws_thresholds.json]
#   8  workstation false promotion             [provenance/workstation/ws_eval.json]
#   9  window-surprise check (workstation)     [provenance/workstation/ws_qcheck.json]
# Steps 7-9 need data/workstation/baseline_frozen_20261017T2315.json; they are skipped if it is missing.
#
# usage: bash tools/rerun_tuning_self.sh [--seeds N] [--resume]
#   --seeds N   default 5; fewer only for a quick mechanics test
#   --resume    keep the outputs and caches of an interrupted run and skip steps 1-2 if they finished
# Caches go to $CSIEM_WORK (default ~/csiem_rerun), which is wiped at the start so nothing stale is reused.
set -euo pipefail
SEEDS=5; RESUME=0
while [ $# -gt 0 ]; do
    case "$1" in
        --seeds) SEEDS="${2:?--seeds needs a number}"; shift 2 ;;
        --resume) RESUME=1; shift ;;
        *) echo "unknown option $1"; exit 1 ;;
    esac
done
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"; cd "$ROOT"
D="$ROOT/data/ait_ads"; C="$D/alerts_csv"; T="$ROOT/tools"; P="$ROOT/provenance/ait"; PW="$ROOT/provenance/workstation"
WSC="$ROOT/data/workstation/baseline_frozen_20261017T2315.json"
OUT="$P/rerun_self"; WORK="${CSIEM_WORK:-$HOME/csiem_rerun}"
TUNE="harrison russellmitchell shaw wheeler"

env | grep -q '^CONTEXTSIEM_' && { echo "a CONTEXTSIEM_* variable is set; unset it first: $(env | grep '^CONTEXTSIEM_' | cut -d= -f1 | tr '\n' ' ')"; exit 1; }
python3 -c "import numpy, sklearn, scipy.stats" || { echo "numpy / scikit-learn / scipy missing: activate the environment (source ~/.venvs/csiem/bin/activate)"; exit 1; }
echo "9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9  $D/ait_ads.zip" | sha256sum -c --quiet -
echo "633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0  $D/labels.csv" | sha256sum -c --quiet -
[ -d "$C" ] || { echo "$C missing: unzip data/ait_ads/alerts_csv.zip -d data/ait_ads/alerts_csv"; exit 1; }
HAVE_WS=1; [ -f "$WSC" ] || { HAVE_WS=0; echo "workstation corpus not found: steps 7-9 will be skipped"; }

[ "$RESUME" = 1 ] || rm -rf "$OUT" "$WORK/main" "$WORK/norecon"
mkdir -p "$OUT" "$WORK/main" "$WORK/norecon"
LOG="$OUT/RUN_LOG_self.txt"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
START=$(date -Iseconds)
python3 -m pip freeze > "$OUT/pip_freeze_self.txt" 2>/dev/null || true
log "start: seeds $SEEDS, work dir $WORK, commit $(git rev-parse --short HEAD 2>/dev/null || echo none)$([ "$RESUME" = 1 ] && echo ', resumed')"

if [ "$RESUME" = 1 ] && [ -s "$OUT/eval_tuning_set_self.json" ] && [ -s "$OUT/eval_tuning_set_noscans_self.json" ] \
   && ls "$WORK/main"/evalcache_*_clean_sid1.pkl >/dev/null 2>&1; then
    log "1-2 already done: skipped (resume)"
else
# 1 and 2 (+9) in parallel: the main run in one directory, the workstation check then the no-recon run in another
log "1 all systems + 2 no-reconnaissance (+9 window-surprise check) -- the long part"
rm -f "$OUT/eval_tuning_set_self.json" "$OUT/eval_tuning_set_noscans_self.json"
( cd "$WORK/main" && python3 "$T/ait_eval.py" "$D/ait_ads.zip" "$D/labels.csv" "$C" "$T" "$P/host_roles.json" \
      "$OUT/eval_tuning_set_self.json" --scenarios $TUNE --seeds "$SEEDS" > "$OUT/eval_tuning_set_self.out" 2>&1 ) &
PA=$!
( if [ "$HAVE_WS" = 1 ]; then python3 "$T/ws_qcheck.py" "$T" "$WSC" "$OUT/ws_qcheck_self.json" --seeds 5 > "$OUT/ws_qcheck_self.out" 2>&1 \
      || echo "step 9 (ws_qcheck) failed, see ws_qcheck_self.out; continuing with step 2" | tee -a "$LOG"; fi
  cd "$WORK/norecon" && CONTEXTSIEM_DROP_LABELS=service_scan,dirb,wpscan python3 "$T/ait_eval.py" "$D/ait_ads.zip" "$D/labels.csv" "$C" "$T" \
      "$P/host_roles.json" "$OUT/eval_tuning_set_noscans_self.json" --scenarios $TUNE --seeds "$SEEDS" > "$OUT/eval_tuning_set_noscans_self.out" 2>&1 ) &
PB=$!
wait "$PA"; wait "$PB"
for n in eval_tuning_set eval_tuning_set_noscans; do
    python3 "$T/ait_report.py" "$T" "$OUT/${n}_self.json" > "$OUT/${n}_self_report.txt"
    python3 "$T/ait_holm.py" "$T" "$OUT/${n}_self.json" > "$OUT/${n}_self_holm.txt"
done
log "1-2 done"
fi

cd "$WORK/main"     # the remaining steps read the caches written by step 1
log "3 weight search (forest caches first)"
python3 "$T/ait_param_lab.py" "$T" "$P/host_roles.json" "$OUT/param_lab_self.json" --seeds "$SEEDS" --variants delta86400 > "$OUT/param_lab_self.out" 2>&1
python3 "$T/ait_weight_lab.py" "$T" "$P/host_roles.json" "$OUT/weight_lab_self.json" --seeds "$SEEDS" > "$OUT/weight_lab_verdict_self.txt" 2>&1
log "4 B_RBA selection"
python3 "$T/ait_rba_tune.py" "$T" "$OUT/rba_config_self.json" "$OUT/rba_tune_self.json" > "$OUT/rba_tune_report_self.txt" 2>&1
log "5 variety as a fifth term"
python3 "$T/ait_weight_lab.py" "$T" "$P/host_roles.json" "$OUT/weight_lab_variety_self.json" --seeds "$SEEDS" --variety variety_1d_triangle > "$OUT/weight_lab_variety_verdict_self.txt" 2>&1
log "6 calibration guard"
python3 "$T/ait_calib_guard.py" "$T" $TUNE > "$OUT/calib_guard_pooled_self.txt" 2>&1
if [ "$HAVE_WS" = 1 ]; then
    log "7 workstation thresholds"
    python3 "$T/ait_thresholds.py" "$T" "$P/host_roles.json" "$OUT/ws_thresholds_self.json" --seeds "$SEEDS" > "$OUT/ws_thresholds_self.out" 2>&1
    log "8 workstation false promotion"
    python3 "$T/ws_eval.py" "$T" "$WSC" "$OUT/ws_thresholds_self.json" "$OUT/ws_eval_self.json" --seeds 5 > "$OUT/ws_eval_self_log.txt" 2>&1
fi
cd "$ROOT"
log "comparing with the saved files"
python3 "$T/compare_rerun.py" "$OUT" "$P" "$PW" "$ROOT/tools/rba_config.json" | tee "$OUT/COMPARISON_self.txt"
{ echo "rerun on this machine: seeds $SEEDS"; echo "commit $(git rev-parse HEAD 2>/dev/null || echo none)"
  echo "started $START, finished $(date -Iseconds)"; python3 -c "import sys, numpy, sklearn, scipy; print('python', sys.version.split()[0], 'numpy', numpy.__version__, 'scikit-learn', sklearn.__version__, 'scipy', scipy.__version__)"
  echo "workstation steps: $([ "$HAVE_WS" = 1 ] && echo run || echo skipped)"; } > "$OUT/RUN_RECORD_self.txt"
log "done: $OUT (see COMPARISON_self.txt)"
