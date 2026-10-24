# Reproducing the AIT-ADS results in Deliverable 3

Every AIT-ADS number in `References/Deliverable3_ContextAwareSIEM.tex` is produced by a
script in `tools/` and saved in this folder. This file says which command produces which
table, from which data, in which environment. All commands run from the repository root.

## 1. Data (not in git: `data/` is gitignored by policy)

| File | Source | SHA-256 |
|---|---|---|
| `data/ait_ads/ait_ads.zip` | AIT Alert Data Set, Zenodo record 8263181 (`ait_ads.zip`) | `9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9` |
| `data/ait_ads/labels.csv` | same Zenodo record (`labels.csv`, attack-step time intervals) | `633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0` |
| `data/ait_ads/alerts_csv.zip` | GitHub `ait-aecid/alert-data-set`, commit `ce927dd`, `alerts_csv/alerts_csv.zip` (per-alert event labels) | `2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3` |

Unzip the labels once: `unzip data/ait_ads/alerts_csv.zip -d data/ait_ads/alerts_csv`
(gives `data/ait_ads/alerts_csv/<scenario>_alerts.txt`).

Shorthand used below:

    D=data/ait_ads; C=data/ait_ads/alerts_csv; T=tools; P=provenance/ait

## 2. Environment

The runs were made on Linux (2 CPU cores) with Python 3.11.15, numpy 2.4.4,
scikit-learn 1.8.0 and scipy 1.17.1 (`tools/requirements-ait.txt`). Every model is seeded
(`random_state` = seed), so a rerun with the same versions reproduces the saved numbers
exactly; this was checked for two of them (Sec. 5). Other scikit-learn versions may differ
in the last digits.

    python3 -m pip install -r tools/requirements-ait.txt

The scripts write caches (`cache_*.pkl`, `evalcache_*.pkl`) to the current directory; they
are safe to delete, and should be deleted before running a script from an older commit,
whose cache names are not keyed by the rule-identity switch below. Runtimes are for 2 cores; the large scenarios (harrison, wheeler) take
most of it.

## 3. Rule identity switch

Results produced before 2026-10-14 collapsed every Suricata alert into Wazuh rule 86601.
`window_builder.py` now uses the Suricata signature as the rule identity; set
`CONTEXTSIEM_SURICATA_ID=0` to reproduce the earlier results. Caches are keyed by the switch.

Per-host equal-share training (Sec. III-E) is the method from 2026-10-23 (`seq_scoring.STRATIFY`).
Results produced before that date used volume-weighted training; set `CONTEXTSIEM_STRATIFY=0`
to reproduce them. Tables IX and X and `tuning_objective.json` / `eval_tuning_set.json` were
regenerated with stratification on 2026-10-23 (earlier versions are in git history at `db4d5c2`).
`CONTEXTSIEM_CALIB` selects the calibration of S_seq: `shrink` (default from 2026-10-23, Sec. III-E: w * own held-out CDF + (1 - w) * pooled CDF, w = n/(n + n0), n0 = `CONTEXTSIEM_SHRINK_N0`, default 100), `own_pooled` (the earlier rule: own CDF with at least `MIN_HOST_CAL` = 500 held-out windows, else pooled) or `locscale` (tested and rejected). Tables IX and X, `tuning_objective.json` and `eval_tuning_set.json` were regenerated under `shrink` on 2026-10-23; the `own_pooled` versions are in git history at `54fffc8`, and `eval_tuning_set_cal100.json` / `diag_wheeler_cal100.txt` used `own_pooled`.
`CONTEXTSIEM_SEQ_ENTITIES` selects the entity types whose windows feed the sequence term: `host` (default from 2026-10-24) or `all` (host and source-address windows, every earlier result). `CONTEXTSIEM_GROUP_SCORE` selects the queue's group score: `pi` (default, the method) or `max` (the ablation arm B2_max). Tables IX and X, `tuning_objective.json` and `eval_tuning_set.json` were regenerated with host windows on 2026-10-24; the versions with both entity types are in git history at `64a0282`.

## 4. Table / claim → command → output

| D3 item | Command | Output in `provenance/ait/` | Time |
|---|---|---|---|
| Table V (AIT-ADS scenarios) | `python3 $T/ait_stats.py $D/ait_ads.zip $D/labels.csv $C $P/ait_stats.json fox harrison russellmitchell santos shaw wardbeck wheeler wilson` | `ait_stats.json` | ~10 min |
| "What reaches the layer" (Sec. IV-A) | `python3 $T/ait_analyses.py step-coverage $P/ait_stats.json $D/labels.csv $C` | printed | <1 min |
| Preliminary check table and contamination numbers (Sec. V) | `CONTEXTSIEM_SURICATA_ID=0 python3 $T/ait_smoke.py $D/ait_ads.zip $D/labels.csv $C $T <scenarios>`; add `CLEAN=1` for the oracle-cleaned baseline | `contamination_recorded.txt`, `contamination_oracle_cleaned.txt` | ~15 min |
| First window sweep (superseded, kept for the record) | `git show 0fd0d2a:tools/ait_sweep.py > /tmp/ait_sweep_v1.py`, then `CONTEXTSIEM_SURICATA_ID=0 python3 /tmp/ait_sweep_v1.py $D/ait_ads.zip $D/labels.csv $C $T out.json harrison wheeler russellmitchell shaw` (seed-averaged scores, calibration on training windows) | `window_sweep_v1_traincal.json` | ~60 min |
| Table VII (window sweep, Suricata collapsed) | `CONTEXTSIEM_SURICATA_ID=0 SEEDS=5 python3 $T/ait_sweep.py $D/ait_ads.zip $D/labels.csv $C $T $P/window_sweep.json harrison wheeler russellmitchell shaw`; rank columns: `python3 $T/ait_analyses.py sweep-ranks $P/window_sweep.json` | `window_sweep.json` | ~45 min |
| First group-score study (superseded) | `CONTEXTSIEM_SURICATA_ID=0 SAVE_DIR=scores CONFIGS=alert5,alert20,entry20d60 python3 $T/ait_sweep.py ... harrison wheeler russellmitchell shaw`, then `python3 $T/ait_queue.py scores alert5 alert20 entry20d60` | `queue_variants.json` | ~20 min |
| Host roles and S_exp (Sec. III-F) | `python3 $T/exposure.py build $C $P/host_roles.json` | `host_roles.json` | <1 min |
| Table IX (tuning under the protocol objective) | `SAVE_DIR=scores3 CONFIGS=alert5,alert20,entry20d60 python3 $T/ait_sweep.py $D/ait_ads.zip $D/labels.csv $C $T s2.json harrison wheeler russellmitchell shaw`, then `python3 $T/ait_tune.py scores3 $P/host_roles.json $T tune.json` | `tuning_objective.json` (Part A in full, Part B top 20 plus the named configurations) | ~25 min + 2 min |
| Table X (all systems, tuning set, including within-host AUC from 2026-10-24) and the paired tests | `python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json ev.json --scenarios harrison russellmitchell wheeler shaw --seeds 5`, then `python3 $T/ait_report.py $T ev.json` | `eval_tuning_set.json`, `eval_tuning_set_report.txt` | ~15 min |
| Per-host stratification and calibration-fallback check (2026-10-23) | `python3 $T/ait_eval.py ... --scenarios <tuning> --seeds 1` once to create `evalcache_*` files, then `python3 $T/ait_strat.py $P/host_roles.json $T strat.json harrison russellmitchell wheeler shaw` | `stratification_check.json`, `stratification_check_report.txt` | ~25 min |
| Host-rarity ranking (2026-10-23) | `python3 $T/ait_analyses.py host-rarity $T harrison russellmitchell wheeler shaw` (same caches) | in `stratification_check_report.txt` | <1 min |
| Calibration threshold 100 instead of 500 (sensitivity, 2026-10-23) | `CONTEXTSIEM_CALIB=own_pooled CONTEXTSIEM_MIN_HOST_CAL=100 python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json ev100.json --scenarios harrison russellmitchell wheeler shaw --seeds 5`, then `python3 $T/ait_report.py $T ev100.json` | `eval_tuning_set_cal100.json`, `eval_tuning_set_cal100_report.txt` | ~15 min |
| Calibration modes for hosts with small baselines (2026-10-23, tuning set; default unchanged) | `CONTEXTSIEM_CALIB=locscale python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json ev_locscale.json --scenarios harrison russellmitchell wheeler shaw --seeds 5`, the same with `CONTEXTSIEM_CALIB=shrink`, and `CONTEXTSIEM_CALIB=own_pooled ... --seeds 1` for the default's per-host check; then `python3 $T/ait_report.py $T <file>` | `eval_tuning_set_calib_locscale.json`, `eval_tuning_set_calib_shrink.json`, `eval_tuning_set_calib_ownpooled_seed0.json` and their `_report.txt` | ~15 min each |
| Shrinkage constant n0 = 30 and 300 instead of 100 (robustness, 2026-10-23) | `CONTEXTSIEM_SHRINK_N0=30 python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json ev.json --scenarios harrison russellmitchell wheeler shaw --seeds 5`, the same with 300; then `python3 $T/ait_report.py $T ev.json` | `eval_tuning_set_shrink_n030.json`, `eval_tuning_set_shrink_n0300.json` and their `_report.txt` | ~15 min each |
| Wheeler privilege escalation under own-host calibration (diagnosis, 2026-10-23) | in the directory holding the `evalcache_*` files: `CONTEXTSIEM_CALIB=own_pooled python3 $T/ait_diag_wheeler.py $P/host_roles.json $T wheeler 100` | `diag_wheeler_cal100.txt` | ~3 min |
| Temporal-score diagnosis: who outranks the attack (2026-10-24) | `DUMP_DIR=dump python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json ev.json --scenarios harrison russellmitchell wheeler shaw --seeds 5` (the dump does not change any result), then `python3 $T/ait_blockers.py dump $T 100` | `diag_blockers_report.txt` | ~15 min |
| Within-host separation (attack vs benign alerts on the same host; host rarity is 0.5 there by construction) | `python3 $T/ait_withinhost.py dump $T` (same dump) | `diag_withinhost_report.txt` | <1 min |
| Calibration variants offline (shrink, pooled, tail, episode, host-only, source-only) | in the directory holding the `evalcache_*` files: `python3 $T/ait_calib_lab.py $T lab.json --seeds 5`; variant `shrink` reproduces Table X's B2 | `diag_calib_lab.json`, `diag_calib_lab_report.txt` | ~8 min |
| Sequence term from host windows only (2026-10-24, tuning set; adopted the same day, so `eval_tuning_set.json` now holds this configuration plus the B2_max arm) | `CONTEXTSIEM_SEQ_ENTITIES=host python3 $T/ait_eval.py $D/ait_ads.zip $D/labels.csv $C $T $P/host_roles.json ev.json --scenarios harrison russellmitchell wheeler shaw --seeds 5`, then `python3 $T/ait_report.py $T ev.json` | `eval_tuning_set_host_only.json`, `eval_tuning_set_host_only_report.txt` | ~15 min |
| Test 2: benign windows that cap the attack on wheeler's intranet server, feature attribution | in the directory holding the `evalcache_*` files: `python3 $T/ait_diag_burst.py $P/host_roles.json $T wheeler 5` | `diag_burst_wheeler.txt` | ~3 min |
| First-item veto of the tuning protocol (Sec. IV-C, 2026-10-24) | `python3 $T/ait_veto.py scores3 $T entry20d60:pi` on the `SAVE_DIR` of the Table IX sweep | `tuning_veto_report.txt` | ~2 min |
| Calibration on training vs held-out windows (Sec. III-E) | `python3 $T/ait_analyses.py calib-synthetic` | printed | ~3 min |

The test scenarios (fox, santos, wardbeck, wilson) appear only in Table V and the
preliminary check. `ait_eval.py` refuses them unless `--allow-test` is given; the protocol
is run on them once, after every choice is fixed.

## 5. Checks performed

- `CONTEXTSIEM_SURICATA_ID=0 SEEDS=5 ait_sweep.py ... shaw` (alert20, entry20d60)
  reproduced the per-seed AUCs and first-item ranks in `window_sweep.json` exactly.
- `CONTEXTSIEM_SURICATA_ID=0 ait_smoke.py ... harrison` reproduced the harrison block of
  `contamination_recorded.txt` exactly.
- `ait_analyses.py sweep-ranks` reproduces the rank columns of Table VII and the
  "1.0 / 2.0 / 4.2 non-scan stages in the top ten" figures; `step-coverage` reproduces the
  attack-step counts; `calib-synthetic` reproduces 5.19 % vs 5.06 %.
- Unit tests: `for t in test_parse_wazuh test_entries test_eval_metrics test_accumulator test_active_time; do python3 $T/$t.py; done`
