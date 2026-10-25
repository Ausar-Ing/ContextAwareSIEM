#!/usr/bin/env python3
"""Near-empty ("young") window variants of Component 6 on the tuning scenarios
(follows test 2: wheeler's capping windows are anomalous mainly for holding few
entries). Host windows only, shrinkage calibration, pi group score, as the method.

Variants (forests refitted for each; per scenario and seed):
  base        the method (must reproduce Table X's B2)
  noent       model input without window_entries
  noent_dur   model input without window_entries and window_duration_s
  fill5       windows with fewer than 5 entries are unscored (baseline median 50,
              "no temporal evidence"), and are left out of training and calibration
  fill10      the same with 10 entries
  noent_fill5 noent and fill5 together
  novwXX      the method's forest, with an explicit novelty term in the group priority:
              (1 - w) * 100 min(1, pi/8) + w * 100 * [a member's host window flags its rule
              as novel], w = XX/100 (tests whether the novelty flag, which separates attack
              from benign alerts within a host better than S_seq, adds to the ranking)

Per variant: alpha-nDCG@20, MRR, first-item ranks of non-scan stages (for the
protocol's tie rule and first-item veto against `base`), the within-host AUC, and
the calibration check (benign evaluation host windows above 99, per host).

usage: ait_feature_lab.py <wb_dir> <out.json> [--seeds 5] [--variants a,b] [scenario ...]
"""
import sys, os, json, pickle, collections, argparse, time
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("out")
ap.add_argument("--seeds", type=int, default=5)
ap.add_argument("--variants", default="base,noent,noent_dur,fill5,fill10,noent_fill5")
ap.add_argument("scenarios", nargs="*")
args = ap.parse_args()
scs = args.scenarios or ["harrison", "russellmitchell", "shaw", "wheeler"]
assert not {"fox", "santos", "wardbeck", "wilson"} & set(scs), "tuning scenarios only"
sys.path.insert(0, args.wb)
import window_builder as W
import seq_scoring as C6
import eval_metrics as M

ENT = W.ENTRY_FEATURE_NAMES.index("window_entries")
DUR = W.ENTRY_FEATURE_NAMES.index("window_duration_s")
U_MAX = 1 - 1e-5


def build(sc):
    """same rows and queue groups as ait_eval.py (cached by ait_calib_lab.py)"""
    cache = f"labrows_{sc}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    sys.exit(f"run ait_calib_lab.py first to create {cache}")


NOV = W.ENTRY_FEATURE_NAMES.index("novel_rule_flag")
_FIT = {}


def make_model(variant, seed):
    if variant.startswith("novw"):
        variant = "base"
    drop = {"noent": [ENT], "noent_dur": [ENT, DUR], "noent_fill5": [ENT]}.get(variant, [])
    # prep() deletes night_fraction (the last feature), so model-input positions of
    # window_entries and window_duration_s equal their feature positions
    class Model(C6.TypeModel):
        def prep(self, F, entries):
            X = C6.TypeModel.prep(F, entries)
            return np.delete(X, drop, axis=1) if drop else X
    return Model(seed)


def min_fill(variant):
    if variant.startswith("novw"):
        return 0
    return {"fill5": 5, "fill10": 10, "noent_fill5": 5}.get(variant, 0)


def surprise(u, n):
    u = np.clip(u, 1e-12, U_MAX)
    return -np.log10(np.maximum(-np.expm1(n * np.log(u)), 1e-300))


def run(D, variant, seed):
    d = D["rows"]["host"]
    tsw = D["ts"][d["j"]]; hw = D["hosts"][d["j"]]
    ok = d["ok"].copy()
    mf = min_fill(variant)
    if mf:
        ok &= d["F"][:, ENT] >= mf
    base = ok & (tsw < D["t_atk"])
    key = (id(D), seed) if (variant == "base" or variant.startswith("novw")) else None
    if key is not None and key in _FIT:
        S = _FIT[key]
    else:
        m = make_model(variant, seed)
        S = np.full(len(d["j"]), -1.0)
        if m.fit(d["F"][base], list(hw[base]), True):
            S[ok] = m.score(d["F"][ok], list(hw[ok]), True)
        if key is not None:
            _FIT[key] = S
    n = len(D["ts"]); ev = D["ev"]; gid = D["gid"]; G = D["G"]
    sa = np.full(n, -1.0); np.maximum.at(sa, d["j"], S)
    se = sa[ev]
    s = np.where(se < 0, 50.0, se)
    gm = np.full(G, -np.inf); np.maximum.at(gm, gid, s)
    k = np.bincount(gid, minlength=G).astype(float)
    pi = surprise(gm / 100, k)
    if variant.startswith("novw"):
        w = int(variant[4:]) / 100
        nv = np.zeros(n); np.maximum.at(nv, d["j"], np.where(d["ok"], d["F"][:, NOV], 0.0))
        gn = np.zeros(G); np.maximum.at(gn, gid, nv[ev])
        pi = (1 - w) * 100 * np.minimum(1, pi / 8) + w * 100 * gn
    stages = M.item_stages(gid, D["L"], G)
    f = M.first_item_ranks(pi, stages)
    hosts_ev = D["hosts"][ev]
    w = M.within_host_auc(se, D["L"], hosts_ev)
    lab = D["labels"][d["j"]]
    chk = {}
    mb = (S >= 0) & (tsw >= D["t_atk"]) & np.isin(lab, list(M.BENIGN))
    for h in set(hw[mb]):
        mh = mb & (hw == h)
        chk[str(h)] = [float(np.mean(S[mh] > 99)), int(mh.sum())]
    return {"andcg20": M.alpha_ndcg(pi, stages, 20), "andcg10": M.alpha_ndcg(pi, stages, 10),
            "mrr": M.mrr_nonscan(f), "first": {s_: float(v) for s_, v in f.items()},
            "within": w["macro"], "within_hosts": {str(h): v for h, v in w["hosts"].items()}, "calib": chk,
            "unscored_eval_share": float(np.mean(se < 0))}


OUT = json.load(open(args.out)) if os.path.exists(args.out) else {}
for sc in scs:
    D = build(sc)
    for v in args.variants.split(","):
        if v in OUT.get(sc, {}) and len(OUT[sc][v]) >= args.seeds:
            continue
        t0 = time.time()
        OUT.setdefault(sc, {})[v] = [run(D, v, seed) for seed in range(args.seeds)]
        print(f"{sc} {v}: aNDCG@20 {np.mean([r['andcg20'] for r in OUT[sc][v]]):.3f} "
              f"MRR {np.mean([r['mrr'] for r in OUT[sc][v]]):.3f} within {np.nanmean([r['within'] for r in OUT[sc][v]]):.3f} "
              f"({time.time() - t0:.0f}s)", flush=True)
        json.dump(OUT, open(args.out, "w"), indent=1)
