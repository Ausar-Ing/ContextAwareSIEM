#!/usr/bin/env python3
"""Calibration variants for S_seq, evaluated offline on the tuning scenarios.

The forests are fitted once per scenario and seed exactly as in ait_eval.py (entry
windows N=20, delta=60 s, per-host equal-share training, stride 10) and their raw
scores cached; each variant only changes how raw scores become S_seq, so B2's queue,
alpha-nDCG@20, the non-scan first-item ranks and the per-host calibration check
(benign evaluation host windows above 99, which uses no attack labels) are
recomputed in seconds. Variant `shrink` must reproduce ait_eval.py's B2.

Variants
  shrink        current method: w*F_own + (1-w)*F_pool, w = n/(n+100)
  tail          shrink, but each empirical CDF continues above its upper tail with an
                exponential (GPD shape 0) fitted to the top TAIL_FRAC of that sample,
                so windows beyond everything in the baseline are ordered by how far
                beyond they are instead of tying at 100
  episode       shrink with held-out windows weighted 1/(size of their episode),
                episode = the host's held-out windows separated by less than EPISODE_S,
                so one burst of overlapping windows counts once
  tail+episode  both
  host_only     shrink, sequence term from host windows only (diagnostic)
  srcip_only    shrink, sequence term from source-address windows only (diagnostic)
  pooled        no per-host term (w = 0): S_seq is the percentile among all hosts' held-out windows
                of the entity type, i.e. the raw score's order within the type (diagnostic)
  a+b           combinations, e.g. pooled+host_only
Ranking: groups by pi(g) = -log10(1 - u_max^k) with u clipped at 1 - U_EPS; U_EPS is
1e-5 for shrink (as in ait_eval.py) and 1e-12 for the tail variants, whose point is to
resolve the region above the old clip. Ordering by pi equals ordering by the capped
sequence term whenever pi < lambda = 8.

usage: ait_calib_lab.py <wb_dir> <out.json> [--seeds 5] [--variants v1,v2,...] [scenario ...]
"""
import sys, os, json, pickle, collections, argparse, time
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("out")
ap.add_argument("--seeds", type=int, default=5)
ap.add_argument("--variants", default="shrink,pooled,tail,episode,tail+episode,host_only,srcip_only,pooled+host_only")
ap.add_argument("scenarios", nargs="*")
args = ap.parse_args()
scs = args.scenarios or ["harrison", "russellmitchell", "shaw", "wheeler"]
assert not {"fox", "santos", "wardbeck", "wilson"} & set(scs), "tuning scenarios only"
sys.path.insert(0, args.wb)
import window_builder as W
import seq_scoring as C6
import eval_metrics as M

N0 = C6.SHRINK_N0
TAIL_FRAC = float(os.environ.get("LAB_TAIL_FRAC", 0.1))
EPISODE_S = float(os.environ.get("LAB_EPISODE_S", 3600))
DELTA_Q = 3600.0
host_of = lambda a: next(v for t, v in a.entities if t == "host")


def build(sc):
    cache = f"labrows_{sc}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    A, labels, t_atk = pickle.load(open(f"evalcache_{sc}_clean_sid1.pkl", "rb"))
    wb = W.WindowBuilder(N=20, learn_rules=True, downtime_gap_s=None, site_utc_offset_h=0.0, collapse_s=60.0)
    rows = collections.defaultdict(lambda: {"j": [], "F": [], "ok": []})
    for j, a in enumerate(A):
        if a.ts >= t_atk and wb.learn_rules:
            wb.learn_rules = False
        for e, f, ok in wb.push(a):
            d = rows[e[0]]; d["j"].append(j); d["F"].append(f); d["ok"].append(ok)
    rows = {k: {"j": np.array(v["j"]), "F": np.array(v["F"]), "ok": np.array(v["ok"])} for k, v in rows.items()}
    ts = np.array([a.ts for a in A]); hosts = np.array([host_of(a) for a in A], dtype=object)
    roles = np.array([a.agent_ip for a in A], dtype=object)
    ev = np.array([j for j, a in enumerate(A) if a.ts >= t_atk and a.admissible])
    L = np.array([labels[j] for j in ev], dtype=object)
    gid, last, cur, nxt = [], {}, {}, 0
    for j in ev:
        key = (hosts[j], A[j].rule_id)
        if key not in last or ts[j] - last[key] > DELTA_Q:
            cur[key] = nxt; nxt += 1
        last[key] = ts[j]; gid.append(cur[key])
    out = dict(rows=rows, ts=ts, hosts=hosts, ip=roles, labels=np.array(labels, dtype=object), t_atk=t_atk,
               ev=ev, L=L, gid=np.array(gid), G=nxt)
    pickle.dump(out, open(cache, "wb"))
    return out


def fit(sc, D, seed):
    """raw scores of every window and the held-out calibration samples, per entity type"""
    cache = f"labfit_{sc}_s{seed}.pkl"
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    res = {}
    for et, d in D["rows"].items():
        tsw = D["ts"][d["j"]]; hw = D["hosts"][d["j"]]
        base = d["ok"] & (tsw < D["t_atk"])
        if base.sum() == 0:
            continue
        m = C6.TypeModel(seed)
        if not m.fit(d["F"][base], list(hw[base]), True):
            continue
        raw = np.full(len(d["j"]), np.nan)
        raw[d["ok"]] = m._raw_scores(d["F"][d["ok"]], True)
        bi = np.flatnonzero(base)
        held = bi[~m._train_mask(len(bi), hw[bi])]
        res[et] = dict(raw=raw, held=held)
    pickle.dump(res, open(cache, "wb"))
    return res


class Ref:
    """weighted empirical CDF with an optional exponential upper tail"""
    def __init__(self, v, wts=None, tail=False):
        o = np.argsort(v); self.v = v[o]
        w = np.ones(len(v)) if wts is None else wts[o]
        self.cw = np.cumsum(w) / w.sum()
        self.tail = tail and len(v) >= 10
        if self.tail:
            m = max(3, int(np.ceil(TAIL_FRAC * len(v))))
            self.t = self.v[-m]; ex = self.v[-m:] - self.t
            self.beta = max(ex.mean(), 1e-6)
            self.pt = 1 - self.cw[-m - 1] if m < len(v) else 1.0      # mass above the threshold
    def surv(self, x):
        """P(X > x)"""
        i = np.searchsorted(self.v, x, side="right")
        s = np.where(i > 0, 1 - self.cw[np.maximum(i - 1, 0)], 1.0)
        if self.tail:
            hi = x >= self.t
            s = np.where(hi, self.pt * np.exp(-(x - self.t) / self.beta), s)
        return s


def episode_weights(tsw):
    o = np.argsort(tsw); t = tsw[o]
    ep = np.concatenate([[0], np.cumsum(np.diff(t) >= EPISODE_S)])
    size = np.bincount(ep)
    w = np.empty(len(t)); w[o] = 1.0 / size[ep]
    return w


def calibrate(D, fr, et, variant):
    """surv-of-window (1 - u) for every window of type et under the variant; nan where unscored"""
    d = D["rows"][et]; f = fr[et]; raw = f["raw"]
    hw = D["hosts"][d["j"]]; tsw = D["ts"][d["j"]]
    held = f["held"]
    tail = "tail" in variant; epi = "episode" in variant
    hh = hw[held]
    wts = np.ones(len(held))
    if epi:
        for h in set(hh):
            m = hh == h
            wts[m] = episode_weights(tsw[held][m])
    pool = Ref(raw[held], wts if epi else None, tail)
    s = np.full(len(raw), np.nan)
    ok = ~np.isnan(raw)
    for h in set(hw[ok]):
        m = ok & (hw == h)
        mh = hh == h; n = int(mh.sum())
        sp = pool.surv(raw[m])
        if n:
            own = Ref(raw[held][mh], wts[mh] if epi else None, tail).surv(raw[m])
            w = 0.0 if "pooled" in variant else n / (n + N0)
            s[m] = w * own + (1 - w) * sp
        else:
            s[m] = sp
    return s


def run_variant(D, fr, variant):
    n = len(D["ts"]); ev = D["ev"]; gid = D["gid"]; G = D["G"]
    surv_alert = np.full(n, np.inf)                  # min survival = max S over entity types
    types = ["host"] if "host_only" in variant else ["srcip"] if "srcip_only" in variant else list(fr)
    cal = variant.replace("host_only", "").replace("srcip_only", "").strip("+") or "shrink"
    sv_host = None
    for et in types:
        if et not in fr:
            continue
        s = calibrate(D, fr, et, cal)
        if et == "host":
            sv_host = s
        ok = ~np.isnan(s)
        np.minimum.at(surv_alert, D["rows"][et]["j"][ok], s[ok])
    sa = surv_alert[ev]
    sa = np.where(np.isinf(sa), 0.5, sa)             # cold start: baseline median
    eps = 1e-12 if "tail" in variant else 1e-5
    if "tail" not in variant:
        # reproduce ait_eval.py exactly: S rounded through the percent scale, u = S/100
        sa = 1 - (100 * (1 - sa)) / 100
    gs = np.full(G, np.inf); np.minimum.at(gs, gid, sa)
    k = np.bincount(gid, minlength=G).astype(float)
    u = np.clip(1 - gs, 1e-12, 1 - eps)
    pi = -np.log10(np.maximum(-np.expm1(k * np.log(u)), 1e-300))
    stages = M.item_stages(gid, D["L"], G)
    f = M.first_item_ranks(pi, stages)
    out = {"andcg20": M.alpha_ndcg(pi, stages, 20), "andcg10": M.alpha_ndcg(pi, stages, 10),
           "mrr": M.mrr_nonscan(f), "first": {s_: float(v) for s_, v in f.items()}}
    # calibration check on benign evaluation-period host windows (no attack labels used)
    if sv_host is None and "host" in fr:
        sv_host = calibrate(D, fr, "host", cal)
    if sv_host is not None:
        d = D["rows"]["host"]; tsw = D["ts"][d["j"]]
        lab = D["labels"][d["j"]]
        m = (~np.isnan(sv_host)) & (tsw >= D["t_atk"]) & np.isin(lab, list(M.BENIGN))
        chk = {}
        for h in set(D["hosts"][d["j"]][m]):
            mh = m & (D["hosts"][d["j"]] == h)
            chk[h] = [float(np.mean(sv_host[mh] < 0.01)), int(mh.sum())]
        out["calib"] = chk
    return out


OUT = {}
variants = args.variants.split(",")
for sc in scs:
    t0 = time.time()
    D = build(sc)
    for seed in range(args.seeds):
        fr = fit(sc, D, seed)
        for v in variants:
            OUT.setdefault(sc, {}).setdefault(v, []).append(run_variant(D, fr, v))
    print(f"{sc}: {time.time() - t0:.0f}s", flush=True)
json.dump(OUT, open(args.out, "w"), indent=1)

roles = json.load(open("host_roles.json"))
print(f"\n{'variant':14s} " + " ".join(f"{s[:9]:>9s}" for s in scs) + "   mean@20   @10    MRR")
for v in variants:
    per = [np.mean([r["andcg20"] for r in OUT[sc][v]]) for sc in scs]
    a10 = np.mean([np.mean([r["andcg10"] for r in OUT[sc][v]]) for sc in scs])
    mrr = np.mean([np.mean([r["mrr"] for r in OUT[sc][v]]) for sc in scs])
    print(f"{v:14s} " + " ".join(f"{x:9.3f}" for x in per) + f"   {np.mean(per):.3f}   {a10:.3f}  {mrr:.3f}")
print("\nnon-scan first-item ranks (mean over seeds)")
for sc in scs:
    sts = [s for s in OUT[sc][variants[0]][0]["first"]]
    for st in sts:
        print(f"  {sc:15s} {st:24s} " + " ".join(f"{v}={np.mean([r['first'][st] for r in OUT[sc][v]]):6.1f}" for v in variants))
print("\ncalibration check, seed 0: benign evaluation host windows above 99 per host (n windows); quiet hosts marked *")
for sc in scs:
    D = build(sc)
    ipof = {h: ip for h, ip in zip(D["hosts"], D["ip"])}
    for v in variants:
        c = OUT[sc][v][0].get("calib", {})
        items = sorted(c.items(), key=lambda kv: -kv[1][0])
        print(f"  {sc:15s} {v:13s} " + ", ".join(
            f"{roles[sc][ipof[h]]['role']}{'*' if roles[sc][ipof[h]]['role'] in ('intranet_server','internal_share','cloud_share') else ''} "
            f"{100*x[0]:.0f}%({x[1]})" for h, x in items[:7]))
