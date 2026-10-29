"""Risk-based alerting comparator (B_RBA), after Uetz et al., "Can Risk-Based Alerting Mitigate
Cybersecurity Alert Fatigue?" (arXiv:2609.02465, 2026) and their CATS implementation
(github.com/962012d09b/cats, commit 628cf48, backend/modules). Five modules, each scoring an
alert in [0, 1]:

  level         rule level / 15 (CATS level_score.py, Wazuh branch)
  accumulation  alerts of the same host in the window: 1 - 0.5^(c / (1 + E)), box or triangle
  variety       distinct rule types of the same host in the window (closest occurrence of each type)
  rarity        alerts of the same rule type in the window: (N - 1) / (c + N - 2), N = 1 + E
  aperiodicity  spectral flatness of the same rule type's alert times in the window (1 s bins),
                blended towards 1 for few events (small_n = 5), normalized so the mean is 0.5

centred=True reproduces CATS's "Past + Future" windows (half the window on each side of the alert,
distances relative to the half-window) for the fidelity check against the published numbers only
(tools/rba_fidelity.py); it uses future alerts and is never used by the evaluation.

Two deliberate departures from CATS, both to make the comparator causal like every other
system here: (1) windows are trailing only ("Past"); CATS's better-performing centered windows
use future alerts. (2) Every normalizer that CATS estimates from the whole file (expected counts
per group, alert-type frequencies, the aperiodicity normalization exponent) is estimated from
the pre-attack period only. Grouping follows the CATS defaults: hostname for accumulation and
variety, alert type for rarity and aperiodicity. Pipeline: weighted arithmetic mean of the module
scores (the CATS default). Queue groups take the maximum of their members' scores, as B0 does.
"""
import math, collections
import numpy as np

WINDOWS = {"1m": 60.0, "1h": 3600.0, "1d": 86400.0}
SHAPES = ("box", "triangle")
SMALL_N = 5
APER_CAP = 3000
EULER = 0.5772156649015329


def _p_at_least_one(rel_w, n):
    return 1.0 - math.exp(-rel_w * n)


def _cond_exp(rel_w, n):
    lam, w = n, rel_w
    if w * lam < 1 / (2 * 365 * 24 * 60):
        return 0.5 * w
    p = _p_at_least_one(w, lam)
    return (1 - math.exp(-lam * w) * (1 + lam * w)) / (lam * p)


def _exp_rel_distance(rel_w, counts):
    num = sum(_p_at_least_one(rel_w, n) * _cond_exp(rel_w, n) for n in counts)
    den = sum(_p_at_least_one(rel_w, n) for n in counts)
    return 0.0 if den == 0 else num / den / rel_w


def aperiodicity_score(times, small_n=SMALL_N):
    """CATS src/aperiodicity.py, 1 s bins"""
    n = len(times)
    if n <= 2:
        return 1.0
    off = np.asarray(times, float) - times[0]
    span = off[-1]
    if span <= 1.0:
        return 1.0
    nb = int(math.ceil(span))
    idx = np.minimum(off.astype(np.int64), nb - 1)
    c = np.bincount(idx, minlength=nb).astype(float)
    c -= c.mean()
    p = np.abs(np.fft.rfft(c)) ** 2
    p = p[1:]
    if len(p) == 0 or p.mean() <= 0:
        return 1.0
    sf = math.exp(np.mean(np.log(np.maximum(p, np.finfo(float).tiny)))) / p.mean()
    sf = float(np.clip(sf / math.exp(-EULER), 0.0, 1.0))
    conf = 1.0 - math.exp(-n / small_n)
    return sf * conf + (1.0 - conf)


def module_scores(ts, host, rule, lvl, t_atk, score_idx, variants=None, aper_base_sample=2000, rng_seed=0,
                  centred=False):
    """Per-alert scores of every module variant for the alerts at positions `score_idx`.
    ts, host, rule, lvl: arrays over all admitted alerts in time order (baseline and evaluation).
    Returns {variant_name: scores aligned with score_idx}."""
    ts = np.asarray(ts, float); n = len(ts)
    base = ts < t_atk
    T = max(ts[base].max() - ts[base].min(), 1.0) if base.any() else 1.0
    nbase = int(base.sum())
    hosts_b = set(np.asarray(host, dtype=object)[base]); rules_b = collections.Counter(np.asarray(rule, dtype=object)[base])
    n_hosts = max(1, len(hosts_b)); n_rules = max(1, len(rules_b))
    type_counts_per_host = {r: c / n_hosts for r, c in rules_b.items()}
    out = {}
    out["level"] = np.asarray(lvl, float)[score_idx] / 15.0
    want = set(variants) if variants else None

    def need(name):
        return want is None or name in want

    # positions of each alert within its host group and its rule group (time order)
    by_host = collections.defaultdict(list); by_rule = collections.defaultdict(list)
    for j in range(n):
        by_host[host[j]].append(j); by_rule[rule[j]].append(j)
    pos_h = np.empty(n, int); pos_r = np.empty(n, int)
    for g in by_host.values():
        for i, j in enumerate(g): pos_h[j] = i
    for g in by_rule.values():
        for i, j in enumerate(g): pos_r[j] = i
    ts_h = {h: ts[g] for h, g in by_host.items()}; cs_h = {h: np.concatenate([[0.0], np.cumsum(ts[g])]) for h, g in by_host.items()}
    ts_r = {r: ts[g] for r, g in by_rule.items()}; cs_r = {r: np.concatenate([[0.0], np.cumsum(ts[g])]) for r, g in by_rule.items()}

    def window_counts(tsg, csg, i, W):
        t = tsg[i]
        if not centred:
            lo = int(np.searchsorted(tsg, t - W, "left"))
            c = i - lo + 1
            tri = c - (c * t - (csg[i + 1] - csg[lo])) / W
            return c, tri
        hw = W / 2
        lo = int(np.searchsorted(tsg, t - hw, "left")); hi = int(np.searchsorted(tsg, t + hw, "right"))
        cl, cr = i - lo + 1, hi - i - 1
        dist = (cl * t - (csg[i + 1] - csg[lo])) + ((csg[hi] - csg[i + 1]) - cr * t)
        return cl + cr, (cl + cr) - dist / hw

    for wn, W in WINDOWS.items():
        exp_h = (W / T) * nbase / n_hosts            # expected additional alerts per host in the window
        exp_r = (W / T) * nbase / n_rules            # expected additional alerts per rule type in the window
        acc_b, acc_t, rar_b, rar_t = (np.empty(len(score_idx)) for _ in range(4))
        for k, j in enumerate(score_idx):
            c, tri = window_counts(ts_h[host[j]], cs_h[host[j]], pos_h[j], W)
            acc_b[k] = 1 - 0.5 ** (c / (1 + exp_h))
            acc_t[k] = 1 - 0.5 ** (tri / (1 + 0.5 * exp_h))
            c, tri = window_counts(ts_r[rule[j]], cs_r[rule[j]], pos_r[j], W)
            Nb = 1 + exp_r; Nt = 1 + 0.5 * exp_r
            rar_b[k] = 1.0 if Nb == 1 else (Nb - 1) / (c + Nb - 2)
            rar_t[k] = 1.0 if Nt == 1 else (Nt - 1) / (tri + Nt - 2)
        for name, v in ((f"accumulation_{wn}_box", acc_b), (f"accumulation_{wn}_triangle", acc_t),
                        (f"rarity_{wn}_box", rar_b), (f"rarity_{wn}_triangle", rar_t)):
            if need(name):
                out[name] = np.clip(v, 0, 1)
        # variety: distinct rule types of the host in the trailing window, closest occurrence of each
        if need(f"variety_{wn}_box") or need(f"variety_{wn}_triangle"):
            rel = W / T
            erd = _exp_rel_distance(rel, list(type_counts_per_host.values()))
            pall = {r: _p_at_least_one(rel, c) for r, c in type_counts_per_host.items()}
            ptot = sum(pall.values())
            want_k = {j: k for k, j in enumerate(score_idx)}
            vb = np.empty(len(score_idx)); vt = np.empty(len(score_idx))
            for h, g in by_host.items():
                if centred:
                    hw = W / 2
                    tt = collections.defaultdict(list)
                    for j in g:
                        tt[rule[j]].append(ts[j])
                    tt = {r: np.asarray(v) for r, v in tt.items()}
                    for j in g:
                        if j not in want_k:
                            continue
                        t = ts[j]; live = []
                        for r, arr in tt.items():
                            q = int(np.searchsorted(arr, t))
                            d = min(abs(arr[q - 1] - t) if q > 0 else np.inf, abs(arr[q] - t) if q < len(arr) else np.inf)
                            if d <= hw:
                                live.append(d)
                        ev = ptot - pall.get(rule[j], 0.0); k = want_k[j]
                        vb[k] = 1 - 0.5 ** (len(live) / (ev + 1))
                        vt[k] = 1 - 0.5 ** (sum(1 - d / hw for d in live) / (1 + ev * (1 - erd)))
                    continue
                last = {}
                for j in g:
                    last[rule[j]] = ts[j]
                    if j in want_k:
                        t = ts[j]
                        live = [t - lt for lt in last.values() if t - lt <= W]
                        ev = ptot - pall.get(rule[j], 0.0)
                        k = want_k[j]
                        vb[k] = 1 - 0.5 ** (len(live) / (ev + 1))
                        vt[k] = 1 - 0.5 ** (sum(1 - d / W for d in live) / (1 + ev * (1 - erd)))
            out[f"variety_{wn}_box"] = np.clip(vb, 0, 1); out[f"variety_{wn}_triangle"] = np.clip(vt, 0, 1)
        # aperiodicity of the alert's rule type in the trailing window, normalized on the baseline.
        # Cost control (an approximation, stated in the paper): per rule type at most APER_CAP of
        # the scored alerts, evenly spaced in time, get their own FFT; the others take the value of
        # the nearest preceding sampled alert of the same rule type.
        name = f"aperiodicity_{wn}"
        if need(name):
            def ap(j):
                tsg = ts_r[rule[j]]; i = pos_r[j]
                if centred:
                    lo = int(np.searchsorted(tsg, tsg[i] - W / 2, "left")); hi = int(np.searchsorted(tsg, tsg[i] + W / 2, "right"))
                    return aperiodicity_score(tsg[lo:hi])
                lo = int(np.searchsorted(tsg, tsg[i] - W, "left"))
                return aperiodicity_score(tsg[lo:i + 1])
            raw = np.empty(len(score_idx))
            per_rule = collections.defaultdict(list)
            for k, j in enumerate(score_idx):
                per_rule[rule[j]].append(k)
            for r, ks in per_rule.items():
                m = len(ks)
                samp = set(np.linspace(0, m - 1, min(m, APER_CAP)).round().astype(int).tolist())
                cur = None
                for q, k in enumerate(ks):
                    if q in samp or cur is None:
                        cur = ap(score_idx[k])
                    raw[k] = cur
            bidx = np.flatnonzero(base)
            if len(bidx) > aper_base_sample:
                bidx = np.random.default_rng(rng_seed).choice(bidx, aper_base_sample, replace=False)
            mbar = float(np.mean([ap(j) for j in bidx])) if len(bidx) else 0.5
            if 0 < mbar < 1:
                raw = raw ** (math.log(0.5) / math.log(mbar))
            out[name] = np.clip(raw, 0, 1)
    return out


MODULES = ("level", "accumulation", "variety", "rarity", "aperiodicity")


def variant_names():
    names = {"level": ["level"]}
    for m in ("accumulation", "variety", "rarity"):
        names[m] = [f"{m}_{w}_{s}" for w in WINDOWS for s in SHAPES]
    names["aperiodicity"] = [f"aperiodicity_{w}" for w in WINDOWS]
    return names


def combine(scores, config):
    """config: {"variants": {module: variant}, "weights": {module: w}} -> weighted arithmetic mean"""
    tot = sum(config["weights"].values())
    return sum(config["weights"][m] * scores[config["variants"][m]] for m in MODULES if config["weights"].get(m, 0) > 0) / tot
