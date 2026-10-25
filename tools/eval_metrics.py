#!/usr/bin/env python3
"""
Evaluation metrics of Deliverable 3, Sec. IV-C, in one place, used by tuning
and by the final evaluation alike.

Ground truth: AIT-ADS event labels, graded by what the attacker's action
achieved (Table VI), fixed before any test result:
    3  user change, sudo escalation, exfiltration     control or data
    2  online password cracking                        a credential attack
    1  service scan, directory scan, WordPress scan    reconnaissance
    0  benign
A queue item's stages are the labels among its members; its grade is the
highest of them.

Ranks are average ranks (1 = top, ties share the mean position), the expected
rank under random tie-breaking.
"""
from __future__ import annotations

import math

import numpy as np

GRADES = {"attacker_change_user": 3, "escalated_sudo_command": 3, "dnsteal": 3,
          "online_cracking": 2,
          "service_scan": 1, "dirb": 1, "wpscan": 1}
SCANS = {"service_scan", "dirb", "wpscan"}
BENIGN = {"-", "unmatched"}


def ranks_desc(x: np.ndarray) -> np.ndarray:
    x = np.asarray(x, float)
    order = np.argsort(-x, kind="mergesort")
    r = np.empty(len(x)); r[order] = np.arange(1, len(x) + 1)
    _, inv, cnt = np.unique(-x, return_inverse=True, return_counts=True)
    return (np.bincount(inv, weights=r) / cnt)[inv]


def item_stages(gid: np.ndarray, labels, G: int) -> list:
    """Set of attack stages in each queue item."""
    st = [set() for _ in range(G)]
    for g, l in zip(gid, labels):
        if l not in BENIGN:
            st[g].add(l)
    return st


def alpha_ndcg(scores: np.ndarray, stages: list, k: int, alpha: float = 0.5,
               grades: dict = GRADES) -> float:
    """Graded alpha-nDCG@k (Clarke et al. 2008). Gain at rank i is
    sum over stages s in item i of g_s * (1 - alpha)^(items above i containing s),
    discounted by log2(i + 1); the ideal ordering is built greedily, as is
    standard since the exact ideal is NP-hard. Ties in `scores` are broken by
    averaging the DCG over random tie orders (50 draws), so tied systems such
    as B0 get their expected value rather than a lucky order."""
    def dcg(order):
        seen, total = {}, 0.0
        for i, it in enumerate(order[:k]):
            gain = sum(grades.get(s, 0) * (1 - alpha) ** seen.get(s, 0) for s in stages[it])
            for s in stages[it]:
                seen[s] = seen.get(s, 0) + 1
            total += gain / math.log2(i + 2)
        return total
    # greedy ideal
    remaining = [i for i in range(len(stages)) if stages[i]]
    seen, ideal = {}, []
    for _ in range(min(k, len(remaining))):
        best = max(remaining, key=lambda it: sum(grades.get(s, 0) * (1 - alpha) ** seen.get(s, 0)
                                                 for s in stages[it]))
        ideal.append(best); remaining.remove(best)
        for s in stages[best]:
            seen[s] = seen.get(s, 0) + 1
    idcg = dcg(ideal)
    if idcg == 0:
        return float("nan")
    scores = np.asarray(scores, float)
    if len(np.unique(scores)) == len(scores):
        return dcg(list(np.argsort(-scores, kind="mergesort"))) / idcg
    rng = np.random.default_rng(0)
    vals = []
    for _ in range(50):
        jitter = rng.random(len(scores))
        vals.append(dcg(list(np.lexsort((jitter, -scores)))) / idcg)
    return float(np.mean(vals))


def first_item_ranks(scores: np.ndarray, stages: list) -> dict:
    r = ranks_desc(scores)
    out = {}
    for it, ss in enumerate(stages):
        for s in ss:
            out[s] = min(out.get(s, np.inf), r[it])
    return out


def mrr_nonscan(first: dict) -> float:
    v = [1.0 / x for s, x in first.items() if s not in SCANS]
    return float(np.mean(v)) if v else float("nan")


def coverage(first: dict, k: int) -> dict:
    ns = [s for s in first if s not in SCANS]
    sc = [s for s in first if s in SCANS]
    return {"nonscan": (sum(first[s] <= k for s in ns), len(ns)),
            "scan": (sum(first[s] <= k for s in sc), len(sc))}


def auc(pos: np.ndarray, neg: np.ndarray) -> float:
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    allv = np.concatenate([pos, neg]); r = ranks_desc(-allv)
    return float((r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def macro_auc(alert_scores: np.ndarray, labels) -> float:
    """Mean over non-scan stages of the AUC of that stage's alerts vs benign."""
    labels = np.asarray(labels, dtype=object)
    ben = np.isin(labels, list(BENIGN))
    stages = sorted({l for l in labels if l not in BENIGN and l not in SCANS})
    v = [auc(alert_scores[labels == s], alert_scores[ben]) for s in stages]
    return float(np.mean(v)) if v else float("nan")



# Robustness grades (Deliverable 3, Sec. IV-C): binary, and (2, 1, 1) -- control or data 2,
# credential attack and reconnaissance 1. With alpha = 1 only the first item of a stage counts.
GRADES_BINARY = {s: 1 for s in GRADES}
GRADES_211 = {s: (2 if g == 3 else 1) for s, g in GRADES.items()}


def per_day(scores: np.ndarray, stages: list, days, k: int = 20) -> dict:
    """Per-day ranking: an analyst works one day's queue at a time, so each item
    competes only with items of its own day (the day of its first member). Returns
    the mean alpha-nDCG@k over days holding at least one attack item, and the MRR of
    non-scan stages with each stage's first-item rank taken in the day queue where
    it ranks best."""
    scores = np.asarray(scores, float); days = np.asarray(days)
    nd, first = [], {}
    for d in sorted(set(days.tolist())):
        idx = np.flatnonzero(days == d)
        st = [stages[i] for i in idx]
        if not any(st):
            continue
        v = alpha_ndcg(scores[idx], st, k)
        if not math.isnan(v):
            nd.append(v)
        for s_, r in first_item_ranks(scores[idx], st).items():
            first[s_] = min(first.get(s_, np.inf), r)
    return {"andcg": float(np.mean(nd)) if nd else float("nan"), "mrr": mrr_nonscan(first),
            "first": {s_: float(v) for s_, v in first.items()}, "days": len(nd)}

MIN_WITHIN = 5          # attack and benign alerts a host needs for within_host_auc


def within_host_auc(alert_scores: np.ndarray, labels, hosts) -> dict:
    """Separation that host rarity cannot supply: for each host carrying at least
    MIN_WITHIN non-scan attack alerts and MIN_WITHIN benign alerts, the AUC of its
    non-scan attack alerts against its benign alerts. A score constant within a host
    (host rarity) gets 0.5 by construction. Returns {"macro": mean over eligible
    hosts (nan if none), "hosts": {host: [auc, n_attack, n_benign]}}."""
    labels = np.asarray(labels, dtype=object); hosts = np.asarray(hosts, dtype=object)
    att = np.array([l not in BENIGN and l not in SCANS for l in labels])
    ben = np.isin(labels, list(BENIGN))
    out = {}
    for h in sorted(set(hosts[att])):
        m = hosts == h
        na, nb = int((m & att).sum()), int((m & ben).sum())
        if na >= MIN_WITHIN and nb >= MIN_WITHIN:
            out[h] = [auc(alert_scores[m & att], alert_scores[m & ben]), na, nb]
    return {"macro": float(np.mean([v[0] for v in out.values()])) if out else float("nan"), "hosts": out}

def _stage(s):
    return s[-1] if isinstance(s, tuple) else s      # keys may be (scenario, stage)


def paired_ranks(first_a: dict, first_b: dict) -> dict:
    """Paired comparison over the non-scan stages present in both: improved
    (a ranks the stage earlier), worsened, tied, and a Wilcoxon signed-rank p."""
    common = [s for s in first_a if s in first_b and _stage(s) not in SCANS]
    d = np.array([first_b[s] - first_a[s] for s in common])        # > 0: a better
    out = {"n": len(common), "a_better": int((d > 0).sum()), "b_better": int((d < 0).sum()),
           "tied": int((d == 0).sum())}
    try:
        from scipy.stats import wilcoxon
        out["wilcoxon_p"] = float(wilcoxon(d[d != 0]).pvalue) if (d != 0).sum() >= 1 else 1.0
    except Exception:
        out["wilcoxon_p"] = float("nan")
    return out
