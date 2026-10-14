#!/usr/bin/env python3
"""
Component 8 (Entity Risk Accumulation) as specified in Deliverable 3, Sec. III-H.

    R_e(t) = sum_g v_g (1 + ln k_g) 2^(-(t - t_g^last)/h)
           + a_s * max_{a: t - tau(a) < T} q(a, e) 2^(-(t - tau(a))/h)

    q(a, e) = 100 * min(1, -log10(1 - u^{n_e}) / lambda),   u = S_seq(a, e)/100,
    n_e = max(1, entries the entity opened in the preceding T / N)

Accumulation groups g are (entity, rule) runs split when the rule is silent for
longer than T. v_g is the static value of the group's first member,
a_r * S_rule + a_c * S_exp; the accumulator keeps its OWN weights (a_r, a_c, a_s)
rather than the queue's, because the queue's tuned weights give the static terms
zero weight, which would leave the accumulator with no group evidence at all.

Escalation (risk notable) when, together:
  R_e(t) > theta_k                    theta_k: 99.9th percentile of R over the
                                      baseline period for entity type k
  >= 2 contributing groups            a group contributes while its decayed term
                                      is >= CONTRIB_FRAC of R_e(t)
  >= 2 ATT&CK tactics contributed by different rules among those groups

A notable is an episode per entity: it opens when the conditions first hold
and closes when R_e falls back below theta_k. It records the queue groups
(gids) of its contributing alerts so that Component 9 can absorb them.

Approximation, stated: groups whose last member is older than T are dropped
from the sum. Their decayed weight is at most 2^(-T/h) = 1/64 of their value at
h = 4 h, and the contribution rule already excludes them from escalation.
"""
from __future__ import annotations

import collections
import math

import numpy as np

T_S = 24 * 3600.0
H_S = 4 * 3600.0
LAMBDA = 4.0
CONTRIB_FRAC = 0.10
THETA_Q = 99.9
U_MAX = 1 - 1e-5


def q_score(s_seq: float, n_e: float, lam: float = LAMBDA) -> float:
    u = min(max(s_seq / 100.0, 1e-12), U_MAX)
    p = -math.expm1(n_e * math.log(u))
    return 100.0 * min(1.0, -math.log10(max(p, 1e-300)) / lam)


class _Group:
    __slots__ = ("rule", "v", "k", "t_last", "gids", "tactics")

    def __init__(self, rule, v, t, tactics):
        self.rule, self.v, self.k, self.t_last = rule, v, 0, t
        self.gids, self.tactics = set(), set(tactics)


class Accumulator:
    """Streams one corpus; call push() for every (alert, entity) in time order."""

    def __init__(self, N: int, a_r=0.3, a_c=0.2, a_s=0.5, T=T_S, h=H_S, lam=LAMBDA):
        self.N, self.a_r, self.a_c, self.a_s = N, a_r, a_c, a_s
        self.T, self.h, self.lam = T, h, lam
        self.groups = collections.defaultdict(dict)        # entity -> rule -> _Group
        self.entry_opens = collections.defaultdict(collections.deque)
        self.qmax = collections.defaultdict(collections.deque)   # entity -> deque[(t, log2 key, q)]

    def push(self, ent, t, rule, s_rule, s_exp, s_seq, opened_entry, tactics, gid=None):
        """Update entity `ent` with one alert; return (R, components) at time t.
        s_seq < 0 means the window was not scoreable (no window evidence)."""
        T, h = self.T, self.h
        # --- group term
        gs = self.groups[ent]
        g = gs.get(rule)
        if g is None or t - g.t_last > T:
            g = _Group(rule, self.a_r * s_rule + self.a_c * s_exp, t, tactics)
            gs[rule] = g
        g.k += 1; g.t_last = t
        if tactics:
            g.tactics.update(tactics)
        if gid is not None:
            g.gids.add(gid)
        # --- window term: n_e from entries opened in the last T, running max of decayed q
        eo = self.entry_opens[ent]
        if opened_entry:
            eo.append(t)
        while eo and t - eo[0] > T:
            eo.popleft()
        dq = self.qmax[ent]
        if s_seq >= 0:
            n_e = max(1.0, len(eo) / self.N)
            q = q_score(s_seq, n_e, self.lam)
            if q > 0:
                key = math.log2(q) + t / h            # decayed q = 2^(key - t/h)
                while dq and dq[-1][1] <= key:        # monotone deque: drop dominated
                    dq.pop()
                dq.append((t, key, q))
        while dq and t - dq[0][0] >= T:
            dq.popleft()
        wterm = self.a_s * (2.0 ** (dq[0][1] - t / h)) if dq else 0.0
        # --- sum over live groups, prune stale ones
        terms = {}
        for r, gg in list(gs.items()):
            age = t - gg.t_last
            if age > T:
                del gs[r]; continue
            terms[r] = gg.v * (1.0 + math.log(gg.k)) * 2.0 ** (-age / h)
        R = sum(terms.values()) + wterm
        return R, terms, wterm

    def contributing(self, ent, R, terms):
        return [self.groups[ent][r] for r, v in terms.items() if R > 0 and v >= CONTRIB_FRAC * R]


def tactics_from_different_rules(groups) -> bool:
    """True if two distinct tactics are contributed by two different rules:
    tactic t1 from rule r1 and tactic t2 != t1 from rule r2 != r1. One rule
    carrying several tactics never satisfies this on its own."""
    pairs = {(tac, g.rule) for g in groups for tac in g.tactics}
    return any(t1 != t2 and r1 != r2 for t1, r1 in pairs for t2, r2 in pairs)


def run(stream, N, theta=None, **kw):
    """stream: iterable of dicts with keys ent, etype, t, rule, s_rule, s_exp, s_seq,
    opened, tactics, gid, baseline (bool). Returns
      R_base: {etype: [R at baseline alert times]}   (for theta calibration)
      notables: list of {ent, etype, t_open, t_close, R_peak, gids, rules, tactics}
    If theta is None only R_base is computed."""
    acc = Accumulator(N, **kw)
    R_base = collections.defaultdict(list)
    open_nb, notables = {}, []
    for x in stream:
        R, terms, wterm = acc.push(x["ent"], x["t"], x["rule"], x["s_rule"], x["s_exp"],
                                   x["s_seq"], x["opened"], x["tactics"], x["gid"])
        if x["baseline"]:
            R_base[x["etype"]].append(R)
            continue
        if theta is None:
            continue
        th = theta.get(x["etype"], math.inf)
        ent = x["ent"]
        nb = open_nb.get(ent)
        if R > th:
            contrib = acc.contributing(ent, R, terms)
            if nb is None and len(contrib) >= 2 and tactics_from_different_rules(contrib):
                nb = {"ent": ent, "etype": x["etype"], "t_open": x["t"], "R_peak": R, "gids": set(),
                      "rules": set(), "tactics": set()}
                open_nb[ent] = nb; notables.append(nb)
            if nb is not None:
                nb["R_peak"] = max(nb["R_peak"], R)
                for g in contrib:
                    nb["gids"] |= g.gids; nb["rules"].add(g.rule); nb["tactics"] |= g.tactics
        elif nb is not None:
            nb["t_close"] = x["t"]; del open_nb[ent]
    return R_base, notables


def calibrate_theta(R_base: dict, q: float = THETA_Q) -> dict:
    return {k: float(np.percentile(v, q)) for k, v in R_base.items() if len(v) >= 100}


def merge_notables(notables):
    """Notables sharing any queue group become one incident (union-find on gids)."""
    parent = list(range(len(notables)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]; i = parent[i]
        return i
    owner = {}
    for i, nb in enumerate(notables):
        for g in nb["gids"]:
            if g in owner:
                parent[find(i)] = find(owner[g])
            else:
                owner[g] = i
    inc = collections.defaultdict(lambda: {"members": [], "gids": set(), "R_peak": 0.0, "t_open": math.inf,
                                            "etypes": set(), "tactics": set()})
    for i, nb in enumerate(notables):
        r = inc[find(i)]
        r["members"].append(nb["ent"]); r["gids"] |= nb["gids"]; r["R_peak"] = max(r["R_peak"], nb["R_peak"])
        r["t_open"] = min(r["t_open"], nb["t_open"]); r["etypes"].add(nb["etype"]); r["tactics"] |= nb["tactics"]
    return list(inc.values())
