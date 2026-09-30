#!/usr/bin/env python3
"""
Reference implementation of Component 5 (Temporal Context Window Builder)
from system_model.md, plus the feature map of section 4.2.6.

Works on real Wazuh alerts (JSONL from alerts.json) and on simulated streams.
Kept dependency-light on purpose: numpy only.

The point of this file is that the feature map exists in one place, is used
identically by the study script and by any future implementation, and can be
run against recorded data to check that a feature is populated at all.
"""
from __future__ import annotations

import collections
import datetime as dt
import math
import re
from dataclasses import dataclass, field

import numpy as np

# --- section 4.2.3 admission policy -----------------------------------------
COMPLIANCE_GROUPS = {"sca", "rootcheck", "policy_monitoring", "ciscat"}

# --- host identity across re-enrollment (COLLECTION_RECORD.md Part B #2) ----
# Wazuh keys an agent by the id in client.keys, not by the machine. On
# 2026-09-27 ~11:46 the Windows endpoint was re-enrolled and came back as
# 002 "TestRun1"; agent ossec.conf (278DBA62...) and version (4.14.7) are
# unchanged, so the generating process is the same and this is an identity
# change only. Without this map one physical host becomes two entities and
# every host window is split at the re-enrollment. Raw id is kept in
# Alert.agent_id for filtering and audit.
HOST_ALIASES = {"002": "001"}

# --- section 4.2.6.1 tactic ordering ----------------------------------------
TACTIC_ORDINAL = {
    "TA0043": 1,   # Reconnaissance
    "TA0042": 2,   # Resource Development
    "TA0001": 3,   # Initial Access
    "TA0002": 4,   # Execution
    "TA0003": 5,   # Persistence
    "TA0004": 6,   # Privilege Escalation
    "TA0005": 7,   # Defense Evasion
    "TA0006": 8,   # Credential Access
    "TA0007": 9,   # Discovery
    "TA0008": 10,  # Lateral Movement
    "TA0009": 11,  # Collection
    "TA0011": 12,  # Command and Control
    "TA0010": 13,  # Exfiltration
    "TA0040": 14,  # Impact
}

FEATURE_NAMES = [
    "window_size",
    "window_duration_s",
    "distinct_rule_count",
    "repeat_ratio",
    "rule_level_max",
    "rule_level_mean",
    "rule_level_trend",
    "distinct_technique_count",
    "distinct_tactic_count",
    "tactic_progression",
    "inter_arrival_mean_s",
    "inter_arrival_min_s",
    "burst_ratio",
    "novel_rule_flag",
    "night_fraction",
]

# section 4.3.3: heavy-tailed features, log1p before fitting
LOG_FEATURES = ["window_duration_s", "inter_arrival_mean_s", "inter_arrival_min_s"]
LOG_IDX = [FEATURE_NAMES.index(f) for f in LOG_FEATURES]

MIN_WINDOW_FOR_SCORING = 3          # section 4.2.5 cold start
INTER_ARRIVAL_FLOOR_S = 0.001       # section 4.2.2
WORK_START, WORK_END = 9, 18        # night_fraction definition, LOCAL hours
# night_fraction is a local-time concept. Wazuh timestamps are converted to UTC
# at Component 2, so the offset of the monitored site must be applied back here
# or the feature measures the wrong thing. Asia/Bangkok is UTC+7; a 15:00 local
# workday would otherwise be scored as night (08:00 UTC < WORK_START).
SITE_UTC_OFFSET_H = 7.0


@dataclass
class Alert:
    """Normalized alert -- section 4.1.2 schema, fields the window builder uses."""
    alert_id: str
    ingest_seq: int
    ts: float                       # epoch seconds, UTC
    rule_id: str
    rule_level: int
    rule_groups: tuple = ()
    techniques: tuple = ()
    tactics: tuple = ()
    entities: tuple = ()            # ((type, id), ...)
    agent_id: str = ""              # raw Wazuh agent id, BEFORE HOST_ALIASES
    label: int = 0                  # evaluation only, never a feature

    @property
    def admissible(self) -> bool:
        return not (set(self.rule_groups) & COMPLIANCE_GROUPS)


# --- section 4.1.3 entity resolution ----------------------------------------
# Accounts that are the operating system rather than a person. Treating SYSTEM
# as a user entity produces one enormous "user" whose behaviour is really the
# machine's -- the same failure mode as admitting compliance alerts at
# Component 1. Computer accounts end in "$"; "-" is Windows' empty placeholder.
MACHINE_ACCOUNTS = {"system", "local service", "network service",
                    "anonymous logon", "local system", "-", ""}

# Logon-family Windows events name the account being acted on in
# targetUserName; everything else (process creation above all) names the acting
# account in subjectUserName. Picking the right one per event keeps the "user"
# entity semantically consistent: it is always the human the alert is about.
LOGON_EVENT_IDS = {"4624", "4625", "4634", "4647", "4648", "4672", "4778", "4779"}

NON_ROUTABLE_SRCIP = {"-", "::1", "127.0.0.1", "0.0.0.0", ""}


def _clean_user(v):
    """Normalise one raw account string to a stable entity id, or None.

    Two normalisations, both needed for entity resolution to be consistent:
    Sysmon writes `DOMAIN\\user` in data.win.eventdata.user while the Security
    channel writes a bare `user` in subjectUserName, and Windows accounts are
    case-insensitive. Without both, one human resolves as several entities and
    every per-entity window is fragmented.
    """
    if v is None:
        return None
    u = str(v).strip()
    if "\\" in u:                       # DOMAIN\user -> user
        u = u.rsplit("\\", 1)[-1]
    if "@" in u:                        # user@domain -> user (UPN form)
        u = u.split("@", 1)[0]
    u = u.casefold()
    if u in MACHINE_ACCOUNTS or u.endswith("$"):
        return None
    return u


def parse_wazuh(line_or_obj, seq: int) -> Alert:
    """Map one raw Wazuh alert dict onto Alert. Entity resolution is
    section 4.1.3: host always, user and srcip when the decoder supplies them.

    Reads BOTH field families. The Linux/PAM decoders use data.srcuser /
    data.dstuser; Windows eventchannel alerts -- which are the entire endpoint
    stream -- put identity under data.win.eventdata.* instead. Measured on the
    live capture 2026-09-12: subjectUserName 2689, targetUserName 291,
    win.eventdata.user 147, dstuser 116, srcuser 39, srcip 0. Reading only the
    first family resolved ~5% of alerts and made per-entity-type modelling of
    `user` impossible.
    """
    r = line_or_obj
    rule = r["rule"]
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", r["timestamp"])
    ts = dt.datetime.fromisoformat(s).timestamp()
    data = r.get("data", {}) or {}
    win = (data.get("win") or {})
    wed = (win.get("eventdata") or {})
    eid = str((win.get("system") or {}).get("eventID") or "")

    aid = str(r["agent"]["id"])
    ents = [("host", HOST_ALIASES.get(aid, aid))]

    if eid in LOGON_EVENT_IDS:
        order = (wed.get("targetUserName"), wed.get("subjectUserName"))
    else:
        order = (wed.get("subjectUserName"), wed.get("targetUserName"))
    user = None
    for cand in order + (wed.get("user"), data.get("dstuser"), data.get("srcuser")):
        user = _clean_user(cand)
        if user:
            break
    if user:
        ents.append(("user", user))

    srcip = str(data.get("srcip") or wed.get("ipAddress") or "").strip()
    if srcip and srcip not in NON_ROUTABLE_SRCIP:
        ents.append(("srcip", srcip))
    return Alert(
        alert_id=r.get("id", str(seq)),
        ingest_seq=seq,
        ts=ts,
        rule_id=str(rule["id"]),
        rule_level=int(rule["level"]),
        rule_groups=tuple(rule.get("groups", ())),
        techniques=tuple(rule.get("mitre_techniques", ()) or ()),
        tactics=tuple(rule.get("mitre_tactics", ()) or ()),
        entities=tuple(ents),
        agent_id=aid,
    )


class WindowBuilder:
    """Section 4.2. One instance per run; holds one deque per entity.

    `baseline_rules` supports novel_rule_flag (feature 14): the set of
    (entity, rule_id) pairs observed during the baseline period. Passing None
    makes the builder learn it online, which is what happens during baseline
    collection itself.
    """

    def __init__(self, N: int = 20, T_hours: float = 24.0,
                 baseline_rules: set | None = None, learn_rules: bool = False,
                 site_utc_offset_h: float = SITE_UTC_OFFSET_H):
        self.N = N
        self.T = T_hours * 3600.0
        self.tz = site_utc_offset_h * 3600.0
        self.win: dict = collections.defaultdict(collections.deque)
        self.baseline_rules = set() if baseline_rules is None else set(baseline_rules)
        self.learn_rules = learn_rules or baseline_rules is None

    def push(self, a: Alert):
        """Admit an alert into every window it belongs to. Returns
        [(entity, features, scoreable), ...] -- one entry per resolved entity."""
        if not a.admissible:
            return []
        out = []
        for e in a.entities:
            d = self.win[e]
            d.append(a)
            # eviction: count bound and time bound, section 4.2.4
            while len(d) > self.N:
                d.popleft()
            while d and (a.ts - d[0].ts) > self.T:
                d.popleft()
            feats = self.features(list(d), a, e)
            scoreable = len(d) >= MIN_WINDOW_FOR_SCORING
            out.append((e, feats, scoreable))
            if self.learn_rules:
                self.baseline_rules.add((e, a.rule_id))
        return out

    def features(self, w: list, cur: Alert, ent=None) -> np.ndarray:
        n = len(w)
        ts = np.array([x.ts for x in w])
        lv = np.array([x.rule_level for x in w], dtype=float)

        duration = float(ts[-1] - ts[0])
        rules = [x.rule_id for x in w]
        cnt = collections.Counter(rules)
        distinct_rules = len(cnt)
        repeat_ratio = cnt.most_common(1)[0][1] / n

        if n >= 2:
            # OLS slope of level on position, closed form (polyfit is ~40x slower)
            xm = (n - 1) / 2.0
            sxx = n * (n * n - 1) / 12.0
            trend = float(((np.arange(n) - xm) * lv).sum() / sxx)
            gaps = np.diff(ts)
            gaps = np.maximum(gaps, INTER_ARRIVAL_FLOOR_S)
            ia_mean, ia_min = float(gaps.mean()), float(gaps.min())
        else:
            trend, ia_mean, ia_min = 0.0, 0.0, 0.0

        techs = set()
        tacs = set()
        for x in w:
            techs.update(x.techniques)
            tacs.update(x.tactics)

        # tactic_progression: Spearman rho between position and tactic ordinal,
        # lowest ordinal when an alert carries several. 0 if < 3 mapped alerts.
        pos, ordi = [], []
        for i, x in enumerate(w):
            o = [TACTIC_ORDINAL[t] for t in x.tactics if t in TACTIC_ORDINAL]
            if o:
                pos.append(i)
                ordi.append(min(o))
        prog = 0.0
        if len(pos) >= 3 and len(set(ordi)) > 1:
            prog = float(_spearman(np.array(pos, float), np.array(ordi, float)))

        burst = float((ts >= cur.ts - 60.0).sum()) / n
        # feature 14: rule unseen for THIS entity during baseline
        novel = 0.0 if (ent, cur.rule_id) in self.baseline_rules else 1.0
        hours = ((ts + self.tz) % 86400.0) // 3600.0   # LOCAL hour-of-day
        night = float(((hours < WORK_START) | (hours >= WORK_END)).mean())

        return np.array([
            n, duration, distinct_rules, repeat_ratio,
            lv.max(), lv.mean(), trend,
            len(techs), len(tacs), prog,
            ia_mean, ia_min, burst, novel, night,
        ], dtype=float)


def _spearman(a: np.ndarray, b: np.ndarray) -> float:
    ra, rb = _rank(a), _rank(b)
    ra = ra - ra.mean()
    rb = rb - rb.mean()
    den = math.sqrt((ra * ra).sum() * (rb * rb).sum())
    return 0.0 if den == 0 else float((ra * rb).sum() / den)


def _rank(x: np.ndarray) -> np.ndarray:
    """Average ranks, ties shared. Windows are <= N elements so this is small."""
    order = x.argsort(kind="stable")
    r = np.empty(len(x), float)
    r[order] = np.arange(len(x), dtype=float)
    u, inv, cnts = np.unique(x, return_inverse=True, return_counts=True)
    if (cnts > 1).any():
        sums = np.zeros(len(u))
        np.add.at(sums, inv, r)
        r = (sums / cnts)[inv]
    return r


def log_transform(X: np.ndarray) -> np.ndarray:
    """Section 4.3.3 preprocessing. Applied to the model input, not the feature."""
    X = X.copy()
    X[:, LOG_IDX] = np.log1p(np.maximum(X[:, LOG_IDX], 0.0))
    return X
