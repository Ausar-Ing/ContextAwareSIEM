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
import os
import re
from dataclasses import dataclass, field

import numpy as np

# --- section 4.2.3 admission policy -----------------------------------------
COMPLIANCE_GROUPS = {"sca", "rootcheck", "policy_monitoring", "ciscat"}
# Vulnerability-detector results (provisional decision on Q16, 2026-10-27/28): like configuration
# assessment they describe an exploitable state, not anyone's activity, and on the workstation they
# arrive in bursts (958 alerts in 10 distinct minutes, levels up to 13). Excluded at admission on the
# same grounds. None occur in the AIT-ADS tuning scenarios; on the workstation the excluded run
# (ws_eval.py --exclude-vulndet, 2026-10-25) left every result unchanged.
STATE_GROUPS = {"vulnerability-detector"}
EXCLUDED_GROUPS = COMPLIANCE_GROUPS | STATE_GROUPS

# --- scan-timed integrity monitoring (admission, section 4.2.3) -------------
# A FIM alert from a SCHEDULED syscheck scan carries the time the scan ran, not
# the time the change happened. Measured 2026-09-30 on the wk3 corpus: registry
# rules 750/752/594 put 1,190 alerts into 4 distinct minutes (up to 392 in one),
# which the timing features would read as a burst. Same objection as SCA. The
# criterion is syscheck.mode, which states the reason directly; realtime and
# whodata FIM alerts keep near-change timestamps and stay admitted. Windows
# registry monitoring is scan-only, so registry rules are treated as scheduled
# if an alert ever lacks the mode field.
REGISTRY_FIM_RULES = {"594", "597", "598", "750", "751", "752"}


def _scan_timed(r: dict) -> bool:
    groups = set((r.get("rule") or {}).get("groups") or ())
    if "syscheck" not in groups:
        return False
    mode = str(((r.get("syscheck") or {}).get("mode")) or "").casefold()
    if mode:
        return mode == "scheduled"
    return str((r.get("rule") or {}).get("id")) in REGISTRY_FIM_RULES


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

# Wazuh writes MITRE in TWO shapes, and a parser must read both:
#   detection rules (everything the admission filter lets through):
#       rule.mitre = {"id": ["T1078"], "tactic": ["Defense Evasion", ...],
#                     "technique": ["Valid Accounts"]}        <- tactic NAMES
#   SCA / compliance checks:
#       rule.mitre_techniques = ["T1005"], rule.mitre_tactics = ["TA0005"]  <- IDs
# Until 2026-09-30 only the second shape was read, so no admitted alert ever
# carried a technique or tactic and features 8-10 were identically zero for a
# reason that had nothing to do with the data. Tactics are normalised to TA ids
# so the two shapes count alike and TACTIC_ORDINAL applies to both.
TACTIC_NAME_TO_ID = {
    "reconnaissance": "TA0043", "resource development": "TA0042",
    "initial access": "TA0001", "execution": "TA0002", "persistence": "TA0003",
    "privilege escalation": "TA0004", "defense evasion": "TA0005",
    "credential access": "TA0006", "discovery": "TA0007",
    "lateral movement": "TA0008", "collection": "TA0009",
    "command and control": "TA0011", "exfiltration": "TA0010", "impact": "TA0040",
}


def _mitre(rule: dict):
    """(techniques, tactics) from either Wazuh shape; tactics as TA ids."""
    m = rule.get("mitre") or {}
    tech = list(m.get("id") or ()) + list(rule.get("mitre_techniques") or ())
    tac = []
    for t in list(m.get("tactic") or ()) + list(rule.get("mitre_tactics") or ()):
        t = str(t).strip()
        tac.append(t if t.upper().startswith("TA") else TACTIC_NAME_TO_ID.get(t.casefold(), t))
    # de-duplicate, keep order: one alert's tags are one piece of evidence
    return tuple(dict.fromkeys(tech)), tuple(dict.fromkeys(tac))


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

# Entry mode (collapse_s set): the window holds ENTRIES, not alerts. An entry is
# a run of one rule on one entity with no gap longer than delta = collapse_s
# between consecutive members. Same 15 slots, restated over entries; the three
# whose meaning changes are renamed so a printout cannot be misread:
#   slot 0  window_size   -> window_entries     (entries, not alerts)
#   slot 3  repeat_ratio  -> volume_share_max   (alerts in the largest entry /
#                                                alerts represented by the window)
#   slot 12 burst_ratio   -> current_run_length (alerts in the current alert's entry)
# Everything else is computed over entries: levels are each entry's max level,
# tactics/techniques the union of its members, timing uses entry START times.
ENTRY_FEATURE_NAMES = list(FEATURE_NAMES)
ENTRY_FEATURE_NAMES[0] = "window_entries"
ENTRY_FEATURE_NAMES[3] = "volume_share_max"
ENTRY_FEATURE_NAMES[12] = "current_run_length"

# section 4.3.3: heavy-tailed features, log1p before fitting
LOG_FEATURES = ["window_duration_s", "inter_arrival_mean_s", "inter_arrival_min_s"]
LOG_IDX = [FEATURE_NAMES.index(f) for f in LOG_FEATURES]
ENTRY_LOG_IDX = LOG_IDX + [12]       # run length is a count with a heavy tail

MIN_WINDOW_FOR_SCORING = 3          # section 4.2.5 cold start

# Active-time correction (baseline_collection_protocol.md 2.1). A gap longer
# than G in a host's GLOBAL alert stream -- every alert from that host, of any
# entity and including compliance alerts the admission filter later drops --
# is taken as the host being off. Timing features subtract it: the host being
# off is not the entity being quiet, and only the second is evidence.
# G = 1800 s is the value the gate's derived threshold (20x median gap, floor
# 1800 s) resolved to on the live corpus and was frozen at in
# COLLECTION_RECORD.md D.1 (2026-09-18). It is a fixed parameter here, not
# re-derived online, so the feature map does not drift with the data.
DOWNTIME_GAP_S = 1800.0
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

    scan_timed: bool = False         # FIM result from a scheduled scan

    @property
    def admissible(self) -> bool:
        return not (set(self.rule_groups) & EXCLUDED_GROUPS) and not self.scan_timed


@dataclass
class Entry:
    """A collapsed run: one rule on one entity, members no more than delta apart.
    Duck-types the Alert fields the feature map reads (ts, rule_id, rule_level,
    techniques, tactics) so the timing code is shared; ts is the run's START."""
    rule_id: str
    rule_level: int
    ts: float                        # first member
    t_last: float                    # newest member
    count: int = 1
    techniques: tuple = ()
    tactics: tuple = ()

    def absorb(self, a: "Alert"):
        self.t_last = max(self.t_last, a.ts)
        self.count += 1
        self.rule_level = max(self.rule_level, a.rule_level)
        if a.techniques:
            self.techniques = tuple(dict.fromkeys(self.techniques + a.techniques))
        if a.tactics:
            self.tactics = tuple(dict.fromkeys(self.tactics + a.tactics))


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


# Reproducibility switch for results produced before 2026-10-14, when every
# Suricata alert still carried Wazuh rule 86601 (Deliverable 3, Tables VII and
# the first group-score study). CONTEXTSIEM_SURICATA_ID=0 restores that
# behaviour; the default is the specified method.
SURICATA_SIGNATURE_IDENTITY = os.environ.get("CONTEXTSIEM_SURICATA_ID", "1") != "0"


def _rule_identity(rule: dict, data: dict) -> str:
    """The rule identity the layer reasons about (Deliverable 3, Sec. III-B).

    Wazuh decodes every Suricata alert with ONE rule, 86601, whatever signature
    fired; all of AIT-ADS's network alerts would otherwise share a single rule
    id, so novelty, distinct-rule counts, runs and queue groups could not tell a
    TLS parsing complaint from DNS exfiltration. The Suricata signature id is a
    detector rule identifier, not log content, so using it keeps the layer
    content-blind. Measured on shaw: 16,692 Suricata alerts, 10 signatures.
    """
    rid = str(rule["id"])
    if SURICATA_SIGNATURE_IDENTITY and "suricata" in (rule.get("groups") or ()):
        sid = ((data or {}).get("alert") or {}).get("signature_id")
        if sid not in (None, ""):
            return f"suricata:{sid}"
    return rid


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
    # Live alerts.json carries "timestamp" (+0700 style offset); alerts exported
    # from the indexer, as in the public AIT-ADS set, carry only "@timestamp"
    # (ISO, "Z"). Both are the event time Wazuh assigned.
    raw_ts = r.get("timestamp") or r["@timestamp"]
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", raw_ts.replace("Z", "+00:00"))
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

    srcip = str(data.get("srcip") or data.get("src_ip")   # src_ip: Suricata eve.json
                or wed.get("ipAddress") or "").strip()
    if srcip and srcip not in NON_ROUTABLE_SRCIP:
        ents.append(("srcip", srcip))
    return Alert(
        alert_id=r.get("id", str(seq)),
        ingest_seq=seq,
        ts=ts,
        rule_id=_rule_identity(rule, data),
        rule_level=int(rule["level"]),
        rule_groups=tuple(rule.get("groups", ())),
        techniques=_mitre(rule)[0],
        tactics=_mitre(rule)[1],
        entities=tuple(ents),
        agent_id=aid,
        scan_timed=_scan_timed(r),
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
                 site_utc_offset_h: float = SITE_UTC_OFFSET_H,
                 downtime_gap_s: float | None = DOWNTIME_GAP_S,
                 collapse_s: float | None = None):
        self.N = N
        # Entry mode: None keeps the alert window of D2 (N alerts). A number is
        # delta, the largest gap inside one run; the window is then the last N
        # ENTRIES within T, so a flood of one rule occupies one slot instead of
        # pushing every other rule out.
        self.delta = collapse_s
        self.feature_names = FEATURE_NAMES if collapse_s is None else ENTRY_FEATURE_NAMES
        self.T = T_hours * 3600.0
        self.tz = site_utc_offset_h * 3600.0
        self.win: dict = collections.defaultdict(collections.deque)
        self.baseline_rules = set() if baseline_rules is None else set(baseline_rules)
        self.learn_rules = learn_rules or baseline_rules is None
        # Active-time correction state. None disables it (wall-clock timing),
        # which is what the frozen simulation studies were run with.
        self.G = downtime_gap_s
        self._last_seen: dict = {}                       # host -> newest ts
        self._down: dict = collections.defaultdict(list)  # host -> [(st, en)]
        self.downtime_log: list = []   # every interval detected, for audit

    @staticmethod
    def _host_of(a: Alert):
        for t, v in a.entities:
            if t == "host":
                return v
        return None

    def observe(self, a: Alert):
        """Update host liveness from ANY alert, admissible or not. Causal: a
        downtime interval is only known once the first alert after it arrives,
        and it can only ever affect windows built from that alert onwards."""
        if self.G is None:
            return
        h = self._host_of(a)
        if h is None:
            return
        last = self._last_seen.get(h)
        if last is not None and a.ts - last > self.G:
            self._down[h].append((last, a.ts))
            self.downtime_log.append((h, last, a.ts))
        if last is None or a.ts > last:
            self._last_seen[h] = a.ts
        # Windows never hold an alert older than T (wall clock), so no interval
        # ending before that can overlap one. Keeps state bounded.
        iv = self._down[h]
        while iv and iv[0][1] < a.ts - self.T:
            iv.pop(0)

    def _downtime_in(self, host, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Seconds of detected host downtime inside each [a_i, b_i]."""
        out = np.zeros_like(a, dtype=float)
        for st, en in self._down.get(host, ()):
            out += np.clip(np.minimum(b, en) - np.maximum(a, st), 0.0, None)
        return out

    def push(self, a: Alert):
        """Admit an alert into every window it belongs to. Returns
        [(entity, features, scoreable), ...] -- one entry per resolved entity.

        Feed EVERY alert, not only admissible ones: inadmissible alerts still
        prove the host was on, and dropping them before this call would
        manufacture downtime out of a compliance scan's quiet neighbours."""
        self.observe(a)
        if not a.admissible:
            return []
        if self.delta is not None:
            return self._push_entries(a)
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

    def _push_entries(self, a: Alert):
        """Entry-mode admission. The alert joins the most recent entry of its
        rule if that entry's newest member is at most delta old; otherwise it
        opens a new entry. Only the most recent entry of a rule is a candidate,
        so runs are split at every gap > delta and never re-joined. Interleaved
        rules (A B A B ...) each keep their own run."""
        out = []
        for e in a.entities:
            d = self.win[e]
            cur = None
            for x in reversed(d):
                if x.rule_id == a.rule_id:
                    if a.ts - x.t_last <= self.delta:
                        cur = x
                    break
            if cur is not None:
                cur.absorb(a)
            else:
                cur = Entry(a.rule_id, a.rule_level, a.ts, a.ts, 1, a.techniques, a.tactics)
                d.append(cur)
                while len(d) > self.N:
                    d.popleft()
            # time bound on the NEWEST member: an entry still receiving alerts
            # is live however long ago it started. Entries are ordered by start,
            # so a stale one can sit behind a live one; filter, do not popleft.
            if any(a.ts - x.t_last > self.T for x in d):
                self.win[e] = d = collections.deque(x for x in d if a.ts - x.t_last <= self.T)
            w = list(d)
            feats = self.features_entries(w, a, cur, e)
            scoreable = sum(x.count for x in w) >= MIN_WINDOW_FOR_SCORING
            out.append((e, feats, scoreable))
            if self.learn_rules:
                self.baseline_rules.add((e, a.rule_id))
        return out

    def _timing(self, ts: np.ndarray, cur: Alert):
        """Active gaps between consecutive times, and the observed subset used
        for inter-arrival statistics (fully-down gaps dropped). Shared by both
        modes; see features() for the reasoning."""
        n = len(ts)
        raw_gaps = np.diff(ts) if n >= 2 else np.zeros(0)
        if n >= 2 and self.G is not None:
            host = self._host_of(cur)
            down = self._downtime_in(host, ts[:-1], ts[1:])
            act_gaps = np.maximum(raw_gaps - down, 0.0)
            obs_gaps = act_gaps[~((down > 0) & (act_gaps <= 0.0))]
        else:
            act_gaps = obs_gaps = raw_gaps
        return act_gaps, obs_gaps

    def features_entries(self, w: list, cur: Alert, cur_entry: Entry, ent=None) -> np.ndarray:
        """The feature map over entries (ENTRY_FEATURE_NAMES). w is ordered by
        entry start; cur is the alert just admitted, cur_entry the entry it is in."""
        n = len(w)
        starts = np.array([x.ts for x in w])
        lv = np.array([x.rule_level for x in w], dtype=float)
        counts = np.array([x.count for x in w], dtype=float)

        _, obs_gaps = self._timing(starts, cur)
        # duration: active span from the first entry's start to NOW (the current
        # alert), which may lie inside a run that started earlier.
        span, _ = self._timing(np.append(starts, max(cur.ts, starts[-1])), cur)
        duration = float(span.sum())

        rules = [x.rule_id for x in w]
        distinct_rules = len(set(rules))
        volume_share = float(counts.max() / counts.sum())

        if n >= 2:
            xm = (n - 1) / 2.0
            sxx = n * (n * n - 1) / 12.0
            trend = float(((np.arange(n) - xm) * lv).sum() / sxx)
            if len(obs_gaps):
                gaps = np.maximum(obs_gaps, INTER_ARRIVAL_FLOOR_S)
                ia_mean, ia_min = float(gaps.mean()), float(gaps.min())
            else:
                ia_mean, ia_min = 0.0, 0.0
        else:
            trend, ia_mean, ia_min = 0.0, 0.0, 0.0

        techs, tacs = set(), set()
        pos, ordi = [], []
        for i, x in enumerate(w):
            techs.update(x.techniques)
            tacs.update(x.tactics)
            o = [TACTIC_ORDINAL[t] for t in x.tactics if t in TACTIC_ORDINAL]
            if o:
                pos.append(i)
                ordi.append(min(o))
        prog = 0.0
        if len(pos) >= 3 and len(set(ordi)) > 1:
            prog = float(_spearman(np.array(pos, float), np.array(ordi, float)))

        novel = 0.0 if (ent, cur.rule_id) in self.baseline_rules else 1.0
        hours = ((starts + self.tz) % 86400.0) // 3600.0
        night = float(((hours < WORK_START) | (hours >= WORK_END)).mean())

        return np.array([
            n, duration, distinct_rules, volume_share,
            lv.max(), lv.mean(), trend,
            len(techs), len(tacs), prog,
            ia_mean, ia_min, float(cur_entry.count), novel, night,
        ], dtype=float)

    def features(self, w: list, cur: Alert, ent=None) -> np.ndarray:
        n = len(w)
        ts = np.array([x.ts for x in w])
        lv = np.array([x.rule_level for x in w], dtype=float)

        # Active-time correction (protocol 2.1): subtract detected host
        # downtime from every gap. Downtime is taken from the host of the
        # CURRENT alert. Exact on a single-host testbed; a user entity whose
        # window spans several hosts would need the union of their uptime,
        # which is out of scope while there is one monitored host.
        #
        # A gap that is ENTIRELY downtime (for the host entity, the overnight
        # gap is exactly the detected interval) has zero active length. It is
        # not an observation of the entity at all, so it is dropped from the
        # inter-arrival statistics rather than counted as a 0 s gap -- counted,
        # it would hit INTER_ARRIVAL_FLOOR_S and make every morning window look
        # like it holds two simultaneous alerts, the burst signature. It still
        # contributes nothing to duration, which is correct either way.
        raw_gaps = np.diff(ts) if n >= 2 else np.zeros(0)
        if n >= 2 and self.G is not None:
            host = self._host_of(cur)
            down = self._downtime_in(host, ts[:-1], ts[1:])
            act_gaps = np.maximum(raw_gaps - down, 0.0)
            obs_gaps = act_gaps[~((down > 0) & (act_gaps <= 0.0))]
        else:
            act_gaps = obs_gaps = raw_gaps
        duration = float(act_gaps.sum())
        rules = [x.rule_id for x in w]
        cnt = collections.Counter(rules)
        distinct_rules = len(cnt)
        repeat_ratio = cnt.most_common(1)[0][1] / n

        if n >= 2:
            # OLS slope of level on position, closed form (polyfit is ~40x slower)
            xm = (n - 1) / 2.0
            sxx = n * (n * n - 1) / 12.0
            trend = float(((np.arange(n) - xm) * lv).sum() / sxx)
            if len(obs_gaps):
                gaps = np.maximum(obs_gaps, INTER_ARRIVAL_FLOOR_S)
                ia_mean, ia_min = float(gaps.mean()), float(gaps.min())
            else:                       # only gap was the host being off
                ia_mean, ia_min = 0.0, 0.0
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


def log_transform(X: np.ndarray, entries: bool = False) -> np.ndarray:
    """Section 4.3.3 preprocessing. Applied to the model input, not the feature.
    entries=True for entry-mode vectors, which also log the run length."""
    X = X.copy()
    idx = ENTRY_LOG_IDX if entries else LOG_IDX
    X[:, idx] = np.log1p(np.maximum(X[:, idx], 0.0))
    return X
