#!/usr/bin/env python3
"""Regression tests for window_builder.parse_wazuh field mapping.

    python3 tools/test_parse_wazuh.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import window_builder as W  # noqa: E402

FAILED = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  -- ' + detail) if detail else ''}")
    if not ok:
        FAILED.append(name)


def alert(rule_extra, agent="001"):
    r = {"timestamp": "2026-09-12T12:14:04.000+0700", "id": "1",
         "rule": {"id": "60118", "level": 3, "groups": ["windows"], **rule_extra},
         "agent": {"id": agent}, "data": {}}
    return W.parse_wazuh(r, 0)


print("parse_wazuh")
# Detection-rule shape, as rule 5501 / 67028 write it: nested, tactic NAMES
a = alert({"mitre": {"id": ["T1078"], "tactic": ["Defense Evasion", "Persistence"],
                     "technique": ["Valid Accounts"]}})
check("nested rule.mitre is read (detection rules)",
      a.techniques == ("T1078",) and a.tactics == ("TA0005", "TA0003"), f"{a.techniques} {a.tactics}")
# SCA shape: flat keys, tactic IDs
b = alert({"groups": ["sca"], "mitre_techniques": ["T1005"], "mitre_tactics": ["TA0005"]})
check("flat mitre_* keys are read (SCA)", b.techniques == ("T1005",) and b.tactics == ("TA0005",))
check("tactic names and ids normalise to the same id", a.tactics[0] == b.tactics[0])
c = alert({})
check("no MITRE -> empty, not an error", c.techniques == () and c.tactics == ())
d = alert({"mitre": {"id": ["T1078"], "tactic": ["Persistence"]},
           "mitre_techniques": ["T1078"], "mitre_tactics": ["TA0003"]})
check("both shapes on one alert are de-duplicated", d.techniques == ("T1078",) and d.tactics == ("TA0003",))
e = alert({}, agent="002")
check("re-enrolled agent 002 resolves to host 001, raw id kept",
      ("host", "001") in e.entities and e.agent_id == "002")

print(f"\n{'ALL PASS' if not FAILED else str(len(FAILED)) + ' FAILED: ' + ', '.join(FAILED)}")
sys.exit(1 if FAILED else 0)
