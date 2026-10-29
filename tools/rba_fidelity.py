#!/usr/bin/env python3
"""Fidelity check of the B_RBA comparator (tools/rba.py) against Uetz et al., "Can Risk-Based
Alerting Mitigate Cybersecurity Alert Fatigue?" (arXiv:2609.02465v1), Table 4a: per-module AUROC
on AIT-ADS russellmitchell, Wazuh and Suricata alerts scored separately, every alert of the
scenario, positives = CATS's `misuse` flag.

Input: the two files CATS ships for this scenario (github.com/962012d09b/cats, commit 628cf48,
datasets/ait_wazuh.zip and datasets/ait_suricata.zip, one JSON alert per line).
Setting reproduced: CATS's defaults as in the paper -- normalizers from the whole file (here: every
alert counted as baseline), grouping by hostname (Wazuh) or source IP (Suricata) for accumulation
and variety, by alert type for rarity and aperiodicity, centred ("Past + Future") windows. The
trailing windows used by the evaluation are reported beside them. Known approximations: no
clipping of windows at the file edges, and aperiodicity normalized on a 2000-alert sample.
Tuning-scenario data only.

usage: rba_fidelity.py <ait_wazuh.jsonl> <ait_suricata.jsonl> <out.json>
"""
import sys, os, json, datetime
import numpy as np
from sklearn.metrics import roc_auc_score
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rba

# Uetz et al. Table 4a (default parametrization), AIT-ADS: (Wazuh, Suricata)
PAPER = {"level": (0.99, 0.81),
         "accumulation_1m": (1.00, 0.66), "accumulation_1h": (1.00, 0.48), "accumulation_1d": (1.00, 0.55),
         "variety_1m": (1.00, 0.80), "variety_1h": (1.00, 0.96), "variety_1d": (1.00, 0.79),
         "rarity_1m": (0.00, 0.59), "rarity_1h": (0.00, 0.88), "rarity_1d": (0.07, 0.99),
         "aperiodicity_1m": (0.10, 0.42), "aperiodicity_1h": (0.00, 0.72), "aperiodicity_1d": (0.01, 0.95)}


def load(path, group_field):
    rows = [json.loads(l) for l in open(path)]
    rows.sort(key=lambda r: r["features"]["timestamp"])
    f = [r["features"] for r in rows]
    ts = np.array([datetime.datetime.fromisoformat(x["timestamp"].replace("Z", "+00:00")).timestamp() for x in f])
    return (ts, np.array([x[group_field] for x in f], dtype=object), np.array([x["rule_id"] for x in f], dtype=object),
            np.array([int(x["rule_level"]) for x in f]), np.array([int(r["metadata"]["misuse"]) for r in rows]))


def level_score(lvl, kind):
    if kind == "wazuh":
        return lvl / 15.0
    return np.array([{1: 0.75, 2: 0.5}.get(int(v), 0.25) for v in lvl])  # CATS Suricata severity map


def main():
    out = {}
    for kind, path, gf in (("wazuh", sys.argv[1], "hostname"), ("suricata", sys.argv[2], "source_ip")):
        ts, grp, rule, lvl, y = load(path, gf)
        idx = np.arange(len(ts))
        res = {"n": int(len(y)), "positives": int(y.sum()), "auroc": {}}
        res["auroc"]["level"] = float(roc_auc_score(y, level_score(lvl, kind)))
        for centred in (True, False):
            sc = rba.module_scores(ts, grp, rule, lvl, np.inf, idx, centred=centred)
            for name, v in sc.items():
                if name != "level":
                    res["auroc"][f"{name}_{'centred' if centred else 'past'}"] = float(roc_auc_score(y, v))
        out[kind] = res
    out["paper_table4a"] = PAPER
    json.dump(out, open(sys.argv[3], "w"), indent=1)
    # comparison table: paper (centred, triangle default) vs ours, centred triangle and box, and past triangle
    lines = ["module            | Wazuh: paper  ours-ctr-tri  ours-ctr-box  ours-past-tri | Suricata: paper  ours-ctr-tri  ours-ctr-box  ours-past-tri"]
    for key, (pw, ps) in PAPER.items():
        row = [f"{key:17s}"]
        for kind, p in (("wazuh", pw), ("suricata", ps)):
            a = out[kind]["auroc"]
            if key == "level":
                vals = [a["level"]] * 3
            elif key.startswith("aperiodicity"):
                vals = [a[f"{key}_centred"], float("nan"), a[f"{key}_past"]]
            else:
                vals = [a[f"{key}_triangle_centred"], a[f"{key}_box_centred"], a[f"{key}_triangle_past"]]
            row.append(f"{p:5.2f}  " + "  ".join(f"{v:12.2f}" for v in vals))
        lines.append(" | ".join(row))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
