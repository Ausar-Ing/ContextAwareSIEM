#!/usr/bin/env python3
"""Per-scenario AIT-ADS statistics after deduplication, for the paper's dataset table.
usage: ait_stats.py <ait_ads.zip> <labels.csv> <alerts_csv_dir> <out.json> <scenario> [...]"""
import sys, json, zipfile, csv, collections, datetime as dt
zp, lp, cd, out = sys.argv[1:5]
res = {}
ph = collections.defaultdict(list)
for r in csv.DictReader(open(lp)):
    ph[r["scenario"]].append(float(r["start"]))
for sc in sys.argv[5:]:
    lab = collections.defaultdict(list)
    for r in csv.DictReader(open(f"{cd}/{sc}_alerts.txt")):
        nm = r["name"]; nm = nm[7:] if nm.startswith("Wazuh: ") else nm
        if nm.startswith("AMiner"): continue
        lab[(int(r["time"]), r["ip"], nm)].append(r["event_label"])
    t_atk = min(ph[sc]); agents = set(); raw = dup = adm = base = 0; t0 = None; t1 = None
    stage = collections.Counter(); rules = set(); mitre = 0
    with zipfile.ZipFile(zp).open(f"{sc}_wazuh.json") as f:
        for line in f:
            r = json.loads(line); raw += 1
            if r.get("location", "").endswith("suricata/fast.log"):
                dup += 1; continue
            g = set(r["rule"].get("groups", []))
            if g & {"sca", "rootcheck", "policy_monitoring", "ciscat"} or \
               ("syscheck" in g and (r.get("syscheck") or {}).get("mode") == "scheduled"):
                continue
            t = dt.datetime.fromisoformat(r["@timestamp"].replace("Z", "+00:00")).timestamp()
            t0 = t if t0 is None else min(t0, t); t1 = t if t1 is None else max(t1, t)
            adm += 1; agents.add(r["agent"]["id"]); rules.add(r["rule"]["id"])
            if "mitre" in r["rule"]: mitre += 1
            if t < t_atk: base += 1
            k = (int(t), r["agent"].get("ip"), r["rule"]["description"])
            l = lab[k].pop() if lab.get(k) else "-"
            if l != "-": stage[l] += 1
    res[sc] = dict(raw=raw, suricata_dup=dup, admitted=adm, baseline_admitted=base, hosts=len(agents),
                   rules=len(rules), mitre_pct=round(100 * mitre / adm, 1),
                   span_days=round((t1 - t0) / 86400, 1), baseline_days=round((t_atk - t0) / 86400, 1),
                   stages=dict(stage))
    print(sc, res[sc], flush=True)
json.dump(res, open(out, "w"), indent=1)
