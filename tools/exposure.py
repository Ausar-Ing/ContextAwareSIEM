#!/usr/bin/env python3
"""
Component 4 for AIT-ADS: exposure score S_exp from documented host roles.

Roles come from the dataset itself, not from anything the layer infers: the
authors' per-alert CSVs (ait-aecid/alert-data-set, alerts_csv.zip) name the host
behind every agent address (intranet_server, vpn, ...), and the AIT-LDS paper
(Landauer et al., TDSC 2023, Sec. 3.2.1, ref 22) places each role in a network
zone: an intranet with the WordPress intranet server and the Samba file share;
a DMZ with VPN, mail, cloud share and web servers; the firewall joining the
zones and serving internal DNS; and an Internet zone with global DNS and the
external mail servers used by external employees, which the organisation does
not own.

    S_exp = 100 * (criticality + exposure) / 2

  exposure     1   reachable from the Internet (DMZ servers, firewall)
               0.5 intranet, reachable from outside only through the VPN
               0   not an organisational asset (Internet zone)
  criticality  1   holds organisational data or controls access
               0.5 organisational service without core data (web server)
               0   not an organisational asset

The table was fixed from the role descriptions before any ranking result was
computed with it. It is a documented-role proxy, not an asset inventory, which
neither corpus has (Deliverable 3, open point 4).

usage: exposure.py build <alerts_csv_dir> <out.json>    builds the ip -> role table
"""
from __future__ import annotations

import csv
import glob
import json
import os
import sys

ROLE_SCORES = {
    #  role               (criticality, exposure)   zone
    "intranet_server":    (1.0, 0.5),               # intranet: WordPress intranet
    "internal_share":     (1.0, 0.5),               # intranet: Samba file share
    "inet-firewall":      (1.0, 1.0),               # joins zones, internal DNS
    "vpn":                (1.0, 1.0),               # DMZ: remote access
    "mail":               (1.0, 1.0),               # DMZ: organisation's mail server
    "cloud_share":        (1.0, 1.0),               # DMZ: cloud file share
    "webserver":          (0.5, 1.0),               # DMZ: web server
    "external_mail":      (0.0, 0.0),               # Internet: external employees' mail servers
    "inet-dns":           (0.0, 0.0),               # Internet: global DNS
}


def role_of(hostname: str) -> str:
    """AIT host names: fixed role names, plus '<surname>_mail' for the external
    mail servers, whose names are random per scenario."""
    if hostname in ROLE_SCORES:
        return hostname
    if hostname.endswith("_mail"):
        return "external_mail"
    raise KeyError(f"unknown AIT host role: {hostname}")


def s_exp(role: str) -> float:
    c, x = ROLE_SCORES[role]
    return 100.0 * (c + x) / 2.0


def build(csv_dir: str) -> dict:
    """{scenario: {agent_ip: {"host": name, "role": role, "s_exp": score}}}"""
    out = {}
    for f in sorted(glob.glob(os.path.join(csv_dir, "*_alerts.txt"))):
        sc = os.path.basename(f).split("_")[0]
        seen = {}
        for r in csv.DictReader(open(f)):
            if r["name"].startswith("AMiner"):
                continue
            seen.setdefault(r["ip"], r["host"])
        out[sc] = {ip: {"host": h, "role": role_of(h), "s_exp": s_exp(role_of(h))}
                   for ip, h in sorted(seen.items())}
    return out


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "build":
        t = build(sys.argv[2])
        json.dump({"_meta": {"source": "ait-aecid/alert-data-set alerts_csv (ip -> host); roles and zones per "
                                       "Landauer et al. TDSC 2023 Sec. 3.2.1", "formula": "100*(criticality+exposure)/2",
                             "role_scores": {k: list(v) for k, v in ROLE_SCORES.items()}},
                   **t}, open(sys.argv[3], "w"), indent=1)
        for sc, m in t.items():
            print(sc, {v["role"]: v["s_exp"] for v in m.values()})
    else:
        print(__doc__)
