#!/usr/bin/env python3
"""Compare a rerun (tools/rerun_tuning_self.sh, files *_self.*) with the saved tuning-set results.

Per item: IDENTICAL (every compared number equal), LAST DIGIT (all differences within one unit in the last
printed digit, e.g. a different library version), DIFFERENT (anything larger, or a changed count), MISSING.
Reports and Holm files are compared line by line for the systems / comparisons present in both, so a saved
file made before an arm existed is still comparable; timing lines are ignored.

usage: compare_rerun.py <rerun_dir> <provenance/ait> <provenance/workstation> <tools/rba_config.json>
"""
import sys, os, re, json

R, P, PW, RBA = sys.argv[1:5]
NUM = re.compile(r"-?\d+\.\d+|-?\d+")
TIMING = re.compile(r"\(\d+s\)|scores \d+s|\d+s\):|seconds|^\[")
results = []


def nums(s):
    return [float(x) for x in NUM.findall(s)]


def verdict_numbers(pairs, tol=0.0015):
    """pairs: list of (label, a_numbers, b_numbers); counts (integers) must match exactly"""
    worst, diffs = 0.0, []
    for lab, a, b in pairs:
        if len(a) != len(b):
            diffs.append(f"{lab}: different shape"); worst = float("inf"); continue
        for x, y in zip(a, b):
            d = abs(x - y)
            if d > 0:
                is_count = float(x).is_integer() and float(y).is_integer()
                worst = max(worst, float("inf") if is_count else d)
                diffs.append(f"{lab}: {y} -> {x}")
    if not pairs:
        return "MISSING", ["nothing comparable"]
    if worst == 0:
        return "IDENTICAL", []
    return ("LAST DIGIT" if worst <= tol else "DIFFERENT"), diffs[:8]


def table_rows(path, start_pat, stop_blank=True):
    """{first token: rest of line} for the table after the header line matching start_pat"""
    rows, on = {}, False
    for line in open(path):
        if re.match(start_pat, line):
            on = True; continue
        if on:
            if not line.strip():
                if stop_blank:
                    break
                continue
            tok = line.split()
            rows[tok[0]] = " ".join(tok[1:])
    return rows


def cmp_report(name, mine, saved):
    if not (os.path.exists(mine) and os.path.exists(saved)):
        results.append((name, "MISSING", [mine if not os.path.exists(mine) else saved])); return
    pairs = []
    for hdr in (r"^system\s+aNDCG@10", r"^system\s+@20\s+binary"):
        a, b = table_rows(mine, hdr), table_rows(saved, hdr)
        for k in sorted(set(a) & set(b)):
            pairs.append((k, nums(a[k].replace("±", " ")), nums(b[k].replace("±", " "))))
    results.append((name, *verdict_numbers(pairs)))


def holm_lines(path):
    out = {}
    for line in open(path):
        m = re.match(r"^(\w+)\s+(\S+)\s+vs\s+(\S+)\s*:\s*n=\s*(\d+)\s+\S+ earlier\s+(\d+), \S+ earlier\s+(\d+), tied\s+(\d+)\s+p=([\d.]+)\s+Holm p=([\d.]+)", line)
        if m:
            out[(m.group(2), m.group(3))] = (m.group(1), [float(x) for x in m.groups()[3:8]], float(m.group(9)))
    return out


def cmp_holm(name, mine, saved):
    if not (os.path.exists(mine) and os.path.exists(saved)):
        results.append((name, "MISSING", [mine if not os.path.exists(mine) else saved])); return
    a, b = holm_lines(mine), holm_lines(saved)
    pairs = []
    for k in sorted(set(a) & set(b)):
        fa, va, ha = a[k]; fb, vb, hb = b[k]
        pairs.append((f"{k[0]} vs {k[1]}", va + ([ha] if fa == fb else []), vb + ([hb] if fa == fb else [])))
    results.append((name, *verdict_numbers(pairs)))


def cmp_text(name, mine, saved, keep=None):
    if not (os.path.exists(mine) and os.path.exists(saved)):
        results.append((name, "MISSING", [mine if not os.path.exists(mine) else saved])); return
    def lines(p):
        L = [l.rstrip() for l in open(p) if l.strip() and not TIMING.search(l)]
        return [l for l in L if keep is None or keep(l)]
    a, b = lines(mine), lines(saved)
    if len(a) != len(b):
        results.append((name, "DIFFERENT", [f"{len(b)} lines saved, {len(a)} now"])); return
    pairs = []
    for x, y in zip(a, b):
        if re.sub(NUM, "#", x) != re.sub(NUM, "#", y):
            results.append((name, "DIFFERENT", [f"saved: {y}", f"now:   {x}"])); return
        pairs.append((x[:40], nums(x), nums(y)))
    results.append((name, *verdict_numbers(pairs)))


def leaves(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("seconds", "t_open", "holdout_start_utc", "T0", "T1", "date", "source"):
                continue
            yield from leaves(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaves(v, f"{path}[{i}]")
    elif isinstance(o, bool) or o is None or isinstance(o, str):
        yield path, o
    elif isinstance(o, (int, float)):
        yield path, float(o)


def cmp_json(name, mine, saved, tol=1e-6, select=None):
    if not (os.path.exists(mine) and os.path.exists(saved)):
        results.append((name, "MISSING", [mine if not os.path.exists(mine) else saved])); return
    a, b = json.load(open(mine)), json.load(open(saved))
    if select:
        a, b = select(a), select(b)
    la, lb = dict(leaves(a)), dict(leaves(b))
    common = sorted(set(la) & set(lb))
    if not common:
        results.append((name, "MISSING", ["no common fields"])); return
    worst, diffs = 0.0, []
    for k in common:
        x, y = la[k], lb[k]
        if isinstance(x, float) and isinstance(y, float):
            d = abs(x - y)
            if d > 0:
                worst = max(worst, d); diffs.append(f"{k}: {y:.6g} -> {x:.6g}")
        elif x != y:
            worst = float("inf"); diffs.append(f"{k}: {y} -> {x}")
    only = len(set(la) ^ set(lb))
    note = [f"{only} fields present in only one file"] if only else []
    if worst == 0:
        results.append((name, "IDENTICAL", note))
    else:
        results.append((name, "LAST DIGIT" if worst <= tol else "DIFFERENT", diffs[:8] + note))


cmp_report("1 all systems: report", f"{R}/eval_tuning_set_self_report.txt", f"{P}/eval_tuning_set_ablations_1031_report.txt")
cmp_holm("1 all systems: paired tests", f"{R}/eval_tuning_set_self_holm.txt", f"{P}/eval_tuning_set_ablations_1031_holm.txt")
cmp_report("1 all systems vs the 27 Oct run", f"{R}/eval_tuning_set_self_report.txt", f"{P}/eval_tuning_set_report.txt")
cmp_report("2 no-reconnaissance: report", f"{R}/eval_tuning_set_noscans_self_report.txt", f"{P}/eval_tuning_set_noscans_report.txt")
cmp_holm("2 no-reconnaissance: paired tests", f"{R}/eval_tuning_set_noscans_self_holm.txt", f"{P}/eval_tuning_set_noscans_holm.txt")
cmp_json("3 forest caches and C8 constants (delta86400 variant)", f"{R}/param_lab_self.json", f"{P}/param_lab.json",
         select=lambda d: {sc: v.get("delta86400") for sc, v in d.items() if isinstance(v, dict)})
cmp_text("3 weight search verdict", f"{R}/weight_lab_verdict_self.txt", f"{P}/weight_lab_verdict.txt")
cmp_json("4 B_RBA configuration", f"{R}/rba_config_self.json", RBA, select=lambda c: {"variants": c["variants"], "weights": c["weights"]})
cmp_text("4 B_RBA selection report", f"{R}/rba_tune_report_self.txt", f"{P}/rba_tune_report.txt")
cmp_text("5 variety as a fifth term", f"{R}/weight_lab_variety_verdict_self.txt", f"{P}/weight_lab_variety_verdict.txt")
cmp_text("6 calibration guard", f"{R}/calib_guard_pooled_self.txt", f"{P}/calib_guard_pooled.txt",
         keep=lambda l: "|" in l or l.startswith("TOTAL"))
cmp_json("7 workstation thresholds", f"{R}/ws_thresholds_self.json", f"{PW}/ws_thresholds.json")
cmp_json("8 workstation false promotion", f"{R}/ws_eval_self.json", f"{PW}/ws_eval.json")
cmp_json("9 window-surprise check", f"{R}/ws_qcheck_self.json", f"{PW}/ws_qcheck.json")

w = max(len(n) for n, _, _ in results)
print("Comparison of this rerun with the saved tuning-set results")
print("IDENTICAL = every number equal; LAST DIGIT = within one unit of the last printed digit; DIFFERENT = look at it\n")
for n, v, d in results:
    print(f"{n:{w}s}  {v}")
    for x in d:
        print(f"{'':{w}s}    {x}")
bad = [n for n, v, _ in results if v in ("DIFFERENT", "MISSING")]
print(f"\n{len(results) - len(bad)} of {len(results)} items identical or within the last digit" + (f"; check: {', '.join(bad)}" if bad else ""))
