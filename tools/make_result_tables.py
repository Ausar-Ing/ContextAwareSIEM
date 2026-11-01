#!/usr/bin/env python3
"""LaTeX tables for the paper's Results section, generated from ait_eval.py outputs so that no number is
retyped by hand. Built 2026-11-01 for the locked test run (provenance/ait/test/), and tested on the
tuning-set outputs, which have the same format. Statistics are computed exactly as in ait_holm.py
(eval_metrics.paired_ranks; Holm step-down within each family) and checked against it at run time.

Tables written (each a \\begin{table}...\\end{table} block, into one .tex file to \\input):
  tab:res-main      every system: alpha-nDCG@10/20/50 (seed SD for seeded systems), MRR, non-scan coverage@20,
                    macro-AUC, within-host AUC
  tab:res-paired    the pre-registered comparisons by family: earlier / later / tied, Wilcoxon p, Holm p
  tab:res-stages    first-item rank of every non-scan stage occurrence for B0_host, B0_rank, B_RBA, B2, B3
  tab:res-norecon   (with --norecon) key systems without reconnaissance; B2 vs B_RBA paired test
  tab:res-cleaned   (with --cleaned) the cleaned-baseline scenario beside its recorded run
  tab:res-b3        B3 incidents per scenario: incidents, attack / benign, time to first attack notable, stages

usage: make_result_tables.py <wb_dir> <recorded.json> <out.tex> [--norecon <json>] [--cleaned <json>]
                             [--label-note "tuning set, not results"]
"""
import sys, json, argparse, subprocess, os
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("wb"); ap.add_argument("recorded"); ap.add_argument("out")
ap.add_argument("--norecon"); ap.add_argument("--cleaned")
ap.add_argument("--label-note", default="")
args = ap.parse_args()
sys.path.insert(0, args.wb)
import eval_metrics as M

PRIMARY = [("B2", "B0_host"), ("B2", "B0_rank")]
PUBLISHED = [("B2", "B_RBA")]
SECONDARY = [("B2", "B0"), ("B2", "B1"), ("B2", "B2'"), ("B2", "B2_nov"), ("B2", "B2_seq"),
             ("B2", "B2_alert"), ("B2", "B2_max"), ("B2", "B2_pooled"), ("B2", "B2_notime"),
             ("B3", "B2"), ("B3", "B3_bestgrp"), ("B3", "B3_noabs")]
MAIN_ROWS = ["B0", "B1", "B0_rank", "B0_host", "B_RBA", "B2", "B3"]
ABL_ROWS = ["B2'", "B2_nov", "B2_seq", "B2_alert", "B2_max", "B2_pooled", "B2_notime", "B2_def", "B3_bestgrp", "B3_noabs"]
STAGE_SYS = ["B0_host", "B0_rank", "B_RBA", "B2", "B3"]
STAGE_NAMES = {"attacker_change_user": "user change", "escalated_sudo_command": "sudo esc.",
               "dnsteal": "exfiltration", "online_cracking": "password cracking", "crack_passwords": "password cracking"}
NOTE = f" ({args.label_note})" if args.label_note else ""


def tex(name):
    """system name as LaTeX"""
    if name == "B2'":
        return "B2$'$"
    if "_" in name:
        b, s = name.split("_", 1)
        return f"{b}$_\\mathrm{{{s}}}$"
    return name


def load(p):
    return json.load(open(p))


def rows_of(R, sc, name):
    r = R[sc]
    if name in r["seeded"]:
        return r["seeded"][name]
    if name in r["deterministic"]:
        return [r["deterministic"][name]]
    return None


def has(R, name):
    return all(rows_of(R, sc, name) is not None for sc in R)


def mean_metric(R, name, key):
    v = []
    for sc in sorted(R):
        xs = [x.get(key) for x in rows_of(R, sc, name) if x.get(key) is not None]
        xs = [x for x in xs if not (isinstance(x, float) and np.isnan(x))]
        if xs:
            v.append(np.mean(xs))
    return float(np.mean(v)) if v else None


def seed_sd(R, name, key="andcg20"):
    seeds = max(len(rows_of(R, sc, name)) for sc in R)
    if seeds < 2:
        return None
    per = [np.mean([rows_of(R, sc, name)[min(i, len(rows_of(R, sc, name)) - 1)][key] for sc in sorted(R)]) for i in range(seeds)]
    return float(np.std(per))


def coverage(R, name):
    got, tot = 0.0, 0
    for sc in sorted(R):
        xs = [x for x in rows_of(R, sc, name) if "cov20" in x]
        if not xs:
            return None
        got += float(np.mean([x["cov20"]["nonscan"][0] for x in xs])); tot += xs[0]["cov20"]["nonscan"][1]
    return got, tot


def firsts(R, name):
    out = {}
    for sc in sorted(R):
        rows = rows_of(R, sc, name)
        for st in rows[0]["first"]:
            out[(sc, st)] = float(np.mean([x["first"][st] for x in rows if st in x["first"]]))
    return out


def paired_all(R):
    res = []
    for a, b in PRIMARY + PUBLISHED + SECONDARY:
        if not (has(R, a) and has(R, b)):
            res.append((a, b, None)); continue
        res.append((a, b, M.paired_ranks(firsts(R, a), firsts(R, b))))
    adj = {}
    for fam in (PRIMARY, PUBLISHED, SECONDARY):
        ps = [(i, r[2]["wilcoxon_p"]) for i, r in enumerate(res) if r[2] is not None and (r[0], r[1]) in fam]
        m, run = len(ps), 0.0
        for rank, (i, p) in enumerate(sorted(ps, key=lambda x: x[1])):
            run = max(run, min(1.0, (m - rank) * p)); adj[i] = run
    for _, _, r in res:
        if r is not None and not np.isfinite(r["wilcoxon_p"]):
            sys.exit("non-finite Wilcoxon p: scipy missing or broken")
    return res, adj


def f3(x):
    return "--" if x is None else f"{x:.3f}"


def fp(p):
    return "--" if p is None else ("$<$0.001" if p < 0.001 else f"{p:.3f}")


R = load(args.recorded)
scs = sorted(R)
seeds = R[scs[0]]["meta"].get("seeds")
out = [f"% generated by tools/make_result_tables.py from {os.path.basename(args.recorded)}"
       f"{' and ' + os.path.basename(args.norecon) if args.norecon else ''}"
       f"{' and ' + os.path.basename(args.cleaned) if args.cleaned else ''}; do not edit by hand"]

# --- main table
lines = [r"\begin{table*}[t]", rf"\caption{{All systems on {', '.join(scs)}{NOTE}: graded $\alpha$-nDCG@$k$ (mean over scenarios; seeded systems over {seeds} seeds, $\pm$ seed SD of @20), MRR of non-scan stages, non-scan stages first met in the top 20, macro-AUC and within-host AUC}}",
         r"\label{tab:res-main}", r"\centering\footnotesize", r"\begin{tabular}{@{}lccccccc@{}}", r"\toprule",
         r"\textbf{System} & \textbf{@10} & \textbf{@20} & \textbf{@50} & \textbf{MRR} & \textbf{Cov@20} & \textbf{macro-AUC} & \textbf{within-host AUC} \\", r"\midrule"]
for group in (MAIN_ROWS, ABL_ROWS):
    for name in group:
        if not has(R, name):
            continue
        sd = seed_sd(R, name)
        cov = coverage(R, name)
        a20 = f3(mean_metric(R, name, "andcg20")) + (f"$\\pm${sd:.3f}" if sd is not None else "")
        lines.append(f"{tex(name)} & {f3(mean_metric(R, name, 'andcg10'))} & {a20} & {f3(mean_metric(R, name, 'andcg50'))} & "
                     f"{f3(mean_metric(R, name, 'mrr'))} & {('--' if cov is None else f'{cov[0]:.1f}/{cov[1]}')} & "
                     f"{f3(mean_metric(R, name, 'macro_auc'))} & {f3(mean_metric(R, name, 'within_auc'))} \\\\")
    if group is MAIN_ROWS:
        lines.append(r"\midrule")
lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
out += lines

# --- paired comparisons
res, adj = paired_all(R)
lines = [r"\begin{table}[t]", rf"\caption{{Pre-registered paired comparisons of first-item ranks of non-scan stage occurrences{NOTE}: occurrences where the first system is earlier, later or tied; two-sided Wilcoxon $p$; Holm $p$ within each family}}",
         r"\label{tab:res-paired}", r"\centering\footnotesize", r"\setlength{\tabcolsep}{3pt}", r"\begin{tabular}{@{}llccccc@{}}", r"\toprule",
         r"\textbf{Family} & \textbf{Comparison} & \textbf{earlier} & \textbf{later} & \textbf{tied} & $p$ & \textbf{Holm} $p$ \\", r"\midrule"]
fam_name = {**{c: "primary" for c in PRIMARY}, **{c: "published" for c in PUBLISHED}, **{c: "secondary" for c in SECONDARY}}
prev = None
for i, (a, b, p) in enumerate(res):
    fam = fam_name[(a, b)]
    if prev is not None and fam != prev:
        lines.append(r"\midrule")
    prev = fam
    if p is None:
        lines.append(f"{fam} & {tex(a)} vs {tex(b)} & \\multicolumn{{5}}{{c}}{{not available}} \\\\"); continue
    lines.append(f"{fam} & {tex(a)} vs {tex(b)} & {p['a_better']} & {p['b_better']} & {p['tied']} & {fp(p['wilcoxon_p'])} & {fp(adj[i])} \\\\")
lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
out += lines

# --- per-stage first-item ranks
F = {s: firsts(R, s) for s in STAGE_SYS if has(R, s)}
cols = [s for s in STAGE_SYS if s in F]
lines = [r"\begin{table}[t]", rf"\caption{{First-item rank of every non-scan stage occurrence{NOTE} (seeded systems: mean over seeds; lower is earlier)}}",
         r"\label{tab:res-stages}", r"\centering\scriptsize", r"\setlength{\tabcolsep}{3pt}", r"\begin{tabular}{@{}ll" + "r" * len(cols) + r"@{}}", r"\toprule",
         r"\textbf{Scenario} & \textbf{Stage} & " + " & ".join(rf"\textbf{{{tex(c)}}}" for c in cols) + r" \\", r"\midrule"]
keys = sorted(k for k in F[cols[0]] if k[1] not in M.SCANS)
for sc, st in keys:
    lines.append(f"{sc} & {STAGE_NAMES.get(st, st.replace('_', ' '))} & " + " & ".join(f"{F[c].get((sc, st), float('nan')):.1f}" for c in cols) + r" \\")
lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
out += lines

# --- no-reconnaissance condition
if args.norecon:
    N = load(args.norecon)
    lines = [r"\begin{table}[t]", rf"\caption{{No-reconnaissance condition{NOTE}: scan alerts removed from the stream; $\alpha$-nDCG@20 and MRR beside the main run, and the pre-registered paired test of B2 against B$_\mathrm{{RBA}}$}}",
             r"\label{tab:res-norecon}", r"\centering\footnotesize", r"\begin{tabular}{@{}lcccc@{}}", r"\toprule",
             r"& \multicolumn{2}{c}{\textbf{main run}} & \multicolumn{2}{c}{\textbf{no recon.}} \\", r"\textbf{System} & @20 & MRR & @20 & MRR \\", r"\midrule"]
    for name in ["B0_host", "B0_rank", "B_RBA", "B2", "B3"]:
        if has(R, name) and has(N, name):
            lines.append(f"{tex(name)} & {f3(mean_metric(R, name, 'andcg20'))} & {f3(mean_metric(R, name, 'mrr'))} & "
                         f"{f3(mean_metric(N, name, 'andcg20'))} & {f3(mean_metric(N, name, 'mrr'))} \\\\")
    p = M.paired_ranks(firsts(N, "B2"), firsts(N, "B_RBA"))
    if not np.isfinite(p["wilcoxon_p"]):
        sys.exit("non-finite Wilcoxon p: scipy missing or broken")
    lines += [r"\midrule", rf"\multicolumn{{5}}{{@{{}}p{{0.9\columnwidth}}@{{}}}}{{B2 vs B$_\mathrm{{RBA}}$ without reconnaissance: B2 earlier {p['a_better']}, later {p['b_better']}, tied {p['tied']}; $p$ = {fp(p['wilcoxon_p'])}}} \\",
              r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    out += lines

# --- cleaned baseline beside recorded
if args.cleaned:
    Cl = load(args.cleaned)
    lines = [r"\begin{table}[t]", rf"\caption{{Contaminated scenario{NOTE}: recorded baseline (headline) and the baseline with its labelled exfiltration alerts removed from training}}",
             r"\label{tab:res-cleaned}", r"\centering\footnotesize", r"\begin{tabular}{@{}llcccc@{}}", r"\toprule",
             r"\textbf{Scenario} & \textbf{System} & \multicolumn{2}{c}{\textbf{recorded}} & \multicolumn{2}{c}{\textbf{cleaned}} \\", r"& & @20 & MRR & @20 & MRR \\", r"\midrule"]
    for sc in sorted(Cl):
        if sc not in R:
            continue
        Rs, Cs = {sc: R[sc]}, {sc: Cl[sc]}
        for name in ["B_RBA", "B2", "B3"]:
            if has(Rs, name) and has(Cs, name):
                lines.append(f"{sc} & {tex(name)} & {f3(mean_metric(Rs, name, 'andcg20'))} & {f3(mean_metric(Rs, name, 'mrr'))} & "
                             f"{f3(mean_metric(Cs, name, 'andcg20'))} & {f3(mean_metric(Cs, name, 'mrr'))} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    out += lines

# --- B3 incidents
lines = [r"\begin{table}[t]", rf"\caption{{Entity risk accumulation (B3){NOTE}, seed 0: incidents, those containing an attack alert, benign incidents, hours from the first attack step to the first attack notable, and the most stages in one incident}}",
         r"\label{tab:res-b3}", r"\centering\footnotesize", r"\setlength{\tabcolsep}{4pt}", r"\begin{tabular}{@{}lccccc@{}}", r"\toprule",
         r"\textbf{Scenario} & \textbf{incid.} & \textbf{attack} & \textbf{benign} & \textbf{time (h)} & \textbf{stages} \\", r"\midrule"]
for sc in scs:
    b = R[sc]["seeded"]["B3"][0]
    t = "--" if b["time_to_notable_h"] is None else f"{b['time_to_notable_h']:.1f}"
    lines.append(f"{sc} & {b['incidents']} & {b['attack_incidents']} & {b['benign_incidents']} & {t} & {b['max_stages_in_incident']} \\\\")
lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
out += lines

open(args.out, "w").write("\n".join(out) + "\n")

# consistency check against ait_holm.py (same statistics, independent code path)
holm = subprocess.run([sys.executable, os.path.join(args.wb, "ait_holm.py"), args.wb, args.recorded], capture_output=True, text=True)
if holm.returncode == 0:
    import re
    for i, (a, b, p) in enumerate(res):
        if p is None:
            continue
        m = re.search(rf"{re.escape(a)}\s+vs\s+{re.escape(b)}\s*:.*?p=([0-9.]+)\s+Holm p=([0-9.]+)", holm.stdout)
        if not m or abs(float(m.group(1)) - p["wilcoxon_p"]) > 6e-4 or abs(float(m.group(2)) - adj[i]) > 6e-4:
            sys.exit(f"mismatch with ait_holm.py for {a} vs {b}")
    print(f"wrote {args.out}; statistics agree with ait_holm.py")
else:
    print(f"wrote {args.out}; ait_holm.py check skipped ({holm.stderr.strip()[:120]})")
