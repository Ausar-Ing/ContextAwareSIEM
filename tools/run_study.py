#!/usr/bin/env python3
"""Runs the Component 6 sensitivity study and writes figures + results.json."""
from __future__ import annotations
import collections, json, sys, warnings
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, "/home/claude/work")
from if_study import *
from window_builder import FEATURE_NAMES, log_transform

warnings.filterwarnings("ignore")

# --- dataviz palette (light mode, validated categorical slots 1-3) ----------
C1, C2, C3, C4 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#d8d7d2"
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE, "text.color": INK,
    "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.edgecolor": GRID, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 9, "axes.titlesize": 10.5, "legend.frameon": False,
    "lines.linewidth": 2.0, "figure.dpi": 140,
})

SEEDS = list(range(10))
OUT = "/home/claude/work/figures"
import os; os.makedirs(OUT, exist_ok=True)
R = {}

# ---------------------------------------------------------------------------
print("building corpora ...")
rng = np.random.default_rng(7)
BASE_DAYS, EVAL_DAYS = 40, 10
base_stream = gen_stream(rng, days=BASE_DAYS, attacks_per_day=0.0)
eval_stream = gen_stream(rng, days=EVAL_DAYS, attacks_per_day=2.0,
                         start=T0 + (BASE_DAYS + 5) * DAY)
Xb, yb, tb, _, rules = build_windows(base_stream, learn=True)
Xe, ye, te, _, _ = build_windows(eval_stream, baseline_rules=rules)
Xb, Xe = log_transform(Xb), log_transform(Xe)

# host-entity model only, for clarity of the study
hb, he = tb == "host", te == "host"
XB, XE, YE = Xb[hb], Xe[he], ye[he]
# stride subsample the training pool: section 4.3.3
STRIDE = 10
POOL = XB[::STRIDE]
rate = len(base_stream) / BASE_DAYS
R["corpus"] = dict(baseline_alerts=len(base_stream), baseline_alerts_per_day=round(rate),
                   baseline_windows_raw=int(hb.sum()), training_pool_after_stride=len(POOL),
                   eval_windows=len(XE), eval_positive_windows=int(YE.sum()),
                   eval_positive_rate=round(float(YE.mean()), 5))
print("  ", R["corpus"])

# === E1 learning curve =====================================================
print("E1 learning curve ...")
sizes = [50, 100, 250, 500, 1000, 2000, 4000, len(POOL)]
sizes = sorted(set(s for s in sizes if s <= len(POOL)))
e1 = []
for n in sizes:
    a, p = [], []
    for s in SEEDS:
        r = np.random.default_rng(1000 + s)
        idx = r.choice(len(POOL), size=n, replace=False)
        m = fit_iforest(POOL[idx], psi=256, seed=s)
        sc = raw_if_score(m, XE)
        a.append(auc(sc, YE)); p.append(precision_at_k(sc, YE, 20))
    e1.append(dict(n=n, auc_mean=float(np.mean(a)), auc_sd=float(np.std(a)),
                   p20_mean=float(np.mean(p)), p20_sd=float(np.std(p))))
    print(f"   n={n:6d}  AUC {np.mean(a):.3f} +- {np.std(a):.3f}   P@20 {np.mean(p):.3f} +- {np.std(p):.3f}")
R["E1_learning_curve"] = e1

fig, ax = plt.subplots(figsize=(6.4, 3.6))
n_ = [d["n"] for d in e1]; mu = np.array([d["auc_mean"] for d in e1]); sd = np.array([d["auc_sd"] for d in e1])
ax.fill_between(n_, mu - sd, mu + sd, color=C1, alpha=0.16, linewidth=0)
ax.plot(n_, mu, color=C1, marker="o", ms=4.5)
ax.set_xscale("log"); ax.set_xlabel("independent training windows (after stride-10 subsampling)")
ax.set_ylabel("ranking AUC on held-out evaluation")
ax.set_title("Isolation Forest ranking quality vs. baseline size\nband = ±1 sd over 10 seeds", loc="left")
ax.grid(axis="y", alpha=0.5); ax.set_axisbelow(True)
ax.annotate(f"±{sd[0]:.3f}", (n_[0], mu[0]), textcoords="offset points", xytext=(6, -14), color=INK2, fontsize=8)
ax.annotate(f"±{sd[-1]:.3f}", (n_[-1], mu[-1]), textcoords="offset points", xytext=(-34, 8), color=INK2, fontsize=8)
fig.tight_layout(); fig.savefig(f"{OUT}/fig1_learning_curve.png"); plt.close(fig)

# === E2 psi sweep ==========================================================
print("E2 psi sweep ...")
n_fix = min(8000, len(POOL))
psis = [32, 64, 128, 256, 512, 1024, 4096, n_fix]
psis = sorted(set(p for p in psis if p <= n_fix))
e2 = []
for psi in psis:
    a = []
    for s in SEEDS:
        r = np.random.default_rng(2000 + s)
        idx = r.choice(len(POOL), size=n_fix, replace=False)
        m = fit_iforest(POOL[idx], psi=psi, seed=s)
        a.append(auc(raw_if_score(m, XE), YE))
    e2.append(dict(psi=psi, auc_mean=float(np.mean(a)), auc_sd=float(np.std(a))))
    print(f"   psi={psi:6d}  AUC {np.mean(a):.3f} +- {np.std(a):.3f}")
R["E2_psi_sweep"] = e2

fig, ax = plt.subplots(figsize=(6.4, 3.4))
p_ = [d["psi"] for d in e2]; mu = np.array([d["auc_mean"] for d in e2]); sd = np.array([d["auc_sd"] for d in e2])
ax.fill_between(p_, mu - sd, mu + sd, color=C2, alpha=0.16, linewidth=0)
ax.plot(p_, mu, color=C2, marker="o", ms=4.5)
best = int(np.argmax(mu))
ax.scatter([p_[best]], [mu[best]], s=54, facecolor=C2, edgecolor=SURFACE, linewidth=2, zorder=5)
ax.annotate(f"best psi={p_[best]}", (p_[best], mu[best]), textcoords="offset points",
            xytext=(8, 6), color=INK, fontsize=8.5)
ax.set_xscale("log", base=2); ax.set_xlabel("max_samples (psi) — subsample size per tree")
ax.set_ylabel("ranking AUC")
ax.set_title(f"Why psi stays small: training pool fixed at n={n_fix}\nband = ±1 sd over 10 seeds", loc="left")
ax.grid(axis="y", alpha=0.5); ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(f"{OUT}/fig2_psi_sweep.png"); plt.close(fig)

# === E3 method comparison ==================================================
print("E3 method comparison ...")
e3 = collections.defaultdict(list)
for s in SEEDS:
    r = np.random.default_rng(3000 + s)
    idx = r.choice(len(POOL), size=n_fix, replace=False)
    Xtr = POOL[idx]
    m = fit_iforest(Xtr, psi=256, seed=s)
    e3["Isolation Forest"].append(auc(raw_if_score(m, XE), YE))
    e3["max |z| (univariate)"].append(auc(maxz_score(Xtr, XE), YE))
    e3["Mahalanobis (robust)"].append(auc(mahalanobis_score(Xtr, XE, seed=s), YE))
R["E3_methods"] = {k: dict(auc_mean=float(np.mean(v)), auc_sd=float(np.std(v))) for k, v in e3.items()}
for k, v in R["E3_methods"].items():
    print(f"   {k:24s} AUC {v['auc_mean']:.3f} +- {v['auc_sd']:.3f}")

fig, ax = plt.subplots(figsize=(6.4, 2.9))
names = list(e3); vals = [np.mean(e3[k]) for k in names]; errs = [np.std(e3[k]) for k in names]
cols = [C1, C3, C2]
yy = np.arange(len(names))[::-1]
ax.barh(yy, vals, height=0.5, color=cols, edgecolor=SURFACE, linewidth=2)
ax.errorbar(vals, yy, xerr=errs, fmt="none", ecolor=INK2, elinewidth=1.2, capsize=3)
for v, e, y in zip(vals, errs, yy):
    ax.text(v + e + 0.012, y, f"{v:.3f}", va="center", color=INK, fontsize=9)
ax.set_yticks(yy); ax.set_yticklabels(names); ax.set_xlim(0.5, 1.02)
ax.set_xlabel("ranking AUC"); ax.grid(axis="x", alpha=0.5); ax.set_axisbelow(True)
ax.set_title("Does the forest earn its place? (n=%d, 10 seeds)" % n_fix, loc="left")
fig.tight_layout(); fig.savefig(f"{OUT}/fig3_methods.png"); plt.close(fig)

# === E4 mode coverage ======================================================
print("E4 mode coverage ...")
all_modes = list(NORMAL_MODES)
e4 = []
for missing in [None] + all_modes:
    modes = [m for m in all_modes if m != missing]
    r = np.random.default_rng(4242)
    bs = gen_stream(r, days=25, attacks_per_day=0.0, modes=modes)
    Xbm, _, tbm, _, rl = build_windows(bs, learn=True)
    Xbm = log_transform(Xbm)[tbm == "host"][::STRIDE]
    if len(Xbm) < 200:
        continue
    a, fp = [], []
    for s in SEEDS[:5]:
        m = fit_iforest(Xbm, psi=256, seed=s)
        sc = raw_if_score(m, XE)
        a.append(auc(sc, YE))
        top = np.argsort(-sc)[:100]
        fp.append(float((YE[top] == 0).mean()))
    e4.append(dict(missing=missing or "(none — full coverage)",
                   auc_mean=float(np.mean(a)), auc_sd=float(np.std(a)),
                   fp_at_100=float(np.mean(fp))))
    print(f"   missing={str(missing):16s} AUC {np.mean(a):.3f}  FP@100 {np.mean(fp):.3f}")
R["E4_mode_coverage"] = e4

fig, ax = plt.subplots(figsize=(6.4, 3.2))
lbl = [d["missing"] for d in e4]; v = [d["auc_mean"] for d in e4]; er = [d["auc_sd"] for d in e4]
cols = [C3] + [C2] * (len(lbl) - 1)
yy = np.arange(len(lbl))[::-1]
ax.barh(yy, v, height=0.55, color=cols, edgecolor=SURFACE, linewidth=2)
ax.errorbar(v, yy, xerr=er, fmt="none", ecolor=INK2, elinewidth=1.2, capsize=3)
for a_, y in zip(v, yy):
    ax.text(a_ + 0.008, y, f"{a_:.3f}", va="center", color=INK, fontsize=8.5)
ax.set_yticks(yy); ax.set_yticklabels(lbl, fontsize=8.5)
ax.set_xlim(0.4, 1.02); ax.set_xlabel("ranking AUC on the same evaluation set")
ax.set_title("Cost of a normal behaviour mode missing from the baseline\ngreen = baseline covers every mode present at evaluation", loc="left")
ax.grid(axis="x", alpha=0.5); ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(f"{OUT}/fig4_mode_coverage.png"); plt.close(fig)

# === E5 score distribution / calibration ===================================
print("E5 calibration ...")
r = np.random.default_rng(5150)
idx = r.choice(len(POOL), size=n_fix, replace=False)
m = fit_iforest(POOL[idx], psi=256, seed=0)
str_ = raw_if_score(m, POOL[idx]); se = raw_if_score(m, XE)
cal = percentile_calibrate(str_)
R["E5_calibration"] = dict(
    raw_train=dict(min=float(str_.min()), max=float(str_.max()),
                   mean=float(str_.mean()), sd=float(str_.std())),
    raw_eval=dict(min=float(se.min()), max=float(se.max()), mean=float(se.mean()), sd=float(se.std())),
    raw_span_on_0_100=float((se.max() - se.min()) * 100),
    calibrated_sd=float(cal(se).std()),
    raw_p50_p99=[float(np.percentile(se, 50)), float(np.percentile(se, 99))],
)
print("   ", R["E5_calibration"])

fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.1))
ax = axes[0]
ax.hist(se[YE == 0] * 100, bins=60, color=C1, alpha=0.85, label="benign windows")
ax.hist(se[YE == 1] * 100, bins=30, color=C2, alpha=0.9, label="attack windows")
ax.set_xlim(0, 100); ax.set_yscale("log")
ax.set_xlabel("raw score, linearly rescaled to [0,100]"); ax.set_ylabel("windows (log)")
ax.set_title("Raw Isolation Forest score", loc="left"); ax.legend(fontsize=8)
ax.grid(axis="y", alpha=0.4); ax.set_axisbelow(True)
ax = axes[1]
ce = cal(se)
ax.hist(ce[YE == 0], bins=60, color=C1, alpha=0.85, label="benign windows")
ax.hist(ce[YE == 1], bins=30, color=C2, alpha=0.9, label="attack windows")
ax.set_xlim(0, 100); ax.set_yscale("log")
ax.set_xlabel("S_seq = baseline percentile x 100"); ax.set_ylabel("")
ax.set_title("After percentile calibration", loc="left"); ax.legend(fontsize=8)
ax.grid(axis="y", alpha=0.4); ax.set_axisbelow(True)
fig.suptitle("Why S_seq needs calibrating: the raw score never uses its range", x=0.012, ha="left", fontsize=10.5)
fig.tight_layout(rect=(0, 0, 1, 0.93)); fig.savefig(f"{OUT}/fig5_calibration.png"); plt.close(fig)

# === E6 overlap / stride ===================================================
print("E6 stride ...")
e6 = []
for stride in [1, 2, 5, 10, 20]:
    pool = XB[::stride]
    n = min(4000, len(pool))
    a = []
    for s in SEEDS:
        rr = np.random.default_rng(6000 + s)
        ii = rr.choice(len(pool), size=n, replace=False)
        m = fit_iforest(pool[ii], psi=256, seed=s)
        a.append(auc(raw_if_score(m, XE), YE))
    e6.append(dict(stride=stride, rows_available=len(pool), n_used=n,
                   auc_mean=float(np.mean(a)), auc_sd=float(np.std(a))))
    print(f"   stride={stride:3d} rows={len(pool):6d} AUC {np.mean(a):.3f} +- {np.std(a):.3f}")
R["E6_stride"] = e6

json.dump(R, open("/home/claude/work/results.json", "w"), indent=2)
print("\nwrote figures + results.json")
