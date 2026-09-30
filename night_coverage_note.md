# How many awake nights does the baseline need?

ContextAwareSIEM working note — 2026-09-11
Answers the open question left by `baseline_collection_protocol.md` §2 once
running the host continuously for five weeks was ruled out.
Code: `tools/night_coverage_study.py`. Figure: `figures/component6/fig5_night_coverage.png`.

---

## 1. The question

The monitored host is a desktop that has been shut down nightly — measured
25 Aug – 11 Sep 2026 at **50.9% uptime, 12.2 h/day**. Running it continuously
for the whole collection is not practical. The protocol's fallback is a handful
of deliberate full-24-hour nights. This note asks how many, and answers it by
measurement rather than judgement.

Two effects pull in opposite directions and had to be separated:

- **Coverage loss.** Behaviour that only happens at night — scheduled tasks,
  maintenance, backups; the simulator's `nightly` mode — is absent from a
  duty-cycled baseline, so the model has never seen it.
- **Split-budget waste.** `night_fraction` is near-constant on a duty-cycled
  baseline. `component6_isolation_forest.md` §2.2 argues a constant feature is
  worse than an absent one because it still consumes split budget. That argument
  had never been tested.

---

## 2. A bug found on the way, and it matters

`tools/if_study.py` generated each normal-mode event as

```python
day = rng.uniform(0, days)          # <- float
hr  = rng.uniform(h0, h1) % 24
t   = start + day * DAY + hr * HOUR
```

`day` is a **float**, so `day * DAY` carried a random fraction of a day into `t`
and smeared every mode's declared `(h0, h1)` hour window uniformly across the
clock. Verified directly: the `nightly` mode, declared at hours 1–4, generated
alerts uniformly across all 24 hours (per-hour counts 135–380, n=5,671).
`_hour_of()` at the top of the same file is defined and never called — dead code
from the same oversight.

**Consequence: the simulator had no time-of-day structure at all, so
`night_fraction` was pure noise in every study run on it.** Fixed:

```python
day = int(rng.integers(0, max(1, int(math.ceil(days)))))
```

After the fix, with the epoch anchored to local midnight: `nightly` lands at
01:00–04:00 local, `patchday` at 10:00–12:00, `admin` 09:12–18:00,
`interactive` 08:00–19:00 — as declared.

**This does not invalidate the E4 mode-coverage results** (`nightly` −0.027,
`patchday` −0.208): those withheld modes by *name*, removing their rules and
burst patterns, which is a valid manipulation regardless of timing. But any
conclusion in earlier work that depends on *when* alerts arrive is unsupported,
and §5 below flags one E4 number that now needs re-running.

---

## 3. Method

- Baseline 35 days, single host, all five normal modes, duty-cycled to
  **10:00–22:00 local** (12 h/day, matching the measured 12.2). `k` nights are
  held fully open; alerts outside uptime are discarded.
- Evaluation 12 days, 24/7, 2 attack chains/day, disjoint epoch.
- The **active-time correction** of protocol §2.2 is applied in every arm —
  `window_duration_s` and the inter-arrival gaps have detected downtime
  subtracted — so the sweep measures coverage, not the gap artefact.
- `psi = 4096`, stride 10, host-entity model only.
- **Training-pool size held constant** across all `k` (n = 2,342–2,431 depending
  on stream) so the sweep measures *coverage*, not *volume*. Volume is already
  characterised by the E1 learning curve.
- Two feature arms: all fifteen, and fifteen minus `night_fraction`.

---

## 4. Results

Robustness run — mean over 6 forest seeds, then across **3 independent
simulated streams**; ± is the spread across streams.

| Awake nights `k` | all 15 features | `night_fraction` dropped | gain from dropping |
|---|---|---|---|
| 0 | 0.972 ± 0.011 | **0.991 ± 0.002** | **+0.019** |
| 3 | 0.986 ± 0.004 | 0.993 ± 0.002 | +0.007 |
| 5 | 0.988 ± 0.004 | 0.993 ± 0.002 | +0.005 |
| 35 (continuous) | 0.984 ± 0.003 | 0.985 ± 0.002 | +0.002 |

Finer sweep on one stream, 10 forest seeds (the figure): k = 0, 1, 2, 3, 5, 8,
12, 20, 35 → full15 0.978, 0.986, 0.986, 0.989, 0.991, 0.991, 0.989, 0.988,
0.986.

### 4.1 Drop `night_fraction`

**This is the decision that matters, and it is free.** On a duty-cycled baseline
the feature is worth **−0.019 AUC** — it costs more than the entire awake-nights
effect gains. The direction is consistent across all three streams
(−0.015, −0.032, −0.011) and the effect shrinks monotonically as night coverage
improves, exactly as a split-budget explanation predicts.

At full continuous coverage, where the feature finally has real variance
(sd 0.463), it is worth **+0.002** — nothing. So `night_fraction` earns its place
in neither regime. This is the measured confirmation of
`component6_isolation_forest.md` §2.2, which until now was an argument.

### 4.2 Awake nights: three, or none

With `night_fraction` kept, the curve rises steeply from k=0 and has flattened by
**k = 3–5**; nights beyond that buy nothing.

With it dropped, the whole question nearly disappears: k=0 already scores 0.991
and k=5 reaches 0.993 — **+0.002, inside the stream-to-stream spread.**

So the recommendation is: drop the feature, and treat a small number of awake
nights as cheap insurance rather than a requirement. **Three, not thirty-five.**

### 4.3 An anomaly that needs resolving before anything is cited

In the `no_nf` arm, **full continuous coverage (k=35) scores *worse* than the
duty-cycled baseline** — 0.985 against 0.991, consistently across all three
streams. A plausible mechanism: the `nightly` mode is bursty (12-alert bursts),
so a baseline containing it has a wider normal region, and a wider normal region
ranks a bursty attack chain lower.

That is the opposite sign to E4's `nightly` result (−0.027 for withholding it).
The two experiments differ in several ways — E4 ran on the unfixed generator,
used three hosts, and withheld by mode name rather than by time band — so they
are not directly comparable. **E4 should be re-run on the fixed generator before
either number goes in the report.** Until then neither this result nor E4's is
safe to cite on the question of whether broader mode coverage always helps.

---

## 5. What this does and does not support

**Supported:**

- Drop `night_fraction` from the feature set. State the measurement.
- Three deliberate awake nights are sufficient insurance; thirty-five are not
  needed. The uptime constraint is not a threat to the project.
- The split-budget argument for removing constant features is now measured, not
  asserted.

**Not supported, and must not be claimed:**

- Anything about Patch Tuesday. The simulator places `patchday` at 10:00–12:00
  local, inside the duty cycle, so this experiment never tested it. (The
  practical answer comes from elsewhere: Windows Update installs whenever the
  machine is next on, so the burst is captured regardless — shifted in time, not
  missing.)
- That broader mode coverage is neutral or harmful in general. See §4.3.
- Any absolute AUC figure. This is a simulation and characterises the *method's*
  response to a collection choice, not the performance the project will report.

---

## 6. Changes to make

1. `tools/if_study.py` — the `day` bugfix, applied.
2. `system_model.md` §4.2.6 — remove `night_fraction`, cite §4.1 above. The
   feature set becomes fourteen.
3. `baseline_collection_protocol.md` §2.2 — the "drop it or constrain the
   emulation" decision is now settled: drop it. Constraining emulation hours is
   no longer necessary, which returns a degree of freedom to the attack
   scenarios.
4. `COLLECTION_RECORD.md` D.1 — record the decision and its date.
5. Re-run E4 mode coverage on the fixed generator before citing `nightly` or
   `patchday` numbers anywhere.
