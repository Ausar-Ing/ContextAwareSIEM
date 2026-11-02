# Brief: which published methods can be compared with ours, and how

*Self-contained. You need the repository (for the paper draft and the PDFs) and internet access
for the papers. No code, no data download. Report back with the items in Section 7.*

## 1. What this is and why

The supervisor asked for the method to be compared with other papers where possible, and an
ablation study otherwise. One published method is already compared directly: risk-based alerting
after Uetz et al. (`ref26`), reimplemented as `tools/rba.py` and checked against their published
numbers (`provenance/ait/rba_fidelity.txt`). The ablation study is already in the protocol.

What is missing is a defensible answer for every *other* close method: can it be compared with
ours, in numbers or only in words, and if not, why not. Your job is to establish that from the
papers themselves and draft the text the paper needs. You are reading and judging, not
implementing.

## 2. Rules

- **Nothing you produce changes the evaluation.** The comparisons that count are fixed in
  `provenance/ait/PREREGISTRATION.md` and the test run happens once, on Thu 5 Nov. Do not edit
  anything under `tools/` or `provenance/`.
- If you find a method that has **public code, runs on AIT-ADS alerts, and could be run in under a
  day**, tell Anawin by **Wed 4 Nov, 12:00**. Expect it to be added only as an exploratory, post-hoc
  comparison: the freeze is the next day.
- Never run anything on the test scenarios (fox, santos, wardbeck, wilson). You should not need to
  run anything at all.
- Do not contact authors without asking Anawin first.

## 3. What "comparable" has to match

Our setup, so that you can check each paper against it:

| Aspect | Ours |
|---|---|
| Data | AIT Alert Data Set, Zenodo record 8263181 (`ref21`) |
| Scenarios | tuning: harrison, russellmitchell, shaw, wheeler; test (results): fox, santos, wardbeck, wilson |
| Alert source | only the `<scenario>_wazuh.json` files: Wazuh rule alerts plus the Suricata alerts forwarded through Wazuh (the duplicate `fast.log` copy removed). AMiner alerts are not used |
| Unit ranked | queue items: repeat groups (same host and rule, gap at most 24 h), plus notables in B3 |
| Labels | per-alert event labels from the dataset's `alerts_csv` files; used only for scoring and for choosing weights on the tuning set; the detector is trained without labels on each scenario's pre-attack period |
| Main metrics | alpha-nDCG@20; rank of the first queue item of each non-scan attack stage (paired Wilcoxon); MRR; within-host AUC; alert-level macro-AUC |

A published number is **directly comparable** only if the scenario(s), the alert source, the unit
and the metric all match. Anything else is at best a comparison in words.

## 4. Papers to cover

Read the draft first: `References/Deliverable3_ContextAwareSIEM_submission.tex`, sections
*Related Work* and *Experiment Design*. The `refN` numbers below are its bibliography.
PDFs of most are in `References/LiteratureReview/`; the rest are on arXiv or behind the DOI in the
bibliography.

Must cover:
- **`ref27` PACT (Ndichu et al., 2026).** The only other paper we know of that builds a Wazuh alert
  stream from AIT-ADS. This is the most important item; see Section 5.
- **`ref21` Landauer et al. (the dataset paper).** Does it, or the dataset's GitHub page
  (`ait-aecid/alert-data-set`), report any baseline result on the alerts that could sit beside ours?
- **`ref26` Uetz et al.** Already compared. Only record what they report, on which data, with which
  metric, so the table is complete.
- **`ref15` DEEPCASE, `ref5` AlertPro, `ref17` Smart-SIEM, `ref18` Jalalvand et al. (learning to
  defer), `ref29` Freitas et al., `ref9` Shamsi et al., `ref10` Khayat et al., `ref8` Malach et al.
  (CyberShapley), `ref1` Roy and Balde.**

Then search, at most 3 hours: papers that use AIT-ADS (or the AIT Log Data Set's alerts) for alert
prioritization, ranking, aggregation or triage. Start from Google Scholar "Cited by" on `ref21`,
the dataset's GitHub and Zenodo pages, and arXiv for 2025-2026. Include the dataset authors' own
follow-up work on alerts. Only add a paper to the table if it ranks, scores, groups or filters
alerts.

## 5. PACT comparability check

Answer each with a page or section reference:
1. Which AIT-ADS scenarios do they use? Any of fox, santos, wardbeck, wilson?
2. Which alerts: Wazuh only, Suricata, AMiner? How do they build the stream: filtering,
   de-duplication, time range?
3. What is a positive: which event labels, at what unit (alert, event, time interval)?
4. What is the task (screening, classification, ranking) and what labels does the method consume
   during operation (active-learning queries to an analyst)?
5. Which metrics, at which unit, per scenario or pooled?
6. Is their code or derived stream public (URL and commit)?

Verdict, one of:
- **(a) directly comparable:** list exactly which of their numbers and which of ours;
- **(b) comparable after a transformation** we could compute from our saved outputs: describe it.
  It would be reported as post hoc, never as a pre-registered result;
- **(c) not comparable:** the reason in one sentence, as it would appear in the paper.

## 6. Also check our citations

The related-work section quotes specific numbers. For each, confirm it against the paper (page or
table) or report what the paper actually says:
- DEEPCASE: a 90.53% reduction in analyst workload.
- Smart-SIEM: N selected as 30 from 3 to 35; context features add 0.25 to 0.35 F1 across eight
  algorithms; 46,454 labelled events with synthetic oversampling.
- Uetz et al.: best combinations mean AUROC 0.92 against 0.72 for rule level; eight datasets;
  one AIT-ADS scenario; 413 alerts/s (PREREGISTRATION.md Section 9.5).
- PACT: derives a Wazuh alert stream from AIT-ADS.
- Any other number or characterisation in *Related Work* or *Labelled Alert Corpora* about a paper
  you read.

## 7. Report back

One file, `COMPARATORS.md`, sent to Anawin or pushed on a branch `lit/<your-name>` (not `main`):
1. A table, one row per paper: task; unit; labels needed (training / operation); data; uses AIT-ADS
   (which scenarios, which alert source); metrics; code public (URL + commit); verdict (a/b/c); one
   sentence of reason.
2. The PACT answers (Section 5) with page references.
3. Draft paper text: two to five sentences for each group of "not comparable" papers that share a
   reason, written so they can go into the paper's related work or threats section. Plain, no
   claims beyond what the papers say.
4. The citation check (Section 6): OK, or what the paper actually says, with page.
5. Papers found by the search that are not in the bibliography, with full reference and DOI or
   arXiv id.

**Deadlines:** PACT verdict and any runnable candidate by **Wed 4 Nov, 12:00**; the full report by
**Thu 5 Nov, 20:00** (the results and discussion are drafted from Fri 6). Questions go to Anawin.
