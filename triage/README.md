# triage/ - Module C1 baseline triage (model-only)

C1 is the yardstick the gap experiment compares against. It scores every finding
in `data/findings.csv` for exploitability using only cheap static metadata, so
the F harness has a model-only ranking to hold up against model-plus-execution.

## Run

```
python -m triage.rank
```

Writes `triage/scores.csv`: every finding plus a `c1_score` column (probability
of being a true, exploitable finding).

## What it is

- `features.py` - the eight static features, each with a one line rationale
  (severity, reentrancy-family flags, SWC-107, a value-moving function name
  test, and whether the finding is tied to a named function). Derived only from
  columns Module A already produced. No source is read, no analyzer re-run.
- `ground_truth.py` - Module A's SolidiFI rule: a finding on a bug-injected line
  (from `auditor/corpus/*.labels.json`) is a true positive. Used to train C1 and
  as the fallback truth in the harness.
- `rank.py` - trains a small logistic regression (`train_model`, reused by the
  harness) and writes the scores.

## Honesty

This is a baseline, not the contribution. A handful of documented features and a
linear model. Scores are in-sample; C1 only needs to rank findings by static
plausibility, and it is not reported as a generalization result.
