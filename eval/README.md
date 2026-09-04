# eval/ - Module F evaluation harness (the gap)

The headline result is a gap, not a score: the difference in precision, recall,
and false-positive rate between two triage configurations over the same
reentrancy findings.

- **model-only**: threshold the C1 static score (`triage/scores.csv`).
- **model-plus-execution**: start from C1, then trust the execution-grounded
  labels from the exploit agent (`data/labels.csv`). A finding the agent drained
  is forced true; a finding it tried and failed to drain is demoted.

## Run

```
python -m triage.rank      # produce C1 scores first
python -m eval.harness      # print the gap table, write eval/gap_report.md
```

## Reading the output

`harness.py` prints a table with a row per configuration (precision, recall,
fp_rate, and the confusion counts) and a final GAP line showing the delta. It
also states n (findings, execution labels, how many confirmed), the truth source
per row, and whether the live LLM was available. The same content is written to
`gap_report.md`.

## Truth source, stated honestly

- `solidifi-line`: Module A rule, a finding on a SolidiFI-injected line is a true
  positive. Used for corpus findings with no execution label.
- `execution` / `execution(anchor)`: the exploit agent's real forge result is the
  truth for the reentrancy subset. A drained contract is a confirmed true
  positive. A failed drain is scored as negative, a known limitation.

## Joining

`data/findings.csv` keys findings by file stem (`buggy_N`); `data/labels.csv`
keys labels by the tested Solidity contract name. The harness bridges the two by
re-deriving each corpus file's last `contract X` (the same rule the agent uses),
so a label can be joined back to the file's reentrancy findings. The join is at
file granularity, which the report notes.

## Scope

Reentrancy subset only, small n. The gap table says so. This is a prototype
result on the SolidiFI reentrancy corpus plus one execution anchor
(`VulnerableVault`), not a general claim about all vulnerability classes.
