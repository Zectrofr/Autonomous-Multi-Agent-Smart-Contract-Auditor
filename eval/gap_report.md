# Model-only vs model-plus-execution gap

Scope: reentrancy subset only. This is a prototype result on the SolidiFI reentrancy corpus plus one execution anchor, not a general claim about all vulnerability classes.

## Counts (n)

- evaluated findings: 693
- execution labels available: 1 (1 confirmed/drained, 0 failed)
- execution labels that join a corpus finding: 0
- live LLM available at run time: no
- truth source per row: execution(anchor)=1, solidifi-line=692

## Gap table

| configuration | precision | recall | fp_rate | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| model-only | 0.993 | 1.000 | 0.417 | 681 | 5 | 0 | 7 |
| model-plus-execution | 0.993 | 1.000 | 0.417 | 681 | 5 | 0 | 7 |
| **GAP (exec - only)** | **+0.000** | **+0.000** | **+0.000** | | | | |

## Verdict

THIN DUE TO N. Live LLM calls were unavailable (no ANTHROPIC_API_KEY), so no corpus reentrancy victims could be labeled by the agent. The only execution label that joins the finding set is the VulnerableVault anchor, which the static model already ranks correctly, so the override changes nothing measurable. This is a small-n artifact, not evidence that execution grounding fails to help.

## Truth source

- solidifi-line: Module A rule, a finding on a SolidiFI-injected line is a true positive. Used for corpus findings with no execution label.
- execution / execution(anchor): the exploit agent's real forge result is the truth. A drained contract is a confirmed true positive. A failed drain is scored here as negative, a known limitation since a failed attempt does not by itself prove the contract is safe.

## Limitations

- The SolidiFI-line truth rule is generous: it marks whole injected functions as bug lines, so nearly every reentrancy finding counts as a true positive and the model-only baseline already sits near the precision ceiling on this subset. That is precisely why corpus execution labels matter. Some findings the line rule calls true would be demoted by a failed drain, which is the correction execution grounding is meant to supply. That correction could not be measured here because no corpus victim could be labeled without the API key.
- The label-to-finding join is at file granularity: a label records the last contract in a victim file, while a file can carry reentrancy findings across several contracts and functions. A confirmed drain therefore promotes a file's reentrancy findings, not one exact line.
