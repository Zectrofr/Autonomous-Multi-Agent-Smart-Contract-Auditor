# Module A false positive report

Static scan of a labeled corpus with Slither. A finding is scored a true positive when its line is within +/-1 of a known injected bug line for the same contract, and a false positive otherwise. The corpus bugs were injected at recorded locations, so every finding away from an injection site is a false positive by construction.

## Corpus

| metric | value |
| --- | ---: |
| contracts in corpus | 25 |
| contracts scanned | 25 |
| contracts skipped | 0 |
| source lines scanned | 11518 |
| labeled bug lines | 5412 |
| labeled line coverage | 47.0% |

## Headline

| metric | value |
| --- | ---: |
| total findings | 3212 |
| true positives | 2786 |
| false positives | 426 |
| overall false positive rate | 13.3% |

## False positive rate by detector

| detector_id | findings | TP | FP | FP rate |
| --- | ---: | ---: | ---: | ---: |
| naming-convention | 1808 | 1569 | 239 | 13.2% |
| reentrancy-unlimited-gas | 489 | 485 | 4 | 0.8% |
| arbitrary-send-eth | 295 | 295 | 0 | 0.0% |
| low-level-calls | 196 | 195 | 1 | 0.5% |
| reentrancy-eth | 196 | 195 | 1 | 0.5% |
| solc-version | 51 | 0 | 51 | 100.0% |
| constable-states | 24 | 15 | 9 | 37.5% |
| external-function | 19 | 3 | 16 | 84.2% |
| too-many-digits | 18 | 1 | 17 | 94.4% |
| unindexed-event-address | 17 | 17 | 0 | 0.0% |
| timestamp | 12 | 0 | 12 | 100.0% |
| missing-zero-check | 11 | 0 | 11 | 100.0% |
| divide-before-multiply | 9 | 0 | 9 | 100.0% |
| boolean-equal | 7 | 0 | 7 | 100.0% |
| incorrect-equality | 7 | 0 | 7 | 100.0% |
| shadowing-local | 7 | 0 | 7 | 100.0% |
| unimplemented-functions | 7 | 6 | 1 | 14.3% |
| events-access | 6 | 0 | 6 | 100.0% |
| reentrancy-events | 4 | 0 | 4 | 100.0% |
| uninitialized-state | 4 | 4 | 0 | 0.0% |
| assembly | 3 | 0 | 3 | 100.0% |
| dead-code | 3 | 0 | 3 | 100.0% |
| unchecked-transfer | 3 | 0 | 3 | 100.0% |
| calls-loop | 2 | 0 | 2 | 100.0% |
| reentrancy-no-eth | 2 | 0 | 2 | 100.0% |
| arbitrary-send-erc20 | 1 | 0 | 1 | 100.0% |
| cache-array-length | 1 | 0 | 1 | 100.0% |
| controlled-array-length | 1 | 0 | 1 | 100.0% |
| costly-loop | 1 | 0 | 1 | 100.0% |
| cyclomatic-complexity | 1 | 0 | 1 | 100.0% |
| events-maths | 1 | 0 | 1 | 100.0% |
| pragma | 1 | 0 | 1 | 100.0% |
| reentrancy-benign | 1 | 0 | 1 | 100.0% |
| shadowing-abstract | 1 | 0 | 1 | 100.0% |
| shadowing-state | 1 | 1 | 0 | 0.0% |
| uninitialized-local | 1 | 0 | 1 | 100.0% |
| write-after-write | 1 | 0 | 1 | 100.0% |

## False positive rate by severity

| severity | findings | TP | FP | FP rate |
| --- | ---: | ---: | ---: | ---: |
| High | 501 | 495 | 6 | 1.2% |
| Medium | 21 | 0 | 21 | 100.0% |
| Low | 44 | 0 | 44 | 100.0% |
| Info | 2646 | 2291 | 355 | 13.4% |

## Skipped contracts

None. Every contract in the corpus compiled and scanned.

## Compiler selected per contract

| solc version | contracts |
| --- | ---: |
| 0.5.17 | 25 |

## How to read this

- Read the per detector table, not the aggregate. The aggregate is driven by whichever detector happens to fire most often, and on this corpus that is a style rule rather than a security rule.
- Some true positive credit is incidental. The injected snippets carry their own functions and state variables, so naming and style rules that fire on them land inside the labeled window and score as true positives even though they say nothing about the injected bug. That pulls the overall rate down.
- The security relevant rows are the ones Module B should rank on: the reentrancy family, arbitrary send, unchecked calls. Rules that fire on the untouched original contract body, such as compiler version and interface rules, are the clean false positives.
- Watch the labeled line coverage figure above. SolidiFI injects densely, so a large share of every file is a labeled line and a finding can match by position alone. The measured false positive rate is therefore a lower bound: the true rate against a sparser ground truth is higher. Module C exists precisely because line proximity is not proof, and it should re-score these rows by execution.
