# Corpus

25 Solidity contracts with known bug locations, used to measure the static
analyzer false positive rate in Module A.

## Provenance

Every contract here is `buggy_contracts/Re-entrancy/buggy_N.sol` from the
[SolidiFI benchmark](https://github.com/DependableSystemsLab/SolidiFI-benchmark),
copied unmodified. SolidiFI takes real verified contracts from Etherscan and
injects reentrancy snippets at recorded locations, which is what gives us
ground truth to score against.

Pragmas across this set are all in the 0.5 series, so the whole corpus compiles
under solc 0.5.17.

## Labels

Each `buggy_N.sol` has a sibling `buggy_N.labels.json`:

```json
{
  "contract": "buggy_1",
  "origin": "SolidiFI-benchmark buggy_contracts/Re-entrancy/buggy_1.sol",
  "bug_type": "Re-entrancy",
  "injections": [{"loc": 22, "length": 8}],
  "bug_lines": [22, 23, 24, 25, 26, 27, 28, 29]
}
```

- `injections` mirrors SolidiFI's `BugLog_N.csv` rows: `loc` is the first line
  of an injected snippet and `length` is how many lines it spans.
- `bug_lines` is that expanded into every injected line, which is what
  `auditor/scan.py` matches findings against. It is the only field the scanner
  requires, so a hand written corpus only needs to supply this one.

Regenerate with `python -m auditor.build_corpus`. See the top level README.
