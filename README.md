# Autonomous Multi-Agent Smart Contract Auditor

A pipeline that scans Solidity contracts with static analyzers, normalizes the
findings, ranks them, and then verifies them by execution. This repository
currently contains the foundation and **Module A: static scan**.

Module A runs Slither over a labeled corpus, emits a normalized findings list,
and measures the false positive rate against known bug locations. The corpus
comes from [SolidiFI](https://github.com/DependableSystemsLab/SolidiFI-benchmark),
which injects vulnerable snippets into real verified contracts and records
exactly where it put them. That recorded ground truth is what makes the false
positive number a measurement rather than an estimate.

## Layout

```
auditor/
  __init__.py
  scan.py           Module A entrypoint: python -m auditor.scan
  schema.py         findings schema and analyzer output normalization
  build_corpus.py   regenerates the corpus from a SolidiFI checkout
  corpus/           25 contracts, each with a .labels.json of injected bug lines
data/
  findings.csv      one row per finding, written by the scan
  fp_report.md      false positive measurement, written by the scan
requirements.txt
```

## Setup

Python 3.11 is required. Slither's Windows support and the pinned web3 stack are
both happiest there.

```bash
python3.11 -m venv .venv
# Windows:  .venv\Scripts\activate
# POSIX:    source .venv/bin/activate

pip install -r requirements.txt

# Install the compilers the corpus needs. 0.5.17 covers the whole current
# corpus; the others are there so the scan can handle contracts from other
# eras without a code change.
solc-select install 0.4.26 0.5.17 0.6.12 0.8.20

slither --version   # should print 0.11.6
```

## Run

```bash
python -m auditor.scan --corpus auditor/corpus
```

This writes `data/findings.csv` and `data/fp_report.md` and prints a one screen
summary. Useful flags:

| flag | effect |
| --- | --- |
| `--limit N` | scan only the first N contracts, handy while iterating |
| `--timeout N` | per contract analyzer timeout in seconds (default 180) |
| `--keep-raw` | keep the raw Slither JSON under `data/raw/` for debugging |
| `--default-solc V` | compiler to fall back to when no pragma matches |
| `--with-mythril` | also run Mythril (see below) |

Mythril is optional and off by default. A full symbolic execution pass over
this corpus is far too slow to be part of a normal run, so it is not installed
by `requirements.txt` and the runner in `scan.py` was not exercised in the
committed results. To try it: `pip install mythril`, then pass `--with-mythril`.

## Findings schema

Every analyzer row is normalized to the same seven columns, defined in
`auditor/schema.py`:

| column | meaning |
| --- | --- |
| `contract` | corpus unit, i.e. the Solidity file stem such as `buggy_1` |
| `function` | enclosing function as `Contract.function()` when known |
| `line` | 1 based source line the finding is anchored to, 0 when unmapped |
| `detector_id` | analyzer rule id, e.g. `reentrancy-eth` |
| `severity` | exactly one of `High`, `Medium`, `Low`, `Info` |
| `swc_id` | SWC registry id where one applies, otherwise empty |
| `source` | analyzer that produced the row, e.g. `slither` |

`contract` is the file stem rather than the Solidity contract name because the
labels are recorded per file, so the column joins directly against the label
files. The Solidity contract name is preserved inside `function`.

## How the measurement works

**Compiler selection.** Slither compiles with whatever solc is currently
active, so `scan.py` reads each file's pragma, ranks the installed compilers
that satisfy it, and calls `solc-select use` before analyzing. One rule matters
more than the rest: an open ended pragma such as `>=0.5.9` literally admits
0.8.20, but 0.5 era code will not compile there. The ranking therefore adds an
implicit `< next minor` bound, turning `>=0.5.9` into `>=0.5.9 <0.6.0`. Without
that rule two contracts in this corpus fail to compile. Candidates are tried
best first, so a compiler that turns out not to work falls through to the next
one instead of losing the contract.

**Label matching.** Each SolidiFI `BugLog_N.csv` records the first line and the
length of every injected snippet. `build_corpus.py` expands those into the full
set of injected line numbers and writes them to `<contract>.labels.json`. A
finding is scored a true positive when its line is within one line of any
labeled line for the same contract, and a false positive otherwise. The one
line tolerance absorbs the usual off by one between a detector anchoring at a
declaration and anchoring at the statement after it.

**Reading the result.** The overall rate is the headline, but the per detector
table in `fp_report.md` is the number that should drive Module B. Two caveats
are stated in the report itself and are worth repeating: the injected snippets
bring their own functions and state variables, so style rules firing on them
score as true positives without saying anything about the injected bug; and
SolidiFI injects densely enough that a large share of every file is a labeled
line, which means position alone can produce a match. Both push the measured
rate down, so treat it as a lower bound. Module C is the answer to that, since
line proximity is not proof and execution is.

## Regenerating the corpus

The corpus is committed, so this is only needed if you want a different bug
class or a different size.

```bash
git clone https://github.com/DependableSystemsLab/SolidiFI-benchmark
python -m auditor.build_corpus \
    --solidifi SolidiFI-benchmark \
    --out auditor/corpus \
    --bug-type Re-entrancy \
    --count 25
```

Other available `--bug-type` values are the directory names under
`buggy_contracts/`: `Overflow-Underflow`, `TOD`, `Timestamp-Dependency`,
`Unchecked-Send`, `Unhandled-Exceptions`, `tx.origin`.
