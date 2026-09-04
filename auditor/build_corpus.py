"""Build the labeled corpus from a SolidiFI benchmark checkout.

SolidiFI takes real, verified Solidity contracts and injects vulnerable code
snippets at recorded locations. Each buggy_N.sol has a sibling BugLog_N.csv
with the columns:

    loc, length, bug type, approach

where "loc" is the first line of an injected snippet and "length" is how many
lines the snippet spans. This script expands each (loc, length) pair into the
full set of injected line numbers and writes one labels file per contract, so
that auditor/scan.py can score findings without knowing anything about
SolidiFI.

Usage:
    python -m auditor.build_corpus --solidifi <checkout> --out auditor/corpus \
        --bug-type Re-entrancy --count 25

The corpus is committed to the repo, so this only needs rerunning when the
corpus itself changes.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
from pathlib import Path
from typing import List, Tuple

SOLIDIFI_REPO = "https://github.com/DependableSystemsLab/SolidiFI-benchmark"


def _natural_index(path: Path) -> int:
    match = re.search(r"(\d+)", path.stem)
    return int(match.group(1)) if match else 0


def read_bug_log(csv_path: Path) -> Tuple[List[int], List[dict]]:
    """Expand a SolidiFI BugLog into the full set of injected line numbers.

    Parsed defensively: some BugLog files carry UTF-7 style escapes in the bug
    type column ("Re+AC0-erntrancy" for "Re-entrancy") and a few have blank or
    malformed trailing rows, none of which should stop the build.
    """
    bug_lines: set[int] = set()
    injections: List[dict] = []

    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            raw_loc = (row.get("loc") or "").strip()
            raw_len = (row.get("length") or "").strip()
            if not raw_loc.isdigit():
                continue
            loc = int(raw_loc)
            length = int(raw_len) if raw_len.isdigit() and int(raw_len) > 0 else 1
            injections.append({"loc": loc, "length": length})
            # An injected snippet occupies loc .. loc + length - 1 inclusive.
            bug_lines.update(range(loc, loc + length))

    return sorted(bug_lines), injections


def build(solidifi_dir: Path, out_dir: Path, bug_type: str, count: int) -> int:
    src_dir = solidifi_dir / "buggy_contracts" / bug_type
    if not src_dir.is_dir():
        raise SystemExit(
            f"not found: {src_dir}\nClone the benchmark first: git clone {SOLIDIFI_REPO}"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    contracts = sorted(src_dir.glob("buggy_*.sol"), key=_natural_index)

    written = 0
    for sol_path in contracts:
        if written >= count:
            break
        log_path = src_dir / f"BugLog_{_natural_index(sol_path)}.csv"
        if not log_path.exists():
            continue
        bug_lines, injections = read_bug_log(log_path)
        if not bug_lines:
            continue

        shutil.copyfile(sol_path, out_dir / sol_path.name)
        labels = {
            "contract": sol_path.stem,
            "origin": f"SolidiFI-benchmark buggy_contracts/{bug_type}/{sol_path.name}",
            "bug_type": bug_type,
            "injections": injections,
            "bug_lines": bug_lines,
        }
        (out_dir / f"{sol_path.stem}.labels.json").write_text(
            json.dumps(labels, indent=2) + "\n", encoding="utf-8"
        )
        written += 1
        print(f"{sol_path.name}: {len(injections)} injections, {len(bug_lines)} labeled lines")

    print(f"\nwrote {written} contracts and label files to {out_dir}")
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m auditor.build_corpus")
    parser.add_argument("--solidifi", required=True, help="path to a SolidiFI-benchmark checkout")
    parser.add_argument("--out", default="auditor/corpus", help="corpus output directory")
    parser.add_argument("--bug-type", default="Re-entrancy", help="SolidiFI bug class directory")
    parser.add_argument("--count", type=int, default=25, help="how many contracts to take")
    args = parser.parse_args(argv)

    build(Path(args.solidifi).resolve(), Path(args.out).resolve(), args.bug_type, args.count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
