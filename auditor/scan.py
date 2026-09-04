"""Module A: static scan.

Runs Slither over a labeled corpus of Solidity contracts, normalizes every
finding into the shared schema, and measures the false positive rate against
the known bug locations that ship with the corpus.

Usage:
    python -m auditor.scan --corpus auditor/corpus

Outputs:
    data/findings.csv   one row per finding, schema from auditor.schema
    data/fp_report.md   false positive measurement over the scanned corpus

The corpus layout this expects is one Solidity file plus one labels file per
contract:

    auditor/corpus/buggy_1.sol
    auditor/corpus/buggy_1.labels.json

A labels file is JSON with at least a "bug_lines" list of 1 based line numbers
naming every line of injected vulnerable code.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from auditor.schema import (
    FIELDNAMES,
    describe_slither_json,
    make_finding,
    parse_slither_json,
)

# A finding counts as a true positive when its line sits within this many lines
# of a labeled bug line. SolidiFI records the first line of each injected
# snippet, and analyzers frequently anchor one line off (at the opening brace,
# or at the statement after a declaration), so a one line window is the
# conventional tolerance.
LINE_TOLERANCE = 1

# Fallback compiler when a file has no parseable pragma. Overridable via CLI.
DEFAULT_SOLC = "0.8.20"

# How many ranked solc candidates to try before giving up on a contract.
MAX_SOLC_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# solc selection
# ---------------------------------------------------------------------------
#
# Slither compiles with whatever solc is currently active, so before each
# contract we have to point solc-select at a compiler the file's pragma
# actually accepts. The logic is:
#
#   1. Read every "pragma solidity ..." line from the file.
#   2. Split the pragma body into (operator, version) constraints. Pragmas are
#      a conjunction by default ("^0.5.0", ">=0.4.22 <0.6.0"), with "||" giving
#      alternatives.
#   3. Apply an implicit upper bound. A pragma like ">=0.5.9" is technically
#      open ended, so a literal reading admits 0.8.20, but 0.5 era code does
#      not compile on 0.8. Real contracts written against ">=0.5.9" mean
#      "0.5.x", so when a constraint group has no explicit "<" or "<=" we cap
#      it at the next minor release above its highest lower bound. This is the
#      single most important rule here: without it, every open ended pragma in
#      the corpus picks a compiler that cannot parse the file.
#   4. Rank the installed compilers that satisfy the capped constraints,
#      highest first, because later patch releases within a minor series carry
#      bug fixes and Slither's parser is happier on them.
#   5. Fall back, in order, to compilers that satisfy the uncapped constraints
#      and finally to DEFAULT_SOLC. The scan tries the ranked candidates in
#      turn, so a compiler that turns out not to work is not fatal.

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_CONSTRAINT_RE = re.compile(r"(>=|<=|>|<|\^|~|=)?\s*v?(\d+)\.(\d+)(?:\.(\d+))?")

Version = Tuple[int, int, int]


def _parse_version(text: str) -> Optional[Version]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?", text.strip())
    if not match:
        return None
    major, minor, patch = match.group(1), match.group(2), match.group(3)
    return (int(major), int(minor), int(patch or 0))


def _constraint_satisfied(version: Version, op: Optional[str], bound: Version) -> bool:
    """Evaluate one npm style semver constraint against a concrete version."""
    if op in (None, "", "="):
        return version == bound
    if op == ">=":
        return version >= bound
    if op == "<=":
        return version <= bound
    if op == ">":
        return version > bound
    if op == "<":
        return version < bound
    if op == "^":
        # Caret allows changes that do not modify the leftmost nonzero part.
        # Solidity versions are all 0.x, so ^0.5.2 means >=0.5.2 <0.6.0.
        if bound[0] == 0:
            return version >= bound and version[:2] == bound[:2]
        return version >= bound and version[0] == bound[0]
    if op == "~":
        # Tilde allows patch level changes: ~0.5.2 means >=0.5.2 <0.6.0.
        return version >= bound and version[:2] == bound[:2]
    return False


def _pragma_constraints(text: str) -> List[List[Tuple[Optional[str], Version]]]:
    """Return the pragma as a list of alternative conjunctions.

    Each element of the outer list is one "||" alternative; each inner list is
    a set of constraints that must all hold.
    """
    alternatives: List[List[Tuple[Optional[str], Version]]] = []
    for raw_pragma in _PRAGMA_RE.findall(text):
        for branch in raw_pragma.split("||"):
            group: List[Tuple[Optional[str], Version]] = []
            for op, major, minor, patch in _CONSTRAINT_RE.findall(branch):
                bound = (int(major), int(minor), int(patch or 0))
                # A bare "0.5.11" inside a range with no operator is an exact
                # pin; a bare version as the entire pragma is also exact.
                group.append((op or "=", bound))
            if group:
                alternatives.append(group)
    return alternatives


def _cap_open_ended(
    group: Sequence[Tuple[Optional[str], Version]]
) -> List[Tuple[Optional[str], Version]]:
    """Add an implicit "< next minor" bound to a group that has no upper bound.

    ">=0.5.9" becomes ">=0.5.9 <0.6.0". A group that already carries a "<" or
    "<=" constraint, or that pins an exact version, is returned unchanged.
    """
    capped = list(group)
    if any(op in ("<", "<=") for op, _ in capped):
        return capped
    lower_bounds = [bound for op, bound in capped if op in (">=", ">", "^", "~", "=")]
    if not lower_bounds:
        return capped
    highest = max(lower_bounds)
    capped.append(("<", (highest[0], highest[1] + 1, 0)))
    return capped


def rank_solc_versions(
    source_text: str, installed: Sequence[str]
) -> List[Tuple[str, str]]:
    """Rank installed solc versions for a source file, best candidate first.

    Each entry is (version_string, reason). The reason is carried into the scan
    log so the compiler choice stays auditable.
    """
    parsed_installed = [(v, _parse_version(v)) for v in installed]
    parsed_installed = [(v, p) for v, p in parsed_installed if p is not None]
    parsed_installed.sort(key=lambda item: item[1], reverse=True)

    alternatives = _pragma_constraints(source_text)
    if not alternatives:
        return [(DEFAULT_SOLC, "no pragma found, using default")]

    ranked: List[Tuple[str, str]] = []
    seen: set = set()

    def add(version_str: str, reason: str) -> None:
        if version_str not in seen:
            seen.add(version_str)
            ranked.append((version_str, reason))

    capped = [_cap_open_ended(group) for group in alternatives]
    for pool, reason in ((capped, "matches pragma"), (alternatives, "matches open ended pragma")):
        for version_str, version in parsed_installed:
            for group in pool:
                if all(_constraint_satisfied(version, op, bound) for op, bound in group):
                    add(version_str, reason)
                    break

    add(DEFAULT_SOLC, "no installed solc satisfies the pragma, using default")
    return ranked


def pick_solc_version(source_text: str, installed: Sequence[str]) -> Tuple[str, str]:
    """Best single solc for a source file. Thin wrapper over rank_solc_versions."""
    return rank_solc_versions(source_text, installed)[0]


def installed_solc_versions(env: Dict[str, str]) -> List[str]:
    """Ask solc-select which compilers are available locally."""
    try:
        proc = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    versions = []
    for line in proc.stdout.splitlines():
        # Output lines look like "0.5.17" or "0.8.20 (current, set by ...)".
        token = line.strip().split()[0] if line.strip() else ""
        if _parse_version(token):
            versions.append(token)
    return versions


def use_solc(version: str, env: Dict[str, str]) -> bool:
    """Activate a solc version. Returns False when solc-select refuses."""
    try:
        proc = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


# ---------------------------------------------------------------------------
# Analyzer runners
# ---------------------------------------------------------------------------


def _error_summary(proc: subprocess.CompletedProcess) -> str:
    """Pull the most informative line out of a failed analyzer invocation.

    solc prints the diagnostic first and then several lines of source context
    and caret markers, so the last line of output is almost always useless.
    Prefer the first line that looks like an actual error message.
    """
    text = f"{proc.stderr or ''}\n{proc.stdout or ''}"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith(("error", "typeerror", "parsererror", "declarationerror")):
            return stripped[:200]
        if "error:" in lowered or "not found" in lowered:
            return stripped[:200]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:200] if lines else f"exit code {proc.returncode}"


def run_slither(
    sol_path: Path,
    json_out: Path,
    env: Dict[str, str],
    timeout: int,
) -> Tuple[Optional[Any], str]:
    """Run Slither on one file and return (parsed_json, error_message).

    Slither exits nonzero whenever it found issues, so the exit code says
    nothing about success. The JSON document is the source of truth: if it
    exists and parses, the analysis ran.
    """
    if json_out.exists():
        json_out.unlink()

    cmd = [
        "slither",
        str(sol_path),
        "--json",
        str(json_out),
        "--disable-color",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            cwd=str(sol_path.parent),
        )
    except subprocess.TimeoutExpired:
        return None, f"slither timed out after {timeout}s"
    except OSError as exc:
        return None, f"could not launch slither: {exc}"

    if not json_out.exists():
        return None, f"slither produced no JSON ({_error_summary(proc)})"

    try:
        doc = json.loads(json_out.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"slither JSON unreadable: {exc}"

    # Verify the document actually reports success before trusting its results.
    if isinstance(doc, dict) and doc.get("success") is False:
        return None, f"slither reported failure: {doc.get('error')}"

    return doc, ""


def run_mythril(
    sol_path: Path,
    contract: str,
    env: Dict[str, str],
    timeout: int,
) -> Tuple[List[Dict[str, Any]], str]:
    """Optional Mythril pass. Off by default because it is far too slow here.

    Kept small and defensive on purpose. It was not exercised during the corpus
    run that produced the committed report, so treat it as a starting point
    rather than a validated path.
    """
    if shutil.which("myth") is None:
        return [], "mythril requested but 'myth' is not on PATH"

    cmd = ["myth", "analyze", str(sol_path), "-o", "json"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, env=env, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return [], f"mythril timed out after {timeout}s"
    except OSError as exc:
        return [], f"could not launch mythril: {exc}"

    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [], "mythril output was not JSON"

    issues = doc.get("issues") if isinstance(doc, dict) else None
    rows: List[Dict[str, Any]] = []
    for issue in issues or []:
        if not isinstance(issue, dict):
            continue
        rows.append(
            make_finding(
                contract=contract,
                function=issue.get("function") or "",
                line=int(issue.get("lineno") or 0),
                detector_id=str(issue.get("swc-id") or issue.get("title") or "unknown"),
                severity=issue.get("severity"),
                source="mythril",
                swc_id=f"SWC-{issue['swc-id']}" if issue.get("swc-id") else "",
            )
        )
    return rows, ""


# ---------------------------------------------------------------------------
# Corpus and labels
# ---------------------------------------------------------------------------


def load_labels(labels_path: Path) -> List[int]:
    """Read the injected bug lines for one contract.

    The labels file records every line of every injected snippet, not just the
    first line, so that a finding anchored anywhere inside an injected block is
    recognized. See auditor/corpus/README.md for how these were derived.
    """
    try:
        doc = json.loads(labels_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    lines = doc.get("bug_lines") if isinstance(doc, dict) else None
    if not isinstance(lines, list):
        return []
    return sorted({int(n) for n in lines if isinstance(n, (int, float)) and int(n) > 0})


def is_true_positive(line: int, bug_lines: Sequence[int], tolerance: int = LINE_TOLERANCE) -> bool:
    """Label matching: a finding is a true positive when it lands on (or within
    `tolerance` lines of) a known injected bug line for that same contract.

    SolidiFI injects bugs at known locations, so by construction anything
    reported anywhere else in the file is a false positive for this experiment.
    Findings with no usable source mapping arrive as line 0 and can never match.
    """
    if line <= 0 or not bug_lines:
        return False
    return any(abs(line - bug_line) <= tolerance for bug_line in bug_lines)


def discover_corpus(corpus_dir: Path) -> List[Tuple[Path, Path]]:
    """Return sorted (sol_path, labels_path) pairs found in the corpus dir."""
    pairs = []
    for sol_path in sorted(corpus_dir.glob("*.sol"), key=_natural_key):
        labels_path = sol_path.with_suffix("").with_suffix(".labels.json")
        if not labels_path.exists():
            labels_path = sol_path.parent / f"{sol_path.stem}.labels.json"
        pairs.append((sol_path, labels_path))
    return pairs


def _natural_key(path: Path):
    """Sort buggy_2 before buggy_10 so logs read in a sensible order."""
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", path.stem)]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def write_findings_csv(rows: List[Dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in FIELDNAMES})


def _rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a"
    return f"{100.0 * numerator / denominator:.1f}%"


def write_fp_report(
    rows: List[Dict[str, Any]],
    verdicts: List[bool],
    scanned: List[str],
    skipped: List[Tuple[str, str]],
    corpus_size: int,
    out_path: Path,
    solc_choices: Dict[str, str],
    line_stats: Dict[str, Tuple[int, int]],
) -> Dict[str, Any]:
    """Write data/fp_report.md and return the headline numbers."""
    total = len(rows)
    tp = sum(1 for verdict in verdicts if verdict)
    fp = total - tp

    per_detector: Dict[str, Counter] = defaultdict(Counter)
    for row, verdict in zip(rows, verdicts):
        bucket = per_detector[row["detector_id"]]
        bucket["total"] += 1
        bucket["tp" if verdict else "fp"] += 1

    per_severity: Dict[str, Counter] = defaultdict(Counter)
    for row, verdict in zip(rows, verdicts):
        bucket = per_severity[row["severity"]]
        bucket["total"] += 1
        bucket["tp" if verdict else "fp"] += 1

    lines: List[str] = []
    lines.append("# Module A false positive report")
    lines.append("")
    lines.append(
        "Static scan of a labeled corpus with Slither. A finding is scored a "
        f"true positive when its line is within +/-{LINE_TOLERANCE} of a known "
        "injected bug line for the same contract, and a false positive "
        "otherwise. The corpus bugs were injected at recorded locations, so "
        "every finding away from an injection site is a false positive by "
        "construction."
    )
    lines.append("")

    total_source_lines = sum(stats[0] for stats in line_stats.values())
    total_labeled_lines = sum(stats[1] for stats in line_stats.values())

    lines.append("## Corpus")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("| --- | ---: |")
    lines.append(f"| contracts in corpus | {corpus_size} |")
    lines.append(f"| contracts scanned | {len(scanned)} |")
    lines.append(f"| contracts skipped | {len(skipped)} |")
    lines.append(f"| source lines scanned | {total_source_lines} |")
    lines.append(f"| labeled bug lines | {total_labeled_lines} |")
    lines.append(
        f"| labeled line coverage | {_rate(total_labeled_lines, total_source_lines)} |"
    )
    lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("| --- | ---: |")
    lines.append(f"| total findings | {total} |")
    lines.append(f"| true positives | {tp} |")
    lines.append(f"| false positives | {fp} |")
    lines.append(f"| overall false positive rate | {_rate(fp, total)} |")
    lines.append("")

    lines.append("## False positive rate by detector")
    lines.append("")
    lines.append("| detector_id | findings | TP | FP | FP rate |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for detector, bucket in sorted(
        per_detector.items(), key=lambda item: (-item[1]["total"], item[0])
    ):
        lines.append(
            f"| {detector} | {bucket['total']} | {bucket['tp']} | {bucket['fp']} | "
            f"{_rate(bucket['fp'], bucket['total'])} |"
        )
    lines.append("")

    lines.append("## False positive rate by severity")
    lines.append("")
    lines.append("| severity | findings | TP | FP | FP rate |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for severity in ("High", "Medium", "Low", "Info"):
        bucket = per_severity.get(severity)
        if not bucket:
            continue
        lines.append(
            f"| {severity} | {bucket['total']} | {bucket['tp']} | {bucket['fp']} | "
            f"{_rate(bucket['fp'], bucket['total'])} |"
        )
    lines.append("")

    lines.append("## Skipped contracts")
    lines.append("")
    if skipped:
        lines.append("| contract | reason |")
        lines.append("| --- | --- |")
        for name, reason in skipped:
            lines.append(f"| {name} | {reason} |")
    else:
        lines.append("None. Every contract in the corpus compiled and scanned.")
    lines.append("")

    lines.append("## Compiler selected per contract")
    lines.append("")
    version_counts = Counter(solc_choices.values())
    lines.append("| solc version | contracts |")
    lines.append("| --- | ---: |")
    for version, count in sorted(version_counts.items()):
        lines.append(f"| {version} | {count} |")
    lines.append("")

    lines.append("## How to read this")
    lines.append("")
    lines.append(
        "- Read the per detector table, not the aggregate. The aggregate is "
        "driven by whichever detector happens to fire most often, and on this "
        "corpus that is a style rule rather than a security rule."
    )
    lines.append(
        "- Some true positive credit is incidental. The injected snippets "
        "carry their own functions and state variables, so naming and style "
        "rules that fire on them land inside the labeled window and score as "
        "true positives even though they say nothing about the injected bug. "
        "That pulls the overall rate down."
    )
    lines.append(
        "- The security relevant rows are the ones Module B should rank on: "
        "the reentrancy family, arbitrary send, unchecked calls. Rules that "
        "fire on the untouched original contract body, such as compiler "
        "version and interface rules, are the clean false positives."
    )
    lines.append(
        "- Watch the labeled line coverage figure above. SolidiFI injects "
        "densely, so a large share of every file is a labeled line and a "
        "finding can match by position alone. The measured false positive rate "
        "is therefore a lower bound: the true rate against a sparser ground "
        "truth is higher. Module C exists precisely because line proximity is "
        "not proof, and it should re-score these rows by execution."
    )
    lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")

    return {
        "total": total,
        "tp": tp,
        "fp": fp,
        "fp_rate": _rate(fp, total),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor.scan",
        description="Module A: scan a labeled Solidity corpus and measure the "
        "static analyzer false positive rate.",
    )
    parser.add_argument(
        "--corpus",
        default="auditor/corpus",
        help="directory holding .sol files and matching .labels.json files",
    )
    parser.add_argument(
        "--out-dir",
        default="data",
        help="directory for findings.csv and fp_report.md",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="per contract analyzer timeout in seconds",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="scan at most N contracts (0 means all)",
    )
    parser.add_argument(
        "--default-solc",
        default=DEFAULT_SOLC,
        help="compiler to fall back to when no pragma matches an installed solc",
    )
    parser.add_argument(
        "--with-mythril",
        action="store_true",
        help="also run Mythril. Off by default: far too slow for a full corpus.",
    )
    parser.add_argument(
        "--keep-raw",
        action="store_true",
        help="keep the raw analyzer JSON under <out-dir>/raw for debugging",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    global DEFAULT_SOLC
    DEFAULT_SOLC = args.default_solc

    corpus_dir = Path(args.corpus).resolve()
    out_dir = Path(args.out_dir).resolve()
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if not corpus_dir.is_dir():
        print(f"ERROR: corpus directory not found: {corpus_dir}", file=sys.stderr)
        return 2

    env = dict(os.environ)

    if shutil.which("slither") is None:
        print("ERROR: 'slither' is not on PATH. Activate the venv first.", file=sys.stderr)
        return 2

    installed = installed_solc_versions(env)
    if not installed:
        print(
            "WARNING: solc-select reported no installed compilers. "
            "Run 'solc-select install 0.5.17 0.8.20' first.",
            file=sys.stderr,
        )
    print(f"solc versions available: {', '.join(installed) if installed else 'none'}")

    pairs = discover_corpus(corpus_dir)
    if args.limit:
        pairs = pairs[: args.limit]
    corpus_size = len(pairs)
    print(f"corpus: {corpus_size} contracts in {corpus_dir}")
    print("")

    all_rows: List[Dict[str, Any]] = []
    all_verdicts: List[bool] = []
    scanned: List[str] = []
    skipped: List[Tuple[str, str]] = []
    solc_choices: Dict[str, str] = {}
    # contract -> (source line count, labeled bug line count), used to report
    # how much of the corpus is labeled and therefore how generous the line
    # proximity match is.
    line_stats: Dict[str, Tuple[int, int]] = {}
    shape_reported = False
    active_solc: Optional[str] = None

    for index, (sol_path, labels_path) in enumerate(pairs, start=1):
        contract = sol_path.stem
        prefix = f"[{index}/{corpus_size}] {contract}"

        try:
            source_text = sol_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            skipped.append((contract, f"unreadable source: {exc}"))
            print(f"{prefix}: SKIP unreadable source")
            continue

        # Pick and activate a compiler this file's pragma accepts. Candidates
        # are tried best first: a pragma can admit several installed compilers
        # and only some of them actually parse the file, so a failed compile
        # falls through to the next candidate instead of skipping the contract.
        candidates = rank_solc_versions(source_text, installed)[:MAX_SOLC_ATTEMPTS]
        json_out = raw_dir / f"{contract}.slither.json"
        doc = None
        error = "no solc candidate available"
        version = candidates[0][0] if candidates else DEFAULT_SOLC
        reason = ""

        for version, reason in candidates:
            if version != active_solc:
                if not use_solc(version, env):
                    error = f"solc-select could not activate {version}"
                    continue
                active_solc = version
            doc, error = run_slither(sol_path, json_out, env, args.timeout)
            if doc is not None:
                break

        solc_choices[contract] = version
        if doc is None:
            skipped.append((contract, error))
            print(f"{prefix}: SKIP {error}")
            continue

        # Report the observed JSON shape once, so a future Slither release that
        # renames fields is obvious in the log rather than silently returning
        # zero findings.
        if not shape_reported:
            print(f"slither JSON shape: {describe_slither_json(doc)}")
            print("")
            shape_reported = True

        rows = parse_slither_json(doc, contract=contract, target_basename=sol_path.name)

        if args.with_mythril:
            myth_rows, myth_error = run_mythril(sol_path, contract, env, args.timeout)
            if myth_error:
                print(f"{prefix}: mythril note: {myth_error}")
            rows.extend(myth_rows)

        bug_lines = load_labels(labels_path)
        if not bug_lines:
            skipped.append((contract, "no usable labels file"))
            print(f"{prefix}: SKIP no usable labels file")
            continue

        verdicts = [is_true_positive(row["line"], bug_lines) for row in rows]
        all_rows.extend(rows)
        all_verdicts.extend(verdicts)
        scanned.append(contract)
        line_stats[contract] = (len(source_text.splitlines()), len(bug_lines))

        tp_here = sum(1 for verdict in verdicts if verdict)
        print(
            f"{prefix}: solc {version} ({reason}), {len(rows)} findings, "
            f"{tp_here} TP, {len(rows) - tp_here} FP"
        )

        if not args.keep_raw:
            json_out.unlink(missing_ok=True)

    if not args.keep_raw:
        try:
            raw_dir.rmdir()
        except OSError:
            pass

    findings_csv = out_dir / "findings.csv"
    fp_report = out_dir / "fp_report.md"
    write_findings_csv(all_rows, findings_csv)
    headline = write_fp_report(
        all_rows,
        all_verdicts,
        scanned,
        skipped,
        corpus_size,
        fp_report,
        solc_choices,
        line_stats,
    )

    print("")
    print("=" * 62)
    print("MODULE A SUMMARY")
    print("=" * 62)
    print(f"  corpus size          : {corpus_size}")
    print(f"  contracts scanned    : {len(scanned)}")
    print(f"  contracts skipped    : {len(skipped)}")
    print(f"  total findings       : {headline['total']}")
    print(f"  true positives       : {headline['tp']}")
    print(f"  false positives      : {headline['fp']}")
    print(f"  overall FP rate      : {headline['fp_rate']}")
    print("-" * 62)
    print(f"  findings written to  : {findings_csv}")
    print(f"  report written to    : {fp_report}")
    print("=" * 62)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
