"""Foundry execution sandbox for generated exploits.

This module is the execution half of the loop. It takes the files an LLM
generated, writes them into the existing exploits/ Foundry project inside
isolated generated/ subfolders, runs forge test scoped to the generated test,
and parses a clean pass/fail plus the captured failure text.

It deliberately reuses the step one Foundry project (exploits/) rather than
spinning up a second one, so generated exploits compile against the same
forge-std and solc pin. It never writes outside src/generated/ and
test/generated/, so the hand written step one files (VulnerableVault.sol,
Attacker.sol, ReentrancyPoC.t.sol) are physically out of reach.

How pass/fail is parsed (verified against forge 1.8.1 output):

  forge test -vvv --json prints, on a successful compile, a JSON object shaped:

      { "<path>:<Suite>": {
            "test_results": {
                "<testName()>": {
                    "status": "Success" | "Failure",
                    "reason": <string or null>,     # the revert / assertion diff
                    "decoded_logs": [ "<console line>", ... ]
                }
            }
      } }

  A compile error is NOT JSON: forge exits non zero and prints
  "Error: Compiler run failed:" followed by solc diagnostics. So the parser
  tries json.loads first; if that fails, the output is treated as a compile
  error and returned verbatim as the failure text to feed back to the LLM.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from agent.prompts import (
    ATTACKER_PATH,
    EVIDENCE_LOG_AFTER,
    EVIDENCE_LOG_BEFORE,
    EVIDENCE_LOG_PROFIT,
    TEST_PATH,
)

# Reuse Module A's pragma reader and solc version ranking so the sandbox and the
# static scan agree on which compiler a file wants. Imported read only.
from auditor.scan import rank_solc_versions

# Only these two generated paths may be written. Anything else the model tries
# to emit is refused, which is the guard that protects the step one files.
ALLOWED_GENERATED_PATHS = {ATTACKER_PATH, TEST_PATH}

# Candidate solc versions the sandbox is willing to pin a victim to. These are
# the latest patch of each minor series that svm can fetch, so ranking a pragma
# against this list yields a concrete, installable compiler. forge auto installs
# whichever one is chosen on first use. solc-select is not consulted here (the
# corpus run needs no local solc-select state); forge's own svm does the fetch.
CANDIDATE_SOLC = ("0.4.26", "0.5.17", "0.6.12", "0.7.6", "0.8.28")

# Matches the first Solidity pragma line, whatever its constraint body, so the
# victim copy can be re-pinned to an exact installable version.
_PRAGMA_LINE_RE = re.compile(r"pragma\s+solidity\s+[^;]+;", re.IGNORECASE)

# Substrings that mean forge/svm could not obtain the requested solc, as opposed
# to a normal compile error in the source. Used to raise the "cannot get solc"
# stop condition instead of silently labeling it a failed drain.
_SOLC_UNAVAILABLE_MARKERS = (
    "no matching version",
    "could not download",
    "failed to install solc",
    "error installing solc",
    "unable to install solc",
    "could not install solc",
    "svm error",
)


def select_victim_solc(source_text: str) -> tuple[str, str]:
    """Pick a concrete, installable solc version for a victim's pragma.

    Delegates the constraint logic to Module A's rank_solc_versions, which caps
    open ended pragmas (">=0.5.9" really means "0.5.x") so an old contract does
    not get compiled by a too new compiler. Returns (version, reason).
    """
    ranked = rank_solc_versions(source_text, CANDIDATE_SOLC)
    return ranked[0]


def pin_pragma(source_text: str, version: str) -> str:
    """Rewrite the victim's first pragma to an exact version.

    forge's auto detect picks the highest solc that satisfies a pragma, which is
    wrong for an open ended pragma like ">=0.5.9" (it would pick 0.8.x and fail
    to parse 0.5 era syntax). Pinning the copied victim to the exact version we
    chose makes forge compile that file, and only that file, at the right solc,
    while the generated 0.8.x test and forge-std still resolve to 0.8.x.
    """
    return _PRAGMA_LINE_RE.sub(f"pragma solidity {version};", source_text, count=1)


@dataclass
class SandboxResult:
    """Outcome of one compile-and-run cycle."""

    passed: bool
    # On failure, the captured compiler error / revert / assertion diff. This is
    # exactly what gets fed back into the next prompt.
    error_text: str = ""
    # console2 log lines forge decoded, used to build evidence on a pass.
    decoded_logs: List[str] = field(default_factory=list)
    # Short human readable evidence string for the label row.
    evidence: str = ""
    # The raw forge stdout+stderr, kept for debugging.
    raw_output: str = ""
    # True when the failure was forge/svm being unable to obtain the victim's
    # solc, not a normal compile or drain failure. The caller stops on this
    # rather than recording a misleading "failed drain" label.
    solc_unavailable: bool = False


class Sandbox:
    """Writes generated exploits into exploits/ and runs them under forge."""

    def __init__(self, exploits_dir: Path, forge_bin: str = "forge"):
        self.exploits_dir = exploits_dir
        self.forge_bin = forge_bin
        self.gen_src = exploits_dir / "src" / "generated"
        self.gen_test = exploits_dir / "test" / "generated"
        self.out_dir = exploits_dir / "out"
        # The solc version the current victim was pinned to, set by prepare_victim
        # and surfaced for logging and the label reason. None until a victim is
        # prepared.
        self.victim_solc: Optional[str] = None
        self.victim_solc_reason: str = ""

    # -- victim setup -------------------------------------------------------

    def prepare_victim(self, victim_path: Path) -> str:
        """Copy the victim into src/generated/ so imports are stable.

        Working on a copy matches the pipeline design (the exploit runs against
        a copy of the flagged contract) and means the generated attacker and
        test can use fixed relative imports regardless of where the victim
        originally lived. Returns the basename the copy was written under.
        """
        self._clean_generated()
        self.gen_src.mkdir(parents=True, exist_ok=True)
        self.gen_test.mkdir(parents=True, exist_ok=True)
        self._write_pinned_victim(victim_path)
        return victim_path.name

    def _write_pinned_victim(self, victim_path: Path) -> None:
        """Copy the victim into src/generated/ with its pragma pinned.

        The pin is what makes the sandbox version aware: a 0.5.x victim is
        compiled at 0.5.x even though the generated test and forge-std compile at
        0.8.x in the same run. select_victim_solc records the choice so a reader
        of the label can see which compiler confirmed (or failed to confirm) the
        drain.
        """
        source = victim_path.read_text(encoding="utf-8", errors="replace")
        version, reason = select_victim_solc(source)
        self.victim_solc = version
        self.victim_solc_reason = reason
        dest = self.gen_src / victim_path.name
        dest.write_text(pin_pragma(source, version), encoding="utf-8")

    def _clean_generated(self) -> None:
        """Wipe both generated folders.

        Called before every attempt so a broken file from a previous attempt can
        never break the next compile (forge compiles the whole project before
        running any test), and so a failed run leaves the project buildable.
        """
        for folder in (self.gen_src, self.gen_test):
            if folder.exists():
                shutil.rmtree(folder)

    def _clean_out_artifacts(self) -> None:
        """Remove compiled artifacts for the generated files.

        Only the generated test and attacker artifact folders are removed;
        forge-std and the step one artifacts stay cached so the run is fast. The
        victim artifact folder is also removed so a stale victim of the same
        basename from a previous session cannot be picked up by deployCode.
        """
        names = [Path(TEST_PATH).name, Path(ATTACKER_PATH).name]
        for name in self.gen_src.glob("*.sol"):
            names.append(name.name)
        for name in names:
            artifact_dir = self.out_dir / name
            if artifact_dir.exists():
                shutil.rmtree(artifact_dir, ignore_errors=True)

    def cleanup(self) -> None:
        """Remove all generated files. Used after a failed run so that a plain
        `forge test` in exploits/ still compiles and step one still passes."""
        self._clean_generated()

    # -- writing generated files -------------------------------------------

    def write_generated_files(self, files: Dict[str, str], victim_basename: str) -> None:
        """Write the parsed exploit files, re-copying the victim alongside them.

        Only the two allowed generated paths are accepted; a path outside them
        raises, which is the hard guarantee that step one files are never
        touched. The victim copy is refreshed here because _clean_generated in
        the caller's prepare step may run between attempts.
        """
        self.gen_src.mkdir(parents=True, exist_ok=True)
        self.gen_test.mkdir(parents=True, exist_ok=True)

        for rel_path, content in files.items():
            if rel_path not in ALLOWED_GENERATED_PATHS:
                raise ValueError(
                    f"refusing to write outside the generated sandbox: {rel_path}"
                )
            dest = self.exploits_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

    def refresh_victim(self, victim_path: Path) -> None:
        """Ensure the pinned victim copy is present in src/generated/ for this
        attempt (the pragma pinned copy, never the raw file)."""
        self.gen_src.mkdir(parents=True, exist_ok=True)
        dest = self.gen_src / victim_path.name
        if not dest.exists():
            self._write_pinned_victim(victim_path)

    # -- running -----------------------------------------------------------

    def run_generated_test(self, timeout: int = 240) -> SandboxResult:
        """Compile and run only the generated test, and parse the result.

        Scoped with --match-path so the step one suite is not part of this run.
        -vvv --json gives both a machine readable status and the decoded console
        logs used for evidence.
        """
        # Drop stale compiled artifacts for the generated files before running.
        # forge keeps artifacts for contracts that a source file no longer
        # defines, and --match-path runs every test artifact under that path, so
        # a suite from a previous victim's differently shaped test could
        # otherwise re-run as a phantom failure and corrupt the label.
        self._clean_out_artifacts()

        cmd = [
            self.forge_bin,
            "test",
            "--match-path",
            # forge takes a forward slash path even on Windows.
            "test/generated/Exploit.t.sol",
            "-vvv",
            "--json",
        ]
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.exploits_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                passed=False,
                error_text=f"forge test timed out after {timeout}s",
            )
        except OSError as exc:
            return SandboxResult(
                passed=False,
                error_text=f"could not launch forge: {exc}",
            )

        combined = f"{proc.stdout}\n{proc.stderr}".strip()
        return self._parse_forge_output(proc.stdout, combined)

    def _parse_forge_output(self, stdout: str, combined: str) -> SandboxResult:
        """Turn forge output into a SandboxResult.

        The JSON lives in stdout on a successful compile. If json.loads fails,
        the run did not produce test results at all, which in practice means a
        compile error; that whole text is returned as the feedback.
        """
        doc = self._extract_json(stdout)
        if doc is None:
            # No parseable JSON: almost always a compilation failure. Hand the
            # compiler diagnostics back so the next attempt can fix them. If the
            # failure was forge/svm being unable to fetch the victim's solc, flag
            # it so the caller stops and reports precisely instead of pretending
            # the exploit merely failed to drain.
            lowered = combined.lower()
            unavailable = any(m in lowered for m in _SOLC_UNAVAILABLE_MARKERS)
            return SandboxResult(
                passed=False,
                error_text=_trim(combined) or "forge produced no parseable output",
                raw_output=combined,
                solc_unavailable=unavailable,
            )

        # Walk every suite and every test. The generated file should hold one
        # test, but we tolerate more and require all of them to pass.
        all_passed = True
        failures: List[str] = []
        logs: List[str] = []
        saw_a_test = False

        for suite in doc.values():
            if not isinstance(suite, dict):
                continue
            results = suite.get("test_results")
            if not isinstance(results, dict):
                continue
            for test_name, result in results.items():
                if not isinstance(result, dict):
                    continue
                saw_a_test = True
                status = result.get("status")
                logs.extend(result.get("decoded_logs") or [])
                if status != "Success":
                    all_passed = False
                    reason = result.get("reason") or "assertion failed (no reason given)"
                    failures.append(f"{test_name}: {reason}")

        if not saw_a_test:
            return SandboxResult(
                passed=False,
                error_text="forge ran but no generated test was found to execute",
                raw_output=combined,
            )

        if all_passed:
            return SandboxResult(
                passed=True,
                decoded_logs=logs,
                evidence=self._evidence_from_logs(logs),
                raw_output=combined,
            )

        return SandboxResult(
            passed=False,
            error_text=_trim("; ".join(failures)),
            decoded_logs=logs,
            raw_output=combined,
        )

    @staticmethod
    def _extract_json(stdout: str) -> Optional[dict]:
        """Parse the forge JSON object out of stdout.

        forge prints a single JSON object, but a stray warning line can precede
        it, so if a direct parse fails we retry from the first brace.
        """
        stdout = stdout.strip()
        if not stdout:
            return None
        try:
            doc = json.loads(stdout)
            return doc if isinstance(doc, dict) else None
        except json.JSONDecodeError:
            pass
        brace = stdout.find("{")
        if brace == -1:
            return None
        try:
            doc = json.loads(stdout[brace:])
            return doc if isinstance(doc, dict) else None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _evidence_from_logs(logs: List[str]) -> str:
        """Build the evidence string from the required evidence log lines.

        The test prints three labeled uint logs; forge decodes them as
        "<label>: <value>". We read the three values back and render a compact
        summary. If any are missing (the model logged something else) we fall
        back to a generic pass string so evidence is never empty.
        """
        values: Dict[str, Optional[int]] = {
            EVIDENCE_LOG_BEFORE: None,
            EVIDENCE_LOG_AFTER: None,
            EVIDENCE_LOG_PROFIT: None,
        }
        for line in logs:
            for label in values:
                match = re.search(rf"{re.escape(label)}\s*[:=]?\s*(\d+)", line)
                if match:
                    values[label] = int(match.group(1))

        before = values[EVIDENCE_LOG_BEFORE]
        after = values[EVIDENCE_LOG_AFTER]
        profit = values[EVIDENCE_LOG_PROFIT]
        if before is not None and after is not None and profit is not None:
            return (
                f"vault {_wei(before)} -> {_wei(after)}, "
                f"attacker +{_wei(profit)}"
            )
        return "forge test passed and the drained-balance invariant held"


def _wei(amount: int) -> str:
    """Render a wei amount compactly, using e18 shorthand for whole ether."""
    if amount == 0:
        return "0"
    ether = 10 ** 18
    if amount % ether == 0:
        return f"{amount // ether}e18"
    return f"{amount}wei"


def _trim(text: str, limit: int = 600) -> str:
    """Trim captured error text so a huge compiler dump stays promptable."""
    text = text.strip()
    if len(text) <= limit:
        return text
    # Keep the head, where the first and usually root error is.
    return text[:limit] + " ...[truncated]"
