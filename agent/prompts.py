"""Prompt templates for the LLM exploit agent.

The agent asks an LLM to write a proof of concept exploit for a flagged
vulnerability, then confirms it by execution. These templates carry three
things the LLM must get right for the loop to work:

  1. The exact output shape. The response is parsed by machine, so the files
     must arrive between the BEGIN_FILE / END_FILE markers with the exact
     relative paths the sandbox expects. Anything else is unparseable and
     counts as a failed attempt.

  2. The exact import paths and evidence log lines. The sandbox copies the
     victim into src/generated/ and runs the generated test there, so the
     imports are fixed and given to the model verbatim. The three evidence log
     lines let the sandbox read the drained amounts back out of forge output
     without guessing.

  3. The vulnerability context and the invariant to assert. A PoC that merely
     runs is worthless; it must assert a real broken invariant (a drained
     balance, a changed owner). That is what turns a pass into evidence.

On a retry, the previous attempt's captured error (a compiler error, a revert,
or an assertion diff) is fed back in build_user_prompt so the next attempt is
informed by the last failure rather than being a blind re-ask.
"""

from __future__ import annotations

from typing import Optional

# The markers the sandbox parser splits on. Kept boring and unambiguous so they
# never collide with Solidity syntax.
FILE_BEGIN = "BEGIN_FILE:"
FILE_END = "END_FILE"

# The two files the model must emit, at these exact repo relative paths. They
# live in isolated generated/ subfolders so they can never overwrite the hand
# written step one PoC.
ATTACKER_PATH = "src/generated/Attacker.sol"
TEST_PATH = "test/generated/Exploit.t.sol"

# The evidence log lines the test must print. The sandbox reads the drained
# amounts back out of forge's decoded logs by matching these exact labels, so
# they are part of the contract with the model, not a nicety.
EVIDENCE_LOG_BEFORE = "vault_before_wei"
EVIDENCE_LOG_AFTER = "vault_after_wei"
EVIDENCE_LOG_PROFIT = "attacker_profit_wei"


# Per vulnerability class context. Adding a new victim class later means adding
# an entry here plus, if needed, a new invariant description. The prototype ships
# with reentrancy, the guaranteed drainable case.
VULN_PROFILES = {
    "reentrancy": {
        "summary": "reentrancy (SWC-107), a checks effects interactions violation",
        "description": (
            "The victim sends ether with a low level call before it updates its "
            "internal accounting (it zeroes the caller's balance after the call, "
            "not before). A contract whose receive() or fallback() calls back "
            "into the vulnerable withdraw function re-enters while its recorded "
            "balance is still non zero, and can withdraw repeatedly until the "
            "contract is drained."
        ),
        "invariant": (
            "the victim's ether balance is drained to at or near zero, and the "
            "attacker ends up with materially more ether than it deposited "
            "(at least the honest pool it stole)"
        ),
    },
    "access-control": {
        "summary": "a missing access control check (SWC-105)",
        "description": (
            "A state changing function that should be restricted (an owner "
            "setter, a privileged withdraw) has no caller check, so any address "
            "can invoke it and seize control or funds."
        ),
        "invariant": (
            "a privileged state variable changes to a value the attacker chose "
            "(for example the owner becomes the attacker), or funds move to the "
            "attacker, when the call came from an unprivileged address"
        ),
    },
}


SYSTEM_PROMPT = (
    "You are an exploit engineer on a smart contract security team. You write "
    "proof of concept exploits in Solidity and prove them under Foundry. Your "
    "output is compiled and executed by an automated harness, so you follow the "
    "output format exactly and never add prose outside the file markers.\n"
    "\n"
    "Hard rules:\n"
    "1. Emit exactly two files, each wrapped in the markers you are given, at "
    "the exact relative paths requested. No other text before, between, or "
    "after the file blocks.\n"
    "2. The test must assert a REAL broken invariant with forge-std assertions, "
    "not merely that a call returned true. A PoC that does not assert theft is "
    "worthless.\n"
    "3. Use the exact pragma, import paths, and evidence log lines given in the "
    "task. They are fixed by the sandbox layout.\n"
    "4. Do not use any em dash characters anywhere in code or comments.\n"
)


def _evidence_block() -> str:
    """The exact console2 log lines the test must print, described for the LLM."""
    return (
        "In the test, after the attack and any sweep, print these three log "
        "lines with these exact labels so the harness can read the result:\n"
        f'    console2.log("{EVIDENCE_LOG_BEFORE}", vaultBalanceBeforeAttack);\n'
        f'    console2.log("{EVIDENCE_LOG_AFTER}", vaultBalanceAfterAttack);\n'
        f'    console2.log("{EVIDENCE_LOG_PROFIT}", attackerProfitInWei);\n'
        "where attackerProfitInWei is the attacker wallet gain over its deposit."
    )


def build_user_prompt(
    victim_contract_name: str,
    victim_basename: str,
    victim_source: str,
    vuln_class: str,
    pragma: str,
    feedback: Optional[str] = None,
) -> str:
    """Assemble the per attempt user prompt.

    feedback is the captured error from the previous attempt. When present it is
    placed up front so the model treats fixing it as the priority. That is what
    makes this a real retry loop and not a blind re-ask.
    """
    profile = VULN_PROFILES.get(vuln_class, VULN_PROFILES["reentrancy"])

    # Exact import lines. The sandbox copies the victim into src/generated/, so
    # the attacker sits beside it and the test reaches both from test/generated/.
    attacker_imports = (
        f'import {{{victim_contract_name}}} from "./{victim_basename}";'
    )
    test_imports = (
        'import {Test, console2} from "forge-std/Test.sol";\n'
        f'import {{{victim_contract_name}}} from '
        f'"../../src/generated/{victim_basename}";\n'
        'import {Attacker} from "../../src/generated/Attacker.sol";'
    )

    parts = []

    if feedback:
        parts.append(
            "YOUR PREVIOUS ATTEMPT FAILED. Fix this before anything else. The "
            "Foundry harness reported:\n"
            "-----\n"
            f"{feedback.strip()}\n"
            "-----\n"
            "Study the error, correct the cause, and emit the two files again in "
            "full. Common causes: a compile error (wrong types, missing import, "
            "pragma mismatch), a revert during the attack, or an assertion that "
            "did not hold because the exploit did not actually drain the victim.\n"
        )

    parts.append(
        f"Target vulnerability class: {vuln_class} ({profile['summary']}).\n"
        f"How this class works: {profile['description']}\n"
        f"Invariant your test MUST assert: {profile['invariant']}.\n"
    )

    parts.append(
        "Victim contract under audit "
        f"({victim_basename}, primary contract {victim_contract_name}):\n"
        "```solidity\n"
        f"{victim_source}\n"
        "```\n"
    )

    parts.append(
        "Write two files.\n"
        "\n"
        f"FILE 1 at {ATTACKER_PATH}: an Attacker contract that exploits the bug "
        "end to end (deposit a small stake, trigger the vulnerable path, and "
        "drive the exploit until the victim is drained), plus a way for its "
        "owner to collect the stolen ether. Use this pragma and import exactly:\n"
        f"    pragma solidity {pragma};\n"
        f"    {attacker_imports}\n"
        "\n"
        f"FILE 2 at {TEST_PATH}: a Foundry test that funds the victim with a "
        "realistic honest pool (several ether from a few honest depositors), "
        "snapshots balances, runs the attacker, and asserts the broken "
        "invariant above using forge-std assertions (assertApproxEqAbs for the "
        "drained balance, assertGt / assertGe for the attacker profit). Use this "
        "pragma and these imports exactly:\n"
        f"    pragma solidity {pragma};\n"
        f"    {test_imports}\n"
        "\n"
        f"{_evidence_block()}\n"
    )

    parts.append(
        "Output format, followed exactly, nothing else:\n"
        f"{FILE_BEGIN} {ATTACKER_PATH}\n"
        "<the full Solidity source of file 1>\n"
        f"{FILE_END}\n"
        f"{FILE_BEGIN} {TEST_PATH}\n"
        "<the full Solidity source of file 2>\n"
        f"{FILE_END}\n"
    )

    return "\n".join(parts)
