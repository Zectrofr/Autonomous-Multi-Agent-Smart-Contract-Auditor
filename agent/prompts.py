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


def _import_mode_instructions(
    victim_contract_name: str, victim_basename: str, pragma: str
) -> str:
    """FILE 1 / FILE 2 instructions when the victim shares the generated files'
    solc version and can be imported directly. This is the original step one
    flow, unchanged."""
    attacker_imports = f'import {{{victim_contract_name}}} from "./{victim_basename}";'
    test_imports = (
        'import {Test, console2} from "forge-std/Test.sol";\n'
        f'import {{{victim_contract_name}}} from '
        f'"../../src/generated/{victim_basename}";\n'
        'import {Attacker} from "../../src/generated/Attacker.sol";'
    )
    return (
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


def _cross_version_instructions(
    victim_contract_name: str,
    victim_basename: str,
    pragma: str,
    victim_solc: str,
    deploy_code_target: str,
) -> str:
    """FILE 1 / FILE 2 instructions when the victim is an older solc contract.

    The victim compiles separately at its own solc; the generated files are
    0.8.x and must not import the victim (a cross version import does not
    compile). They reach the victim through vm.deployCode and an interface. This
    is the Foundry native pattern for testing a contract of a different compiler
    version, and it keeps forge-std (which needs >=0.8.13) usable in the test.
    """
    test_imports = (
        'import {Test, console2} from "forge-std/Test.sol";\n'
        'import {Attacker} from "../../src/generated/Attacker.sol";'
    )
    return (
        "IMPORTANT COMPILER NOTE. The victim is written for solc "
        f"{victim_solc}, an older compiler than the 0.8.x you must write the "
        "exploit in. You CANNOT import the victim source: forge-std needs solc "
        ">=0.8.13, so the test must be 0.8.x, and a 0.8.x file cannot import a "
        f"{victim_solc} file. Instead, reach the victim at runtime through "
        "vm.deployCode and a Solidity interface you declare yourself. Do not "
        "reproduce or paste the victim's code into your files. Write ordinary "
        "modern 0.8.x Solidity (constructor() keyword, receive() external "
        "payable for the reentry hook, address(x).call{value: v}(\"\") for the "
        "low level call, explicit payable(addr) casts). Solidity 0.8 has checked "
        "arithmetic, which is fine here.\n"
        "\n"
        "Write two files.\n"
        "\n"
        f"FILE 1 at {ATTACKER_PATH}: use exactly:\n"
        f"    pragma solidity {pragma};\n"
        "Declare a minimal interface for only the victim functions you call, for "
        "example:\n"
        "    interface IVictim { function someWithdraw() external; function someDeposit() external payable; }\n"
        "The Attacker takes the victim address in its constructor and casts it to "
        "your interface (IVictim(victimAddr)). It exploits the bug end to end "
        "(stake if the vulnerable path needs a recorded balance, trigger the "
        "vulnerable call, and for reentrancy re-enter from receive()/fallback() "
        "until the victim is drained), and lets its owner collect the stolen "
        "ether. It must NOT import the victim.\n"
        "\n"
        f"FILE 2 at {TEST_PATH}: use exactly:\n"
        f"    pragma solidity {pragma};\n"
        f"    {test_imports}\n"
        "Deploy the victim from its separately compiled artifact with:\n"
        f'    address victimAddr = deployCode("{deploy_code_target}");\n'
        "then declare/reuse an interface to interact with it. Fund a realistic "
        "honest pool through the victim's own deposit path if it has one (several "
        "ether from a few honest depositors via vm.deal + vm.prank), or with "
        "vm.deal(victimAddr, ...) if the vulnerable payout does not depend on a "
        "recorded balance. Snapshot balances, run the attacker, and assert the "
        "broken invariant above using forge-std assertions (assertApproxEqAbs "
        "for the drained balance, assertGt / assertGe for the attacker profit). "
        "If the victim's primary contract constructor needs arguments, pass them "
        'as deployCode("' + deploy_code_target + '", abi.encode(...)).\n'
        "\n"
        "Follow this exact skeleton, filling in the interface functions and the "
        "attack logic. Keep every structural line as shown:\n"
        "\n"
        f"// {ATTACKER_PATH}\n"
        "// SPDX-License-Identifier: MIT\n"
        f"pragma solidity {pragma};\n"
        "interface IVictim {\n"
        "    // declare ONLY the victim functions you call; mark a function payable\n"
        "    // if you send ether to it, e.g. function deposit() external payable;\n"
        "}\n"
        "contract Attacker {\n"
        "    IVictim public victim;\n"
        "    address public owner;\n"
        "    constructor(address victimAddr) { victim = IVictim(victimAddr); owner = msg.sender; }\n"
        "    function attack() external payable { /* stake if needed, then trigger the vulnerable call */ }\n"
        "    receive() external payable { /* re-enter victim.<withdraw>() while it can still pay */ }\n"
        "    function sweep() external { payable(owner).transfer(address(this).balance); }\n"
        "}\n"
        "\n"
        f"// {TEST_PATH}\n"
        "// SPDX-License-Identifier: MIT\n"
        f"pragma solidity {pragma};\n"
        f"{test_imports}\n"
        "interface IVictim {\n"
        "    // declare it AGAIN here with the same functions; interfaces do not\n"
        "    // cross files, so referencing IVictim without this line fails to compile\n"
        "}\n"
        "contract Exploit is Test {\n"
        "    function test_exploit_drains_victim() public {\n"
        f'        address victimAddr = deployCode("{deploy_code_target}");\n'
        "        // fund an honest pool via the victim's deposit path if it has one,\n"
        "        // otherwise vm.deal(victimAddr, 10 ether);\n"
        "        Attacker attacker = new Attacker(victimAddr);   // keep the instance, not an address\n"
        "        uint256 vaultBefore = victimAddr.balance;\n"
        "        attacker.attack{value: 1 ether}();              // call methods on the instance\n"
        "        // sweep, snapshot vaultAfter and attacker profit\n"
        "        // console2.log the three evidence lines, then assert the invariant\n"
        "    }\n"
        "}\n"
        "\n"
        "Hard compile rules from the skeleton: deployCode returns an address (store "
        "it in an address); declare the interface in BOTH files; deploy the attacker "
        "with `new Attacker(victimAddr)` and call methods on that instance, never on "
        "a plain address; mark any interface function you send value to as payable. "
        "Read a contract's ether balance as `address(attacker).balance` and "
        "`victimAddr.balance`, never `attacker.balance`. Only send `{value: ...}` to "
        "deposit-style or stake functions that are payable; a withdraw function "
        "takes no value, so never write `withdraw{value: ...}()`.\n"
        "\n"
        f"{_evidence_block()}\n"
    )


def build_user_prompt(
    victim_contract_name: str,
    victim_basename: str,
    victim_source: str,
    vuln_class: str,
    pragma: str,
    feedback: Optional[str] = None,
    cross_version: bool = False,
    victim_solc: Optional[str] = None,
    deploy_code_target: Optional[str] = None,
) -> str:
    """Assemble the per attempt user prompt.

    feedback is the captured error from the previous attempt. When present it is
    placed up front so the model treats fixing it as the priority. That is what
    makes this a real retry loop and not a blind re-ask.

    Two generation modes:

      import mode (cross_version False): the victim compiles at the same solc as
        the generated files (both 0.8.x), so the attacker and test import the
        victim source directly. This is the original step one flow, unchanged.

      cross version mode (cross_version True): the victim is an older contract
        (for example solc 0.5.x) that cannot be imported into a 0.8.x file, and
        forge-std itself requires >=0.8.13 so the test must be 0.8.x. The victim
        is therefore compiled separately at victim_solc and reached at runtime
        through vm.deployCode plus an interface; the generated files never import
        the victim source. `pragma` here is the 0.8.x pragma for the generated
        files, and deploy_code_target is the "<file>:<Contract>" the test passes
        to vm.deployCode.
    """
    profile = VULN_PROFILES.get(vuln_class, VULN_PROFILES["reentrancy"])

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

    if cross_version:
        parts.append(_cross_version_instructions(
            victim_contract_name=victim_contract_name,
            victim_basename=victim_basename,
            pragma=pragma,
            victim_solc=victim_solc or "an older solc",
            deploy_code_target=deploy_code_target or f"{victim_basename}:{victim_contract_name}",
        ))
    else:
        parts.append(_import_mode_instructions(
            victim_contract_name=victim_contract_name,
            victim_basename=victim_basename,
            pragma=pragma,
        ))

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
