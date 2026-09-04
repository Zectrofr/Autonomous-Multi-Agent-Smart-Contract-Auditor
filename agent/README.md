# Module D step two: the LLM exploit agent

This is the self-improving core of the pipeline. Module A flags suspected
vulnerabilities statically; Module D confirms them by execution. Step one proved
the drain-and-assert mechanism with a hand-written proof of concept. Step two
wraps an LLM around that mechanism so the exploit is generated automatically,
retried on failure, and turned into an execution-grounded training label.

## Why execution labels are the contribution

The label a finding gets does not come from a dataset and does not come from the
model's own claim that it found a bug. It comes from running an exploit:

- The agent asks an LLM to write a proof of concept for the flagged contract.
- It compiles and runs that exploit against a copy of the contract in a Foundry
  sandbox.
- The exploit must assert a real broken invariant: a drained balance, a changed
  owner. Not that a call returned true.
- If forge test genuinely passes, the finding is CONFIRMED by evidence. If it
  fails, the revert or assertion diff is fed back to the LLM for another attempt.
- The final pass/fail is written to `data/labels.csv`, the ground-truth signal
  that will train the ranking model.

A `confirmed=true` row is only ever written when a real forge test passed on an
exploit that asserts a real invariant. There is no mock and no self-report.

## The loop

Per victim, in `agent/run_agent.py`:

1. Build a prompt (`agent/prompts.py`) from the victim source, the suspected
   vulnerability class, the required output shape, and the CEI/reentrancy
   context.
2. Ask the LLM for the exploit files and parse its response into named files.
3. Write them into the `exploits/` Foundry project under isolated subfolders
   (`exploits/src/generated/` and `exploits/test/generated/`), so nothing can
   clobber the hand-written step-one files.
4. Run `forge test` scoped to the generated test (`agent/sandbox.py`). Capture
   pass/fail, and on failure capture the revert reason, compiler error, or
   assertion diff.
5. On failure, feed that captured error back into the next prompt. Attempt 2 is
   informed by attempt 1's actual failure; it is a real retry loop, not a blind
   re-ask.
6. Stop on the first pass or when retries are exhausted (default 3).
7. Append one row to `data/labels.csv` (`agent/labels.py`).

Isolation and safety:

- The sandbox refuses to write any path other than the two generated files, so
  `exploits/src/VulnerableVault.sol`, `exploits/src/Attacker.sol`, and
  `exploits/test/ReentrancyPoC.t.sol` are physically out of reach.
- The generated folders are wiped before each attempt, so a broken file from one
  attempt can never break the next compile, and a failed run leaves the project
  buildable. On a confirmed run the passing generated files are kept on disk as
  the artifact; they are gitignored (reproducible output).

## How pass/fail is parsed

`forge test -vvv --json` prints, on a successful compile, a JSON object shaped:

```
{ "<path>:<Suite>": { "test_results": {
      "<testName()>": { "status": "Success" | "Failure",
                        "reason": <revert / assertion diff or null>,
                        "decoded_logs": [ "<console line>", ... ] } } } }
```

The sandbox reads `status` for pass/fail and `reason` for the failure text. A
compile error is NOT JSON (forge exits non-zero and prints
`Error: Compiler run failed:` with solc diagnostics), so a failed `json.loads`
is treated as a compile failure and the diagnostics are the feedback. On a pass,
the drained amounts are read back out of `decoded_logs` from three evidence log
lines the test is required to print (`vault_before_wei`, `vault_after_wei`,
`attacker_profit_wei`).

## Anthropic SDK and model, verified at runtime

The SDK interface and model string were checked against the installed package
rather than assumed:

- Package: `anthropic` (import the SDK; version is pinned via the venv).
- Client: `anthropic.Anthropic()`, which reads `ANTHROPIC_API_KEY` from the
  environment. The agent fails loudly with setup guidance if the key is missing.
- Call: `client.messages.create(model=..., max_tokens=..., system=...,
  thinking={"type": "adaptive"}, messages=[...])`; the response `content` is a
  list of typed blocks, and the text blocks are concatenated.
- Model: `claude-opus-5`, the current default Claude model (overridable with
  `--model`).

## Run it

From the repo root, with the venv active and Foundry on PATH:

```bash
# Live run (needs ANTHROPIC_API_KEY)
python -m agent.run_agent --victim exploits/src/VulnerableVault.sol --vuln reentrancy
```

Set the key first if it is not already set (PowerShell):

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

Offline self-test, which validates the whole sandbox and labeling path against
real forge execution using a built-in reference exploit (no API key, no
network):

```bash
python -m agent.run_agent --victim exploits/src/VulnerableVault.sol --vuln reentrancy --self-test
```

The self-test is not a mock: the label it writes still comes from a real
`forge test` run. Only the source of the candidate exploit differs (a built-in
reference instead of the LLM), and its label row is tagged
`(self-test reference)` in the evidence column so it is distinguishable from a
live LLM row.

Useful flags: `--retries N` (default 3), `--model <id>`, `--labels <path>`.

## Where labels land

`data/labels.csv`, appended one row per victim. Module D only ever appends to
`data/`; it never touches Module A's `data/findings.csv`. Schema:

```
contract, vuln_class, confirmed, attempts, invariant_asserted, evidence
```

## Adding another victim

1. Put the victim contract in `exploits/src/` (or point `--victim` at any path;
   the sandbox copies it into `src/generated/`).
2. If it is a new vulnerability class, add an entry to `VULN_PROFILES` in
   `agent/prompts.py` with a `summary`, a `description`, and the `invariant` the
   exploit must assert (an `access-control` profile is already stubbed there).
3. Run `python -m agent.run_agent --victim <path> --vuln <class>`.

The prototype ships with reentrancy, the guaranteed-drainable case, because one
end-to-end confirmed drain is enough to prove the loop.
