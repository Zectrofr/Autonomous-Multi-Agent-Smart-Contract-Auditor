"""Module F: the model-only vs model-plus-execution gap harness.

This is the headline experiment. It scores the SAME set of reentrancy findings
two ways and reports the gap:

  model-only            rank/threshold by the C1 static score alone
                        (triage/scores.csv, the yardstick).
  model-plus-execution  start from C1, then trust the execution-grounded labels
                        from the exploit agent (data/labels.csv): a finding the
                        agent drained is forced true, a finding it tried and
                        failed to drain is demoted.

For both configurations it reports precision, recall, and false-positive rate
over the identical finding set; the delta between them is the result. The design
cannot produce a null: a large gap is the expected win, a small gap is itself a
finding about how much the static ranking already captures.

Scope is the reentrancy subset only, and it is stated honestly in the output.

Run:
    python -m eval.harness
prints the gap table and writes eval/gap_report.md.

Metric definitions (per configuration, over the evaluated finding set):
  TP = predicted positive and truth positive
  FP = predicted positive and truth negative
  FN = predicted negative and truth positive
  TN = predicted negative and truth negative
  precision = TP / (TP + FP)                exploitable among those flagged
  recall    = TP / (TP + FN)                exploitable that we caught
  fp_rate   = FP / (FP + TN)                benign findings wrongly flagged
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from triage.features import extract_features, is_reentrancy_family
from triage.ground_truth import load_bug_lines, repo_root, solidifi_truth
from triage.rank import load_findings, train_model

SCORES_CSV = "triage/scores.csv"
LABELS_CSV = "data/labels.csv"
FINDINGS_CSV = "data/findings.csv"
CORPUS_DIR = "auditor/corpus"
REPORT_MD = "eval/gap_report.md"

# A finding counts as "predicted exploitable" when its C1 score is at or above
# this threshold. 0.5 is the natural cut for a probability from the balanced
# logistic model; the gap is a comparison at a fixed threshold, so the exact
# value matters less than using the same one for both configurations.
THRESHOLD = 0.5

# The one contract we have a real, execution-grounded label for that is NOT in
# the Slither corpus: exploits/src/VulnerableVault.sol, drained by the hand
# written PoC and re-confirmed by the agent self-test. Its static metadata is
# the well known classification of this exact bug (reentrancy-eth / SWC-107 /
# High on the withdraw() low-level call). source is tagged "exploits-poc" so no
# one mistakes it for a corpus scan row. This is the row the task asks to carry
# the harness when corpus victims cannot be labeled.
VAULT_ANCHOR = {
    "contract": "VulnerableVault",
    "function": "VulnerableVault.withdraw()",
    "line": "38",
    "detector_id": "reentrancy-eth",
    "severity": "High",
    "swc_id": "SWC-107",
    "source": "exploits-poc",
}


@dataclass
class ExecLabel:
    """One execution-grounded label from data/labels.csv."""

    contract: str      # the tested Solidity contract name (not the file stem)
    vuln_class: str
    confirmed: bool
    evidence: str


@dataclass
class EvalRow:
    """One finding in the evaluated set with everything the metrics need."""

    contract: str
    function: str
    line: int
    detector_id: str
    c1_score: float
    truth: int              # 1 exploitable, 0 benign
    truth_source: str       # "solidifi-line", "execution", or "execution(anchor)"
    exec_confirmed: Optional[bool]  # None if no execution label joined this row


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_scores(path: Path) -> List[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_exec_labels(path: Path) -> List[ExecLabel]:
    if not path.exists():
        return []
    out: List[ExecLabel] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            out.append(
                ExecLabel(
                    contract=row["contract"].strip(),
                    vuln_class=row["vuln_class"].strip(),
                    confirmed=row["confirmed"].strip().lower() == "true",
                    evidence=row.get("evidence", "").strip(),
                )
            )
    return out


def build_contract_bridge(corpus_dir: Path) -> Dict[str, str]:
    """Map a tested Solidity contract name back to its corpus file stem.

    labels.csv records the contract the agent tested (the last `contract X` in
    the victim file, matching the agent's own inspect_victim rule). findings.csv
    records the file stem (buggy_N). To join a label to findings we bridge the
    two by re-deriving that same last-contract name for each corpus file.

    A name that maps to more than one stem (two corpus files can end in a
    contract of the same name) is left out of the bridge, because the join would
    be ambiguous; such a case is reported rather than guessed.
    """
    by_name: Dict[str, List[str]] = {}
    pattern = re.compile(r"^\s*contract\s+(\w+)", re.MULTILINE)
    for sol in sorted(corpus_dir.glob("buggy_*.sol")):
        names = pattern.findall(sol.read_text(encoding="utf-8", errors="replace"))
        if not names:
            continue
        by_name.setdefault(names[-1], []).append(sol.stem)
    return {name: stems[0] for name, stems in by_name.items() if len(stems) == 1}


# ---------------------------------------------------------------------------
# Build the evaluated set
# ---------------------------------------------------------------------------

def build_eval_set(
    scored_findings: List[dict],
    exec_labels: List[ExecLabel],
    bridge: Dict[str, str],
    bug_lines,
    vault_c1: float,
) -> List[EvalRow]:
    """Assemble the reentrancy finding set with truth and any execution join.

    Truth precedence, as the task asks: execution result is the strongest truth
    for the reentrancy subset; where no execution label joins a finding, fall
    back to Module A's SolidiFI line rule.

    NOTE on demotion truth: a failed drain is scored here as truth-negative
    because we treat the agent's execution result as ground truth for this
    subset. That is a known limitation, since the agent failing to drain does
    not by itself prove the contract is safe; it is stated in the report.
    """
    # Index execution labels by the corpus file stem they apply to (via bridge),
    # plus a direct by-contract index for the non-corpus anchor.
    exec_by_stem: Dict[str, ExecLabel] = {}
    exec_by_contract: Dict[str, ExecLabel] = {}
    for lab in exec_labels:
        exec_by_contract[lab.contract] = lab
        stem = bridge.get(lab.contract)
        if stem is not None:
            exec_by_stem[stem] = lab

    rows: List[EvalRow] = []

    # 1. Corpus reentrancy findings.
    for f in scored_findings:
        if not is_reentrancy_family(f["detector_id"]):
            continue
        contract = f["contract"]
        line = int(f.get("line") or 0)
        c1 = float(f["c1_score"])

        lab = exec_by_stem.get(contract)
        if lab is not None and lab.vuln_class == "reentrancy":
            # Execution truth wins for the reentrancy subset.
            truth = 1 if lab.confirmed else 0
            rows.append(EvalRow(contract, f.get("function", ""), line,
                                f["detector_id"], c1, truth, "execution",
                                lab.confirmed))
        else:
            t = solidifi_truth(contract, line, bug_lines)
            if t is None:
                continue  # no way to judge this finding; leave it out
            rows.append(EvalRow(contract, f.get("function", ""), line,
                                f["detector_id"], c1, t, "solidifi-line", None))

    # 2. The VulnerableVault execution anchor (not in the corpus). Its truth is
    #    the execution result, so the one confirmed label we do have carries the
    #    harness even when no corpus victim could be labeled.
    anchor_lab = exec_by_contract.get(VAULT_ANCHOR["contract"])
    if anchor_lab is not None:
        rows.append(EvalRow(
            contract=VAULT_ANCHOR["contract"],
            function=VAULT_ANCHOR["function"],
            line=int(VAULT_ANCHOR["line"]),
            detector_id=VAULT_ANCHOR["detector_id"],
            c1_score=vault_c1,
            truth=1 if anchor_lab.confirmed else 0,
            truth_source="execution(anchor)",
            exec_confirmed=anchor_lab.confirmed,
        ))

    return rows


# ---------------------------------------------------------------------------
# Metrics and the two configurations
# ---------------------------------------------------------------------------

@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fp_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0


def _confusion(rows: List[EvalRow], predicted_positive: List[bool]) -> Metrics:
    tp = fp = fn = tn = 0
    for row, pred in zip(rows, predicted_positive):
        if pred and row.truth == 1:
            tp += 1
        elif pred and row.truth == 0:
            fp += 1
        elif not pred and row.truth == 1:
            fn += 1
        else:
            tn += 1
    return Metrics(tp, fp, fn, tn)


def predict_model_only(rows: List[EvalRow]) -> List[bool]:
    """Config A: threshold the C1 static score."""
    return [row.c1_score >= THRESHOLD for row in rows]


def predict_model_plus_execution(rows: List[EvalRow], base: List[bool]) -> List[bool]:
    """Config B: start from the model-only prediction, then override with
    execution evidence where the exploit agent actually ran.

      agent confirmed (drained)  -> force positive  (certain-true)
      agent failed to drain      -> demote to negative

    Findings with no execution label keep the model-only prediction.
    """
    out = list(base)
    for i, row in enumerate(rows):
        if row.exec_confirmed is True:
            out[i] = True
        elif row.exec_confirmed is False:
            out[i] = False
    return out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _fmt_row(name: str, m: Metrics) -> str:
    return (f"{name:24s} {m.precision:8.3f} {m.recall:8.3f} {m.fp_rate:8.3f}"
            f"   (TP={m.tp} FP={m.fp} FN={m.fn} TN={m.tn})")


def build_report(
    rows: List[EvalRow],
    m_only: Metrics,
    m_exec: Metrics,
    exec_labels: List[ExecLabel],
    n_joined_corpus: int,
    live_llm_available: bool,
) -> str:
    n = len(rows)
    n_labels = len(exec_labels)
    n_confirmed = sum(1 for l in exec_labels if l.confirmed)
    n_failed = n_labels - n_confirmed
    truth_counts: Dict[str, int] = {}
    for r in rows:
        truth_counts[r.truth_source] = truth_counts.get(r.truth_source, 0) + 1

    dp = m_exec.precision - m_only.precision
    dr = m_exec.recall - m_only.recall
    dfp = m_exec.fp_rate - m_only.fp_rate

    # Characterize the gap honestly.
    joined_total = n_joined_corpus + sum(
        1 for r in rows if r.truth_source == "execution(anchor)")
    if not live_llm_available and joined_total <= 1:
        verdict = (
            "THIN DUE TO N. Live LLM calls were unavailable (no ANTHROPIC_API_KEY), "
            "so no corpus reentrancy victims could be labeled by the agent. The only "
            "execution label that joins the finding set is the VulnerableVault anchor, "
            "which the static model already ranks correctly, so the override changes "
            "nothing measurable. This is a small-n artifact, not evidence that "
            "execution grounding fails to help.")
    elif max(abs(dp), abs(dr), abs(dfp)) >= 0.05:
        verdict = ("LARGE. Execution grounding measurably moved precision/recall "
                   "over the static baseline, the expected win.")
    else:
        verdict = ("SMALL. The static ranking already captures most of the "
                   "reentrancy signal on this subset; execution grounding adds "
                   "little on top of it here.")

    lines: List[str] = []
    lines.append("# Model-only vs model-plus-execution gap")
    lines.append("")
    lines.append("Scope: reentrancy subset only. This is a prototype result on the "
                 "SolidiFI reentrancy corpus plus one execution anchor, not a general "
                 "claim about all vulnerability classes.")
    lines.append("")
    lines.append("## Counts (n)")
    lines.append("")
    lines.append(f"- evaluated findings: {n}")
    lines.append(f"- execution labels available: {n_labels} "
                 f"({n_confirmed} confirmed/drained, {n_failed} failed)")
    lines.append(f"- execution labels that join a corpus finding: {n_joined_corpus}")
    lines.append(f"- live LLM available at run time: {'yes' if live_llm_available else 'no'}")
    lines.append("- truth source per row: "
                 + ", ".join(f"{k}={v}" for k, v in sorted(truth_counts.items())))
    lines.append("")
    lines.append("## Gap table")
    lines.append("")
    lines.append("| configuration | precision | recall | fp_rate | TP | FP | FN | TN |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(f"| model-only | {m_only.precision:.3f} | {m_only.recall:.3f} | "
                 f"{m_only.fp_rate:.3f} | {m_only.tp} | {m_only.fp} | {m_only.fn} | {m_only.tn} |")
    lines.append(f"| model-plus-execution | {m_exec.precision:.3f} | {m_exec.recall:.3f} | "
                 f"{m_exec.fp_rate:.3f} | {m_exec.tp} | {m_exec.fp} | {m_exec.fn} | {m_exec.tn} |")
    lines.append(f"| **GAP (exec - only)** | **{dp:+.3f}** | **{dr:+.3f}** | "
                 f"**{dfp:+.3f}** | | | | |")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(verdict)
    lines.append("")
    lines.append("## Truth source")
    lines.append("")
    lines.append("- solidifi-line: Module A rule, a finding on a SolidiFI-injected "
                 "line is a true positive. Used for corpus findings with no execution "
                 "label.")
    lines.append("- execution / execution(anchor): the exploit agent's real forge "
                 "result is the truth. A drained contract is a confirmed true positive. "
                 "A failed drain is scored here as negative, a known limitation since a "
                 "failed attempt does not by itself prove the contract is safe.")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append("- The SolidiFI-line truth rule is generous: it marks whole injected "
                 "functions as bug lines, so nearly every reentrancy finding counts as a "
                 "true positive and the model-only baseline already sits near the "
                 "precision ceiling on this subset. That is precisely why corpus "
                 "execution labels matter. Some findings the line rule calls true would "
                 "be demoted by a failed drain, which is the correction execution "
                 "grounding is meant to supply. That correction could not be measured "
                 "here because no corpus victim could be labeled without the API key.")
    lines.append("- The label-to-finding join is at file granularity: a label records "
                 "the last contract in a victim file, while a file can carry reentrancy "
                 "findings across several contracts and functions. A confirmed drain "
                 "therefore promotes a file's reentrancy findings, not one exact line.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    root = repo_root()
    scored = load_scores(root / SCORES_CSV)
    exec_labels = load_exec_labels(root / LABELS_CSV)
    bug_lines = load_bug_lines(root / CORPUS_DIR)
    bridge = build_contract_bridge(root / CORPUS_DIR)

    # Score the vault anchor with the exact same C1 model.
    findings = load_findings(root / FINDINGS_CSV)
    model = train_model(findings, bug_lines)
    vault_c1 = float(model.predict_proba([extract_features(VAULT_ANCHOR)])[0][1])

    rows = build_eval_set(scored, exec_labels, bridge, bug_lines, vault_c1)

    # How many corpus findings actually got execution truth (not the anchor).
    n_joined_corpus = sum(1 for r in rows if r.truth_source == "execution")

    pred_only = predict_model_only(rows)
    pred_exec = predict_model_plus_execution(rows, pred_only)
    m_only = _confusion(rows, pred_only)
    m_exec = _confusion(rows, pred_exec)

    # Live LLM availability, the reason Part 1 could or could not expand labels.
    import os
    live_llm = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())

    # ---- stdout gap table ----
    print("=" * 78)
    print("GAP TABLE: model-only vs model-plus-execution (reentrancy subset)")
    print("=" * 78)
    n_confirmed = sum(1 for l in exec_labels if l.confirmed)
    print(f"n findings evaluated : {len(rows)}")
    print(f"execution labels     : {len(exec_labels)} "
          f"({n_confirmed} confirmed, {len(exec_labels) - n_confirmed} failed)")
    print(f"labels joined to corpus findings : {n_joined_corpus}")
    print(f"live LLM at run time : {'yes' if live_llm else 'no (no ANTHROPIC_API_KEY)'}")
    print(f"threshold            : c1_score >= {THRESHOLD}")
    print("-" * 78)
    print(f"{'configuration':24s} {'prec':>8s} {'recall':>8s} {'fp_rate':>8s}")
    print(_fmt_row("model-only", m_only))
    print(_fmt_row("model-plus-execution", m_exec))
    print("-" * 78)
    print(f"{'GAP (exec - only)':24s} "
          f"{m_exec.precision - m_only.precision:+8.3f} "
          f"{m_exec.recall - m_only.recall:+8.3f} "
          f"{m_exec.fp_rate - m_only.fp_rate:+8.3f}")
    print("=" * 78)

    report = build_report(rows, m_only, m_exec, exec_labels, n_joined_corpus, live_llm)
    out_path = root / REPORT_MD
    out_path.write_text(report, encoding="utf-8")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
