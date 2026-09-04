"""C1 baseline triage: score every finding for exploitability from static
metadata alone.

This is the model-only configuration and the yardstick the F harness compares
against. It trains a small logistic regression on the SolidiFI ground truth
(finding-on-an-injected-line = true positive) using only the cheap static
features in triage/features.py, then writes a per-finding score column.

Honesty notes:
  - This is a baseline, not the contribution. A handful of documented features
    and a linear model, nothing more.
  - Scores are in-sample (train and score on the same findings). That is fine
    for a yardstick whose only job is to rank findings by static plausibility;
    it is not being reported as a generalization result.

Run:
    python -m triage.rank
writes triage/scores.csv = findings.csv rows plus a c1_score column.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from sklearn.linear_model import LogisticRegression

from triage.features import FEATURE_NAMES, extract_features
from triage.ground_truth import load_bug_lines, repo_root, solidifi_truth

FINDINGS_CSV = "data/findings.csv"
SCORES_CSV = "triage/scores.csv"
CORPUS_DIR = "auditor/corpus"


def load_findings(path: Path) -> List[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def train_model(findings: List[dict], bug_lines) -> LogisticRegression:
    """Fit the C1 baseline on the SolidiFI-labeled findings and return it.

    Exposed as a function so the F harness can score the execution-anchor row
    (VulnerableVault, which is not in findings.csv) with the exact same model.
    Findings whose contract has no SolidiFI label file are skipped for training.
    """
    x_train: List[List[float]] = []
    y_train: List[int] = []
    for row in findings:
        truth = solidifi_truth(row["contract"], int(row.get("line") or 0), bug_lines)
        if truth is None:
            continue
        x_train.append(extract_features(row))
        y_train.append(truth)

    # Small linear model. class_weight balanced so the many Info-level false
    # positives do not swamp the signal. liblinear is deterministic on a problem
    # this small.
    model = LogisticRegression(
        class_weight="balanced",
        solver="liblinear",
        random_state=0,
    )
    model.fit(x_train, y_train)
    # Stash the training counts on the model for the caller's readout.
    model.n_train_ = len(y_train)  # type: ignore[attr-defined]
    model.n_pos_ = int(sum(y_train))  # type: ignore[attr-defined]
    return model


def main() -> int:
    root = repo_root()
    findings = load_findings(root / FINDINGS_CSV)
    bug_lines = load_bug_lines(root / CORPUS_DIR)

    model = train_model(findings, bug_lines)
    n_train = model.n_train_  # type: ignore[attr-defined]
    n_pos = model.n_pos_  # type: ignore[attr-defined]
    print(f"training C1 on {n_train} labeled findings "
          f"({n_pos} true, {n_train - n_pos} false)")
    print(f"features: {', '.join(FEATURE_NAMES)}")

    # Score every finding (including any that had no label file) and write out.
    out_path = root / SCORES_CSV
    fieldnames = list(findings[0].keys()) + ["c1_score"]
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in findings:
            score = float(model.predict_proba([extract_features(row)])[0][1])
            out = dict(row)
            out["c1_score"] = f"{score:.6f}"
            writer.writerow(out)

    # A short readout so a teammate can sanity check the learned weights.
    print(f"wrote {out_path} ({len(findings)} rows)")
    print("learned weights (feature: coef):")
    for name, coef in zip(FEATURE_NAMES, model.coef_[0]):
        print(f"  {name:22s} {coef:+.3f}")
    print(f"  {'(intercept)':22s} {model.intercept_[0]:+.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
