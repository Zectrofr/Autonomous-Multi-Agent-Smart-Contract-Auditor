"""SolidiFI ground truth for scoring findings.

This reuses Module A's rule: a finding is a true positive if it sits on a line
the SolidiFI benchmark injected a bug into. The injected lines live in
auditor/corpus/<stem>.labels.json under "bug_lines". A finding whose line is in
that set is a real (injected) bug; anything else on that corpus file is a false
positive under this rule.

The harness may additionally override this with execution truth for the
reentrancy subset (an agent-confirmed drain is stronger evidence than a line
match), but this module provides the static default truth used both for training
the C1 baseline and for any finding with no execution label.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional, Set


def repo_root() -> Path:
    """Project root, one level up from the triage/ package."""
    return Path(__file__).resolve().parent.parent


def load_bug_lines(corpus_dir: Path) -> Dict[str, Set[int]]:
    """Map each corpus file stem (e.g. buggy_3) to its set of injected bug lines.

    Missing or malformed label files are skipped rather than fatal, so the
    harness keeps working on whatever labels are present.
    """
    bug_lines: Dict[str, Set[int]] = {}
    for label_file in sorted(corpus_dir.glob("*.labels.json")):
        stem = label_file.name[: -len(".labels.json")]
        try:
            data = json.loads(label_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        lines = data.get("bug_lines") or []
        bug_lines[stem] = {int(x) for x in lines}
    return bug_lines


def solidifi_truth(
    contract: str,
    line: int,
    bug_lines: Dict[str, Set[int]],
) -> Optional[int]:
    """Return 1 (true positive), 0 (false positive), or None (no label file).

    contract is the findings.csv contract column, which for the corpus is the
    file stem (buggy_N). None means we have no SolidiFI labels for that file and
    cannot judge the finding by this rule.
    """
    if contract not in bug_lines:
        return None
    return 1 if int(line) in bug_lines[contract] else 0
