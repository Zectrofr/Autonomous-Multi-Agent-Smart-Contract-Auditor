"""Execution grounded label output.

The whole point of Module D is that labels come from execution, not from a
dataset and not from the LLM's own claim of success. This module writes one row
per victim to data/labels.csv, the training signal the ranking model will later
consume.

Schema (exact, in this column order):
    contract, vuln_class, confirmed, attempts, invariant_asserted, evidence

  contract            the victim contract name or file stem
  vuln_class          the suspected vulnerability class, e.g. reentrancy
  confirmed           true only if forge test genuinely passed on an exploit
                      that asserts a real broken invariant; false otherwise
  attempts            how many LLM attempts the loop used before stopping
  invariant_asserted  the invariant the exploit was required to prove
  evidence            a short human readable string: on pass the drained
                      amounts, on fail the final revert or compiler error

data/labels.csv is APPEND only from this module. It never touches Module A's
data/findings.csv.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List

FIELDNAMES: List[str] = [
    "contract",
    "vuln_class",
    "confirmed",
    "attempts",
    "invariant_asserted",
    "evidence",
]


@dataclass
class Label:
    """One execution grounded label row."""

    contract: str
    vuln_class: str
    confirmed: bool
    attempts: int
    invariant_asserted: str
    evidence: str

    def as_row(self) -> dict:
        return {
            "contract": self.contract,
            "vuln_class": self.vuln_class,
            # Written as lowercase true/false as the schema requires.
            "confirmed": "true" if self.confirmed else "false",
            "attempts": str(self.attempts),
            "invariant_asserted": self.invariant_asserted,
            "evidence": self.evidence,
        }


def append_label(label: Label, out_path: Path) -> None:
    """Append one label row, writing the header first if the file is new.

    Append only: an existing data/labels.csv (and every other file under data/)
    keeps its rows. The header is written once, when the file does not yet exist
    or is empty.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not out_path.exists() or out_path.stat().st_size == 0
    with out_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        if write_header:
            writer.writeheader()
        writer.writerow(label.as_row())
