"""Findings schema and normalization helpers for Module A.

Every static analyzer speaks its own dialect. This module is the single place
where a raw analyzer record is turned into the one row shape that the rest of
the pipeline (ranking, then execution based verification) consumes.

The row shape is fixed and ordered:

    contract, function, line, detector_id, severity, swc_id, source

Column meanings:
    contract     Corpus unit the finding belongs to, i.e. the Solidity file
                 stem such as "buggy_1". This is deliberately the file stem and
                 not the Solidity contract name, because the corpus labels are
                 recorded per file, so this column joins directly against the
                 label files. The Solidity contract name is not lost: it is
                 carried in the "function" column using the Slither convention
                 "Contract.function()".
    function     Enclosing function, formatted "Contract.function()" when the
                 analyzer gives us enough context, otherwise the element name
                 or an empty string.
    line         1 based source line the finding is anchored to.
    detector_id  Analyzer rule id, e.g. "reentrancy-eth".
    severity     Normalized to exactly one of High, Medium, Low, Info.
    swc_id       Best effort SWC registry id, e.g. "SWC-107". Empty when the
                 detector has no meaningful SWC counterpart (style and
                 optimization rules mostly).
    source       Analyzer that produced the row, e.g. "slither".
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

# Exact column order used by data/findings.csv. Keep this list authoritative:
# downstream modules read the CSV header, not a hardcoded tuple.
FIELDNAMES: List[str] = [
    "contract",
    "function",
    "line",
    "detector_id",
    "severity",
    "swc_id",
    "source",
]

# Slither reports "impact" as High / Medium / Low / Informational / Optimization.
# The pipeline only carries four buckets, so the last two collapse into Info.
_SEVERITY_MAP = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
    "information": "Info",
    "info": "Info",
    "optimization": "Info",
}

# Best effort Slither detector to SWC registry mapping. Only detectors with a
# defensible SWC counterpart are listed; anything absent normalizes to "".
# Style, naming and gas rules intentionally have no SWC id.
_SWC_MAP = {
    # Reentrancy family
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "reentrancy-benign": "SWC-107",
    "reentrancy-events": "SWC-107",
    "reentrancy-unlimited-gas": "SWC-107",
    # Access control and ether handling
    "arbitrary-send": "SWC-105",
    "arbitrary-send-eth": "SWC-105",
    "arbitrary-send-erc20": "SWC-105",
    "arbitrary-send-erc20-permit": "SWC-105",
    "suicidal": "SWC-106",
    "unprotected-upgrade": "SWC-105",
    "tx-origin": "SWC-115",
    # Unchecked return values
    "unchecked-lowlevel": "SWC-104",
    "unchecked-send": "SWC-104",
    "unchecked-transfer": "SWC-104",
    "unused-return": "SWC-104",
    "low-level-calls": "SWC-104",
    # Delegatecall
    "controlled-delegatecall": "SWC-112",
    "delegatecall-loop": "SWC-112",
    # Randomness and time
    "weak-prng": "SWC-120",
    "timestamp": "SWC-116",
    "block-other-parameters": "SWC-116",
    # Uninitialized storage and state
    "uninitialized-state": "SWC-109",
    "uninitialized-storage": "SWC-109",
    "uninitialized-local": "SWC-109",
    # Shadowing
    "shadowing-state": "SWC-119",
    "shadowing-abstract": "SWC-119",
    "shadowing-builtin": "SWC-119",
    "shadowing-local": "SWC-119",
    # Arithmetic
    "divide-before-multiply": "SWC-101",
    "incorrect-shift": "SWC-101",
    "tautology": "SWC-129",
    "incorrect-equality": "SWC-132",
    # Calls and control flow
    "calls-loop": "SWC-113",
    "msg-value-loop": "SWC-113",
    "assert-state-change": "SWC-110",
    "deprecated-standards": "SWC-111",
    "encode-packed-collision": "SWC-133",
    # Compiler configuration
    "solc-version": "SWC-103",
    "pragma": "SWC-103",
    # Interfaces and initialization
    "unimplemented-functions": "SWC-100",
    "missing-zero-check": "SWC-123",
}


def normalize_severity(raw: Optional[str]) -> str:
    """Collapse an analyzer severity label into High / Medium / Low / Info."""
    if not raw:
        return "Info"
    return _SEVERITY_MAP.get(str(raw).strip().lower(), "Info")


def swc_for(detector_id: Optional[str]) -> str:
    """Return the SWC id for a detector, or "" when there is no sane mapping."""
    if not detector_id:
        return ""
    return _SWC_MAP.get(str(detector_id).strip().lower(), "")


def make_finding(
    contract: str,
    function: str,
    line: int,
    detector_id: str,
    severity: str,
    source: str,
    swc_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build one schema conformant finding row."""
    detector_id = (detector_id or "unknown").strip()
    return {
        "contract": contract,
        "function": function or "",
        "line": int(line),
        "detector_id": detector_id,
        "severity": normalize_severity(severity),
        "swc_id": swc_id if swc_id is not None else swc_for(detector_id),
        "source": source,
    }


# ---------------------------------------------------------------------------
# Slither JSON parsing
# ---------------------------------------------------------------------------
#
# The Slither JSON shape is verified at runtime rather than assumed, because it
# has drifted across releases. As observed with slither-analyzer 0.11.6 the
# document is:
#
#   {"success": bool, "error": str or null,
#    "results": {"detectors": [
#        {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
#         "description": "...", "id": "...", "elements": [
#             {"type": "function" or "node" or "contract" or "variable",
#              "name": "...",
#              "source_mapping": {"lines": [67, 68], "filename_short": "x.sol",
#                                 "filename_absolute": "...", ...},
#              "type_specific_fields": {"parent": {...}, "signature": "..."}}
#         ]}
#    ]}}
#
# Older releases put a bare list at the top level, and some releases spelled the
# mapping key "sourceMapping". Every accessor below therefore probes for the
# alternatives and tolerates missing keys instead of raising.

# Preference order when a detector reports several elements. A "node" pins the
# exact statement, which is the tightest anchor available; a whole contract is
# the loosest. Lower number wins.
_ELEMENT_PRIORITY = {
    "node": 0,
    "expression": 1,
    "variable": 2,
    "function": 3,
    "modifier": 3,
    "pragma": 4,
    "contract": 5,
}


def describe_slither_json(doc: Any) -> str:
    """Human readable one line summary of the JSON shape we actually got.

    Printed once per run so a teammate hitting a future Slither release can see
    immediately whether the document still looks the way this parser expects.
    """
    if isinstance(doc, dict):
        top = sorted(doc.keys())
        results = doc.get("results")
        inner = sorted(results.keys()) if isinstance(results, dict) else type(results).__name__
        dets = _detector_records(doc)
        keys = sorted(dets[0].keys()) if dets else []
        return f"top={top} results={inner} n_detectors={len(dets)} detector_keys={keys}"
    return f"unexpected top level type: {type(doc).__name__}"


def _detector_records(doc: Any) -> List[dict]:
    """Pull the detector result list out of whatever shape Slither handed us."""
    if isinstance(doc, list):
        # Very old Slither wrote a bare list of detector results.
        return [r for r in doc if isinstance(r, dict)]
    if not isinstance(doc, dict):
        return []
    results = doc.get("results")
    if isinstance(results, dict):
        for key in ("detectors", "detector", "results"):
            value = results.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    # Last resort: the detector list sat at the top level under a known key.
    for key in ("detectors", "findings"):
        value = doc.get(key)
        if isinstance(value, list):
            return [r for r in value if isinstance(r, dict)]
    return []


def _source_mapping(element: dict) -> dict:
    """Fetch an element source mapping under either of its historical names."""
    for key in ("source_mapping", "sourceMapping"):
        value = element.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _element_lines(element: dict) -> List[int]:
    lines = _source_mapping(element).get("lines")
    if isinstance(lines, list):
        return [int(n) for n in lines if isinstance(n, (int, float))]
    return []


def _element_filename(element: dict) -> str:
    mapping = _source_mapping(element)
    for key in ("filename_short", "filename_relative", "filename_absolute", "filename"):
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value.replace("\\", "/")
    return ""


def _parent_chain(element: dict) -> Iterable[dict]:
    """Walk type_specific_fields.parent upward, guarding against runaway depth."""
    node = element
    for _ in range(12):
        tsf = node.get("type_specific_fields")
        parent = tsf.get("parent") if isinstance(tsf, dict) else None
        if not isinstance(parent, dict):
            return
        yield parent
        node = parent


def _qualified_function(element: dict) -> str:
    """Render "Contract.function()" for an element, best effort.

    Slither puts the signature on the function element itself and the owning
    contract one level up the parent chain, so we look at the element and then
    walk upward until both halves are found.
    """
    func_name = ""
    contract_name = ""

    for candidate in [element] + list(_parent_chain(element)):
        kind = candidate.get("type")
        tsf = candidate.get("type_specific_fields")
        tsf = tsf if isinstance(tsf, dict) else {}
        if not func_name and kind in ("function", "modifier"):
            func_name = tsf.get("signature") or candidate.get("name") or ""
        if not contract_name and kind == "contract":
            contract_name = candidate.get("name") or ""

    if func_name and contract_name:
        return f"{contract_name}.{func_name}"
    if func_name:
        return func_name
    if contract_name:
        return contract_name
    return element.get("name") or ""


def _pick_anchor(elements: List[dict], target_basename: str) -> Optional[dict]:
    """Choose the element a finding should be anchored to.

    Prefers elements that live in the file we asked Slither to analyze (imports
    and dependencies lose), then the most specific element type, then the
    earliest source line. That keeps the reported line as tight as possible,
    which matters because label matching works on line proximity.
    """
    scored = []
    for element in elements:
        if not isinstance(element, dict):
            continue
        lines = _element_lines(element)
        if not lines:
            continue
        filename = _element_filename(element)
        in_target = 0 if (not target_basename or filename.endswith(target_basename)) else 1
        priority = _ELEMENT_PRIORITY.get(str(element.get("type")), 4)
        scored.append((in_target, priority, min(lines), element))
    if not scored:
        return None
    scored.sort(key=lambda item: (item[0], item[1], item[2]))
    return scored[0][3]


def parse_slither_json(
    doc: Any,
    contract: str,
    target_basename: str = "",
    source: str = "slither",
) -> List[Dict[str, Any]]:
    """Turn a Slither JSON document into schema conformant finding rows.

    Never raises on a malformed document: unusable records are skipped so one
    odd detector result cannot take down a whole corpus run.
    """
    rows: List[Dict[str, Any]] = []
    for record in _detector_records(doc):
        detector_id = record.get("check") or record.get("detector") or "unknown"
        severity = record.get("impact") or record.get("severity")

        elements = record.get("elements")
        elements = elements if isinstance(elements, list) else []
        anchor = _pick_anchor(elements, target_basename)

        if anchor is not None:
            line = min(_element_lines(anchor))
            function = _qualified_function(anchor)
        else:
            # No usable source mapping. Keep the finding (it is still a real
            # detector hit) but anchor it at line 0 so the label matcher can
            # never accidentally score it as a true positive.
            line = 0
            function = ""

        rows.append(
            make_finding(
                contract=contract,
                function=function,
                line=line,
                detector_id=detector_id,
                severity=severity,
                source=source,
            )
        )
    return rows
