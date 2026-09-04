"""Static feature extraction for the C1 baseline triage model.

Everything here is derived from columns Module A already produced in
data/findings.csv (contract, function, line, detector_id, severity, swc_id,
source). No source code is read, no analyzer is re-run: this is deliberately
cheap static metadata so C1 stays a baseline, not the contribution.

The feature list is intentionally small and readable. Each entry below has a
one line rationale so a teammate can see why it might predict exploitability on
this reentrancy focused corpus.
"""

from __future__ import annotations

from typing import Dict, List

# The reentrancy detector family as Slither names it. reentrancy-eth is the
# ether-moving variant that actually lets a contract be drained; the others are
# weaker (unlimited-gas is frequently benign, benign/events are informational).
REENTRANCY_DETECTORS = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "reentrancy-events",
    "reentrancy-unlimited-gas",
}

# Severity to an ordinal rank. Higher means Slither thinks it matters more.
SEVERITY_RANK = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}

# Cheap keyword test on the function name: functions that move value are the
# ones a reentrancy bug can actually drain. Matched case-insensitively as a
# substring, which is enough for this corpus (withdraw_balances_re_ent8, etc.).
VALUE_MOVING_KEYWORDS = (
    "withdraw",
    "claim",
    "cash",
    "redeem",
    "payout",
    "transfer",
    "send",
    "buy",
    "sell",
    "deposit",
)

# The feature vector column order. Kept as a module constant so the ranker and
# any reader use exactly the same ordering.
FEATURE_NAMES: List[str] = [
    "sev_rank",              # ordinal severity (High=3 .. Info=0)
    "is_high",               # 1 if severity is High
    "is_reentrancy_family",  # 1 if the detector is any reentrancy-* rule
    "is_reentrancy_eth",     # 1 if the detector is reentrancy-eth (drainable)
    "is_reentrancy_ugas",    # 1 if reentrancy-unlimited-gas (often benign)
    "is_swc107",             # 1 if the SWC id is SWC-107 (reentrancy)
    "func_moves_value",      # 1 if the function name looks value-moving
    "has_function",          # 1 if the finding is tied to a named function
]


def is_reentrancy_family(detector_id: str) -> bool:
    """True for any reentrancy-* detector."""
    return detector_id in REENTRANCY_DETECTORS or detector_id.startswith("reentrancy")


def _func_moves_value(function: str) -> int:
    name = (function or "").lower()
    return 1 if any(k in name for k in VALUE_MOVING_KEYWORDS) else 0


def extract_features(row: Dict[str, str]) -> List[float]:
    """Turn one findings.csv row (a dict) into a numeric feature vector.

    The order matches FEATURE_NAMES exactly.
    """
    detector = (row.get("detector_id") or "").strip()
    severity = (row.get("severity") or "").strip()
    swc = (row.get("swc_id") or "").strip()
    function = (row.get("function") or "").strip()

    return [
        float(SEVERITY_RANK.get(severity, 0)),
        1.0 if severity == "High" else 0.0,
        1.0 if is_reentrancy_family(detector) else 0.0,
        1.0 if detector == "reentrancy-eth" else 0.0,
        1.0 if detector == "reentrancy-unlimited-gas" else 0.0,
        1.0 if swc == "SWC-107" else 0.0,
        float(_func_moves_value(function)),
        1.0 if function else 0.0,
    ]
