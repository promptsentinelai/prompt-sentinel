"""Shared detection configuration values.

Centralizes detection thresholds and related parameters so that
different detectors stay consistent and avoid duplication.
"""

from typing import TypedDict


class VerdictThresholds(TypedDict):
    block: float
    strip: float
    flag: float


# Mode-specific thresholds for verdict decisions
VERDICT_THRESHOLDS: dict[str, VerdictThresholds] = {
    "strict": {"block": 0.7, "strip": 0.5, "flag": 0.3},
    "moderate": {"block": 0.8, "strip": 0.6, "flag": 0.4},
    "permissive": {"block": 0.9, "strip": 0.7, "flag": 0.5},
}


def get_thresholds(mode: str) -> VerdictThresholds:
    """Return thresholds for a given detection mode.

    Defaults to 'moderate' if mode is unrecognized.
    """
    return VERDICT_THRESHOLDS.get(mode, VERDICT_THRESHOLDS["moderate"])  # type: ignore[return-value]
