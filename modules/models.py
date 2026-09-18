"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List


SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_at_least(value: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(value, 0) >= SEVERITY_ORDER.get(minimum, 0)


@dataclass
class Finding:
    """A single security observation produced by any module."""

    id: str
    title: str
    severity: str            # info | low | medium | high | critical
    category: str            # machine-readable bucket, drives compliance mapping
    description: str
    asset: str = ""          # affected host / IP / MAC
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
