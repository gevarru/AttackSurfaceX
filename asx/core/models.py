"""Core data models: Finding, Severity, Confidence, ScanResult."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _redact(value: str, keep: int = 4) -> str:
    """Redact sensitive values, keeping only a short prefix."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


@dataclass
class Finding:
    """A single, uniform security finding produced by any module."""

    title: str
    severity: Severity
    confidence: Confidence
    target: str
    evidence: str
    remediation: str
    module: str
    cwe: str | None = None
    owasp: str | None = None
    references: list[str] = field(default_factory=list)
    false_positive_notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class ScanResult:
    """Aggregate result of a scan run."""

    target: str
    profile: str
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    duplicates_suppressed: int = 0

    @staticmethod
    def _title_tokens(title: str) -> set[str]:
        import re
        t = re.sub(r"\([^)]*\)", " ", title.lower())  # drop parenthetical noise like "(plugin)"
        for ch in "_/[]:":
            t = t.replace(ch, " ")
        return {tok for tok in t.split() if len(tok) > 2}

    @classmethod
    def _is_duplicate(cls, new: "Finding", existing: "Finding") -> bool:
        # Same target + same weakness class, and titles that share most of
        # their significant tokens (e.g. module vs plugin reporting the same
        # missing header with different wording).
        if new.target != existing.target:
            return False
        if (new.cwe or "").upper() != (existing.cwe or "").upper():
            return False
        if not new.cwe:
            return False
        a = cls._title_tokens(new.title)
        b = cls._title_tokens(existing.title)
        if not a or not b:
            return False
        jaccard = len(a & b) / len(a | b)
        return jaccard >= 0.6

    def add(self, finding: Finding) -> None:
        for existing in self.findings:
            if self._is_duplicate(finding, existing):
                self.duplicates_suppressed += 1
                return
        self.findings.append(finding)

    def finish(self) -> None:
        self.finished_at = time.time()

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.index(f.severity), f.title),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "AttackSurfaceX",
            "version": __import__("asx").__version__,
            "duplicates_suppressed": self.duplicates_suppressed,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "counts": self.counts(),
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
