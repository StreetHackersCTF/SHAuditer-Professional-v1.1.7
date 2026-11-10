from __future__ import annotations
from dataclasses import dataclass, field, asdict


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    asset: str
    service: str | None = None
    port: int | None = None
    severity: str = "INFORMATIONAL"
    confidence: float = 0.0
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    validation_status: str = "UNVALIDATED"
    exploitability: str = "UNKNOWN"
    priority_score: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)
