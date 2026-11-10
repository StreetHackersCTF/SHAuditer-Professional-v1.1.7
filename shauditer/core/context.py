from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AuditContext:
    audit_id: str
    target: object
    workspace: Path
    db: object
    scope: object
    events: object
    runner: object
    config: dict
    profile: str
    dry_run: bool = False
