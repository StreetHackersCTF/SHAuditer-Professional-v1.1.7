from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AuditEvent:
    audit_id: str
    event_type: str
    payload: dict[str, Any]
    previous_state: str | None = None
    new_state: str | None = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


class EventBus:
    def __init__(self, db, workspace: Path):
        self.db = db
        self.event_log = workspace / "logs" / "events.jsonl"
        self.event_log.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AuditEvent) -> None:
        self.db.add_event(event)
        with self.event_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
