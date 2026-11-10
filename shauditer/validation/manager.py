from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil

from shauditer.core.events import AuditEvent, EventBus
from shauditer.security.evidence import sha256_file


VALIDATION_STATUSES = {
    "UNVALIDATED",
    "VALIDATED",
    "NOT_VALIDATED",
    "INCONCLUSIVE",
}

SESSION_TYPES = {
    "APPLICATION_ACCESS",
    "REMOTE_SHELL",
    "LOCAL_SHELL",
    "OTHER",
}

PRIVILEGES = {
    "NONE",
    "APPLICATION",
    "USER",
    "ADMINISTRATOR",
    "ROOT",
    "SYSTEM",
    "OTHER",
}


@dataclass(slots=True)
class ValidationManager:
    db: object
    workspace: Path

    def _bus(self) -> EventBus:
        return EventBus(self.db, self.workspace)


    def import_evidence(
        self,
        audit_id: str,
        source: str | Path,
        operator: str,
        *,
        kind: str = "MANUAL_VALIDATION",
        note: str = "",
    ) -> str:
        source = Path(source).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        evidence_id = f"EV-{audit_id}-MAN-{len(self.db.get_evidence(audit_id)) + 1:05d}"
        dest_dir = self.workspace / "evidence" / "manual"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{evidence_id}-{source.name}"
        shutil.copy2(source, dest)
        digest = sha256_file(dest)
        self.db.add_evidence(
            evidence_id, audit_id, "operator", kind, str(dest), digest,
            metadata={"operator": operator, "note": note, "source_name": source.name},
        )
        self._bus().emit(AuditEvent(
            audit_id,
            "EVIDENCE_IMPORTED",
            {
                "evidence_id": evidence_id,
                "kind": kind,
                "operator": operator,
                "path": str(dest),
                "sha256": digest,
            },
        ))
        return evidence_id

    def approve_validation(self, audit_id: str, finding_id: str, operator: str, note: str = "") -> str:
        finding = self.db.get_finding(audit_id, finding_id)
        if not finding:
            raise KeyError(f"unknown finding: {finding_id}")
        approval_id = self.db.add_approval(
            audit_id,
            finding_id,
            "SAFE_VALIDATION",
            operator,
            approved=True,
            note=note,
        )
        self._bus().emit(AuditEvent(
            audit_id,
            "OPERATOR_APPROVAL_RECORDED",
            {
                "approval_id": approval_id,
                "finding_id": finding_id,
                "action": "SAFE_VALIDATION",
                "operator": operator,
            },
        ))
        return approval_id

    def record_validation(
        self,
        audit_id: str,
        finding_id: str,
        status: str,
        method: str,
        operator: str,
        *,
        note: str = "",
        evidence_id: str | None = None,
    ) -> str:
        status = status.upper()
        if not str(operator).strip() or not str(method).strip():
            raise ValueError("operator identity and validation method are required")
        if status not in VALIDATION_STATUSES:
            raise ValueError(f"unsupported validation status: {status}")
        finding = self.db.get_finding(audit_id, finding_id)
        if not finding:
            raise KeyError(f"unknown finding: {finding_id}")
        if status == "VALIDATED" and not self.db.has_approval(audit_id, finding_id, "SAFE_VALIDATION"):
            raise PermissionError("VALIDATED status requires a recorded operator approval for SAFE_VALIDATION")
        if evidence_id:
            evidence_records = {e["evidence_id"]: e for e in self.db.get_evidence(audit_id)}
            if evidence_id not in evidence_records:
                raise KeyError(f"unknown evidence ID: {evidence_id}")
            record = evidence_records[evidence_id]
            if not Path(record["path"]).is_file() or sha256_file(record["path"]) != record["sha256"]:
                raise ValueError("linked evidence missing or its hash does not match")
        elif status == "VALIDATED":
            raise ValueError("VALIDATED status requires attached, hashed evidence")

        validation_id = self.db.add_validation(
            audit_id,
            finding_id,
            status,
            method,
            operator,
            note=note,
            evidence_id=evidence_id,
        )

        finding["validation_status"] = status
        finding["validation_method"] = method
        if status == "VALIDATED":
            finding["confidence"] = 1.0
            finding["exploitability"] = (
                "OBSERVATION_CONFIRMED" if method == "SAFE_CONTROL_RECHECK" else "CONFIRMED"
            )
        elif status == "NOT_VALIDATED":
            finding["exploitability"] = "NOT_CONFIRMED"
        self.db.upsert_finding(audit_id, finding_id, finding)

        self._bus().emit(AuditEvent(
            audit_id,
            "VALIDATION_RECORDED",
            {
                "validation_id": validation_id,
                "finding_id": finding_id,
                "status": status,
                "method": method,
                "operator": operator,
                "evidence_id": evidence_id,
            },
        ))
        return validation_id

    def record_session(
        self,
        audit_id: str,
        finding_id: str,
        session_type: str,
        privilege: str,
        operator: str,
        *,
        evidence_id: str,
        note: str = "",
    ) -> str:
        session_type = session_type.upper()
        privilege = privilege.upper()
        if session_type not in SESSION_TYPES:
            raise ValueError(f"unsupported session type: {session_type}")
        if privilege not in PRIVILEGES:
            raise ValueError(f"unsupported privilege: {privilege}")
        finding = self.db.get_finding(audit_id, finding_id)
        if not finding:
            raise KeyError(f"unknown finding: {finding_id}")
        if finding.get("validation_status") != "VALIDATED":
            raise PermissionError("a session can only be recorded for a VALIDATED finding")
        if not evidence_id:
            raise ValueError("session recording requires an evidence ID")
        known_evidence = {e["evidence_id"] for e in self.db.get_evidence(audit_id)}
        if evidence_id not in known_evidence:
            raise KeyError(f"unknown evidence ID: {evidence_id}")
        linked = next(e for e in self.db.get_evidence(audit_id) if e["evidence_id"] == evidence_id)
        if not Path(linked["path"]).is_file() or sha256_file(linked["path"]) != linked["sha256"]:
            raise ValueError("session evidence is missing or its hash does not match")

        session_id = self.db.add_session(
            audit_id,
            finding_id,
            session_type,
            privilege,
            operator,
            evidence_id=evidence_id,
            note=note,
        )
        finding["access_status"] = "CONFIRMED"
        finding["access_type"] = session_type
        finding["privilege"] = privilege
        finding["session_id"] = session_id
        self.db.upsert_finding(audit_id, finding_id, finding)

        self._bus().emit(AuditEvent(
            audit_id,
            "ACCESS_CONFIRMED",
            {
                "session_id": session_id,
                "finding_id": finding_id,
                "session_type": session_type,
                "privilege": privilege,
                "operator": operator,
                "evidence_id": evidence_id,
            },
        ))
        return session_id
