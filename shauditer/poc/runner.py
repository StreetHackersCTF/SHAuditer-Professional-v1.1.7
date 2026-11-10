"""Single-use, operator-approved, low-impact proof-of-control verification.

This deliberately provides no payload execution, shell access, brute force,
state-changing HTTP methods, or unrestricted user-defined commands.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from shauditer.core.events import AuditEvent, EventBus
from shauditer.modules.web.posture import probe, sanitized_probe
from shauditer.scope.policy_io import scope_from_dict
from shauditer.scope.validator import ScopeValidator
from shauditer.security.evidence import sha256_file
from shauditer.validation.manager import ValidationManager

ALLOWED = {"HTTP_HEADER", "COOKIE_ATTRIBUTE"}


class PoCManager:
    def __init__(self, db, workspace: Path, *, timeout: float = 6.0):
        self.db = db
        self.workspace = Path(workspace)
        self.timeout = min(max(float(timeout), 1), 15)

    def _finding(self, audit_id, finding_id):
        finding = self.db.get_finding(audit_id, finding_id)
        if not finding:
            raise KeyError(f"unknown finding: {finding_id}")
        if finding.get("poc_type") not in ALLOWED:
            raise ValueError("finding has no supported low-impact verification: use documented manual evidence workflow")
        if not finding.get("poc_parameter") or not finding.get("endpoint"):
            raise ValueError("finding is missing verification metadata")
        return finding

    def approve(self, audit_id: str, finding_id: str, *, operator: str, note: str, acknowledgement: bool) -> str:
        if not acknowledgement:
            raise PermissionError("an explicit approval acknowledgement is required")
        if not operator.strip() or len(operator) > 120:
            raise ValueError("operator identity must be 1–120 characters")
        finding = self._finding(audit_id, finding_id)
        action = "POC:" + finding["poc_type"]
        approval_id = self.db.add_approval(audit_id, finding_id, action, operator.strip(), approved=True, note=note[:1000])
        EventBus(self.db, self.workspace).emit(AuditEvent(audit_id, "POC_APPROVED", {
            "approval_id": approval_id, "operator": operator.strip(), "finding_id": finding_id,
            "check": finding["poc_type"], "single_use": True,
        }))
        return approval_id

    def execute(self, audit_id: str, finding_id: str, *, approval_id: str, operator: str) -> dict:
        finding = self._finding(audit_id, finding_id)
        if not operator.strip():
            raise ValueError("operator identity required")
        endpoint = str(finding["endpoint"])
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("low-impact proof requires an explicit HTTP(S) endpoint")
        scope_file = self.workspace / "metadata" / "scope.json"
        obj = json.loads(scope_file.read_text(encoding="utf-8"))
        scope = ScopeValidator(scope_from_dict(obj))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        decision = scope.authorize(parsed.hostname, port, action="approved proof-of-control")
        if not decision.allowed:
            raise PermissionError(decision.reason)
        # This statement atomically reserves approval ID before making a network
        # connection. Concurrent or repeated requests cannot reuse approval.
        execution_id = "POC-" + uuid4().hex[:16].upper()
        self.db.reserve_poc_execution(execution_id, approval_id, audit_id, finding_id,
                                      "POC:" + finding["poc_type"], operator.strip())
        outcome = "INCONCLUSIVE"
        error = None
        sanitized = None
        evidence_id = None
        try:
            response = probe(endpoint, scope, timeout=self.timeout)
            sanitized = sanitized_probe(response)
            parameter = finding["poc_parameter"].lower()
            headers = response["headers"]
            if finding["poc_type"] == "HTTP_HEADER":
                observed_missing = parameter not in {k.lower() for k, _ in headers}
                outcome = "VALIDATED" if observed_missing else "NOT_VALIDATED"
            else:
                cookies = [v for k, v in headers if k.lower() == "set-cookie"]
                if not cookies:
                    outcome = "INCONCLUSIVE"
                else:
                    missing = any(parameter not in {p.strip().lower() for p in cookie.split(";")[1:]} for cookie in cookies)
                    outcome = "VALIDATED" if missing else "NOT_VALIDATED"
        except Exception as exc:
            # Keep error type only: do not expose raw HTTP secrets or stack traces.
            error = type(exc).__name__
        try:
            safe_record = {
                "audit_id": audit_id, "finding_id": finding_id, "execution_id": execution_id,
                "approval_id": approval_id, "operator": operator.strip(),
                "check": finding["poc_type"], "parameter": finding["poc_parameter"],
                "result": outcome, "scope": "CONTROL_OBSERVATION_ONLY",
                "impact_demonstrated": False, "error_type": error, "observation": sanitized,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
            folder = self.workspace / "evidence" / "poc"
            folder.mkdir(parents=True, exist_ok=True)
            dest = folder / (execution_id + ".json")
            dest.write_text(json.dumps(safe_record, indent=2), encoding="utf-8")
            evidence_id = "EV-" + execution_id
            self.db.add_evidence(evidence_id, audit_id, "approved_poc", "non_destructive_control_verification", str(dest), sha256_file(dest),
                                 metadata={"execution_id": execution_id, "scope": "CONTROL_OBSERVATION_ONLY"})
            # Existing validation ledger requires a SAFE_VALIDATION action; this is
            # recorded as an *engine acknowledgement* after consuming the explicit
            # operator's bound, one-time POC approval.
            validator = ValidationManager(self.db, self.workspace)
            validator.approve_validation(audit_id, finding_id, "SHAuditer-PoC-Engine", note=f"Bound to consumed {approval_id}")
            validator.record_validation(audit_id, finding_id, outcome,
                                        "SAFE_CONTROL_RECHECK", operator.strip(),
                                        note=f"{finding['poc_type']} observation; no exploitation or impact demonstrated", evidence_id=evidence_id)
            self.db.finish_poc_execution(execution_id, outcome, evidence_id=evidence_id)
            EventBus(self.db, self.workspace).emit(AuditEvent(audit_id, "POC_EXECUTED", safe_record))
            return safe_record
        except Exception:
            self.db.finish_poc_execution(execution_id, "FAILED", evidence_id=evidence_id)
            raise
