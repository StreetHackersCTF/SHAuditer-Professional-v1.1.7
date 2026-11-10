from pathlib import Path

import pytest

from shauditer.database.db import Database
from shauditer.models.target import normalize_target
from shauditer.reporting.summary import generate_summary
from shauditer.validation import ValidationManager
from shauditer.workspace.manager import WorkspaceManager


def setup_audit(tmp_path: Path):
    db = Database(tmp_path / "shauditer.db")
    workspace = WorkspaceManager(tmp_path / "workspaces").create("SHA-2026-00001")
    target = normalize_target("10.10.10.10")
    db.create_audit("SHA-2026-00001", target, "COMPLETE", "safe", workspace)
    finding = {
        "finding_id": "F-0001",
        "title": "Synthetic test finding",
        "asset": "10.10.10.10",
        "severity": "HIGH",
        "priority_score": 8.1,
        "confidence": 0.8,
        "validation_status": "UNVALIDATED",
        "exploitability": "UNKNOWN",
    }
    db.upsert_finding("SHA-2026-00001", "F-0001", finding)
    return db, workspace


def test_validated_requires_approval(tmp_path):
    db, workspace = setup_audit(tmp_path)
    manager = ValidationManager(db, workspace)
    with pytest.raises(PermissionError):
        manager.record_validation(
            "SHA-2026-00001", "F-0001", "VALIDATED", "manual lab validation", "tester"
        )


def test_approval_validation_evidence_and_session(tmp_path):
    db, workspace = setup_audit(tmp_path)
    manager = ValidationManager(db, workspace)

    approval_id = manager.approve_validation("SHA-2026-00001", "F-0001", "tester")
    assert approval_id.startswith("AP-")

    proof = tmp_path / "proof.txt"
    proof.write_text("synthetic validation evidence\n", encoding="utf-8")
    evidence_id = manager.import_evidence("SHA-2026-00001", proof, "tester")

    validation_id = manager.record_validation(
        "SHA-2026-00001",
        "F-0001",
        "VALIDATED",
        "manual lab validation",
        "tester",
        evidence_id=evidence_id,
    )
    assert validation_id.startswith("VAL-")

    session_id = manager.record_session(
        "SHA-2026-00001",
        "F-0001",
        "REMOTE_SHELL",
        "USER",
        "tester",
        evidence_id=evidence_id,
    )
    assert session_id.startswith("SES-")

    finding = db.get_finding("SHA-2026-00001", "F-0001")
    assert finding["validation_status"] == "VALIDATED"
    assert finding["access_status"] == "CONFIRMED"
    assert finding["access_type"] == "REMOTE_SHELL"

    report = generate_summary(db, "SHA-2026-00001", workspace)
    assert report["summary"]["validated"] == 1
    assert report["summary"]["access_confirmed"] == 1
    assert (workspace / "reports" / "docx" / "executive-report.docx").exists()
    assert (workspace / "reports" / "docx" / "technical-report.docx").exists()
    assert (workspace / "reports" / "docx" / "complete-assessment.docx").exists()
