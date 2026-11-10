from pathlib import Path

from docx import Document

from shauditer.database.db import Database
from shauditer.models.target import normalize_target
from shauditer.reporting.summary import generate_summary
from shauditer.workspace.manager import WorkspaceManager


def test_generates_three_word_reports_with_detailed_sections(tmp_path):
    db = Database(tmp_path / "shauditer.db")
    workspace = WorkspaceManager(tmp_path / "workspaces").create("SHA-2026-09999")
    db.create_audit("SHA-2026-09999", normalize_target("127.0.0.1"), "COMPLETE", "safe", workspace)
    db.upsert_finding("SHA-2026-09999", "F-0001", {
        "finding_id": "F-0001",
        "title": "Synthetic reporting finding",
        "asset": "127.0.0.1",
        "severity": "HIGH",
        "priority_score": 8.2,
        "confidence": 0.9,
        "validation_status": "UNVALIDATED",
        "exploitability": "UNKNOWN",
        "description": "Synthetic description.",
        "remediation": "Apply the synthetic fix and re-test.",
    })

    report = generate_summary(db, "SHA-2026-09999", workspace)
    docx_dir = workspace / "reports" / "docx"
    expected = ["executive-report.docx", "technical-report.docx", "complete-assessment.docx"]
    for name in expected:
        assert (docx_dir / name).is_file()

    technical = Document(docx_dir / "technical-report.docx")
    text = "\n".join(p.text for p in technical.paragraphs)
    assert "Reconnaissance and Attack Surface" in text
    assert "Vulnerability Assessment" in text
    assert "Exploit Intelligence, Validation and Access" in text
    assert "Mitigation and Remediation Plan" in text
    assert "Evidence and Audit Trail" in text
    assert report["docx_reports"]["technical"].endswith("technical-report.docx")


def test_report_includes_street_hackers_identity_assurance_and_public_research_links(tmp_path):
    db = Database(tmp_path / "shauditer.db")
    workspace = WorkspaceManager(tmp_path / "workspaces").create("SHA-2026-08888")
    db.create_audit("SHA-2026-08888", normalize_target("127.0.0.1"), "COMPLETE", "safe", workspace)
    db.upsert_finding("SHA-2026-08888", "F-0001", {
        "finding_id": "F-0001",
        "title": "Synthetic Remote Code Execution",
        "asset": "127.0.0.1",
        "port": 8080,
        "severity": "CRITICAL",
        "priority_score": 9.4,
        "confidence": 0.92,
        "validation_status": "UNVALIDATED",
        "exploitability": "UNKNOWN",
        "cves": ["CVE-2021-41773"],
        "description": "Synthetic finding used to verify detailed reporting.",
    })
    db.upsert_exploit_intelligence("SHA-2026-08888", "F-0001", {
        "finding_id": "F-0001",
        "cves": ["CVE-2021-41773"],
        "applicability": {"status": "LIKELY", "confidence": 0.85, "reason": "synthetic version match"},
        "module_count": 1,
        "metasploit_modules": {
            "CVE-2021-41773": [{
                "module": "exploit/multi/http/apache_normalize_path_rce",
                "rank": "excellent",
                "check_supported": True,
                "disclosure_date": "2021-10-05",
            }]
        },
        "nvd": {},
    })

    report = generate_summary(db, "SHA-2026-08888", workspace)
    finding = report["findings"][0]
    assert finding["assessment_assurance"]["level"] == "CORROBORATED"
    assert any("rapid7.com" in link["url"] for link in finding["research_links"])
    assert any("github.com/search" in link["url"] for link in finding["research_links"])

    path = workspace / "reports" / "docx" / "technical-report.docx"
    doc = Document(path)
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "Audited by Team Street_Hackers" in text
    assert "Operator-Controlled Exploit Research Procedure" in text
    assert "Safe validation procedure" in text
    assert "CORROBORATED" in text
    assert doc.inline_shapes, "Street_Hackers logo should be embedded on the cover"

    rel_targets = [str(rel.target_ref) for rel in doc.part.rels.values() if getattr(rel, "is_external", False)]
    assert any("rapid7.com" in target for target in rel_targets)
    assert any("github.com/search" in target for target in rel_targets)
