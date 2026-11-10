from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from shauditer.reporting.docx_report import generate_docx_reports
from shauditer.reporting.enrichment import enrich_findings
from shauditer.reporting.quality import evaluate_assessment
from shauditer.reporting.professional import build_workflow, generate_professional_exports
from shauditer.reporting.bundle import bundle_reports
from shauditer.reporting.nist_profile import build_nist_profile


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


def _load_recon(workspace: Path) -> dict:
    recon_path = workspace / "recon" / "normalized.json"
    if recon_path.exists():
        try:
            obj = json.loads(recon_path.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                obj.setdefault("assets", [])
                obj.setdefault("services", [])
                obj.setdefault("technologies", [])
                obj.setdefault("modules", [])
                return obj
        except (OSError, json.JSONDecodeError):
            pass
    return {"assets": [], "services": [], "technologies": [], "modules": []}


def _normalize_severity(value) -> str:
    value = str(value or "INFORMATIONAL").upper()
    return "INFORMATIONAL" if value == "INFO" else value


def _generic_mitigation(finding: dict) -> str:
    severity = _normalize_severity(finding.get("severity"))
    title = str(finding.get("title") or "the affected component")
    if severity in {"CRITICAL", "HIGH"}:
        return (
            f"Confirm the affected version/configuration for {title}, apply the vendor fix or supported upgrade, "
            "reduce external exposure until remediation is complete, and re-test after the change."
        )
    if severity == "MEDIUM":
        return (
            f"Harden {title}, apply available updates, restrict unnecessary network/application exposure, "
            "and verify the control with a targeted re-test."
        )
    return (
        f"Review {title} during normal hardening, remove unnecessary exposure, apply supported configuration guidance, "
        "and confirm the issue is no longer observable during the next assessment."
    )


def _mitigation_row(finding: dict) -> dict:
    specific = str(finding.get("remediation") or "").strip()
    severity = _normalize_severity(finding.get("severity"))
    priority = "IMMEDIATE" if severity == "CRITICAL" else "HIGH" if severity == "HIGH" else "PLANNED"
    return {
        "finding_id": finding.get("finding_id"),
        "severity": severity,
        "remediation_priority": priority,
        "title": finding.get("title"),
        "recommendation": specific or _generic_mitigation(finding),
        "guidance_source": "FINDING_SPECIFIC" if specific else "GENERIC_SHAUDITER",
        "validation_status": finding.get("validation_status", "UNVALIDATED"),
    }


def _report_model(db, audit_id: str, workspace: Path) -> dict:
    audit = db.get_audit(audit_id)
    if not audit:
        raise KeyError(audit_id)

    recon = _load_recon(workspace)
    raw_findings = db.get_findings(audit_id)
    approvals = db.get_approvals(audit_id)
    validations = db.get_validations(audit_id)
    sessions = db.get_sessions(audit_id)
    exploit_intelligence = db.get_all_exploit_intelligence(audit_id)
    exploit_reviews = db.get_exploit_reviews(audit_id)
    evidence = db.get_evidence(audit_id)
    module_runs = db.get_module_runs(audit_id)
    findings = enrich_findings(
        raw_findings,
        exploit_intelligence=exploit_intelligence,
        validations=validations,
        evidence=evidence,
    )
    mitigation = [_mitigation_row(f) for f in findings]

    severity_counts = {
        severity: sum(1 for finding in findings if _normalize_severity(finding.get("severity")) == severity)
        for severity in SEVERITIES
    }

    report = {
        "product": "SHAuditer",
        "full_name": "Smart Hybrid Automated Security Auditor",
        "version": "1.1.7",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit": {k: audit[k] for k in ("audit_id", "target", "state", "profile", "created_at", "updated_at")},
        "recon": recon,
        "module_runs": module_runs,
        "findings": findings,
        "approvals": approvals,
        "validations": validations,
        "sessions": sessions,
        "exploit_intelligence": exploit_intelligence,
        "exploit_reviews": exploit_reviews,
        "poc_executions": db.get_poc_executions(audit_id),
        "evidence": evidence,
        "mitigation": mitigation,
        "summary": {
            "severity": severity_counts,
            "validated": sum(1 for f in findings if f.get("validation_status") == "VALIDATED"),
            "confirmed": sum(1 for f in findings if (f.get("assessment_assurance") or {}).get("level") == "CONFIRMED"),
            "corroborated": sum(1 for f in findings if (f.get("assessment_assurance") or {}).get("level") == "CORROBORATED"),
            "detected_only": sum(1 for f in findings if (f.get("assessment_assurance") or {}).get("level") == "DETECTED"),
            "likely_false_positive": sum(1 for f in findings if (f.get("assessment_assurance") or {}).get("level") == "LIKELY_FALSE_POSITIVE"),
            "not_validated": sum(1 for f in findings if f.get("validation_status") == "NOT_VALIDATED"),
            "unvalidated": sum(1 for f in findings if f.get("validation_status", "UNVALIDATED") == "UNVALIDATED"),
            "access_confirmed": sum(1 for f in findings if f.get("access_status") == "CONFIRMED"),
            "active_sessions": sum(1 for s in sessions if s.get("status") == "ACTIVE"),
            "intelligence_analyzed": len(exploit_intelligence),
            "metasploit_candidates": sum(int(i.get("module_count", 0)) for i in exploit_intelligence),
            "research_approved": sum(1 for r in exploit_reviews if r.get("decision") == "APPROVE_RESEARCH"),
            "assets": len(recon.get("assets") or []),
            "services": len(recon.get("services") or []),
            "technologies": len(recon.get("technologies") or []),
            "evidence": len(evidence),
        },
        "note": (
            "SHAuditer now distinguishes DETECTED, CORROBORATED, CONFIRMED, INCONCLUSIVE, and NOT CONFIRMED assurance states. "
            "A finding is CONFIRMED only when an evidence-backed validation record exists. Scanner detections and CVE/module matches "
            "are documented in detail but are never silently promoted to successful exploitation. Public exploit research references "
            "are provided for authorized operator review; runnable payload/exploit code is not embedded in the report."
        ),
    }
    report["assessment_quality"] = evaluate_assessment(report)
    report["workflow"] = build_workflow(report)
    report["nist_profile"] = build_nist_profile(report, workspace)
    return report


def _csv_safe(value):
    """Treat scanner/user-sourced CSV cells as data in spreadsheet clients."""
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _csv_safe(row.get(k)) for k in fields})


def _write_csvs(report: dict, reports: Path) -> None:
    _write_csv(
        reports / "findings.csv",
        [
            "finding_id", "rank", "severity", "priority_score", "confidence", "title", "asset", "endpoint",
            "template_id", "validation_status", "exploitability", "access_status", "access_type", "privilege", "session_id",
        ],
        report["findings"],
    )
    _write_csv(
        reports / "validations.csv",
        ["validation_id", "finding_id", "status", "method", "operator", "evidence_id", "note", "created_at"],
        report["validations"],
    )
    _write_csv(
        reports / "sessions.csv",
        ["session_id", "finding_id", "session_type", "privilege", "operator", "status", "evidence_id", "note", "created_at", "closed_at"],
        report["sessions"],
    )
    _write_csv(
        reports / "evidence.csv",
        ["evidence_id", "module", "kind", "path", "sha256", "created_at"],
        report["evidence"],
    )
    _write_csv(
        reports / "mitigation-plan.csv",
        ["finding_id", "severity", "remediation_priority", "title", "recommendation", "guidance_source", "validation_status"],
        report["mitigation"],
    )

    services = []
    for service in report["recon"].get("services") or []:
        services.append({
            "address": service.get("address") or service.get("host"),
            "port": service.get("port"),
            "protocol": service.get("protocol"),
            "service": service.get("service") or service.get("name"),
            "product": service.get("product"),
            "version": service.get("version"),
            "extrainfo": service.get("extrainfo"),
            "url": service.get("url"),
            "status_code": service.get("status_code"),
            "title": service.get("title"),
        })
    _write_csv(
        reports / "recon-services.csv",
        ["address", "port", "protocol", "service", "product", "version", "extrainfo", "url", "status_code", "title"],
        services,
    )

    exploit_candidates = []
    for intel in report["exploit_intelligence"]:
        applicability = intel.get("applicability") or {}
        for cve_id, modules in (intel.get("metasploit_modules") or {}).items():
            for module in modules:
                exploit_candidates.append({
                    "intelligence_id": intel.get("intelligence_id"),
                    "finding_id": intel.get("finding_id"),
                    "cve_id": cve_id,
                    "module": module.get("module"),
                    "rank": module.get("rank"),
                    "check_supported": module.get("check_supported"),
                    "disclosure_date": module.get("disclosure_date"),
                    "applicability": applicability.get("status"),
                    "applicability_confidence": applicability.get("confidence"),
                })
    _write_csv(
        reports / "exploit-candidates.csv",
        ["intelligence_id", "finding_id", "cve_id", "module", "rank", "check_supported", "disclosure_date", "applicability", "applicability_confidence"],
        exploit_candidates,
    )
    _write_csv(
        reports / "exploit-reviews.csv",
        ["review_id", "finding_id", "operator", "decision", "module", "note", "created_at"],
        report["exploit_reviews"],
    )


def generate_summary(db, audit_id: str, workspace: Path) -> dict:
    report = _report_model(db, audit_id, workspace)
    reports = workspace / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    report["professional_reports"] = generate_professional_exports(report, reports)

    # Structured support exports are not formal human-facing reports.
    (reports / "assessment.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (reports / "findings.json").write_text(json.dumps(report["findings"], indent=2), encoding="utf-8")
    (reports / "exploit-intelligence.json").write_text(json.dumps(report["exploit_intelligence"], indent=2), encoding="utf-8")
    _write_csvs(report, reports)
    (reports / "assessment-quality.json").write_text(
        json.dumps(report["assessment_quality"], indent=2), encoding="utf-8"
    )

    project_root = Path(__file__).resolve().parents[2]
    project_reports_root = Path(
        os.environ.get("SHAUDITER_PROJECT_REPORTS", str(
            project_root / "reports" if (project_root / "config" / "default.json").exists()
            else workspace.parents[1] / "reports"
        ))
    ).expanduser()
    report["docx_reports"] = generate_docx_reports(
        report,
        workspace,
        project_reports_root=project_reports_root,
    )
    (reports / "assessment.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    bundle_reports(workspace)
    return report
