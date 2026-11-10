"""Evidence-led VA/PT reporting model aligned to NIST SP 800-115's assessment lifecycle.

NIST publishes testing guidance, not a certification scheme for this product.
Optional engagement metadata may be populated locally by the assessor. Unknown
fields are NOT guessed or silently represented as completed procedures.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

METHODOLOGY = (
    ("Planning & scope", "Document authorization, intended targets, exclusions, test limitations and rules of engagement."),
    ("Discovery & examination", "Identify assets/services, review configuration and enumerate exposure within approved scope."),
    ("Vulnerability analysis", "Correlate observations, verify applicability and document uncertainty or false-positive risk."),
    ("Controlled validation", "Use one-time operator authorization for supported non-destructive checks; preserve evidence and record outcomes."),
    ("Reporting & remediation", "Prioritize risk, assign corrective action, communicate results and conduct a targeted retest."),
)
REFERENCE_FRAMEWORKS = [
    {"name": "NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment", "url": "https://csrc.nist.gov/pubs/sp/800/115/final"},
    {"name": "NIST SP 800-53A Rev. 5 — Assessing Security and Privacy Controls", "url": "https://csrc.nist.gov/pubs/sp/800/53/a/r5/final"},
    {"name": "OWASP Web Security Testing Guide 4.2", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
    {"name": "OWASP Top 10:2025", "url": "https://owasp.org/Top10/2025/"},
]
ENGAGEMENT_FIELDS = (
    "client_organization", "client_contact", "assessor", "assessment_lead", "engagement_id",
    "authorization_reference", "rules_of_engagement", "assessment_window", "assessment_type",
    "classification", "version", "approved_by", "test_environment", "constraints", "report_recipient",
)


def build_nist_profile(report: dict, workspace: Path) -> dict:
    """Compute honest structured narrative; no fabricated customer/owner/dates."""
    provided = {}
    source = workspace / "metadata" / "engagement.json"
    if source.is_file() and not source.is_symlink() and source.stat().st_size < 64_000:
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                provided = {k: str(raw[k]).strip()[:300] for k in ENGAGEMENT_FIELDS
                            if isinstance(raw.get(k), (str, int)) and str(raw[k]).strip()}
        except (OSError, ValueError, UnicodeError):
            provided = {}
    audit = report["audit"]
    scope = {}
    scope_file = workspace / "metadata" / "scope.json"
    if scope_file.is_file() and scope_file.stat().st_size < 64_000:
        try:
            data = json.loads(scope_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                scope = {k: data.get(k) for k in ("in_scope", "out_of_scope", "allowed_ports", "excluded_ports", "allowed_domains", "excluded_domains", "mode")}
        except (OSError, ValueError, UnicodeError):
            pass
    modules = report.get("module_runs") or []
    status_counts = {}
    for mod in modules:
        status = str(mod.get("status") or "UNKNOWN").upper()
        status_counts[status] = status_counts.get(status, 0) + 1
    findings = report.get("findings") or []
    mitigation = {m.get("finding_id"): m for m in report.get("mitigation") or []}
    rows = []
    for f in findings:
        ident = str(f.get("finding_id") or "UNASSIGNED")
        m = mitigation.get(ident, {})
        assurance = f.get("assessment_assurance") or {}
        rows.append({
            "finding_id": ident,
            "title": str(f.get("title") or "Untitled"),
            "severity": str(f.get("severity") or "INFORMATIONAL").upper(),
            "asset": str(f.get("asset") or f.get("endpoint") or audit.get("target") or "Unspecified"),
            "validation": str(assurance.get("level") or f.get("validation_status") or "UNVALIDATED"),
            "recommended_action": str(m.get("recommendation") or f.get("remediation") or "Review with system owner and retest"),
            "priority": str(m.get("remediation_priority") or "PLANNED"),
            "owner": "Not assigned",
            "due_date": "To be agreed",
            "status": "Open — pending client triage",
            "retest_evidence": "Pending",
        })
    quality = report.get("assessment_quality") or {}
    return {
        "label": "NIST SP 800-115-aligned security assessment report (not NIST certified)",
        "standard": "NIST SP 800-115 (2008)",
        "assessment_approach": "Scope > Discovery > Examination > Validation > Analysis > Reporting > Retest",
        "classification": provided.get("classification", "CONFIDENTIAL — authorized recipients only"),
        "client_organization": provided.get("client_organization", "Not provided by assessor"),
        "assessor": provided.get("assessor", "Street_Hackers Security Team"),
        "engagement": provided,
        "scope": scope or {"in_scope": [audit.get("target")], "out_of_scope": [], "mode": "Declared target only"},
        "methodology": [{"stage": stage, "description": desc} for stage, desc in METHODOLOGY],
        "references": REFERENCE_FRAMEWORKS,
        "tool_execution": status_counts,
        "coverage_status": str(quality.get("status") or "NOT ASSESSED"),
        "limitations": list(quality.get("limitations") or []),
        "findings_count": len(findings),
        "risk_register": rows,
        "caveat": "Findings do not establish compromise unless separately supported by verified evidence. Unavailable tools, inaccessible assets and skipped techniques are unassessed coverage, not clean results.",
        "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
        "report_approval": "Not signed — client and assessor review required",
    }
