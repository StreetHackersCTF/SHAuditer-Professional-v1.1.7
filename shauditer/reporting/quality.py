"""Conservative assessment-quality evaluation: scanner health is not risk clearance."""
from __future__ import annotations

from pathlib import Path
import json
from shauditer.security.evidence import sha256_file


KEY_MODULES = ("nmap", "httpx", "nuclei")


def verify_evidence_records(records: list[dict]) -> dict:
    results = []
    for entry in records:
        path = Path(str(entry.get("path") or ""))
        expected = str(entry.get("sha256") or "").lower()
        if not path.is_file():
            status, actual = "MISSING", None
        elif not expected:
            status, actual = "NO_HASH", None
        else:
            try:
                actual = sha256_file(path)
                status = "VERIFIED" if actual.lower() == expected else "MISMATCH"
            except OSError:
                actual, status = None, "UNREADABLE"
        results.append({"evidence_id": entry.get("evidence_id"), "status": status,
                        "expected_sha256": expected, "actual_sha256": actual,
                        "path": str(path)})
    return {"total": len(results),
            "verified": sum(x["status"] == "VERIFIED" for x in results),
            "issues": sum(x["status"] != "VERIFIED" for x in results),
            "records": results}


def evaluate_assessment(report: dict, *, verify_hashes: bool = True) -> dict:
    runs = report.get("module_runs") or []
    findings = report.get("findings") or []
    validations = report.get("validations") or []
    evidence = report.get("evidence") or []
    latest = {}
    for run in runs:
        latest[str(run.get("module") or "").lower()] = str(run.get("status") or "UNKNOWN").upper()
    issues = []
    successful = [name for name in KEY_MODULES if latest.get(name) == "SUCCESS"]
    if not runs:
        issues.append("No scanner execution records are present. Zero findings does not establish a clean target.")
    if not successful:
        issues.append("No core scanner completed successfully. Vulnerability coverage is not established.")
    for name in KEY_MODULES:
        status = latest.get(name, "NOT_RUN")
        if status != "SUCCESS":
            issues.append(f"{name}: {status}. Coverage from this module is missing or incomplete.")
    for run in runs:
        meta = run.get("metadata") or run.get("metadata_json") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                meta = {"parse_error": "invalid module metadata"}
        if not isinstance(meta, dict):
            meta = {"parse_error": "invalid module metadata type"}
        if meta.get("timed_out") or meta.get("output_truncated") or meta.get("parse_error") or meta.get("parse_errors"):
            issues.append(f"{run.get('module')}: output was incomplete, truncated or could not be parsed.")
    unvalidated = sum(1 for f in findings if str(f.get("validation_status", "UNVALIDATED")).upper() == "UNVALIDATED")
    if unvalidated:
        issues.append(f"{unvalidated} finding(s) remain without manual validation; detections are not confirmed exploitation.")
    # A validated finding must have a record backed by existing, hashed evidence.
    existing = {str(e.get("evidence_id")) for e in evidence}
    unproven = [v for v in validations if str(v.get("status")).upper() == "VALIDATED" and
                (not v.get("evidence_id") or str(v.get("evidence_id")) not in existing)]
    if unproven:
        issues.append(f"{len(unproven)} validated record(s) lack a linked evidence artifact.")
    integrity = verify_evidence_records(evidence) if verify_hashes else {
        "total": len(evidence), "verified": None, "issues": None, "records": []}
    if verify_hashes and integrity["issues"]:
        issues.append(f"{integrity['issues']} evidence artifact(s) are missing, altered, or cannot be verified.")

    if not successful:
        status = "INSUFFICIENT_COVERAGE"
    elif any(latest.get(name) != "SUCCESS" for name in KEY_MODULES) or unproven or (verify_hashes and integrity["issues"]):
        status = "REVIEW_REQUIRED"
    elif unvalidated:
        status = "VALIDATION_PENDING"
    else:
        status = "READY_FOR_HUMAN_REVIEW"
    return {
        "status": status,
        "core_scanners_successful": len(successful),
        "core_scanners_expected": len(KEY_MODULES),
        "scanner_status": {name: latest.get(name, "NOT_RUN") for name in KEY_MODULES},
        "finding_count": len(findings),
        "unvalidated_findings": unvalidated,
        "limitations": issues,
        "evidence_integrity": integrity,
        "interpretation": "Assessment completeness indicator only; not a security certification or proof of absence of vulnerabilities.",
    }
