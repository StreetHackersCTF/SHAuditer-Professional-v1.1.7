from __future__ import annotations

SEVERITY_BASE = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFORMATIONAL": 1.0,
    "INFO": 1.0,
    "UNKNOWN": 2.0,
}


def score_finding(finding: dict) -> float:
    severity = SEVERITY_BASE.get(str(finding.get("severity", "UNKNOWN")).upper(), 2.0)
    confidence = min(max(float(finding.get("confidence") or 0.5), 0.0), 1.0)
    exposure = 1.0 if str(finding.get("matched_at") or finding.get("endpoint") or "").startswith(("http://", "https://")) else 0.5
    evidence_quality = 1.0 if finding.get("evidence_ids") else 0.5
    exploit_signal = 0.4 if finding.get("cves") else 0.0
    score = (severity * 0.65) + (confidence * 1.6) + (exposure * 0.8) + (evidence_quality * 0.6) + exploit_signal
    return round(min(10.0, score), 2)


def prioritize_findings(findings: list[dict]) -> list[dict]:
    for finding in findings:
        finding["priority_score"] = score_finding(finding)
    findings.sort(key=lambda x: (x.get("priority_score", 0), SEVERITY_BASE.get(str(x.get("severity", "")).upper(), 0)), reverse=True)
    for i, finding in enumerate(findings, 1):
        finding["rank"] = i
    return findings
