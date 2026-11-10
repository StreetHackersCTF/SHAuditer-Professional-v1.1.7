from __future__ import annotations
from copy import deepcopy


def _key(f: dict):
    cves = tuple(sorted(f.get("cves") or []))
    if cves:
        return (f.get("asset"), "cve", cves)
    return (
        f.get("asset"),
        f.get("template_id") or f.get("title"),
        f.get("matched_at") or f.get("endpoint"),
    )


def correlate_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate scanner observations while preserving all supporting evidence."""
    merged: dict[tuple, dict] = {}
    for finding in findings:
        key = _key(finding)
        if key not in merged:
            merged[key] = deepcopy(finding)
            continue
        dst = merged[key]
        for name in ("sources", "cves", "cwes", "evidence_ids", "references"):
            dst[name] = sorted(set((dst.get(name) or []) + (finding.get(name) or [])))
        dst["confidence"] = max(float(dst.get("confidence") or 0), float(finding.get("confidence") or 0))
        if not dst.get("description") and finding.get("description"):
            dst["description"] = finding["description"]
        if not dst.get("remediation") and finding.get("remediation"):
            dst["remediation"] = finding["remediation"]
    return list(merged.values())
