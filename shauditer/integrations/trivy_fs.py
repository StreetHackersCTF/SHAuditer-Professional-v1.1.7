"""Optional offline filesystem vulnerability and misconfiguration adapter for Trivy."""
from __future__ import annotations

import json
from pathlib import Path
from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


def parse_trivy_json(raw: dict, evidence_id: str) -> list[dict]:
    findings = []
    for result in raw.get("Results") or []:
        target = str(result.get("Target") or "unknown")
        for v in result.get("Vulnerabilities") or []:
            cve = str(v.get("VulnerabilityID") or "")
            if not cve: continue
            findings.append({
                "title": f"{cve} in {v.get('PkgName') or 'dependency'}", "asset": target,
                "endpoint": target, "category": "SUPPLY_CHAIN", "severity": str(v.get("Severity") or "UNKNOWN").upper(),
                "confidence": 0.75, "cves": [cve], "cwes": list(v.get("CweIDs") or []),
                "sources": ["trivy_offline"], "evidence_ids": [evidence_id],
                "description": str(v.get("Title") or v.get("Description") or "Offline dependency advisory match")[:2500],
                "remediation": f"Review and upgrade {v.get('PkgName')} to a supported fixed version ({v.get('FixedVersion') or 'consult vendor advisory'}).",
                "references": [v["PrimaryURL"]] if v.get("PrimaryURL") else [],
                "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
            })
        for m in result.get("Misconfigurations") or []:
            code = str(m.get("ID") or "")
            findings.append({
                "title": str(m.get("Title") or code or "Offline misconfiguration"), "asset": target,
                "endpoint": target, "category": "MISCONFIGURATION", "severity": str(m.get("Severity") or "UNKNOWN").upper(),
                "confidence": 0.7, "cves": [], "cwes": [], "sources": ["trivy_offline"],
                "evidence_ids": [evidence_id], "description": str(m.get("Description") or "")[:2500],
                "remediation": str(m.get("Resolution") or "Review scanner advice and harden configuration.")[:1000],
                "rule_id": code, "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
            })
    return findings


class TrivyFSIntegration(Integration):
    name = "trivy_offline"
    executable = "trivy"

    def __init__(self, directory: str | Path):
        self.directory = Path(directory).expanduser().resolve()

    async def run(self, context):
        args = ["fs", "--scanners", "vuln,misconfig", "--format", "json", "--offline-scan",
                "--skip-db-update", "--skip-java-db-update", "--quiet", str(self.directory)]
        run = await context.runner.execute(self.executable, args,
            timeout=int(context.config.get("timeouts", {}).get("trivy", 180)), cwd=context.workspace,
            max_output_bytes=16 * 1024 * 1024, dry_run=context.dry_run)
        if run.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"command": run.command_display, "offline": True})
        raw_path = context.workspace / "scans" / "trivy-fs.json"
        raw_path.write_bytes(run.stdout)
        # Trivy can include sensitive filesystem paths and data. Evidence stays under
        # the owner-only audit workspace; no remote API is called by our wrapper.
        evidence_id = f"EV-{context.audit_id}-TRIVY"
        context.db.add_evidence(evidence_id, context.audit_id, self.name, "offline_scanner_output", str(raw_path), sha256_file(raw_path))
        if run.exit_code or run.timed_out or run.output_truncated:
            return ModuleResult(self.name, "FAILED", metadata={"exit_code": run.exit_code,
                                 "timed_out": run.timed_out, "output_truncated": run.output_truncated})
        try:
            obj = json.loads(run.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return ModuleResult(self.name, "FAILED", metadata={"reason": "invalid offline scanner JSON"})
        return ModuleResult(self.name, "SUCCESS", findings=parse_trivy_json(obj, evidence_id),
                            metadata={"results": len(obj.get("Results") or []), "offline": True})
