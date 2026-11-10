"""Checkov IaC assessment on *local supplied files* only.

Uses --skip-download; no cloud account or network discovery is attempted. The
saved evidence is a sanitized summary rather than the source scanner output.
"""
from __future__ import annotations
import json
from pathlib import Path
from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


def parse_checkov(raw) -> list[dict]:
    blocks = raw if isinstance(raw, list) else [raw]
    findings = []
    for block in blocks:
        if not isinstance(block, dict): continue
        for issue in (block.get("results") or {}).get("failed_checks", [])[:500]:
            if not isinstance(issue, dict): continue
            rule = str(issue.get("check_id") or "UNKNOWN")[:90]
            severity = str(issue.get("severity") or "MEDIUM").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}: severity = "MEDIUM"
            resource = str(issue.get("resource") or "Local infrastructure definition")[:250]
            path = str(issue.get("file_path") or "Local artifact")[:350]
            findings.append({
                "title": f"IaC review: {str(issue.get('check_name') or rule)[:150]}",
                "asset": resource, "endpoint": path,
                "severity": severity, "confidence": 0.7, "cves": [], "cwes": [],
                "sources": ["checkov_local"], "category": "CLOUD_IAC",
                "rule_id": rule,
                "description": "Checkov static policy failure; confirm deployment state, environment and actual exposure before treating as exploitable.",
                "remediation": "Review the relevant Checkov rule and vendor hardening guidance; adjust the IaC template, deploy through change control, and retest.",
                "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
            })
    return findings[:500]


class CheckovLocalIntegration(Integration):
    name = "checkov_local"
    executable = "checkov"

    def __init__(self, directory):
        self.original = Path(directory).expanduser()
        self.directory = self.original.resolve()

    async def run(self, context):
        if self.original.is_symlink() or not self.directory.is_dir():
            return ModuleResult(self.name, "BLOCKED", metadata={"reason": "Local non-symlink artifact directory required"})
        args = ["-d", str(self.directory), "-o", "json", "--quiet", "--skip-download"]
        proc = await context.runner.execute(
            self.executable, args, cwd=context.workspace, dry_run=context.dry_run,
            timeout=int(context.config.get("timeouts", {}).get("artifact_review", 90)),
            max_output_bytes=12*1024*1024)
        if proc.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"command": proc.command_display})
        if proc.timed_out or proc.output_truncated or proc.exit_code not in (0, 1):
            return ModuleResult(self.name, "FAILED", metadata={"exit_code": proc.exit_code, "timed_out": proc.timed_out, "output_truncated": proc.output_truncated})
        try:
            parsed = json.loads(proc.stdout.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return ModuleResult(self.name, "FAILED", metadata={"reason": "Invalid Checkov JSON", "exit_code": proc.exit_code})
        findings = parse_checkov(parsed)
        # Avoid persisting arbitrary source excerpts or secrets embedded in Checkov output.
        summary = {"scanner": "checkov", "count": len(findings),
                   "rules": [{"rule_id": f["rule_id"], "endpoint": f["endpoint"], "severity": f["severity"]} for f in findings]}
        path = context.workspace / "vulnerabilities" / "checkov-summary.json"
        path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        evidence_id = f"EV-{context.audit_id}-CHECKOV"
        context.db.add_evidence(evidence_id, context.audit_id, self.name, "redacted_policy_summary", str(path), sha256_file(path))
        for f in findings: f["evidence_ids"] = [evidence_id]
        return ModuleResult(self.name, "SUCCESS", findings=findings,
                            metadata={"policy_failures": len(findings), "offline": True, "exit_code": proc.exit_code})
