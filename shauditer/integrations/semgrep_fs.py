"""Optional local-only Semgrep check with project-owned reviewed rules."""
from __future__ import annotations
import json
from pathlib import Path

from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


class SemgrepFSIntegration(Integration):
    name = "semgrep_local"
    executable = "semgrep"

    def __init__(self, directory):
        self.directory = Path(directory).expanduser().resolve()

    async def run(self, context) -> ModuleResult:
        if not self.directory.is_dir() or self.directory.is_symlink():
            return ModuleResult(self.name, "BLOCKED", metadata={"reason": "Local source artifact directory required"})
        # No remote rule marketplace, cloud login, or telemetry. Only local rules.
        rules = Path(__file__).resolve().parents[1] / "config" / "semgrep-local.yml"
        if not rules.is_file():
            return ModuleResult(self.name, "FAILED", metadata={"reason": "Packaged Semgrep rules are missing"})
        args = ["scan", "--config", str(rules), "--json", "--metrics", "off",
                "--disable-version-check", "--no-git-ignore", str(self.directory)]
        proc = await context.runner.execute(
            self.executable, args, timeout=int(context.config.get("timeouts", {}).get("artifact_review", 90)),
            cwd=context.workspace, dry_run=context.dry_run,
        )
        if proc.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"command": proc.command_display})
        path = context.workspace / "vulnerabilities" / "semgrep-local.json"
        path.write_bytes(proc.stdout)
        context.db.add_evidence(f"EV-{context.audit_id}-SEMGREP", context.audit_id,
                                self.name, "static_scanner_output", str(path), sha256_file(path))
        try:
            payload = json.loads(proc.stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return ModuleResult(self.name, "FAILED", metadata={"reason": "JSON parse failed", "exit_code": proc.exit_code})
        findings = []
        for result in (payload.get("results") or [])[:500]:
            extra = result.get("extra") or {}
            rule = str(result.get("check_id") or "Unknown rule")
            relative = str(result.get("path") or "")
            desc = str(extra.get("message") or "Static analysis review required")
            findings.append({"title": f"Code review: {rule}", "asset": "Local source artifact", "endpoint": relative,
                             "severity": "MEDIUM", "confidence": 0.5, "sources": ["semgrep_local"],
                             "cves": [], "cwes": ["CWE-95"] if "eval" in rule else [],
                             "description": desc + " Static pattern match only; confirm context and reachability.",
                             "remediation": "Remove dynamic unsafe evaluation, validate input and prefer allowlisted structured APIs where appropriate.",
                             "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN"})
        status = "SUCCESS" if proc.exit_code in {0, 1} and not proc.timed_out and not proc.output_truncated else "FAILED"
        return ModuleResult(self.name, status, findings=findings, metadata={"command": proc.command_display,
                                                                              "exit_code": proc.exit_code, "timed_out": proc.timed_out,
                                                                              "output_truncated": proc.output_truncated})
