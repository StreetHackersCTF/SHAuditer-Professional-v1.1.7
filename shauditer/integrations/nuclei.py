from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urlparse

from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


class NucleiIntegration(Integration):
    name = "nuclei"
    executable = "nuclei"

    def __init__(self, targets: list[str]):
        self.targets = targets

    async def run(self, context) -> ModuleResult:
        approved = []
        blocked = []
        for target in self.targets:
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port
            if port is None and parsed.scheme:
                port = 443 if parsed.scheme == "https" else 80
            decision = context.scope.authorize(host, port=port, action="Nuclei vulnerability discovery")
            if decision.allowed:
                approved.append(target)
            else:
                blocked.append({"target": target, "reason": decision.reason})
        if not approved:
            return ModuleResult(self.name, "BLOCKED", metadata={"blocked": blocked})

        targets_path = context.workspace / "scans" / "nuclei-targets.txt"
        targets_path.write_text("\n".join(approved) + "\n", encoding="utf-8")
        args = [
            "-silent", "-jsonl", "-l", str(targets_path),
            "-exclude-tags", "dos,fuzz,intrusive",
            "-no-interactsh",  # no out-of-band callbacks to external interaction services
            "-severity", "info,low,medium,high,critical",
        ]
        result = await context.runner.execute(
            self.executable, args,
            timeout=int(context.config.get("timeouts", {}).get("nuclei", 1200)),
            cwd=context.workspace, dry_run=context.dry_run,
        )
        if result.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"command": result.command_display, "targets": approved, "blocked": blocked})

        raw_path = context.workspace / "vulnerabilities" / "nuclei.jsonl"
        err_path = context.workspace / "logs" / "nuclei.stderr.txt"
        raw_path.write_bytes(result.stdout)
        err_path.write_bytes(result.stderr)
        evidence_id = f"EV-{context.audit_id}-NUCLEI"
        context.db.add_evidence(evidence_id, context.audit_id, self.name, "raw_scanner_output", str(raw_path), sha256_file(raw_path))

        findings = []
        parse_errors = 0
        for line in result.stdout.decode(errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            info = obj.get("info") or {}
            classification = info.get("classification") or obj.get("classification") or {}
            cves = classification.get("cve-id") or classification.get("cve_id") or []
            cwes = classification.get("cwe-id") or classification.get("cwe_id") or []
            if isinstance(cves, str): cves = [cves]
            if isinstance(cwes, str): cwes = [cwes]
            severity = str(info.get("severity") or obj.get("severity") or "unknown").upper()
            if severity == "INFO":
                severity = "INFORMATIONAL"
            matched_at = obj.get("matched-at") or obj.get("matched_at") or obj.get("url") or obj.get("host")
            parsed = urlparse(matched_at or "")
            asset = parsed.hostname or obj.get("host") or obj.get("ip") or "unknown"
            findings.append({
                "title": info.get("name") or obj.get("template-id") or obj.get("templateID") or "Nuclei finding",
                "asset": asset,
                "endpoint": matched_at,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None),
                "severity": severity,
                "confidence": 0.85,
                "cves": list(cves),
                "cwes": list(cwes),
                "sources": ["nuclei"],
                "evidence_ids": [evidence_id],
                "references": list(info.get("reference") or []),
                "description": info.get("description") or "",
                "remediation": info.get("remediation") or "",
                "template_id": obj.get("template-id") or obj.get("templateID"),
                "matcher_name": obj.get("matcher-name") or obj.get("matcher_name"),
                "matched_at": matched_at,
                "validation_status": "UNVALIDATED",
                "exploitability": "UNKNOWN",
            })
        status = "SUCCESS" if result.exit_code == 0 and not result.timed_out and not result.output_truncated and parse_errors == 0 else "FAILED"
        return ModuleResult(self.name, status, findings=findings, metadata={
            "exit_code": result.exit_code, "timed_out": result.timed_out, "output_truncated": result.output_truncated, "command": result.command_display,
            "targets": approved, "blocked": blocked, "parse_errors": parse_errors,
        })
