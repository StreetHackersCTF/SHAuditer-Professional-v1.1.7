from __future__ import annotations
import json
import shutil
import subprocess

from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


class HttpxIntegration(Integration):
    name = "httpx"
    executable = "httpx"

    def available(self) -> bool:
        path = shutil.which(self.executable)
        if not path:
            return False
        try:
            proc = subprocess.run(
                [path, "-version"], capture_output=True, text=True, timeout=3, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        output = (proc.stdout + "\n" + proc.stderr).lower()
        # ProjectDiscovery httpx supports -version; the Python HTTPX CLI does not.
        return proc.returncode == 0 and "no such option" not in output and "usage: httpx [options] url" not in output

    async def run(self, context) -> ModuleResult:
        decision = context.scope.authorize(context.target, action="HTTP probing")
        if not decision.allowed:
            return ModuleResult(self.name, "BLOCKED", metadata={"reason": decision.reason})
        target = context.target.original if context.target.scheme else context.target.hostname
        args = ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-server"]
        result = await context.runner.execute(self.executable, args, stdin=(target + "\n").encode(), timeout=int(context.config.get("timeouts", {}).get("httpx", 300)), cwd=context.workspace, dry_run=context.dry_run)
        if result.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"command": result.command_display, "stdin": target})
        raw_path = context.workspace / "recon" / "httpx.jsonl"
        err_path = context.workspace / "logs" / "httpx.stderr.txt"
        raw_path.write_bytes(result.stdout)
        err_path.write_bytes(result.stderr)
        context.db.add_evidence(f"EV-{context.audit_id}-HTTPX", context.audit_id, self.name, "raw_scanner_output", str(raw_path), sha256_file(raw_path))
        services, technologies = [], []
        parse_errors = 0
        for line in result.stdout.decode(errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            services.append({
                "url": obj.get("url") or obj.get("input"),
                "host": obj.get("host") or obj.get("input"),
                "port": obj.get("port"),
                "status_code": obj.get("status_code"),
                "title": obj.get("title"),
                "webserver": obj.get("webserver"),
            })
            for tech in obj.get("tech", []) or []:
                technologies.append({"host": obj.get("host") or obj.get("input"), "technology": tech})
        status = "SUCCESS" if result.exit_code == 0 and not result.timed_out and not result.output_truncated and parse_errors == 0 else "FAILED"
        return ModuleResult(self.name, status, services=services, technologies=technologies, metadata={
            "exit_code": result.exit_code, "timed_out": result.timed_out, "output_truncated": result.output_truncated,
            "parse_errors": parse_errors, "command": result.command_display,
        })
