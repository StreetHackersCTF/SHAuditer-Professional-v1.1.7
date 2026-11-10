from __future__ import annotations
from shauditer.integrations.base import Integration, ModuleResult
from shauditer.models.target import TargetType
from shauditer.security.evidence import sha256_file


class SubfinderIntegration(Integration):
    name = "subfinder"
    executable = "subfinder"

    async def run(self, context) -> ModuleResult:
        if context.target.type not in {TargetType.DOMAIN, TargetType.URL}:
            return ModuleResult(self.name, "SKIPPED", metadata={"reason": "target is not a domain/URL"})
        decision = context.scope.authorize(context.target, action="subdomain discovery")
        if not decision.allowed:
            return ModuleResult(self.name, "BLOCKED", metadata={"reason": decision.reason})
        args = ["-silent", "-d", context.target.hostname]
        result = await context.runner.execute(self.executable, args, timeout=int(context.config.get("timeouts", {}).get("subfinder", 300)), cwd=context.workspace, dry_run=context.dry_run)
        if result.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"command": result.command_display})
        raw_path = context.workspace / "recon" / "subfinder.txt"
        err_path = context.workspace / "logs" / "subfinder.stderr.txt"
        raw_path.write_bytes(result.stdout)
        err_path.write_bytes(result.stderr)
        context.db.add_evidence(f"EV-{context.audit_id}-SUBFINDER", context.audit_id, self.name, "raw_scanner_output", str(raw_path), sha256_file(raw_path))
        assets = []
        for line in result.stdout.decode(errors="replace").splitlines():
            host = line.strip().lower()
            if not host:
                continue
            scope = context.scope.authorize(host, action="discovered subdomain")
            assets.append({"hostname": host, "in_scope": scope.allowed})
        status = "SUCCESS" if result.exit_code == 0 and not result.timed_out and not result.output_truncated else "FAILED"
        return ModuleResult(self.name, status, assets=assets, metadata={"exit_code": result.exit_code, "command": result.command_display})
