from __future__ import annotations
import json
import os
from pathlib import Path

from shauditer.core.context import AuditContext
from shauditer.core.events import AuditEvent, EventBus
from shauditer.core.scheduler import ModuleScheduler
from shauditer.core.state import AuditState
from shauditer.database.db import Database
from shauditer.integrations.httpx import HttpxIntegration
from shauditer.integrations.nmap import NmapIntegration
from shauditer.integrations.subfinder import SubfinderIntegration
from shauditer.integrations.nuclei import NucleiIntegration
from shauditer.integrations.artifact_review import ArtifactReviewIntegration
from shauditer.integrations.trivy_fs import TrivyFSIntegration
from shauditer.integrations.semgrep_fs import SemgrepFSIntegration
from shauditer.integrations.checkov_local import CheckovLocalIntegration
from shauditer.integrations.gitleaks_local import GitleaksLocalIntegration
from shauditer.modules.web.posture import WebPostureIntegration
from shauditer.modules.web.tls import TLSPostureIntegration
from shauditer.intelligence.correlation import correlate_findings
from shauditer.intelligence.prioritization import prioritize_findings
from shauditer.models.target import normalize_target
from shauditer.scope.models import ScopePolicy
from shauditer.scope.validator import ScopeValidator
from shauditer.security.runner import SafeProcessRunner
from shauditer.workspace.manager import WorkspaceManager


class AuditEngine:
    def __init__(self, home: str | Path, config: dict):
        self.home = Path(home).expanduser().resolve()
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            self.home.chmod(0o700)
        self.config = config
        self.db = Database(self.home / "shauditer.db")
        self.workspaces = WorkspaceManager(self.home / "workspaces")

    def create_audit(self, raw_target: str, *, profile: str = "safe", scope_policy: ScopePolicy | None = None):
        target = normalize_target(raw_target)
        audit_id = self.db.next_audit_id()
        policy = scope_policy or ScopePolicy(in_scope=[target.network or target.hostname], allowed_domains=[target.hostname])
        from shauditer.scope.validator import ScopeValidator
        scope_check = ScopeValidator(policy).authorize(target, action="new audit")
        if not scope_check.allowed:
            raise PermissionError(scope_check.reason)
        workspace = self.workspaces.create(audit_id)
        self.db.create_audit(audit_id, target, AuditState.CREATED.value, profile, workspace)
        (workspace / "target" / "target.json").write_text(json.dumps(target.to_dict(), indent=2), encoding="utf-8")
        (workspace / "metadata" / "scope.json").write_text(json.dumps({
            "in_scope": policy.in_scope, "out_of_scope": policy.out_of_scope,
            "allowed_ports": sorted(policy.allowed_ports), "excluded_ports": sorted(policy.excluded_ports),
            "allowed_domains": policy.allowed_domains, "excluded_domains": policy.excluded_domains, "mode": policy.mode,
        }, indent=2), encoding="utf-8")
        bus = EventBus(self.db, workspace)
        bus.emit(AuditEvent(audit_id, "TARGET_CREATED", target.to_dict(), new_state=AuditState.CREATED.value))
        return audit_id, target, workspace, policy

    def _set_state(self, audit_id: str, workspace: Path, new_state: AuditState):
        audit = self.db.get_audit(audit_id)
        old = audit["state"] if audit else None
        self.db.update_state(audit_id, new_state.value)
        EventBus(self.db, workspace).emit(AuditEvent(audit_id, "STATE_CHANGED", {}, previous_state=old, new_state=new_state.value))

    async def run_recon(self, audit_id, target, workspace, policy, *, profile="safe", dry_run=False):
        scope = ScopeValidator(policy)
        decision = scope.authorize(target, action="assessment")
        if not decision.allowed:
            raise PermissionError(decision.reason)
        self._set_state(audit_id, workspace, AuditState.SCOPE_VERIFIED)
        bus = EventBus(self.db, workspace)
        bus.emit(AuditEvent(audit_id, "SCOPE_VERIFIED", {"reason": decision.reason}))
        self._set_state(audit_id, workspace, AuditState.RECON_RUNNING)
        context = AuditContext(
            audit_id=audit_id, target=target, workspace=workspace, db=self.db, scope=scope, events=bus,
            runner=SafeProcessRunner(), config=self.config, profile=profile, dry_run=dry_run,
        )
        modules = [SubfinderIntegration(), NmapIntegration(), HttpxIntegration()]
        scheduler = ModuleScheduler(self.config.get("rate_limit", {}).get("max_parallel_modules", 3))
        results = await scheduler.run(modules, context)
        normalized = {
            "assets": [x for r in results for x in r.assets],
            "services": [x for r in results for x in r.services],
            "technologies": [x for r in results for x in r.technologies],
            "modules": [{"name": r.module, "status": r.status, "metadata": r.metadata} for r in results],
        }
        (workspace / "recon" / "normalized.json").write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        self._set_state(audit_id, workspace, AuditState.RECON_COMPLETE)
        bus.emit(AuditEvent(audit_id, "RECON_COMPLETE", {
            "assets": len(normalized["assets"]), "services": len(normalized["services"]),
            "technologies": len(normalized["technologies"]),
        }))
        return normalized

    def _web_targets(self, target, recon: dict) -> list[str]:
        targets = []
        if target.scheme in {"http", "https"}:
            targets.append(target.original)
        for service in recon.get("services", []):
            if service.get("url"):
                targets.append(service["url"])
                continue
            name = str(service.get("service") or "").lower()
            if name in {"http", "https", "ssl/http", "http-proxy"}:
                port = service.get("port")
                scheme = "https" if name == "https" or port == 443 else "http"
                host = service.get("address") or target.hostname
                default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
                targets.append(f"{scheme}://{host}" + ("" if default or not port else f":{port}"))
        if target.type.value in {"Domain", "Host"} and not targets:
            targets.extend([f"https://{target.hostname}", f"http://{target.hostname}"])
        return sorted(set(targets))

    async def run_vulnerability_discovery(self, audit_id, target, workspace, policy, recon, *, profile="safe", dry_run=False, artifacts_dir=None):
        self._set_state(audit_id, workspace, AuditState.VULN_DISCOVERY_RUNNING)
        bus = EventBus(self.db, workspace)
        scope = ScopeValidator(policy)
        context = AuditContext(
            audit_id=audit_id, target=target, workspace=workspace, db=self.db, scope=scope, events=bus,
            runner=SafeProcessRunner(), config=self.config, profile=profile, dry_run=dry_run,
        )
        web_targets = self._web_targets(target, recon)
        scheduler = ModuleScheduler(1)
        modules = []
        if web_targets:
            modules.append(NucleiIntegration(web_targets))
        if not target.network:
            modules.append(WebPostureIntegration())
            modules.append(TLSPostureIntegration())
        if artifacts_dir is not None:
            modules.append(ArtifactReviewIntegration(artifacts_dir))
            modules.append(TrivyFSIntegration(artifacts_dir))
            modules.append(SemgrepFSIntegration(artifacts_dir))
            modules.append(CheckovLocalIntegration(artifacts_dir))
            modules.append(GitleaksLocalIntegration(artifacts_dir))
        results = await scheduler.run(modules, context) if modules else []
        raw_findings = [f for r in results for f in r.findings]
        correlated = correlate_findings(raw_findings)
        self._set_state(audit_id, workspace, AuditState.FINDINGS_CORRELATED)
        prioritized = prioritize_findings(correlated)
        for idx, finding in enumerate(prioritized, 1):
            finding_id = f"F-{idx:04d}"
            finding["finding_id"] = finding_id
            self.db.upsert_finding(audit_id, finding_id, finding)
        (workspace / "vulnerabilities" / "findings.json").write_text(json.dumps(prioritized, indent=2), encoding="utf-8")
        self._set_state(audit_id, workspace, AuditState.FINDINGS_PRIORITIZED)
        bus.emit(AuditEvent(audit_id, "FINDINGS_PRIORITIZED", {
            "count": len(prioritized),
            "critical": sum(1 for f in prioritized if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in prioritized if f.get("severity") == "HIGH"),
        }))
        return prioritized

    async def run_assessment(self, audit_id, target, workspace, policy, *, profile="safe", dry_run=False, artifacts_dir=None):
        recon = await self.run_recon(audit_id, target, workspace, policy, profile=profile, dry_run=dry_run)
        findings = await self.run_vulnerability_discovery(
            audit_id, target, workspace, policy, recon, profile=profile, dry_run=dry_run, artifacts_dir=artifacts_dir
        )
        self._set_state(audit_id, workspace, AuditState.REPORTING)
        return recon, findings
