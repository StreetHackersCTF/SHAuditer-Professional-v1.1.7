from __future__ import annotations

import argparse
import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import smtplib
import shutil
import subprocess
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import webbrowser

from shauditer.core.engine import AuditEngine
from shauditer.core.state import AuditState
from shauditer.intelligence.exploit_intelligence import ExploitIntelligenceManager
from shauditer.reporting.summary import generate_summary
from shauditer.reporting.nist_profile import ENGAGEMENT_FIELDS
from shauditer.reporting.enrichment import enrich_findings
from shauditer.reporting.quality import evaluate_assessment
from shauditer.validation import ValidationManager
from shauditer.poc.runner import PoCManager
from shauditer.scope.policy_io import scope_from_dict
from shauditer.models.target import normalize_target
from shauditer.tools.catalog import inventory
from shauditer.reporting.mail import (mail_report, smtp_settings, smtp_status, sender_address,
    assessment_snapshot_from_records, validate_recipient, compose_client_email, templates_catalog)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "default.json"
if not DEFAULT_CONFIG.exists():
    DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "default.json"
DEFAULT_HOME = Path(os.environ.get("SHAUDITER_HOME", "~/.local/share/SHAuditer")).expanduser()
STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_JSON_BODY = 8 * 1024 * 1024
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024


def _load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Job:
    job_id: str
    kind: str
    audit_id: str | None = None
    status: str = "RUNNING"
    created_at: str = field(default_factory=_utcnow)
    finished_at: str | None = None
    message: str = ""
    error: str | None = None


class JobRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}

    def create(self, kind: str, audit_id: str | None = None) -> Job:
        job = Job(job_id=f"JOB-{secrets.token_hex(4).upper()}", kind=kind, audit_id=audit_id)
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def update(self, job_id: str, **values) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in values.items():
                setattr(job, key, value)

    def list(self, audit_id: str | None = None) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        if audit_id is not None:
            jobs = [j for j in jobs if j.audit_id == audit_id]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return [j.__dict__.copy() for j in jobs[:100]]

    def has_running(self, audit_id: str) -> bool:
        with self._lock:
            return any(j.audit_id == audit_id and j.status == "RUNNING" for j in self._jobs.values())

    def remove_for_audit(self, audit_id: str) -> None:
        with self._lock:
            self._jobs = {job_id: job for job_id, job in self._jobs.items() if job.audit_id != audit_id}


class GUIApplication:
    def __init__(self, home: Path, config_path: Path) -> None:
        self.home = home.expanduser().resolve()
        self.config_path = config_path.expanduser().resolve()
        self.config = _load_config(self.config_path)
        self.engine = AuditEngine(self.home, self.config)
        self.project_reports_root = Path(
            os.environ.get("SHAUDITER_PROJECT_REPORTS", str(
                PROJECT_ROOT / "reports" if (PROJECT_ROOT / "config" / "default.json").exists()
                else self.home / "reports"
            ))
        ).expanduser().resolve()
        self.jobs = JobRegistry()
        self.token = secrets.token_urlsafe(32)

    def engagement_metadata(self, audit_id: str) -> dict:
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError(f"unknown audit ID: {audit_id}")
        path = Path(row["workspace"]) / "metadata" / "engagement.json"
        if not path.is_file() or path.is_symlink():
            return {}
        try:
            if path.stat().st_size > 64_000:
                return {}
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                return {}
            return {k: str(value[k])[:300] for k in ENGAGEMENT_FIELDS
                    if isinstance(value.get(k), (str, int)) and str(value[k]).strip()}
        except (OSError, UnicodeError, ValueError):
            return {}

    def save_engagement_metadata(self, audit_id: str, data: dict) -> dict:
        if not isinstance(data, dict):
            raise ValueError("engagement must be an object")
        unknown = set(data) - set(ENGAGEMENT_FIELDS)
        if unknown:
            raise ValueError("unsupported engagement metadata field")
        clean = {}
        for key, value in data.items():
            if not isinstance(value, str):
                raise ValueError(f"{key} must be a text value")
            if len(value) > 300 or "\x00" in value:
                raise ValueError(f"{key} must be at most 300 characters without control bytes")
            if value.strip():
                clean[key] = value.strip()
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError(f"unknown audit ID: {audit_id}")
        folder = Path(row["workspace"]) / "metadata"
        folder.mkdir(parents=True, exist_ok=True)
        destination = folder / "engagement.json"
        if destination.is_symlink():
            raise PermissionError("engagement metadata path cannot be a symlink")
        tmp = folder / ("engagement-" + secrets.token_hex(8) + ".tmp")
        try:
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(clean, handle, indent=2)
                handle.write("\n")
            os.replace(tmp, destination)
        finally:
            tmp.unlink(missing_ok=True)
        return clean

    def audit_payload(self, audit_id: str) -> dict:
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError(f"unknown audit ID: {audit_id}")
        workspace = Path(row["workspace"])
        recon = {}
        recon_path = workspace / "recon" / "normalized.json"
        if recon_path.is_file():
            try:
                recon = json.loads(recon_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                recon = {}
        approvals = self.engine.db.get_approvals(audit_id)
        evidence = self.engine.db.get_evidence(audit_id)
        validations = self.engine.db.get_validations(audit_id)
        exploit_intelligence = self.engine.db.get_all_exploit_intelligence(audit_id)
        findings = enrich_findings(
            self.engine.db.get_findings(audit_id),
            exploit_intelligence=exploit_intelligence,
            validations=validations,
            evidence=evidence,
        )
        quality = evaluate_assessment({"module_runs": self.engine.db.get_module_runs(audit_id),
                                       "findings": findings, "validations": validations,
                                       "evidence": evidence})
        return {
            "assessment_quality": quality,
            "engagement_details": self.engagement_metadata(audit_id),
            "audit": row,
            "findings": findings,
            "approvals": approvals,
            "module_runs": self.engine.db.get_module_runs(audit_id),
            "evidence": evidence,
            "validations": validations,
            "sessions": self.engine.db.get_sessions(audit_id),
            "exploit_intelligence": exploit_intelligence,
            "exploit_reviews": self.engine.db.get_exploit_reviews(audit_id),
            "poc_executions": self.engine.db.get_poc_executions(audit_id),
            "events": self.engine.db.get_events(audit_id),
            "recon": recon,
            "jobs": self.jobs.list(audit_id),
            "report_available": (workspace / "reports" / "docx" / "technical-report.docx").is_file(),
            "delivery_available": smtp_status()["ready"],
            "status_detail": self._assessment_status(audit_id),
            "report_files": {
                "executive": f"/reports/{audit_id}/executive-report.docx",
                "technical": f"/reports/{audit_id}/technical-report.docx",
                "complete": f"/reports/{audit_id}/complete-assessment.docx",
                "pdf": f"/reports/{audit_id}/assessment.pdf",
                "html": f"/reports/{audit_id}/assessment.html",
                "bundle": f"/reports/{audit_id}/assessment-bundle.zip",
                "json": f"/reports/{audit_id}/assessment.json",
                "csv": f"/reports/{audit_id}/findings.csv",
            },
        }

    def _assessment_status(self, audit_id: str) -> dict:
        """Explain *why* an assessment has sparse or zero findings."""
        runs = self.engine.db.get_module_runs(audit_id)
        findings = self.engine.db.get_findings(audit_id)
        audits = self.engine.db.get_audit(audit_id)
        checks = []
        for run in runs:
            metadata = run.get("metadata") or run.get("metadata_json") or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except ValueError:
                    metadata = {}
            if not isinstance(metadata, dict):
                metadata = {}
            checks.append({"module": run.get("module"), "status": run.get("status"),
                           "reason": str(metadata.get("error") or metadata.get("reason") or metadata.get("executable") or
                                         ("No matches in the module output" if run.get("status") == "SUCCESS" else ""))[:300],
                           "timed_out": bool(metadata.get("timed_out")),
                           "parse_errors": int(metadata.get("parse_errors") or 0)})
        broken = [x for x in checks if x["status"] not in {"SUCCESS", "NOT_APPLICABLE"}]
        successful = sum(x["status"] == "SUCCESS" for x in checks)
        messages = []
        if not runs:
            messages.append("No modules have finished. Check progress or restart an authorized assessment.")
        if broken:
            messages.append(f"{len(broken)} module(s) did not complete successfully; open tool diagnostics and verify installed binaries.")
        if not findings:
            messages.append("No vulnerability findings were recorded. This is NOT proof that the target is secure.")
            if not successful:
                messages.append("No scanner finished successfully. Install required tools and verify target reachability/scope.")
        elif not any(f.get("cves") for f in findings):
            messages.append("Findings exist, but none have CVE identifiers; public CVE/PoC research will show generic guidance only.")
        return {"state": (audits or {}).get("state"), "module_count": len(checks),
                "success_count": successful, "failed_count": len(broken), "finding_count": len(findings),
                "messages": messages, "checks": checks}

    def email_preview(self, audit_id: str, payload: dict) -> dict:
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError("unknown audit")
        sender = sender_address()
        # Preview does not require credentials and never transmits an email.
        assessment = self.audit_payload(audit_id)
        snapshot = assessment_snapshot_from_records(assessment["findings"], assessment["assessment_quality"])
        if payload.get("recipient"):
            validate_recipient(payload["recipient"])
        return compose_client_email(
            audit_id, target=row["target"],
            format_name=str(payload.get("format") or "pdf"),
            template_name=str(payload.get("template") or "final_delivery"),
            client_name=str(payload.get("client_name") or ""),
            client_organization=str(payload.get("client_organization") or ""),
            sender_email=sender, assessment_snapshot=snapshot,
            subject=payload.get("subject"), body=payload.get("body"),
        )

    def send_report(self, audit_id: str, recipient: str, format_name: str, acknowledge: bool,
                    *, template_name: str = "final_delivery", client_name: str = "",
                    client_organization: str = "", subject: str | None = None,
                    body: str | None = None) -> dict:
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError("unknown audit")
        if not acknowledge:
            raise PermissionError("confirm confidential report email delivery")
        assessment = self.audit_payload(audit_id)
        snapshot = assessment_snapshot_from_records(assessment["findings"], assessment["assessment_quality"])
        try:
            return mail_report(Path(row["workspace"]), audit_id, recipient, format_name,
                               consent=True, target=row["target"], template_name=template_name,
                               assessment_snapshot=snapshot,
                               client_name=client_name, client_organization=client_organization,
                               subject=subject, body=body)
        except (OSError, smtplib.SMTPException) as exc:
            # Credentials, SMTP replies and attachment content must not be
            # reflected to browsers. Detailed diagnostics stay with SMTP admins.
            raise RuntimeError(f"SMTP delivery failed ({type(exc).__name__}); check server, TLS and credentials") from None

    def _run_job(self, job: Job, func) -> None:
        def worker():
            try:
                func()
                self.jobs.update(job.job_id, status="COMPLETE", finished_at=_utcnow(), message="Completed")
            except Exception as exc:  # surfaced in UI; detailed traceback remains local
                self.jobs.update(
                    job.job_id,
                    status="FAILED",
                    finished_at=_utcnow(),
                    error=f"{type(exc).__name__}: {exc}",
                    message="Failed",
                )
                traceback.print_exc()

        threading.Thread(target=worker, name=job.job_id, daemon=True).start()

    def start_audit(self, target_text: str, profile: str, scope: dict | None = None, artifacts_dir: str | None = None) -> dict:
        policy = scope_from_dict(scope, default_target=normalize_target(target_text)) if scope else None
        audit_id, target, workspace, policy = self.engine.create_audit(target_text, profile=profile, scope_policy=policy)
        job = self.jobs.create("AUDIT", audit_id)

        def run():
            self.jobs.update(job.job_id, message="Reconnaissance and vulnerability discovery running")
            asyncio.run(
                self.engine.run_assessment(
                    audit_id,
                    target,
                    workspace,
                    policy,
                    profile=profile,
                    dry_run=False,
                    artifacts_dir=artifacts_dir,
                )
            )
            self.engine._set_state(audit_id, workspace, AuditState.COMPLETE)
            generate_summary(self.engine.db, audit_id, workspace)

        self._run_job(job, run)
        return {"audit_id": audit_id, "job": job.__dict__.copy()}

    def generate_report(self, audit_id: str) -> dict:
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError(f"unknown audit ID: {audit_id}")
        workspace = Path(row["workspace"])
        report = generate_summary(self.engine.db, audit_id, workspace)
        return {
            "report": report,
            "docx": {
                "executive": f"/reports/{audit_id}/executive-report.docx",
                "technical": f"/reports/{audit_id}/technical-report.docx",
                "complete": f"/reports/{audit_id}/complete-assessment.docx",
                "pdf": f"/reports/{audit_id}/assessment.pdf",
                "html": f"/reports/{audit_id}/assessment.html",
                "bundle": f"/reports/{audit_id}/assessment-bundle.zip",
                "json": f"/reports/{audit_id}/assessment.json",
                "csv": f"/reports/{audit_id}/findings.csv",
            },
            "workspace_report_dir": str(workspace / "reports" / "docx"),
            "project_report_dir": str(self.project_reports_root / audit_id),
        }

    def run_intelligence(self, audit_id: str, finding_id: str, *, offline: bool, metasploit: bool) -> dict:
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError(f"unknown audit ID: {audit_id}")
        manager = ExploitIntelligenceManager(self.engine.db, Path(row["workspace"]), self.config)
        record = asyncio.run(manager.analyze(audit_id, finding_id, offline=offline, metasploit=metasploit))
        generate_summary(self.engine.db, audit_id, Path(row["workspace"]))
        return record

    def start_intel_all(self, audit_id: str, top: int, *, offline: bool, metasploit: bool) -> dict:
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError(f"unknown audit ID: {audit_id}")
        findings = [f for f in self.engine.db.get_findings(audit_id) if f.get("cves")]
        findings.sort(key=lambda f: float(f.get("priority_score") or 0), reverse=True)
        selected = findings[: max(1, min(int(top), 50))]
        job = self.jobs.create("INTELLIGENCE", audit_id)

        def run():
            manager = ExploitIntelligenceManager(self.engine.db, Path(row["workspace"]), self.config)
            total = len(selected)
            for idx, finding in enumerate(selected, 1):
                self.jobs.update(job.job_id, message=f"Analyzing {idx}/{total}: {finding['finding_id']}")
                asyncio.run(
                    manager.analyze(
                        audit_id,
                        finding["finding_id"],
                        offline=offline,
                        metasploit=metasploit,
                    )
                )
            generate_summary(self.engine.db, audit_id, Path(row["workspace"]))

        self._run_job(job, run)
        return {"selected": len(selected), "job": job.__dict__.copy()}

    def delete_audit(self, audit_id: str, confirmation: str) -> dict:
        """Permanently remove an audit, its workspace, mirrored reports and DB rows.

        Deletion is deliberately strict: an exact audit-ID confirmation is required,
        active jobs block deletion, and filesystem paths must resolve to SHAuditer-owned
        locations before recursive removal is allowed.
        """
        row = self.engine.db.get_audit(audit_id)
        if not row:
            raise KeyError(f"unknown audit ID: {audit_id}")
        if confirmation.strip() != audit_id:
            raise PermissionError("delete confirmation must exactly match the audit ID")
        if self.jobs.has_running(audit_id):
            raise PermissionError("cannot delete an audit while a job is running")
        state = str(row.get("state") or "").upper()
        if "RUNNING" in state or state == "REPORTING":
            raise PermissionError(f"cannot delete audit while state is {state}")

        workspace = Path(row["workspace"]).expanduser().resolve()
        workspaces_root = (self.home / "workspaces").resolve()
        if workspace.parent != workspaces_root or workspace.name != audit_id:
            raise PermissionError("refusing to delete workspace outside the SHAuditer workspaces directory")

        project_report = (self.project_reports_root / audit_id).resolve()
        project_reports_root = self.project_reports_root
        if project_report.parent != project_reports_root or project_report.name != audit_id:
            raise PermissionError("refusing to delete report path outside the SHAuditer reports directory")

        deleted_db = self.engine.db.delete_audit(audit_id)
        workspace_deleted = False
        project_report_deleted = False
        if workspace.exists():
            shutil.rmtree(workspace)
            workspace_deleted = True
        if project_report.exists():
            shutil.rmtree(project_report)
            project_report_deleted = True
        self.jobs.remove_for_audit(audit_id)
        return {
            "audit_id": audit_id,
            "deleted": True,
            "workspace_deleted": workspace_deleted,
            "project_report_deleted": project_report_deleted,
            "database_rows": deleted_db,
        }

    def diagnostics(self) -> dict:
        tools = []
        for tool in ("nmap", "httpx", "subfinder", "nuclei", "trivy", "msfconsole"):
            path = shutil.which(tool)
            status = "NOT_INSTALLED"
            detail = "Optional tool not installed"
            if path:
                status = "OK"
                detail = path
                if tool == "httpx":
                    try:
                        proc = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=3, check=False)
                        output = (proc.stdout + "\n" + proc.stderr).lower()
                        if proc.returncode != 0 or "no such option" in output or "usage: httpx [options] url" in output:
                            status = "WRONG_BINARY"
                            detail = f"{path} — install ProjectDiscovery httpx"
                    except (OSError, subprocess.TimeoutExpired):
                        status = "UNUSABLE"
                        detail = path
            tools.append({"name": tool, "status": status, "detail": detail})
        return {"python": os.sys.version.split()[0], "home": str(self.home), "tools": tools,
                "catalog": inventory(), "smtp_configured": bool(os.environ.get("SHAUDITER_SMTP_HOST") and os.environ.get("SHAUDITER_SMTP_FROM"))}


class RequestHandler(BaseHTTPRequestHandler):
    app: GUIApplication
    server_version = "SHAuditerGUI/0.6"

    def log_message(self, format: str, *args) -> None:
        print(f"[GUI] {self.address_string()} - {format % args}")

    def _security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, status: int, payload) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, status: int, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self._security_headers(content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_JSON_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("JSON object required")
        return obj

    def _trusted_host(self) -> bool:
        # DNS-rebinding protection: reject requests with remote Host headers
        # even though the server binds only to loopback.
        host_header = self.headers.get("Host", "")
        try:
            parsed = urlparse("http://" + host_header)
            if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                return False
            return parsed.port == self.server.server_port
        except ValueError:
            return False

    def _authorized_post(self) -> bool:
        if not self._trusted_host():
            return False
        token = self.headers.get("X-SHAuditer-Token", "")
        if not secrets.compare_digest(token, self.app.token):
            return False
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlparse(origin)
            if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                return False
            if parsed.port != self.server.server_port:
                return False
        return True

    def _static(self, relative: str) -> None:
        if relative == "index.html":
            text = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
            text = text.replace("__SHAUDITER_TOKEN__", self.app.token)
            self._send_bytes(200, text.encode("utf-8"), "text/html; charset=utf-8")
            return
        path = (STATIC_DIR / relative).resolve()
        if STATIC_DIR.resolve() not in path.parents or not path.is_file():
            self._send_json(404, {"error": "not found"})
            return
        content_types = {".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}
        self._send_bytes(200, path.read_bytes(), content_types.get(path.suffix, "application/octet-stream"))

    def do_GET(self) -> None:
        if not self._trusted_host():
            return self._send_json(403, {"error": "untrusted Host header"})
        path = urlparse(self.path).path
        try:
            if path == "/":
                return self._static("index.html")
            if path.startswith("/static/"):
                return self._static(path.removeprefix("/static/"))
            if path == "/api/health":
                return self._send_json(200, {"status": "ok", "version": "1.1.7"})
            if path == "/api/audits":
                audits = self.app.engine.db.list_audits(100)
                return self._send_json(200, {"audits": audits, "jobs": self.app.jobs.list()})
            if path == "/api/diagnostics":
                return self._send_json(200, self.app.diagnostics())
            if path == "/api/tools":
                return self._send_json(200, {"tools": inventory(), "note": "Catalog entries are not all integrated scan modules. Install from reviewed official sources."})
            if path == "/api/mail/templates":
                mail_config = smtp_status()
                return self._send_json(200, {"templates": templates_catalog(),
                    "sender": mail_config["sender"], "display_name": mail_config["display_name"],
                    "reply_to": mail_config["reply_to"], "setup_hint": mail_config["hint"],
                    "smtp_configured": mail_config["ready"]})
            if path.startswith("/api/audits/"):
                audit_id = path.split("/")[3]
                return self._send_json(200, self.app.audit_payload(audit_id))
            if path.startswith("/reports/") and path.endswith((".docx", ".pdf", ".html", ".zip", ".json", ".csv")):
                parts = path.strip("/").split("/")
                if len(parts) != 3:
                    raise KeyError("invalid report path")
                audit_id, filename = parts[1], Path(parts[2]).name
                allowed = {"executive-report.docx", "technical-report.docx", "complete-assessment.docx", "assessment.pdf", "assessment.html", "assessment-bundle.zip", "assessment.json", "findings.csv"}
                if filename not in allowed:
                    raise KeyError("unsupported report")
                row = self.app.engine.db.get_audit(audit_id)
                if not row:
                    raise KeyError("unknown audit")
                report_path = Path(row["workspace"]) / "reports" / ("docx" if filename.endswith(".docx") else "") / filename
                if not report_path.is_file():
                    raise FileNotFoundError("report not generated")
                data = report_path.read_bytes()
                self.send_response(200)
                mime = ("application/pdf" if filename.endswith(".pdf") else
                        "text/html; charset=utf-8" if filename.endswith(".html") else
                        "application/zip" if filename.endswith(".zip") else
                        "application/json" if filename.endswith(".json") else
                        "text/csv" if filename.endswith(".csv") else
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                self.send_header("Content-Type", mime)
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            return self._send_json(404, {"error": "not found"})
        except KeyError as exc:
            return self._send_json(404, {"error": str(exc)})
        except FileNotFoundError as exc:
            return self._send_json(404, {"error": str(exc)})
        except Exception as exc:
            traceback.print_exc()
            return self._send_json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self) -> None:
        if not self._authorized_post():
            return self._send_json(403, {"error": "invalid local action token"})
        path = urlparse(self.path).path
        try:
            body = self._read_json()
            if path == "/api/audits":
                if body.get("authorized") is not True:
                    return self._send_json(400, {"error": "authorization acknowledgement is required"})
                target = str(body.get("target") or "").strip()
                if not target:
                    return self._send_json(400, {"error": "target is required"})
                profile = str(body.get("profile") or "safe")
                if profile not in {"safe", "standard"}:
                    return self._send_json(400, {"error": "invalid profile"})
                return self._send_json(202, self.app.start_audit(target, profile, scope=body.get("scope"), artifacts_dir=body.get("artifacts_dir")))

            parts = path.strip("/").split("/")
            if len(parts) >= 3 and parts[0] == "api" and parts[1] == "audits":
                audit_id = parts[2]
                row = self.app.engine.db.get_audit(audit_id)
                if not row:
                    raise KeyError(f"unknown audit ID: {audit_id}")
                workspace = Path(row["workspace"])
                manager = ValidationManager(self.app.engine.db, workspace)

                if len(parts) == 4 and parts[3] == "delete":
                    return self._send_json(200, self.app.delete_audit(audit_id, str(body.get("confirm") or "")))
                if len(parts) == 4 and parts[3] == "poc-history":
                    return self._send_json(200, {"executions": self.app.engine.db.get_poc_executions(audit_id)})
                if len(parts) == 4 and parts[3] == "engagement":
                    return self._send_json(200, {"engagement": self.app.save_engagement_metadata(audit_id, body)})
                if len(parts) == 4 and parts[3] == "report":
                    return self._send_json(200, self.app.generate_report(audit_id))
                if len(parts) == 5 and parts[3] == "email" and parts[4] == "preview":
                    return self._send_json(200, {"preview": self.app.email_preview(audit_id, body)})
                if len(parts) == 4 and parts[3] == "email":
                    result = self.app.send_report(audit_id, str(body.get("recipient") or ""),
                                                  str(body.get("format") or "pdf"),
                                                  body.get("acknowledge") is True,
                                                  template_name=str(body.get("template") or "final_delivery"),
                                                  client_name=str(body.get("client_name") or ""),
                                                  client_organization=str(body.get("client_organization") or ""),
                                                  subject=body.get("subject"), body=body.get("body"))
                    return self._send_json(200, {"sent": True, "delivery": result})
                if len(parts) == 4 and parts[3] == "intel-all":
                    return self._send_json(
                        202,
                        self.app.start_intel_all(
                            audit_id,
                            int(body.get("top", 5)),
                            offline=bool(body.get("offline", False)),
                            metasploit=bool(body.get("metasploit", True)),
                        ),
                    )
                if len(parts) == 4 and parts[3] == "evidence":
                    filename = Path(str(body.get("filename") or "evidence.bin")).name
                    raw_b64 = str(body.get("content_base64") or "")
                    data = base64.b64decode(raw_b64, validate=True)
                    if len(data) > MAX_EVIDENCE_BYTES:
                        return self._send_json(400, {"error": "evidence file exceeds 5 MiB GUI limit"})
                    operator = str(body.get("operator") or "").strip()
                    if not operator:
                        return self._send_json(400, {"error": "operator is required"})
                    upload_dir = workspace / "metadata" / "gui-uploads"
                    upload_dir.mkdir(parents=True, exist_ok=True)
                    temp = upload_dir / f"{secrets.token_hex(6)}-{filename}"
                    temp.write_bytes(data)
                    try:
                        evidence_id = manager.import_evidence(
                            audit_id,
                            temp,
                            operator,
                            kind=str(body.get("kind") or "MANUAL_VALIDATION"),
                            note=str(body.get("note") or ""),
                        )
                    finally:
                        temp.unlink(missing_ok=True)
                    generate_summary(self.app.engine.db, audit_id, workspace)
                    return self._send_json(200, {"evidence_id": evidence_id})

                if len(parts) >= 5 and parts[3] == "findings":
                    finding_id = parts[4]
                    if not self.app.engine.db.get_finding(audit_id, finding_id):
                        raise KeyError(f"unknown finding: {finding_id}")
                    action = parts[5] if len(parts) > 5 else ""
                    if action == "poc-approve":
                        poc = PoCManager(self.app.engine.db, workspace)
                        approval_id = poc.approve(audit_id, finding_id,
                                                  operator=str(body.get("operator") or ""),
                                                  note=str(body.get("note") or ""),
                                                  acknowledgement=body.get("acknowledge") is True)
                        generate_summary(self.app.engine.db, audit_id, workspace)
                        return self._send_json(200, {"approval_id": approval_id, "expires_minutes": 60})
                    if action == "poc-run":
                        poc = PoCManager(self.app.engine.db, workspace)
                        response = poc.execute(audit_id, finding_id, approval_id=str(body.get("approval_id") or ""),
                                               operator=str(body.get("operator") or ""))
                        generate_summary(self.app.engine.db, audit_id, workspace)
                        return self._send_json(200, response)
                    if action == "intel":
                        record = self.app.run_intelligence(
                            audit_id,
                            finding_id,
                            offline=bool(body.get("offline", False)),
                            metasploit=bool(body.get("metasploit", True)),
                        )
                        return self._send_json(200, record)
                    if action == "approve":
                        operator = str(body.get("operator") or "").strip()
                        if not operator:
                            return self._send_json(400, {"error": "operator is required"})
                        approval_id = manager.approve_validation(audit_id, finding_id, operator, str(body.get("note") or ""))
                        generate_summary(self.app.engine.db, audit_id, workspace)
                        return self._send_json(200, {"approval_id": approval_id})
                    if action == "validate":
                        operator = str(body.get("operator") or "").strip()
                        method = str(body.get("method") or "").strip()
                        status = str(body.get("status") or "").strip().upper()
                        if not operator or not method:
                            return self._send_json(400, {"error": "operator and method are required"})
                        validation_id = manager.record_validation(
                            audit_id,
                            finding_id,
                            status,
                            method,
                            operator,
                            evidence_id=body.get("evidence_id") or None,
                            note=str(body.get("note") or ""),
                        )
                        generate_summary(self.app.engine.db, audit_id, workspace)
                        return self._send_json(200, {"validation_id": validation_id})
                    if action == "session":
                        operator = str(body.get("operator") or "").strip()
                        evidence_id = str(body.get("evidence_id") or "").strip()
                        if not operator or not evidence_id:
                            return self._send_json(400, {"error": "operator and evidence ID are required"})
                        session_id = manager.record_session(
                            audit_id,
                            finding_id,
                            str(body.get("session_type") or "OTHER"),
                            str(body.get("privilege") or "OTHER"),
                            operator,
                            evidence_id=evidence_id,
                            note=str(body.get("note") or ""),
                        )
                        generate_summary(self.app.engine.db, audit_id, workspace)
                        return self._send_json(200, {"session_id": session_id})
                    if action == "review":
                        intel_manager = ExploitIntelligenceManager(self.app.engine.db, workspace, self.app.config)
                        review_id = intel_manager.record_review(
                            audit_id,
                            finding_id,
                            str(body.get("operator") or "").strip(),
                            str(body.get("decision") or "DEFER").upper(),
                            module=body.get("module") or None,
                            note=str(body.get("note") or ""),
                        )
                        generate_summary(self.app.engine.db, audit_id, workspace)
                        return self._send_json(200, {"review_id": review_id})

            return self._send_json(404, {"error": "not found"})
        except (ValueError, json.JSONDecodeError, base64.binascii.Error) as exc:
            return self._send_json(400, {"error": str(exc)})
        except PermissionError as exc:
            return self._send_json(409, {"error": str(exc)})
        except KeyError as exc:
            return self._send_json(404, {"error": str(exc)})
        except Exception as exc:
            traceback.print_exc()
            return self._send_json(500, {"error": f"{type(exc).__name__}: {exc}"})


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="shauditer-gui", description="SHAuditer local graphical dashboard")
    p.add_argument("--home", default=str(DEFAULT_HOME), help="SHAuditer data directory")
    p.add_argument("--config", default=str(DEFAULT_CONFIG), help="configuration JSON")
    p.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"], help="loopback bind address")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true")
    return p


def serve(home: Path, config_path: Path, *, host: str = "127.0.0.1", port: int = 8765, no_browser: bool = False) -> None:
    app = GUIApplication(home, config_path)
    RequestHandler.app = app
    server = ThreadingHTTPServer((host, port), RequestHandler)
    url = f"http://{host}:{port}/"
    print("SHAuditer Graphical Dashboard v1.1.7")
    print(f"Listening only on loopback: {url}")
    print("Press Ctrl+C to stop.")
    if not no_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping SHAuditer GUI...")
    finally:
        server.server_close()


def main() -> None:
    if os.name == "posix":
        os.umask(0o077)  # audit workspaces may hold confidential client data
    args = parser().parse_args()
    serve(Path(args.home), Path(args.config), host=args.host, port=args.port, no_browser=args.no_browser)


if __name__ == "__main__":
    main()
