"""Regression tests for professional v1.0 features (offline, no external targets)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

import pytest

from shauditer.core.engine import AuditEngine
from shauditer.models.target import normalize_target
from shauditer.modules.artifacts import scan_directory
from shauditer.modules.web.posture import review_response_headers, sanitized_probe, _resolve_pinned
from shauditer.poc.runner import PoCManager
from shauditer.reporting.professional import build_workflow
from shauditer.reporting.summary import generate_summary
from shauditer.scope.models import ScopePolicy
from shauditer.scope.validator import ScopeValidator


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_cloud_container_ai_rules_detected_offline(tmp_path):
    write(tmp_path / "Dockerfile", "FROM ubuntu:latest\nRUN curl https://example.org/bootstrap | sh\n")
    write(tmp_path / "network.tf", '''resource "aws_security_group_rule" "ssh" {\n  cidr_blocks = ["0.0.0.0/0"]\n  from_port = 22\n  to_port = 22\n}''')
    write(tmp_path / "k8s.yaml", '''kind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: app\n      image: demo:latest\n      securityContext:\n        privileged: true''')
    write(tmp_path / "agent-config.json", json.dumps({"guardrails_enabled": False,
          "tools": {"allow_all": True}, "prompt_logging": True, "redact_pii": False}))
    write(tmp_path / "iam.json", json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    result = scan_directory(tmp_path)
    rules = {f["rule_id"] for f in result["findings"]}
    for expected in ("DOCKER-001", "DOCKER-002", "DOCKER-003", "IAC-001", "K8S-001", "K8S-003", "K8S-005", "AI-002", "AI-003", "AI-004", "CLOUD-001"):
        assert expected in rules
    assert len(result["inspected"]) == 5
    assert result["coverage"]["cloud_api_connected"] is False
    assert all(f["validation_status"] == "UNVALIDATED" for f in result["findings"])


def test_ignored_and_oversize_and_no_secrets_copied(tmp_path):
    write(tmp_path / ".git" / "agent-config.json", '{"guardrails_enabled": false}')
    write(tmp_path / ".env", "API_TOKEN=SECRET-SHOULD-NOT-APPEAR")
    write(tmp_path / "dockerfile", "FROM alpine:3.20\nUSER app\n")
    write(tmp_path / "big.tf", "x" * 1_000_001)
    result = scan_directory(tmp_path)
    serialized = json.dumps(result)
    assert "SECRET-SHOULD-NOT-APPEAR" not in serialized
    assert len(result["findings"]) == 0
    assert "big.tf" in serialized


def test_web_posture_missing_headers_is_observation_not_exploit():
    findings = review_response_headers("https://example.org/", [("Server", "nginx"), ("Set-Cookie", "s=PRIVATE; Path=/")])
    bytitle = {f["title"]: f for f in findings}
    assert "HTTP Strict Transport Security is missing" in bytitle
    assert "Cookie missing Secure attribute" in bytitle
    assert "Cookie missing HttpOnly attribute" in bytitle
    assert bytitle["HTTP Strict Transport Security is missing"]["poc_parameter"] == "strict-transport-security"
    assert all(f["exploitability"] == "UNKNOWN" for f in findings)
    assert "PRIVATE" not in json.dumps(findings)
    result = sanitized_probe({"url":"https://example.org", "status":200,
             "observed_at":"now", "headers":[("Set-Cookie","session=VERY-SECRET"),("Server","x")]})
    assert "VERY-SECRET" not in json.dumps(result)


def test_public_hostname_dns_to_loopback_denied_unless_ip_scoped(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))])
    scope = ScopeValidator(ScopePolicy(in_scope=["test.example"]))
    with pytest.raises(PermissionError):
        _resolve_pinned("test.example", 443, scope)
    explicit = ScopeValidator(ScopePolicy(in_scope=["test.example", "127.0.0.1"]))
    assert _resolve_pinned("test.example", 443, explicit) == "127.0.0.1"


def _make_audit(tmp_path):
    engine = AuditEngine(tmp_path / "home", {"rate_limit": {"max_parallel_modules": 1}})
    audit, target, workspace, _ = engine.create_audit("https://example.org")
    engine.db.upsert_finding(audit, "F-0001", {
        "finding_id": "F-0001", "title": "Missing HSTS", "asset": "example.org", "endpoint": "https://example.org/",
        "poc_type": "HTTP_HEADER", "poc_parameter": "strict-transport-security", "severity":"LOW", "confidence": .8,
        "sources": ["web_posture"], "cves": [], "cwes": ["CWE-319"], "remediation": "Enable HSTS after testing.",
        "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN"})
    return engine, audit, workspace


def test_one_time_poc_approval_bound_to_operator_finding_and_single_use(tmp_path, monkeypatch):
    engine, audit, workspace = _make_audit(tmp_path)
    manager = PoCManager(engine.db, workspace)
    from shauditer.poc import runner
    monkeypatch.setattr(runner, "probe", lambda *args, **kwargs: {
        "url": "https://example.org/", "headers": [("Server", "test")], "status": 200,
        "observed_at": "2026-11-03T10:00:00+00:00"})
    with pytest.raises(PermissionError):
        manager.approve(audit, "F-0001", operator="tester", note="", acknowledgement=False)
    approved = manager.approve(audit, "F-0001", operator="tester", note="authorized lab", acknowledgement=True)
    with pytest.raises(PermissionError):
        manager.execute(audit, "F-0001", approval_id=approved, operator="other-operator")
    result = manager.execute(audit, "F-0001", approval_id=approved, operator="tester")
    assert result["result"] == "VALIDATED"
    assert result["impact_demonstrated"] is False
    assert engine.db.get_finding(audit,"F-0001")["exploitability"] == "OBSERVATION_CONFIRMED"
    assert len(engine.db.get_poc_executions(audit)) == 1
    assert len(engine.db.get_validations(audit)) == 1
    with pytest.raises(PermissionError, match="already consumed"):
        manager.execute(audit,"F-0001",approval_id=approved,operator="tester")


def test_successful_fix_not_validated_and_no_second_use(tmp_path, monkeypatch):
    engine, audit, workspace = _make_audit(tmp_path)
    from shauditer.poc import runner
    monkeypatch.setattr(runner, "probe", lambda *args, **kwargs: {
        "url": "https://example.org/", "headers": [("Strict-Transport-Security", "max-age=86400")],
        "status": 200, "observed_at": "now"})
    manager = PoCManager(engine.db, workspace)
    approval = manager.approve(audit, "F-0001", operator="tester", note="", acknowledgement=True)
    result = manager.execute(audit, "F-0001", approval_id=approval, operator="tester")
    assert result["result"] == "NOT_VALIDATED"
    assert engine.db.get_finding(audit,"F-0001")["validation_status"] == "NOT_VALIDATED"


def test_expired_approval_rejected(tmp_path, monkeypatch):
    engine, audit, workspace = _make_audit(tmp_path)
    manager = PoCManager(engine.db, workspace)
    approval = manager.approve(audit,"F-0001",operator="tester",note="",acknowledgement=True)
    with engine.db.connect() as conn:
        conn.execute("UPDATE approvals SET created_at=? WHERE approval_id=?",
             ((datetime.now(timezone.utc)-timedelta(hours=2)).isoformat(), approval))
    with pytest.raises(PermissionError, match="expired"):
        manager.execute(audit,"F-0001",approval_id=approval,operator="tester")


def test_pdf_html_and_docx_exports(tmp_path, monkeypatch):
    engine, audit, workspace = _make_audit(tmp_path)
    monkeypatch.setenv("SHAUDITER_PROJECT_REPORTS", str(tmp_path / "mirror"))
    report = generate_summary(engine.db, audit, workspace)
    assert report["version"] == "1.1.7"
    pdf = workspace / "reports" / "assessment.pdf"
    html = workspace / "reports" / "assessment.html"
    assert pdf.read_bytes().startswith(b"%PDF-")
    assert "Five-phase assessment workflow" in html.read_text(encoding="utf-8")
    assert "Enable HSTS after testing" in html.read_text(encoding="utf-8")
    assert (workspace / "reports" / "docx" / "complete-assessment.docx").is_file()
    assert len(report["workflow"]) == 5
    assert report["workflow"][3]["status"] == "AWAITING OPERATOR"
    assert "No core scanner completed successfully" in html.read_text(encoding="utf-8")


def test_all_target_forms_are_supported():
    for text in ("https://example.com/path?x=1", "example.com", "server.local", "192.0.2.10", "2001:db8::1", "192.0.2.0/28"):
        assert normalize_target(text).hostname


def test_cloud_json_array_action_is_not_an_exception(tmp_path):
    write(tmp_path/"iam.json", json.dumps({"Statement": [{"Effect":"Allow", "Action":["s3:GetObject"], "Resource":"*"}]}))
    assert scan_directory(tmp_path)["findings"] == []


def test_html_safely_escapes_scanner_supplied_titles(tmp_path, monkeypatch):
    engine, audit, workspace = _make_audit(tmp_path)
    row = engine.db.get_finding(audit, "F-0001")
    row["title"] = '<script>alert(1)</script>'
    engine.db.upsert_finding(audit, "F-0001", row)
    monkeypatch.setenv("SHAUDITER_PROJECT_REPORTS", str(tmp_path / "mirror"))
    generate_summary(engine.db, audit, workspace)
    html = (workspace / "reports" / "assessment.html").read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert '<script>alert(1)</script>' not in html


def test_openapi_inventory_and_auth_review(tmp_path):
    spec = {"openapi": "3.1.0", "servers": [{"url":"http://api.example.org"}],
            "security": [{"Bearer": []}], "paths": {"/public": {"get": {"security": []}},
              "/private": {"get": {"security": [{"Bearer":[]}]}}}}
    write(tmp_path / "openapi.json", json.dumps(spec))
    result = scan_directory(tmp_path)
    assert result["coverage"]["api_operations_discovered"] == 2
    assert {f["rule_id"] for f in result["findings"]} == {"API-001", "API-002"}
    assert any(entry["path"] == "/private" and entry["auth_declared"] for entry in result["api_endpoints"])


def test_trivy_parser_dependency_vuln_and_misconfiguration():
    from shauditer.integrations.trivy_fs import parse_trivy_json
    fixture = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2025-0001", "PkgName": "sample-lib", "Severity": "HIGH", "FixedVersion": "2.0"}],
        "Misconfigurations": [{"ID":"KSV001", "Title":"Unsafe resource", "Severity":"MEDIUM", "Resolution":"Harden resource"}]}]}
    findings = parse_trivy_json(fixture, "EV-1")
    assert len(findings) == 2
    assert findings[0]["cves"] == ["CVE-2025-0001"]
    assert findings[0]["remediation"].endswith("(2.0).")
    assert findings[1]["remediation"] == "Harden resource"


def test_live_local_http_posture_and_single_use_check(tmp_path, monkeypatch):
    """End-to-end local integration; never contacts an external target."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from shauditer.integrations.nuclei import NucleiIntegration

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        engine = AuditEngine(tmp_path / "audit-home", {"timeouts": {"web_posture": 2}, "rate_limit":{"max_parallel_modules":1}})
        aid, tgt, ws, policy = engine.create_audit(target)
        write(tmp_path/"artifacts"/"Dockerfile", "FROM ubuntu:latest\nRUN echo test\n")
        # Prevent third-party scanner use during this deterministic local-only test.
        monkeypatch.setattr(NucleiIntegration, "available", lambda *_: False)
        from shauditer.integrations.trivy_fs import TrivyFSIntegration
        monkeypatch.setattr(TrivyFSIntegration, "available", lambda *_: False)
        from shauditer.integrations.base import ModuleResult
        findings = __import__('asyncio').run(engine.run_vulnerability_discovery(
            aid, tgt, ws, policy, {"services": []}, artifacts_dir=tmp_path / "artifacts"))
        assert any(f["poc_type"] == "HTTP_HEADER" for f in findings)
        assert any(f.get("rule_id") == "DOCKER-001" for f in findings)
        assert any(r["module"] == "web_posture" and r["status"] == "SUCCESS" for r in engine.db.get_module_runs(aid))
        header_finding = next(f for f in findings if f.get("poc_type") == "HTTP_HEADER")
        manager = PoCManager(engine.db, ws)
        approval = manager.approve(aid, header_finding["finding_id"], operator="local-tester", note="safe loopback test", acknowledgement=True)
        proof = manager.execute(aid, header_finding["finding_id"], approval_id=approval, operator="local-tester")
        assert proof["result"] == "VALIDATED"
        monkeypatch.setenv("SHAUDITER_PROJECT_REPORTS", str(tmp_path/"mirror"))
        report = generate_summary(engine.db, aid, ws)
        assert report["summary"]["validated"] >= 1
        assert (ws/"reports"/"assessment.pdf").exists()
        assert len(report["poc_executions"]) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
