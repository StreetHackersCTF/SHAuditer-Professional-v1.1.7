"""New v1.1.6 tests use no public targets and do not send real email."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile

import pytest

from shauditer.intelligence.exploit_intelligence import NvdClient
from shauditer.intelligence.public_sources import ThreatContext, priority_context, research_references, safe_check_code
from shauditer.intelligence.searchsploit import parse_searchsploit_json
from shauditer.reporting.bundle import bundle_reports
from shauditer.reporting.mail import mail_report, smtp_settings, validate_recipient
from shauditer.tools.catalog import TOOLS, inventory
from shauditer.gui.server import GUIApplication, STATIC_DIR


def test_nvd_api_uses_singular_id_and_checks_exact_identifier(monkeypatch):
    seen = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self, limit):
            return json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2026-10400", "descriptions": []}},
                                                     {"cve": {"id": "CVE-2026-10401", "descriptions": []}}]}).encode()
    def fake_open(req, timeout):
        seen.append(parse_qs(urlsplit(req.full_url).query))
        return Response()
    monkeypatch.setattr("shauditer.intelligence.exploit_intelligence.urlopen", fake_open)
    result = NvdClient().fetch(["CVE-2026-10400"])
    assert seen == [{"cveId": ["CVE-2026-10400"]}]
    assert list(result) == ["CVE-2026-10400"]


def test_public_exploit_sources_are_labeled_not_claimed():
    refs = research_references({"cves": ["CVE-2026-10400"]})
    assert {r["provider"] for r in refs} >= {"NIST NVD", "CISA", "Rapid7", "GitHub", "Exploit Database"}
    assert all(r["kind"] in {"search", "advisory"} for r in refs)
    assert research_references({"cves": ["not-a-cve"]}) == []
    code = safe_check_code({"poc_type": "HTTP_HEADER", "endpoint": "https://example.org/?q=';echo xyz"})
    assert code.startswith("# Manual operator review") and "curl --head" in code
    assert safe_check_code({"title": "SQL injection", "endpoint": "https://example.org"}) is None


def test_threat_context_fetch_is_source_scoped_and_offline_fake(monkeypatch):
    urls = []
    def fake_read(url, **_):
        urls.append(url)
        if "first.org" in url:
            return {"data": [{"cve": "CVE-2026-10400", "epss": "0.82", "percentile": "0.95", "date": "2026-11-01"}]}
        return {"vulnerabilities": [{"cveID": "CVE-2026-10400", "dateAdded": "2026-11-02"}]}
    monkeypatch.setattr("shauditer.intelligence.public_sources.read_json", fake_read)
    feed = ThreatContext().fetch(["CVE-2026-10400"])
    assert feed["epss"]["CVE-2026-10400"]["score"] == .82
    assert feed["kev"]["CVE-2026-10400"]["date_added"] == "2026-11-02"
    assert "KNOWN EXPLOITED" in priority_context(feed)
    assert len(urls) == 2 and all(url.startswith("https://") for url in urls)


def test_searchsploit_parse_only_metadata():
    data = json.dumps({"RESULTS_EXPLOIT": [{"EDB-ID": "51234", "Title": "Example Advisory", "Path": "/private/secret", "Type": "webapps"}]})
    result = parse_searchsploit_json(data)
    assert result[0]["url"] == "https://www.exploit-db.com/exploits/51234"
    assert "/private/secret" not in str(result)


def test_bundle_integrity_and_no_raw_evidence(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "assessment.pdf").write_bytes(b"%PDF-minimal")
    (reports / "assessment.json").write_text('{"status": "TEST"}')
    (reports / "raw-secrets.txt").write_text("do not publish")
    result = bundle_reports(tmp_path)
    with ZipFile(result) as archive:
        assert "raw-secrets.txt" not in archive.namelist()
        manifest = json.loads(archive.read("SHA256-MANIFEST.json"))
        assert all(hashlib.sha256(archive.read(x["file"])).hexdigest() == x["sha256"] for x in manifest["files"])


def test_email_validation_and_required_consent(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "assessment.pdf").write_bytes(b"%PDF-test")
    with pytest.raises(PermissionError):
        mail_report(tmp_path, "SHA-TEST", "team@example.com", "pdf")
    for item in ("a@example.org\nBcc:bad@example.org", "a@example.org,b@example.org", "nope", "a@localhost"):
        with pytest.raises(ValueError): validate_recipient(item)
    with pytest.raises(ValueError): mail_report(tmp_path, "SHA-TEST", "x@example.org", "../../secrets", consent=True)
    with pytest.raises(RuntimeError): smtp_settings({})


def test_mail_uses_tls_and_sends_only_operator_selected_attachment(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "assessment.pdf").write_bytes(b"%PDF-safe-report")
    sent = []
    class SMTP:
        def __init__(self, host, port, timeout, **kw):
            sent.append(("connect", host, port))
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def ehlo(self): sent.append(("ehlo",))
        def starttls(self, context): sent.append(("tls",))
        def login(self, user, password, *, initial_response_ok=True):
            assert initial_response_ok is False
            sent.append(("login", user))
        def send_message(self, msg):
            sent.append(("send", msg["To"], msg["Subject"], msg.get_payload()[1].get_filename()))
    monkeypatch.setattr("shauditer.reporting.mail.smtplib.SMTP", SMTP)
    config = {"host": "smtp.example.org", "port": 587, "sender": "sender@example.org", "username": "u", "password": "secret", "ssl_mode": False}
    result = mail_report(tmp_path, "SHA-TEST", "auditor@example.org", "pdf", config=config, consent=True)
    assert result["status"] == "SENT"
    assert sent.index(("tls",)) < sent.index(("login", "u")) < next(i for i, x in enumerate(sent) if x[0] == "send")
    assert sent[-1][-1] == "assessment.pdf"
    assert "secret" not in (tmp_path / "metadata" / "email-delivery.jsonl").read_text()


def test_toolhub_has_official_repos_and_semgrep_integrated():
    assert len(TOOLS) >= 24
    assert any(t.name == "Semgrep" and t.integration == "INTEGRATED" for t in TOOLS)
    assert all(t.repo.startswith("https://github.com/") for t in TOOLS)
    assert len(inventory()) == len(TOOLS)
    index = (STATIC_DIR / "index.html").read_text()
    for element in ("statusRing", "toolHubGrid", "sendReportForm", "bundleReportBtn"):
        assert f'id="{element}"' in index


def test_gui_status_explains_empty_results_and_report_mail_requires_consent(tmp_path):
    app = GUIApplication(tmp_path / "home", Path(__file__).resolve().parents[1] / "config" / "default.json")
    audit, target, workspace, policy = app.engine.create_audit("https://example.org")
    status = app.audit_payload(audit)["status_detail"]
    assert status["finding_count"] == 0
    assert "NOT proof" not in str(status) or "NOT proof" in str(status)
    assert any("NOT proof" in text for text in status["messages"])
    with pytest.raises(PermissionError): app.send_report(audit, "authorized@example.org", "pdf", False)
