"""No real SMTP or public target is used by these tests."""
import json
from pathlib import Path
import pytest

from shauditer.gui.server import GUIApplication, STATIC_DIR
from shauditer.reporting.mail import (
    EMAIL_TEMPLATES, compose_client_email, mail_report, smtp_settings, templates_catalog
)
from shauditer.cli.app import parser


def test_eight_industry_templates_have_distinct_types_and_safe_default_language():
    names = {item['id'] for item in templates_catalog()}
    assert names == {'final_delivery', 'executive_delivery', 'urgent_findings',
                     'remediation_followup', 'retest_results', 'engagement_closure',
                     'report_revision', 'technical_debrief'}
    for name in names:
        entry = compose_client_email('SHA-2026-100', target='https://audit.example.org',
                                     template_name=name, client_name='Nisha',
                                     client_organization='Example Ltd', sender_email='audit@street-hackers.example',
                                     date='03 November 2026')
        assert 'Example Ltd' in entry['subject']
        assert 'SHA-2026-100' in entry['body']
        assert 'https://audit.example.org' in entry['body']
        assert 'Nisha' in entry['body']
        assert 'Street_Hackers' in entry['body']
        assert 'audit@street-hackers.example' in entry['body']
        assert '\n' not in entry['subject']


def test_sender_identity_and_reply_to_config():
    conf = smtp_settings({'SHAUDITER_SMTP_HOST': 'smtp.street-hackers.example',
                          'SHAUDITER_SMTP_FROM': 'reports@street-hackers.example',
                          'SHAUDITER_SMTP_DISPLAY_NAME': 'Street_Hackers Security Team',
                          'SHAUDITER_SMTP_REPLY_TO': 'soc@street-hackers.example'})
    assert conf['sender'] == 'reports@street-hackers.example'
    assert conf['display_name'] == 'Street_Hackers Security Team'
    assert conf['reply_to'] == 'soc@street-hackers.example'
    with pytest.raises(ValueError):
        smtp_settings({'SHAUDITER_SMTP_HOST': 'smtp.example.org',
                       'SHAUDITER_SMTP_FROM': 'reports@example.org',
                       'SHAUDITER_SMTP_REPLY_TO': 'soc@example.org\nBcc:evil@example.org'})


def test_client_templates_reject_header_injection_and_invalid_inputs():
    for overrides in ({'subject': 'Subject\nBcc: attacker@example.org'},
                      {'client_name': 'Client\r\nBcc: attacker@example.org'},
                      {'client_organization': 'Name\nMore'},
                      {'template_name': '../../unsafe'},
                      {'body': '\x00payload'}):
        with pytest.raises(ValueError):
            compose_client_email('SHA-100', **overrides)
    custom = compose_client_email('SHA-100', subject='Client handover', body='Dear Client,\nSee attached.')
    assert custom['subject'] == 'Client handover' and 'Dear Client,' in custom['body']


def test_client_switch_emails_keep_separate_recipients_and_no_secret_in_log(tmp_path, monkeypatch):
    reports = tmp_path / 'reports'
    reports.mkdir()
    (reports / 'assessment.pdf').write_bytes(b'%PDF-1.4 mock')
    sent = []
    class FakeSMTP:
        def __init__(self, host, port, timeout, **_):
            assert host == 'smtp.street-hackers.example'
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def ehlo(self): pass
        def starttls(self, context): pass
        def login(self, user, password, *, initial_response_ok=True):
            assert password == 'PASSWORD_MUST_STAY_PRIVATE'
            assert initial_response_ok is False
        def send_message(self, message): sent.append(message)

    monkeypatch.setattr('shauditer.reporting.mail.smtplib.SMTP', FakeSMTP)
    settings = smtp_settings({'SHAUDITER_SMTP_HOST': 'smtp.street-hackers.example',
                              'SHAUDITER_SMTP_FROM': 'reports@street-hackers.example',
                              'SHAUDITER_SMTP_USER': 'reports@street-hackers.example',
                              'SHAUDITER_SMTP_PASSWORD': 'PASSWORD_MUST_STAY_PRIVATE'})
    with pytest.raises(PermissionError):
        mail_report(tmp_path, 'SHA-01', 'client-one@example.org', 'pdf', config=settings)
    a = mail_report(tmp_path, 'SHA-01', 'client-one@example.org', 'pdf', config=settings,
                    client_name='Contact One', client_organization='Client One',
                    target='https://one.example.org', consent=True)
    b = mail_report(tmp_path, 'SHA-02', 'client-two@example.org', 'pdf', config=settings,
                    client_name='Contact Two', client_organization='Client Two',
                    target='https://two.example.org', template_name='retest_results', consent=True)
    assert a['delivery_stage'] == b['delivery_stage'] == 'SMTP_ACCEPTED'
    assert sent[0]['To'] == 'client-one@example.org' and sent[1]['To'] == 'client-two@example.org'
    assert sent[0]['From'] == sent[1]['From'] == 'Street_Hackers Security Team <reports@street-hackers.example>'
    assert 'Client One' in sent[0]['Subject'] and 'Client Two' in sent[1]['Subject']
    assert sent[0].get_payload()[1].get_filename() == 'assessment.pdf'
    assert 'two.example.org' not in sent[0].get_payload()[0].get_content()
    assert 'one.example.org' not in sent[1].get_payload()[0].get_content()
    lines = (tmp_path / 'metadata' / 'email-delivery.jsonl').read_text()
    assert 'PASSWORD_MUST_STAY_PRIVATE' not in lines
    assert len(lines.splitlines()) == 2


def test_gui_previews_client_mail_without_smtp(tmp_path):
    app = GUIApplication(tmp_path / 'home', Path(__file__).resolve().parents[1] / 'config' / 'default.json')
    audit_id, _, _, _ = app.engine.create_audit('https://staging.example.org')
    msg = app.email_preview(audit_id, {'template': 'final_delivery', 'client_name': 'Client Contact',
                                       'client_organization': 'New Client', 'format': 'pdf',
                                       'recipient': 'security@new-client.example'})
    assert 'New Client' in msg['subject']
    assert 'staging.example.org' in msg['body']
    with pytest.raises(ValueError):
        app.email_preview(audit_id, {'recipient': 'fake@example.org,evil@example.org'})


def test_dashboard_has_mutable_client_preview_and_cli_support():
    html = (STATIC_DIR / 'index.html').read_text()
    js = (STATIC_DIR / 'app.js').read_text()
    for element in ('reportClientOrganization', 'reportClientName', 'reportEmailTemplate',
                    'reportSubject', 'reportBody', 'previewReportBtn', 'reportPreviewCard'):
        assert f'id="{element}"' in html
    assert 'resetClientDelivery()' in js
    assert 'email/preview' in js
    parsed = parser().parse_args(['mail', 'SHA-01', '--to', 'client@example.org', '--template', 'retest_results',
                                  '--client-organization', 'Client Ltd', '--preview'])
    assert parsed.preview is True and parsed.template == 'retest_results'


def test_default_gmail_address_and_readiness_require_private_credential(monkeypatch):
    from shauditer.reporting.mail import (DEFAULT_STREET_HACKERS_EMAIL, sender_address,
                                           smtp_status, smtp_settings)
    email = "streethackers03012026@gmail.com"
    assert DEFAULT_STREET_HACKERS_EMAIL == email
    assert sender_address({}) == email
    before = smtp_status({})
    assert before["sender"] == email
    assert before["ready"] is False
    assert "App Password" in before["hint"]
    with pytest.raises(RuntimeError, match="credential"):
        smtp_settings({})
    configured = smtp_settings({"SHAUDITER_SMTP_PASSWORD": "MOCK_APP_PASSWORD_NOT_REAL"})
    assert configured["host"] == "smtp.gmail.com"
    assert configured["port"] == 587
    assert configured["sender"] == configured["username"] == email
    assert smtp_status({"SHAUDITER_SMTP_PASSWORD": "MOCK_APP_PASSWORD_NOT_REAL"})["ready"]
    assert smtp_status({"SHAUDITER_SMTP_FROM": "team@company.example"})["ready"] is False


def test_factual_risk_snapshot_and_default_email_are_safe_for_clients():
    from shauditer.reporting.mail import assessment_snapshot_from_records
    data = [
      {"severity": "CRITICAL", "validation_status": "UNVALIDATED"},
      {"severity": "HIGH", "validation_status": "VALIDATED"},
      {"severity": "MEDIUM", "validation_status": "UNVALIDATED"},
      {"severity": "LOW", "validation_status": "UNVALIDATED"},
      {"severity": "INFO", "validation_status": "UNVALIDATED"},
    ]
    snapshot = assessment_snapshot_from_records(data, {
        "status": "REVIEW_REQUIRED", "unvalidated_findings": 4
    })
    assert "Recorded findings: 5" in snapshot
    assert "Critical 1, High 1, Medium 1, Low 1, Informational 1" in snapshot
    assert "manual validation: 4" in snapshot
    assert "REVIEW_REQUIRED" in snapshot
    assert "proof of compromise" in snapshot
    email = compose_client_email("AUDIT-99", target="192.0.2.1", client_name="Security Team",
        client_organization="Company ABC", assessment_snapshot=snapshot)
    assert "streethackers03012026@gmail.com" in email["body"]
    assert "Critical 1" in email["body"]
    assert "Assign a remediation owner" in email["body"]
    assert "Company ABC" in email["subject"]


def test_dashboard_gmail_sender_fallback_and_factual_snapshot(tmp_path, monkeypatch):
    from shauditer.reporting.mail import DEFAULT_STREET_HACKERS_EMAIL
    for key in ("SHAUDITER_SMTP_HOST", "SHAUDITER_SMTP_FROM", "SHAUDITER_SMTP_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    app = GUIApplication(tmp_path / "isolated_home", Path(__file__).resolve().parents[1] / "config" / "default.json")
    audit_id, *_ = app.engine.create_audit("https://example.org")
    preview = app.email_preview(audit_id, {"recipient": "sec@client.example", "template": "final_delivery",
                                            "client_organization": "Client"})
    assert DEFAULT_STREET_HACKERS_EMAIL in preview["body"]
    assert "INSUFFICIENT_COVERAGE" in preview["body"]
    assert "Recorded findings: 0" in preview["body"]
    assert not app.audit_payload(audit_id)["delivery_available"]


def test_gmail_465_smtp_ssl_uses_compatible_authentication(tmp_path, monkeypatch):
    """Regression: Gmail supports 465 SSL and AUTH with delayed initial response."""
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "assessment.pdf").write_bytes(b"%PDF-1.4 fake report")
    calls = []

    class FakeSMTPSsl:
        def __init__(self, host, port, timeout, **kwargs):
            assert host == "smtp.gmail.com"
            assert port == 465
            assert kwargs.get("context") is not None
            calls.append("connect_ssl")
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def login(self, user, password, *, initial_response_ok=True):
            assert user == "streethackers03012026@gmail.com"
            assert password == "EXAMPLE_TEST_CREDENTIAL"
            assert initial_response_ok is False
            calls.append("authenticated")
        def send_message(self, message):
            assert message["To"] == "tester@example.org"
            calls.append("sent")
        def starttls(self, **kwargs):
            raise AssertionError("SMTP_SSL must not use STARTTLS")

    monkeypatch.setattr("shauditer.reporting.mail.smtplib.SMTP_SSL", FakeSMTPSsl)
    cfg = smtp_settings({
        "SHAUDITER_SMTP_HOST": "smtp.gmail.com",
        "SHAUDITER_SMTP_PORT": "465",
        "SHAUDITER_SMTP_SSL": "true",
        "SHAUDITER_SMTP_USER": "streethackers03012026@gmail.com",
        "SHAUDITER_SMTP_FROM": "streethackers03012026@gmail.com",
        "SHAUDITER_SMTP_PASSWORD": "EXAMPLE_TEST_CREDENTIAL",
    })
    result = mail_report(tmp_path, "SMOKE-465", "tester@example.org", "pdf", config=cfg, consent=True)
    assert calls == ["connect_ssl", "authenticated", "sent"]
    assert result["delivery_stage"] == "SMTP_ACCEPTED"
