"""v1.1.7 release tests: offline-only, no SMTP delivery or public scanning."""
from __future__ import annotations
import asyncio
from pathlib import Path
import json
from types import SimpleNamespace

from shauditer.core.engine import AuditEngine
from shauditer.integrations.base import ModuleResult
from shauditer.integrations.checkov_local import CheckovLocalIntegration, parse_checkov
from shauditer.integrations.gitleaks_local import GitleaksLocalIntegration, parse_gitleaks
from shauditer.reporting.summary import generate_summary
from shauditer.tools.catalog import TOOLS


def test_theme_switching_assets_and_graphical_dashboard():
    root = Path(__file__).resolve().parents[1] / 'shauditer/gui/static'
    html = (root / 'index.html').read_text()
    js = (root / 'app.js').read_text()
    css = (root / 'styles.css').read_text()
    assert 'id="themeToggle"' in html
    assert 'id="riskWheel"' in html
    assert 'localStorage.setItem(THEME_KEY,theme)' in js
    assert 'aria-pressed' in js
    assert ':root[data-theme="light"] .sidebar' in css
    assert 'prefers-reduced-motion:reduce' in css
    assert 'v1.1.7' in html


def test_real_integrations_in_new_tool_catalog():
    assert len(TOOLS) >= 55
    assert any(t.name == 'Gitleaks' and t.integration == 'INTEGRATED' for t in TOOLS)
    assert any(t.name == 'Checkov' and t.integration == 'INTEGRATED' for t in TOOLS)
    assert any(t.name == 'Garak' and t.integration == 'CATALOG_ONLY' for t in TOOLS)
    assert all(t.repo.startswith('https://github.com/') for t in TOOLS)


def test_checkov_parser_reports_context_without_source_excerpt():
    raw = {'results': {'failed_checks': [{
        'check_id':'CKV_AWS_123', 'check_name':'S3 public access',
        'severity':'HIGH', 'resource':'aws_s3_bucket.example',
        'file_path':'/app/main.tf', 'code_block':'APIKEY=SHOULD-NOT-REACH-REPORT'}]}}
    items = parse_checkov(raw)
    assert items[0]['severity'] == 'HIGH'
    assert items[0]['rule_id'] == 'CKV_AWS_123'
    assert 'SHOULD-NOT' not in json.dumps(items)
    assert items[0]['validation_status']=='UNVALIDATED'


def test_gitleaks_parser_redacts_secret_data():
    data = [{'File':'src/secrets.py', 'RuleID':'generic-api-key', 'Secret':'DO-NOT-REPORT-THIS',
             'Match':'key=DO-NOT-REPORT-THIS', 'Line':9}]
    items = parse_gitleaks(data)
    assert 'DO-NOT-REPORT-THIS' not in json.dumps(items)
    assert 'src/secrets.py' in json.dumps(items)
    assert items[0]['severity']=='HIGH'


def test_checkov_integration_offline_redacts_evidence(tmp_path):
    (tmp_path/'local').mkdir()
    workspace = tmp_path/'workspace'; (workspace/'vulnerabilities').mkdir(parents=True)
    records=[]
    class DummyRunner:
        async def execute(self, program,args,**kw):
            assert '--skip-download' in args
            assert args[1] == str((tmp_path/'local').resolve())
            return SimpleNamespace(stdout=json.dumps({'results': {'failed_checks': [{
                'check_id':'CKV_X','check_name':'Fail','file_path':'main.tf',
                'code_block':'token=NEVER-PERSIST-ME'}]}}).encode(),
                exit_code=1, timed_out=False,output_truncated=False,dry_run=False)
    db=SimpleNamespace(add_evidence=lambda *args: records.append(args))
    context=SimpleNamespace(runner=DummyRunner(),config={},workspace=workspace,db=db,audit_id='SHA-TEST',dry_run=False)
    result=asyncio.run(CheckovLocalIntegration(tmp_path/'local').run(context))
    assert result.status=='SUCCESS' and len(result.findings)==1
    content=(workspace/'vulnerabilities/checkov-summary.json').read_text()
    assert 'NEVER-PERSIST-ME' not in content
    assert records


def test_gitleaks_integration_removes_raw_secret_file(tmp_path):
    (tmp_path/'local').mkdir()
    workspace = tmp_path/'workspace'
    (workspace/'vulnerabilities').mkdir(parents=True)
    (workspace/'scans').mkdir(parents=True)
    records=[]
    class DummyRunner:
        async def execute(self,program,args,**kw):
            assert '--redact=100' in args
            report=Path(args[args.index('--report-path')+1])
            report.write_text(json.dumps([{'File':'local/.env','RuleID':'generic-secret','Secret':'SECRET-DO-NOT-KEEP'}]))
            return SimpleNamespace(exit_code=1, timed_out=False,output_truncated=False,dry_run=False)
    ctx=SimpleNamespace(runner=DummyRunner(),config={},workspace=workspace,
                        db=SimpleNamespace(add_evidence=lambda *args: records.append(args)),audit_id='SHA-TEST',dry_run=False)
    result=asyncio.run(GitleaksLocalIntegration(tmp_path/'local').run(ctx))
    assert result.status=='SUCCESS'
    assert not (workspace/'scans/gitleaks-private-raw.json').exists()
    assert 'SECRET-DO-NOT-KEEP' not in (workspace/'vulnerabilities/gitleaks-summary.json').read_text()
    assert records


def test_nist_report_model_and_export_fidelity(tmp_path,monkeypatch):
    engine=AuditEngine(tmp_path/'home',{'rate_limit': {'max_parallel_modules':1}})
    audit, _, workspace, _=engine.create_audit('https://example.org')
    (workspace/'metadata/engagement.json').write_text(json.dumps({
        'client_organization':'Example Client Limited',
        'authorization_reference':'SIGNED-ROE-001',
        'assessment_window':'2026-11-01 through 2026-11-02',
        'assessment_lead':'Security Assessment Team',
        'unsupported_custom_field':'SHOULD_NOT_RENDER'}))
    engine.db.upsert_finding(audit,'F-0001',{
        'finding_id':'F-0001','title':'Missing secure header','asset':'example.org',
        'endpoint':'https://example.org','severity':'MEDIUM','confidence':0.7,
        'sources':['web_posture'],'cves':[],'cwes':[],
        'description':'Security response header not set','remediation':'Enable security headers.',
        'validation_status':'UNVALIDATED','exploitability':'UNKNOWN'})
    monkeypatch.setenv('SHAUDITER_PROJECT_REPORTS',str(tmp_path/'mirrors'))
    report=generate_summary(engine.db,audit,workspace)
    profile=report['nist_profile']
    assert report['version']=='1.1.7'
    assert 'not NIST certified' in profile['label']
    assert profile['client_organization']=='Example Client Limited'
    assert profile['engagement']['authorization_reference']=='SIGNED-ROE-001'
    assert 'unsupported_custom_field' not in json.dumps(profile)
    assert profile['risk_register'][0]['owner']=='Not assigned'
    assert profile['coverage_status']!='READY_FOR_HUMAN_REVIEW'
    html=(workspace/'reports/assessment.html').read_text()
    assert 'Risk Register and Remediation Plan' in html
    assert 'SIGNED-ROE-001' in html
    assert 'Assessment Methodology' in html
    assert 'This is not NIST accreditation or certification' in html
    assert 'POA&amp;M' in html
    assert (workspace/'reports/assessment.pdf').read_bytes().startswith(b'%PDF-')
    from docx import Document
    doc=Document(workspace/'reports/docx/technical-report.docx')
    alltext=' '.join(p.text for p in doc.paragraphs)
    assert 'NIST-Aligned Engagement Record' in alltext
    assert 'Risk Register and Plan of Action' in alltext


def test_engagement_gui_editor_persists_per_audit_and_rejects_unexpected_fields(tmp_path):
    from shauditer.gui.server import GUIApplication
    root = Path(__file__).resolve().parents[1]
    app = GUIApplication(tmp_path/'home', root/'config/default.json')
    a, _t1, wa, _p1 = app.engine.create_audit('https://example.com')
    b, _t2, wb, _p2 = app.engine.create_audit('https://test.example.com')
    clean=app.save_engagement_metadata(a, {
        'client_organization':'Customer One',
        'authorization_reference':'Signed ROE 2026',
        'assessment_window':'2026-11-01 UTC',
    })
    assert clean['client_organization']=='Customer One'
    assert app.audit_payload(a)['engagement_details']['authorization_reference']=='Signed ROE 2026'
    assert app.audit_payload(b)['engagement_details']=={}
    assert (wa/'metadata/engagement.json').exists()
    assert not (wb/'metadata/engagement.json').exists()
    try:
        app.save_engagement_metadata(a,{'customer_password':'not allowed'})
        assert False, 'unknown field allowed'
    except ValueError:
        pass
    try:
        app.save_engagement_metadata(a,{'client_organization':'X'*301})
        assert False, 'excessive field accepted'
    except ValueError:
        pass
    assert app.engagement_metadata(a)['client_organization']=='Customer One'


def test_engagement_editor_bound_to_report_and_safe_route():
    root=Path(__file__).resolve().parents[1]
    html=(root/'shauditer/gui/static/index.html').read_text()
    js=(root/'shauditer/gui/static/app.js').read_text()
    backend=(root/'shauditer/gui/server.py').read_text()
    assert 'id="engagementForm"' in html
    assert 'id="engAuthorization"' in html
    assert '/engagement`' in js
    assert 'save_engagement_metadata' in backend
    assert 'renderEngagementOnce' in js
