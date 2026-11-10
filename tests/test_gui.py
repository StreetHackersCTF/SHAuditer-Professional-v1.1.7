from pathlib import Path

from shauditer.gui.server import GUIApplication, STATIC_DIR


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG = PROJECT_ROOT / "config" / "default.json"


def test_gui_shares_core_database_and_generates_report(tmp_path):
    app = GUIApplication(tmp_path / "home", CONFIG)
    audit_id, _target, workspace, _policy = app.engine.create_audit("127.0.0.1", profile="safe")
    payload = app.audit_payload(audit_id)
    assert payload["audit"]["audit_id"] == audit_id
    assert payload["findings"] == []
    assert payload["report_available"] is False

    result = app.generate_report(audit_id)
    assert result["docx"]["technical"].endswith("/technical-report.docx")
    assert (workspace / "reports" / "docx" / "executive-report.docx").is_file()
    assert (workspace / "reports" / "docx" / "technical-report.docx").is_file()
    assert (workspace / "reports" / "docx" / "complete-assessment.docx").is_file()
    assert app.audit_payload(audit_id)["report_available"] is True


def test_gui_static_bundle_is_local_only():
    index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    css = (STATIC_DIR / "styles.css").read_text(encoding="utf-8")
    assert "__SHAUDITER_TOKEN__" in index
    assert 'src="http' not in index and 'href="http' not in index
    assert "X-SHAuditer-Token" in js
    assert "--accent" in css


def test_gui_has_detailed_recon_mitigation_and_docx_views():
    index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert 'data-view="mitigation"' in index
    assert 'id="technologyList"' in index
    assert 'id="moduleRunList"' in index
    assert 'id="mitigationTable"' in index
    assert 'id="completeReportBtn"' in index
    assert "renderMitigation" in js
    assert "renderSeverityBars" in js


def test_gui_brand_assets_and_delete_controls_exist():
    index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert (STATIC_DIR / "assets" / "street_hackers_logo.png").is_file()
    assert (STATIC_DIR / "assets" / "street_hackers_scene.png").is_file()
    assert "street_hackers_logo.png" in index
    assert "street_hackers_scene.png" in index
    assert 'id="deleteAuditDialog"' in index
    assert 'id="deleteAuditBtn"' in index
    assert "/delete`" in js or "/delete'" in js or "/delete\"" in js
    assert "openDeleteAudit" in js


def test_gui_delete_audit_removes_workspace_mirror_and_database(tmp_path):
    app = GUIApplication(tmp_path / "home", CONFIG)
    audit_id, _target, workspace, _policy = app.engine.create_audit("127.0.0.1", profile="safe")
    app.generate_report(audit_id)
    mirror = app.project_reports_root / audit_id
    assert workspace.is_dir()
    assert mirror.is_dir()
    assert app.engine.db.get_audit(audit_id) is not None

    result = app.delete_audit(audit_id, audit_id)
    assert result["deleted"] is True
    assert app.engine.db.get_audit(audit_id) is None
    assert not workspace.exists()
    assert not mirror.exists()


def test_gui_delete_audit_requires_exact_confirmation(tmp_path):
    app = GUIApplication(tmp_path / "home", CONFIG)
    audit_id, _target, workspace, _policy = app.engine.create_audit("127.0.0.1", profile="safe")
    try:
        app.delete_audit(audit_id, "DELETE")
    except PermissionError:
        pass
    else:
        raise AssertionError("delete_audit accepted an invalid confirmation")
    assert app.engine.db.get_audit(audit_id) is not None
    assert workspace.exists()
