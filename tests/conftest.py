import pytest


@pytest.fixture(autouse=True)
def isolate_project_report_mirror(tmp_path, monkeypatch):
    monkeypatch.setenv("SHAUDITER_PROJECT_REPORTS", str(tmp_path / "project-reports"))
