from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from shauditer.integrations.nmap import NmapIntegration
from shauditer.models.target import normalize_target
from shauditer.reporting.quality import evaluate_assessment, verify_evidence_records
from shauditer.scope.models import ScopePolicy
from shauditer.scope.policy_io import scope_from_dict
from shauditer.scope.validator import ScopeValidator
from shauditer.security.evidence import sha256_file
from shauditer.security.runner import ProcessResult, SafeProcessRunner
from shauditer.gui.server import RequestHandler


def test_cidr_must_fit_completely_inside_positive_scope():
    validator = ScopeValidator(ScopePolicy(in_scope=["10.10.0.0/24"]))
    assert validator.authorize(normalize_target("10.10.0.0/24")).allowed
    assert not validator.authorize(normalize_target("10.10.0.0/16")).allowed
    assert not validator.authorize("10.10.1.0/24").allowed


def test_excluded_host_blocks_entire_network_request():
    policy = ScopePolicy(in_scope=["10.10.0.0/24"], out_of_scope=["10.10.0.5"])
    assert not ScopeValidator(policy).authorize(normalize_target("10.10.0.0/24")).allowed
    assert ScopeValidator(policy).authorize("10.10.0.6").allowed


def test_scope_wildcard_requires_subdomain_boundary():
    v = ScopeValidator(ScopePolicy(in_scope=["*.example.com"]))
    assert v.authorize("www.example.com").allowed
    assert v.authorize("api.v1.example.com").allowed
    assert not v.authorize("example.com").allowed
    assert not v.authorize("evil-example.com").allowed


def test_scope_file_validation_rejects_global_wildcard_and_ports():
    with pytest.raises(ValueError):
        scope_from_dict({"in_scope": ["*"]})
    with pytest.raises(ValueError):
        scope_from_dict({"in_scope": ["example.com"], "allowed_ports": [70000]})
    with pytest.raises(ValueError):
        scope_from_dict({"in_scope": []})


def test_scope_file_includes_target_and_allows_explicit_exclusions():
    target = normalize_target("lab.example.com")
    policy = scope_from_dict({"in_scope": ["*.example.com"], "out_of_scope": ["admin.example.com"]}, default_target=target)
    v = ScopeValidator(policy)
    assert v.authorize(target).allowed
    assert v.authorize("dev.example.com").allowed
    assert not v.authorize("admin.example.com").allowed


def test_target_url_rejects_embedded_credentials_and_fragments():
    with pytest.raises(ValueError):
        normalize_target("https://admin:secret@example.com/")
    with pytest.raises(ValueError):
        normalize_target("https://example.com/#secret")


def test_quality_gate_does_not_treat_failed_scans_as_clean():
    q = evaluate_assessment({"module_runs": [{"module": "nmap", "status": "FAILED"}],
                             "findings": [], "evidence": []})
    assert q["status"] == "INSUFFICIENT_COVERAGE"
    assert any("does not establish a clean target" in x or "not established" in x for x in q["limitations"])


def test_quality_gate_flags_missing_scanner_and_validation():
    q = evaluate_assessment({"module_runs": [{"module": "nmap", "status": "SUCCESS"},
                                            {"module": "httpx", "status": "SUCCESS"}],
                             "findings": [{"validation_status": "UNVALIDATED"}], "evidence": []})
    assert q["status"] == "REVIEW_REQUIRED"
    assert q["unvalidated_findings"] == 1


def test_evidence_integrity_detects_tampering(tmp_path):
    artifact = tmp_path / "proof.txt"
    artifact.write_text("good proof", encoding="utf-8")
    record = {"evidence_id": "EV-1", "path": str(artifact), "sha256": sha256_file(artifact)}
    assert verify_evidence_records([record])["verified"] == 1
    artifact.write_text("modified proof", encoding="utf-8")
    assert verify_evidence_records([record])["records"][0]["status"] == "MISMATCH"


class FakeDryRunner:
    async def execute(self, program, args, **kwargs):
        return ProcessResult(program, args, 0, b"", b"", "start", "end", dry_run=True)


def test_nmap_applies_positive_port_restrictions(tmp_path):
    policy = ScopePolicy(in_scope=["10.10.10.2"], allowed_ports={80, 443}, excluded_ports={80})
    ctx = SimpleNamespace(target=normalize_target("10.10.10.2"), scope=ScopeValidator(policy),
                          config={"recon": {}}, runner=FakeDryRunner(), workspace=tmp_path, dry_run=True)
    result = asyncio.run(NmapIntegration().run(ctx))
    assert result.status == "DRY_RUN"
    assert "-p 443" in result.metadata["command"]
    assert "--top-ports" not in result.metadata["command"]


def test_nmap_blocks_oversized_network_before_execution(tmp_path):
    target = normalize_target("10.10.0.0/16")
    ctx = SimpleNamespace(target=target, scope=ScopeValidator(ScopePolicy(in_scope=["10.10.0.0/16"])),
                          config={"recon": {"max_cidr_addresses": 256}},
                          runner=FakeDryRunner(), workspace=tmp_path, dry_run=True)
    result = asyncio.run(NmapIntegration().run(ctx))
    assert result.status == "BLOCKED"
    assert "65536" in result.metadata["reason"]


def test_process_runner_output_bounding():
    result = asyncio.run(SafeProcessRunner().execute(
        sys.executable, ["-c", "print('X' * 50000)"], max_output_bytes=1024, timeout=5
    ))
    assert result.output_truncated is True
    assert result.exit_code != 0


def test_process_runner_timeout():
    result = asyncio.run(SafeProcessRunner().execute(
        sys.executable, ["-c", "import time;time.sleep(1)"], timeout=0.1
    ))
    assert result.timed_out is True


def test_dashboard_rejects_dns_rebinding_host():
    handler = RequestHandler.__new__(RequestHandler)
    handler.server = SimpleNamespace(server_port=8765)
    handler.headers = {"Host": "outside.example.com:8765"}
    assert not handler._trusted_host()
    handler.headers = {"Host": "127.0.0.1:8765"}
    assert handler._trusted_host()
    handler.headers = {"Host": "localhost:4444"}
    assert not handler._trusted_host()


def test_csv_cells_are_not_interpreted_as_formulas():
    from shauditer.reporting.summary import _csv_safe
    assert _csv_safe('=HYPERLINK("http://example.org")').startswith("'=")
    assert _csv_safe(' @malicious') == "' @malicious"
    assert _csv_safe('normal') == 'normal'
    assert _csv_safe(42) == 42


def test_quality_gate_decodes_sqlite_module_metadata():
    q = evaluate_assessment({"module_runs": [{"module": "nmap", "status": "SUCCESS", "metadata_json": '{"parse_errors": 3}'}], "findings": [], "evidence": []})
    assert any("incomplete" in note for note in q["limitations"])
