from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from shauditer.cli.ui import print_banner
from shauditer.core.engine import AuditEngine
from shauditer.models.target import Target, TargetType
from shauditer.intelligence.exploit_intelligence import ExploitIntelligenceManager
from shauditer.reporting.summary import generate_summary
from shauditer.reporting.quality import evaluate_assessment, verify_evidence_records
from shauditer.scope.models import ScopePolicy
from shauditer.scope.policy_io import load_scope_file
from shauditer.validation import ValidationManager
from shauditer.poc.runner import PoCManager


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = (PROJECT_ROOT / "config" / "default.json")
if not DEFAULT_CONFIG.exists():
    DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "default.json"
DEFAULT_HOME = Path(os.environ.get("SHAUDITER_HOME", "~/.local/share/SHAuditer")).expanduser()


def load_config(path: Path = DEFAULT_CONFIG):
    return json.loads(path.read_text(encoding="utf-8"))


def authorization_prompt(target: str) -> bool:
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║                    AUTHORIZATION                         ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║ Target: {target[:47]:<47}║")
    print("║ Mode: Authorized Security Assessment                     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("Only continue if you are authorized to test this target.")
    return input("Continue? [y/N] ").strip().lower() in {"y", "yes"}


def build_engine(args):
    return AuditEngine(args.home, load_config(Path(args.config)))


def _audit_or_exit(engine, audit_id: str):
    row = engine.db.get_audit(audit_id)
    if not row:
        raise SystemExit(f"unknown audit ID: {audit_id}")
    return row


def _validation_manager(engine, row) -> ValidationManager:
    return ValidationManager(engine.db, Path(row["workspace"]))


def _intelligence_manager(engine, row) -> ExploitIntelligenceManager:
    return ExploitIntelligenceManager(engine.db, Path(row["workspace"]), engine.config)


def cmd_audit(args):
    if not args.authorized and not sys.stdin.isatty():
        raise SystemExit("non-interactive audits require --authorized to acknowledge assessment authorization")
    if not args.authorized and not authorization_prompt(args.target):
        raise SystemExit("authorization not confirmed; audit cancelled")

    engine = build_engine(args)
    scope_policy = load_scope_file(args.scope_file) if getattr(args, "scope_file", None) else None
    audit_id, target, workspace, policy = engine.create_audit(args.target, profile=args.profile, scope_policy=scope_policy)
    print(f"[+] Audit ID: {audit_id}")
    print(f"[+] Target: {target.original}")
    print(f"[+] Workspace: {workspace}")

    normalized, findings = asyncio.run(
        engine.run_assessment(
            audit_id,
            target,
            workspace,
            policy,
            profile=args.profile,
            dry_run=args.dry_run,
            artifacts_dir=getattr(args, "artifacts", None),
        )
    )

    print("[+] Reconnaissance complete")
    print(f"    Assets: {len(normalized['assets'])}")
    print(f"    Services: {len(normalized['services'])}")
    print(f"    Technologies: {len(normalized['technologies'])}")
    for module in normalized["modules"]:
        print(f"    {module['name']}: {module['status']}")

    print(f"[+] Prioritized findings: {len(findings)}")
    if findings:
        top = findings[0]
        print(f"    Top: {top['finding_id']} {top['severity']} priority={top['priority_score']} {top['title']}")
        print("    Validation: UNVALIDATED — scanner detection is not treated as successful exploitation")

    report = generate_summary(engine.db, audit_id, workspace)
    engine._set_state(
        audit_id,
        workspace,
        __import__("shauditer.core.state", fromlist=["AuditState"]).AuditState.COMPLETE,
    )
    # Regenerate once more so the report reflects the final COMPLETE state.
    report = generate_summary(engine.db, audit_id, workspace)
    print(f"[+] Executive DOCX: {workspace / 'reports' / 'docx' / 'executive-report.docx'}")
    print(f"[+] Technical DOCX: {workspace / 'reports' / 'docx' / 'technical-report.docx'}")
    print(f"[+] Complete DOCX:  {workspace / 'reports' / 'docx' / 'complete-assessment.docx'}")
    print(f"[+] PDF Report:    {workspace / 'reports' / 'assessment.pdf'}")
    print(f"[+] HTML Report:   {workspace / 'reports' / 'assessment.html'}")
    print(f"[+] Mirrored reports: {Path(os.environ.get('SHAUDITER_PROJECT_REPORTS', str(PROJECT_ROOT / 'reports' if (PROJECT_ROOT / 'config' / 'default.json').exists() else engine.home / 'reports'))) / audit_id}")
    if findings:
        print(f"[+] Review top finding: ./SHAuditer finding {audit_id} {findings[0]['finding_id']}")
        if findings[0].get("cves"):
            print(f"[+] Exploit intelligence: ./SHAuditer intel {audit_id} {findings[0]['finding_id']}")
    if args.json:
        print(json.dumps(report, indent=2))


def _target_from_audit(row):
    obj = json.loads(row["target_json"])
    return Target(
        original=obj["original"],
        type=TargetType(obj["type"]),
        hostname=obj["hostname"],
        scheme=obj.get("scheme"),
        port=obj.get("port"),
        path=obj.get("path"),
        network=obj.get("network"),
    )


def _policy_from_workspace(workspace: Path):
    obj = json.loads((workspace / "metadata" / "scope.json").read_text(encoding="utf-8"))
    return ScopePolicy(
        in_scope=obj.get("in_scope", []),
        out_of_scope=obj.get("out_of_scope", []),
        allowed_ports=set(obj.get("allowed_ports", [])),
        excluded_ports=set(obj.get("excluded_ports", [])),
        allowed_domains=obj.get("allowed_domains", []),
        excluded_domains=obj.get("excluded_domains", []),
        mode=obj.get("mode", "authorized-security-assessment"),
    )


def cmd_resume(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    workspace = Path(row["workspace"])
    target = _target_from_audit(row)
    policy = _policy_from_workspace(workspace)

    if row["state"] in {"RECON_COMPLETE", "FINDINGS_PRIORITIZED", "COMPLETE"} and not args.rerun_recon:
        print(f"[+] {args.audit_id} already completed reconnaissance; use --rerun-recon to run it again")
        generate_summary(engine.db, args.audit_id, workspace)
        return

    if not args.authorized and not authorization_prompt(row["target"]):
        raise SystemExit("authorization not confirmed; resume cancelled")

    asyncio.run(
        engine.run_assessment(
            args.audit_id,
            target,
            workspace,
            policy,
            profile=row["profile"],
            dry_run=args.dry_run,
        )
    )
    engine._set_state(
        args.audit_id,
        workspace,
        __import__("shauditer.core.state", fromlist=["AuditState"]).AuditState.COMPLETE,
    )
    generate_summary(engine.db, args.audit_id, workspace)
    print(f"[+] Resumed: {args.audit_id}")


def cmd_status(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    print(json.dumps({
        "audit_id": row["audit_id"],
        "target": row["target"],
        "state": row["state"],
        "profile": row["profile"],
        "workspace": row["workspace"],
        "module_runs": engine.db.get_module_runs(args.audit_id),
        "validations": engine.db.get_validations(args.audit_id),
        "sessions": engine.db.get_sessions(args.audit_id),
        "exploit_intelligence": engine.db.get_all_exploit_intelligence(args.audit_id),
        "exploit_reviews": engine.db.get_exploit_reviews(args.audit_id),
        "poc_executions": engine.db.get_poc_executions(args.audit_id),
    }, indent=2))


def cmd_report(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    workspace = Path(row["workspace"])
    report = generate_summary(engine.db, args.audit_id, workspace)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(workspace / "reports" / "docx" / "executive-report.docx")
        print(workspace / "reports" / "docx" / "technical-report.docx")
        print(workspace / "reports" / "docx" / "complete-assessment.docx")
        print(workspace / "reports" / "assessment.pdf")
        print(workspace / "reports" / "assessment.html")


def cmd_quality(args):
    """Explain missing scanner coverage and integrity issues without rescanning."""
    engine = build_engine(args)
    _audit_or_exit(engine, args.audit_id)
    report_stub = {
        "module_runs": engine.db.get_module_runs(args.audit_id),
        "findings": engine.db.get_findings(args.audit_id),
        "validations": engine.db.get_validations(args.audit_id),
        "evidence": engine.db.get_evidence(args.audit_id),
    }
    result = evaluate_assessment(report_stub)
    print(json.dumps(result, indent=2))
    if args.strict and result["status"] != "READY_FOR_HUMAN_REVIEW":
        raise SystemExit(2)


def cmd_verify_evidence(args):
    engine = build_engine(args)
    _audit_or_exit(engine, args.audit_id)
    result = verify_evidence_records(engine.db.get_evidence(args.audit_id))
    print(json.dumps(result, indent=2))
    if args.strict and result["issues"]:
        raise SystemExit(2)


def cmd_finding(args):
    engine = build_engine(args)
    _audit_or_exit(engine, args.audit_id)
    finding = engine.db.get_finding(args.audit_id, args.finding_id)
    if not finding:
        raise SystemExit(f"unknown finding: {args.finding_id}")
    out = {
        "finding": finding,
        "approvals": engine.db.get_approvals(args.audit_id, args.finding_id),
        "validations": engine.db.get_validations(args.audit_id, args.finding_id),
        "sessions": [s for s in engine.db.get_sessions(args.audit_id) if s.get("finding_id") == args.finding_id],
        "exploit_intelligence": engine.db.get_exploit_intelligence(args.audit_id, args.finding_id),
        "exploit_reviews": engine.db.get_exploit_reviews(args.audit_id, args.finding_id),
    }
    print(json.dumps(out, indent=2))


def cmd_approve(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = _validation_manager(engine, row)
    approval_id = manager.approve_validation(
        args.audit_id,
        args.finding_id,
        args.operator,
        note=args.note,
    )
    generate_summary(engine.db, args.audit_id, Path(row["workspace"]))
    print(f"[+] Operator approval recorded: {approval_id}")
    print("    Approval permits recording an authorized validation result; it does not automatically execute an exploit.")


def cmd_poc_approve(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = PoCManager(engine.db, Path(row["workspace"]))
    approval_id = manager.approve(args.audit_id, args.finding_id, operator=args.operator,
                                  note=args.note, acknowledgement=args.acknowledge)
    print(f"[+] One-time PoC approval: {approval_id}")
    print("    Bound to this finding and operator; expires in 1 hour. Reuse is refused.")


def cmd_poc_run(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    workspace = Path(row["workspace"])
    manager = PoCManager(engine.db, workspace, timeout=float(engine.config.get("timeouts", {}).get("web_posture", 6)))
    result = manager.execute(args.audit_id, args.finding_id, approval_id=args.approval,
                             operator=args.operator)
    generate_summary(engine.db, args.audit_id, workspace)
    print(json.dumps(result, indent=2))


def cmd_poc_history(args):
    engine = build_engine(args)
    _audit_or_exit(engine, args.audit_id)
    print(json.dumps(engine.db.get_poc_executions(args.audit_id), indent=2))


def cmd_evidence(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = _validation_manager(engine, row)
    evidence_id = manager.import_evidence(
        args.audit_id,
        args.file,
        args.operator,
        kind=args.kind,
        note=args.note,
    )
    generate_summary(engine.db, args.audit_id, Path(row["workspace"]))
    print(f"[+] Evidence imported: {evidence_id}")


def cmd_validate(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = _validation_manager(engine, row)
    validation_id = manager.record_validation(
        args.audit_id,
        args.finding_id,
        args.status,
        args.method,
        args.operator,
        note=args.note,
        evidence_id=args.evidence,
    )
    generate_summary(engine.db, args.audit_id, Path(row["workspace"]))
    print(f"[+] Validation recorded: {validation_id}")
    print(f"    {args.finding_id}: {args.status.upper()}")


def cmd_session(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = _validation_manager(engine, row)
    session_id = manager.record_session(
        args.audit_id,
        args.finding_id,
        args.type,
        args.privilege,
        args.operator,
        evidence_id=args.evidence,
        note=args.note,
    )
    generate_summary(engine.db, args.audit_id, Path(row["workspace"]))
    print(f"[+] Evidence-backed access session recorded: {session_id}")
    print("    This command records an already established authorized session; it does not create a shell or payload.")


def cmd_sessions(args):
    engine = build_engine(args)
    _audit_or_exit(engine, args.audit_id)
    print(json.dumps(engine.db.get_sessions(args.audit_id), indent=2))


def cmd_intel(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = _intelligence_manager(engine, row)
    record = asyncio.run(
        manager.analyze(
            args.audit_id,
            args.finding_id,
            offline=args.offline,
            metasploit=not args.no_metasploit,
            api_key=args.nvd_api_key,
        )
    )
    generate_summary(engine.db, args.audit_id, Path(row["workspace"]))
    if args.json:
        print(json.dumps(record, indent=2))
        return
    applicability = record["applicability"]
    print(f"[+] Exploit intelligence: {record['intelligence_id']}")
    print(f"    Finding: {args.finding_id}")
    print(f"    CVEs: {', '.join(record['cves']) if record['cves'] else 'none'}")
    print(f"    Applicability: {applicability['status']} ({int(applicability['confidence'] * 100)}% confidence)")
    print(f"    Local Metasploit candidates: {record['module_count']}")
    for cve, modules in record["metasploit_modules"].items():
        for module in modules:
            check = "check" if module.get("check_supported") else "no-check/unknown"
            print(f"      {cve}: {module['module']}  rank={module.get('rank') or 'unknown'}  {check}")
    print("    Policy: intelligence only — no module or payload was executed")
    print(f"[+] DOCX reports regenerated: {Path(row['workspace']) / 'reports' / 'docx'}")


def cmd_exploit_review(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = _intelligence_manager(engine, row)
    review_id = manager.record_review(
        args.audit_id,
        args.finding_id,
        args.operator,
        args.decision,
        module=args.module,
        note=args.note,
    )
    generate_summary(engine.db, args.audit_id, Path(row["workspace"]))
    print(f"[+] Exploit research review recorded: {review_id}")
    print(f"    Decision: {args.decision}")
    print("    This review does not authorize or execute exploitation, payload generation, or shell creation.")


def cmd_intel_all(args):
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    manager = _intelligence_manager(engine, row)
    findings = [f for f in engine.db.get_findings(args.audit_id) if f.get("cves")]
    findings.sort(key=lambda f: float(f.get("priority_score", 0)), reverse=True)
    selected = findings[: max(0, args.top)]
    results = []
    failures = []
    for finding in selected:
        finding_id = finding["finding_id"]
        try:
            record = asyncio.run(
                manager.analyze(
                    args.audit_id,
                    finding_id,
                    offline=args.offline,
                    metasploit=not args.no_metasploit,
                    api_key=args.nvd_api_key,
                )
            )
            results.append(record)
            app = record.get("applicability") or {}
            print(
                f"[+] {finding_id}: {app.get('status', 'UNKNOWN')} "
                f"({int(float(app.get('confidence', 0)) * 100)}%) — "
                f"Metasploit candidates={record.get('module_count', 0)}"
            )
        except Exception as exc:
            failures.append({"finding_id": finding_id, "error": f"{type(exc).__name__}: {exc}"})
            print(f"[!] {finding_id}: intelligence failed: {type(exc).__name__}: {exc}")
    report = generate_summary(engine.db, args.audit_id, Path(row["workspace"]))
    payload = {"analyzed": len(results), "failed": failures, "results": results}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"[+] Intelligence complete: {len(results)}/{len(selected)} findings analyzed")
        print(f"[+] DOCX reports: {Path(row['workspace']) / 'reports' / 'docx'}")


def cmd_list(args):
    engine = build_engine(args)
    for row in engine.db.list_audits():
        print(f"{row['audit_id']}  {row['state']:<18}  {row['target']}")



def cmd_gui(args):
    from shauditer.gui.server import serve
    serve(Path(args.home), Path(args.config), host=args.host, port=args.port, no_browser=args.no_browser)

def cmd_doctor(args):
    print("SHAuditer system diagnostics")
    print(f"Python: {sys.version.split()[0]}")
    for tool in ("nmap", "httpx", "subfinder", "nuclei", "trivy", "semgrep", "searchsploit", "msfconsole"):
        path = shutil.which(tool)
        if not path:
            print(f"{tool:<12} NOT INSTALLED (optional)")
            continue
        if tool == "httpx":
            try:
                proc = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=3, check=False)
                output = (proc.stdout + "\n" + proc.stderr).lower()
                if proc.returncode != 0 or "no such option" in output or "usage: httpx [options] url" in output:
                    print(f"{tool:<12} WRONG BINARY {path} (install ProjectDiscovery httpx)")
                    continue
            except (OSError, subprocess.TimeoutExpired):
                print(f"{tool:<12} UNUSABLE {path}")
                continue
        print(f"{tool:<12} OK {path}")
    print(f"Data home: {Path(args.home).expanduser().resolve()}")
    print("Validation subsystem: operator approval + evidence-backed result/session recording")
    print("Exploit intelligence: NVD + CISA KEV + FIRST EPSS + local SearchSploit/Metasploit metadata")
    print("Full catalog: ./SHAuditer tools --instructions")
    print("Secure report email: configure SHAUDITER_SMTP_* and run ./SHAuditer mail --help")


def interactive(args):
    print_banner()
    while True:
        print(
            "[1] Start New Audit\n"
            "[2] Resume Audit\n"
            "[3] View Previous Audits\n"
            "[4] Configuration\n"
            "[5] Plugin Manager\n"
            "[6] System Diagnostics\n"
            "[7] Graphical Dashboard\n"
            "[8] Exit"
        )
        choice = input("Selection > ").strip()
        if choice == "1":
            target = input("Target > ").strip()
            ns = argparse.Namespace(**vars(args))
            ns.target = target
            ns.profile = "safe"
            ns.authorized = False
            ns.dry_run = False
            ns.json = False
            cmd_audit(ns)
        elif choice == "2":
            aid = input("Audit ID > ").strip()
            ns = argparse.Namespace(**vars(args))
            ns.audit_id = aid
            ns.authorized = False
            ns.dry_run = False
            ns.rerun_recon = False
            cmd_resume(ns)
        elif choice == "3":
            cmd_list(args)
        elif choice == "4":
            print(DEFAULT_CONFIG.read_text(encoding="utf-8"))
        elif choice == "5":
            print("Plugin API is scaffolded; dynamic plugin installation lands in a later milestone.")
        elif choice == "6":
            cmd_doctor(args)
        elif choice == "7":
            ns = argparse.Namespace(**vars(args))
            ns.host = "127.0.0.1"
            ns.port = 8765
            ns.no_browser = False
            cmd_gui(ns)
        elif choice == "8":
            return
        else:
            print("Invalid selection")


def cmd_tools(args):
    from shauditer.tools.catalog import inventory
    items = inventory()
    if args.json:
        print(json.dumps(items, indent=2))
        return
    for item in items:
        print(f"[{item['status']:<9}] {item['name']:<25} {item['category']:<20} {item['integration']}")
        if args.instructions:
            print(f"  Upstream: {item['repo']}\n  Linux: {item['linux']}\n  macOS: {item['macos']}\n  Windows: {item['windows']}")
    print("Catalog-only tools are not invoked by the audit engine. Install only reviewed software from verified upstreams.")


def cmd_mail(args):
    from shauditer.reporting.mail import (mail_report, compose_client_email, validate_recipient,
        sender_address, assessment_snapshot_from_records)
    from shauditer.reporting.quality import evaluate_assessment
    engine = build_engine(args)
    row = _audit_or_exit(engine, args.audit_id)
    recipient = validate_recipient(args.to)
    custom_body = Path(args.body_file).read_text(encoding="utf-8") if args.body_file else None
    findings = engine.db.get_findings(args.audit_id)
    quality = evaluate_assessment({"module_runs": engine.db.get_module_runs(args.audit_id),
                                   "findings": findings, "validations": engine.db.get_validations(args.audit_id),
                                   "evidence": engine.db.get_evidence(args.audit_id)}, verify_hashes=False)
    snapshot = assessment_snapshot_from_records(findings, quality)
    kwargs = {"template_name": args.template, "client_name": args.client_name or "",
              "client_organization": args.client_organization or "",
              "subject": args.subject, "body": custom_body}
    if args.preview:
        preview = compose_client_email(args.audit_id, target=row["target"], format_name=args.format,
                                       sender_email=sender_address(), assessment_snapshot=snapshot, **kwargs)
        print(json.dumps({"to": recipient, "from": sender_address(), **preview}, indent=2))
        print("[i] Preview only: no email was sent.")
        return
    result = mail_report(Path(row['workspace']), args.audit_id, recipient, args.format,
                         consent=args.confirm_send, target=row["target"],
                         assessment_snapshot=snapshot, **kwargs)
    print(f"[+] Confidential {result['report']} accepted by SMTP for {result['recipient']} at {result['sent_at']}")


def parser():
    p = argparse.ArgumentParser(prog="SHAuditer", description="Smart Hybrid Automated Security Auditor")
    p.add_argument("--home", default=str(DEFAULT_HOME), help="SHAuditer data directory")
    p.add_argument("--config", default=str(DEFAULT_CONFIG), help="configuration JSON")

    # Compatibility with the original product-spec flag style.
    p.add_argument("--target", dest="legacy_target")
    p.add_argument("--profile", dest="legacy_profile", choices=["safe", "standard"])
    p.add_argument("--authorized", dest="legacy_authorized", action="store_true")
    p.add_argument("--dry-run", dest="legacy_dry_run", action="store_true")
    p.add_argument("--json", dest="legacy_json", action="store_true")
    p.add_argument("--resume", dest="legacy_resume")
    p.add_argument("--report", dest="legacy_report")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="start a new authorized assessment")
    a.add_argument("target")
    a.add_argument("--profile", default="safe", choices=["safe", "standard"])
    a.add_argument("--authorized", action="store_true", help="acknowledge you are authorized to assess the target")
    a.add_argument("--dry-run", action="store_true")
    a.add_argument("--scope-file", help="JSON file defining authorized in/out-of-scope hosts and ports")
    a.add_argument("--artifacts", help="optional local directory of cloud IaC, Docker/K8s and AI configuration files to review offline")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_audit)

    r = sub.add_parser("resume", help="resume an audit")
    r.add_argument("audit_id")
    r.add_argument("--authorized", action="store_true")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--rerun-recon", action="store_true")
    r.set_defaults(func=cmd_resume)

    s = sub.add_parser("status", help="show audit status")
    s.add_argument("audit_id")
    s.set_defaults(func=cmd_status)

    rep = sub.add_parser("report", help="regenerate PDF, HTML, DOCX and JSON/CSV reports")
    rep.add_argument("audit_id")
    rep.add_argument("--json", action="store_true")
    rep.set_defaults(func=cmd_report)

    qual = sub.add_parser("quality", help="check scanner coverage, findings assurance and evidence integrity")
    qual.add_argument("audit_id")
    qual.add_argument("--strict", action="store_true", help="exit 2 unless automated quality checks pass")
    qual.set_defaults(func=cmd_quality)

    evcheck = sub.add_parser("verify-evidence", help="verify all saved evidence SHA-256 hashes")
    evcheck.add_argument("audit_id")
    evcheck.add_argument("--strict", action="store_true", help="exit 2 if an evidence artifact has an issue")
    evcheck.set_defaults(func=cmd_verify_evidence)

    f = sub.add_parser("finding", help="review a finding and its validation/session history")
    f.add_argument("audit_id")
    f.add_argument("finding_id")
    f.set_defaults(func=cmd_finding)

    intel = sub.add_parser("intel", help="analyze CVE applicability and discover local Metasploit module candidates (read-only)")
    intel.add_argument("audit_id")
    intel.add_argument("finding_id")
    intel.add_argument("--offline", action="store_true", help="do not query NVD; use local finding data only")
    intel.add_argument("--no-metasploit", action="store_true", help="skip local Metasploit module discovery")
    intel.add_argument("--nvd-api-key", default=None, help="optional NVD API key; not stored by SHAuditer")
    intel.add_argument("--json", action="store_true")
    intel.set_defaults(func=cmd_intel)

    ia = sub.add_parser("intel-all", help="analyze exploit intelligence for the highest-priority CVE findings")
    ia.add_argument("audit_id")
    ia.add_argument("--top", type=int, default=5, help="maximum CVE findings to analyze (default: 5)")
    ia.add_argument("--offline", action="store_true")
    ia.add_argument("--no-metasploit", action="store_true")
    ia.add_argument("--nvd-api-key", default=None, help="optional NVD API key; not stored by SHAuditer")
    ia.add_argument("--json", action="store_true")
    ia.set_defaults(func=cmd_intel_all)

    er = sub.add_parser("exploit-review", help="record an operator review of exploit intelligence; does not execute a module")
    er.add_argument("audit_id")
    er.add_argument("finding_id")
    er.add_argument("--operator", required=True)
    er.add_argument("--decision", required=True, choices=["APPROVE_RESEARCH", "DEFER", "REJECT"])
    er.add_argument("--module", default=None, help="optional candidate module path from the latest intelligence record")
    er.add_argument("--note", default="")
    er.set_defaults(func=cmd_exploit_review)

    ap = sub.add_parser("approve", help="record operator approval for safe validation")
    ap.add_argument("audit_id")
    ap.add_argument("finding_id")
    ap.add_argument("--operator", required=True)
    ap.add_argument("--note", default="")
    ap.set_defaults(func=cmd_approve)

    pa = sub.add_parser("poc-approve", help="approve one supported, non-destructive proof-of-control request")
    pa.add_argument("audit_id")
    pa.add_argument("finding_id")
    pa.add_argument("--operator", required=True)
    pa.add_argument("--note", default="")
    pa.add_argument("--acknowledge", action="store_true", help="explicitly approve exactly one active HTTP request")
    pa.set_defaults(func=cmd_poc_approve)

    pr = sub.add_parser("poc-run", help="consume a single-use approval and recheck the selected control")
    pr.add_argument("audit_id")
    pr.add_argument("finding_id")
    pr.add_argument("--approval", required=True)
    pr.add_argument("--operator", required=True)
    pr.set_defaults(func=cmd_poc_run)

    ph = sub.add_parser("poc-history", help="show the immutable single-use proof execution ledger")
    ph.add_argument("audit_id")
    ph.set_defaults(func=cmd_poc_history)

    ev = sub.add_parser("evidence", help="import an operator-provided evidence file into the audit workspace")
    ev.add_argument("audit_id")
    ev.add_argument("file")
    ev.add_argument("--operator", required=True)
    ev.add_argument("--kind", default="MANUAL_VALIDATION")
    ev.add_argument("--note", default="")
    ev.set_defaults(func=cmd_evidence)

    val = sub.add_parser("validate", help="record an authorized validation result")
    val.add_argument("audit_id")
    val.add_argument("finding_id")
    val.add_argument("--status", required=True, choices=["VALIDATED", "NOT_VALIDATED", "INCONCLUSIVE"])
    val.add_argument("--method", required=True, help="human-readable validation method")
    val.add_argument("--operator", required=True)
    val.add_argument("--evidence", default=None, help="optional evidence ID")
    val.add_argument("--note", default="")
    val.set_defaults(func=cmd_validate)

    ses = sub.add_parser(
        "session",
        help="record an already-established authorized access session; this command does not create a shell",
    )
    ses.add_argument("audit_id")
    ses.add_argument("finding_id")
    ses.add_argument("--type", required=True, choices=["APPLICATION_ACCESS", "REMOTE_SHELL", "LOCAL_SHELL", "OTHER"])
    ses.add_argument("--privilege", required=True, choices=["NONE", "APPLICATION", "USER", "ADMINISTRATOR", "ROOT", "SYSTEM", "OTHER"])
    ses.add_argument("--operator", required=True)
    ses.add_argument("--evidence", required=True)
    ses.add_argument("--note", default="")
    ses.set_defaults(func=cmd_session)

    sl = sub.add_parser("sessions", help="list recorded access sessions for an audit")
    sl.add_argument("audit_id")
    sl.set_defaults(func=cmd_sessions)

    l = sub.add_parser("list", help="list previous audits")
    l.set_defaults(func=cmd_list)

    tools = sub.add_parser("tools", help="cross-platform catalog of official security tooling")
    tools.add_argument("--json", action="store_true")
    tools.add_argument("--instructions", action="store_true", help="show official project links and reviewable installation commands")
    tools.set_defaults(func=cmd_tools)

    mail = sub.add_parser("mail", help="email a generated report via configured TLS SMTP")
    mail.add_argument("audit_id")
    mail.add_argument("--to", required=True, help="one intended recipient email address")
    mail.add_argument("--format", choices=["pdf", "html", "executive", "technical", "complete", "bundle"], default="pdf")
    mail.add_argument("--template", choices=["final_delivery", "executive_delivery", "urgent_findings",
                                             "remediation_followup", "retest_results", "engagement_closure"],
                      default="final_delivery", help="professional report email message template")
    mail.add_argument("--client-name", default="", help="client's contact person (changes per engagement)")
    mail.add_argument("--client-organization", default="", help="client organization (changes per engagement)")
    mail.add_argument("--subject", help="optional edited subject")
    mail.add_argument("--body-file", help="optional UTF-8 file containing edited message")
    mail.add_argument("--preview", action="store_true", help="preview client message; never send email")
    mail.add_argument("--confirm-send", action="store_true", help="required approval to send confidential report")
    mail.set_defaults(func=cmd_mail)

    d = sub.add_parser("doctor", help="system diagnostics")
    d.set_defaults(func=cmd_doctor)

    g = sub.add_parser("gui", help="launch the local graphical dashboard")
    g.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"])
    g.add_argument("--port", type=int, default=8765)
    g.add_argument("--no-browser", action="store_true")
    g.set_defaults(func=cmd_gui)
    return p


def main():
    if os.name == "posix":
        os.umask(0o077)  # local reports, raw evidence, and scanner logs are sensitive
    p = parser()
    args = p.parse_args()
    if args.command is None:
        if args.legacy_target:
            ns = argparse.Namespace(**vars(args))
            ns.target = args.legacy_target
            ns.profile = args.legacy_profile or "safe"
            ns.authorized = args.legacy_authorized
            ns.dry_run = args.legacy_dry_run
            ns.json = args.legacy_json
            cmd_audit(ns)
            return
        if args.legacy_resume:
            ns = argparse.Namespace(**vars(args))
            ns.audit_id = args.legacy_resume
            ns.authorized = args.legacy_authorized
            ns.dry_run = args.legacy_dry_run
            ns.rerun_recon = False
            cmd_resume(ns)
            return
        if args.legacy_report:
            ns = argparse.Namespace(**vars(args))
            ns.audit_id = args.legacy_report
            ns.json = args.legacy_json
            cmd_report(ns)
            return
        interactive(args)
        return
    args.func(args)


if __name__ == "__main__":
    main()
