"""Local Gitleaks review. Never record or transmit matching secret material."""
from __future__ import annotations
import json
from pathlib import Path
from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


def parse_gitleaks(raw) -> list[dict]:
    findings=[]
    if not isinstance(raw,list): return findings
    for entry in raw[:250]:
        if not isinstance(entry,dict): continue
        rule=str(entry.get("RuleID") or "Secret pattern")[:90]
        path=str(entry.get("File") or "Local artifact")[:350]
        findings.append({"title": f"Potential secret exposure: {rule}",
            "asset":"Local artifact repository", "endpoint":path,
            "severity":"HIGH", "confidence":0.6, "sources":["gitleaks_local"],
            "category":"SECRETS", "cves":[],"cwes":["CWE-798"],
            "description":"A local static secret-pattern match was detected. Values and snippets are intentionally excluded from report evidence; verify without copying credentials.",
            "remediation":"Revoke or rotate any real credential using your approved secret-management process; remove it from current and historical source control where feasible, and review exposure logs.",
            "validation_status":"UNVALIDATED","exploitability":"UNKNOWN",
            "rule_id":rule})
    return findings


class GitleaksLocalIntegration(Integration):
    name="gitleaks_local"
    executable="gitleaks"
    def __init__(self,directory):
        self.original=Path(directory).expanduser();self.directory=self.original.resolve()
    async def run(self,context):
        if self.original.is_symlink() or not self.directory.is_dir():
            return ModuleResult(self.name,"BLOCKED",metadata={"reason":"Local non-symlink artifact directory required"})
        report_path=context.workspace/"scans"/"gitleaks-private-raw.json"
        # Gitleaks writes a temporary redacted report. Never persist it or include it in bundles.
        args=["dir",str(self.directory),"--no-banner","--redact=100","--report-format","json","--report-path",str(report_path)]
        try:
            proc=await context.runner.execute(self.executable,args,cwd=context.workspace,dry_run=context.dry_run,
                timeout=int(context.config.get("timeouts",{}).get("artifact_review",90)),max_output_bytes=2*1024*1024)
            if proc.dry_run:return ModuleResult(self.name,"DRY_RUN",metadata={"command":"gitleaks dir <approved local artifacts> --redact=100"})
            if proc.timed_out or proc.output_truncated or proc.exit_code not in (0,1):
                return ModuleResult(self.name,"FAILED",metadata={"exit_code":proc.exit_code,"timed_out":proc.timed_out,"output_truncated":proc.output_truncated})
            if not report_path.is_file():
                if proc.exit_code==0:
                    findings=[]
                else:
                    return ModuleResult(self.name,"FAILED",metadata={"reason":"No Gitleaks report produced"})
            else:
                raw=json.loads(report_path.read_text(encoding="utf-8"))
                findings=parse_gitleaks(raw)
            summary={"scanner":"gitleaks", "count":len(findings),
                     "detections":[{"rule":f["rule_id"],"file":f["endpoint"]} for f in findings]}
            safe_path=context.workspace/"vulnerabilities"/"gitleaks-summary.json"
            safe_path.write_text(json.dumps(summary,indent=2),encoding="utf-8")
            evidence_id=f"EV-{context.audit_id}-GITLEAKS"
            context.db.add_evidence(evidence_id,context.audit_id,self.name,"metadata_only_secrets_summary",str(safe_path),sha256_file(safe_path))
            for f in findings:f["evidence_ids"]=[evidence_id]
            return ModuleResult(self.name,"SUCCESS",findings=findings,metadata={"possible_secrets":len(findings),"offline":True})
        except (UnicodeDecodeError,ValueError,OSError) as exc:
            return ModuleResult(self.name,"FAILED",metadata={"reason":type(exc).__name__})
        finally:
            # Delete raw matcher output after parsing, even on a failed run.
            try:report_path.unlink(missing_ok=True)
            except OSError:pass
