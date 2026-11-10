"""Offline professional configuration analysis adapter."""
from __future__ import annotations

import json
from pathlib import Path
from shauditer.integrations.base import Integration, ModuleResult
from shauditer.modules.artifacts import scan_directory
from shauditer.security.evidence import sha256_file


class ArtifactReviewIntegration(Integration):
    name = "artifact_review"
    executable = ""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)

    def available(self):
        return True

    async def run(self, context) -> ModuleResult:
        if context.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"location": str(self.directory), "no_files_opened": True})
        result = await __import__("asyncio").to_thread(scan_directory, self.directory)
        dest = context.workspace / "scans" / "artifact-review.json"
        # Do not archive local source files, credentials, secrets, or complete manifests.
        dest.write_text(json.dumps(result, indent=2), encoding="utf-8")
        evidence_id = f"EV-{context.audit_id}-ARTIFACT"
        context.db.add_evidence(evidence_id, context.audit_id, self.name, "sanitized_offline_scan", str(dest), sha256_file(dest))
        for finding in result["findings"]:
            finding["evidence_ids"] = [evidence_id]
        return ModuleResult(self.name, "SUCCESS" if not result["skipped"] else "PARTIAL",
                            findings=result["findings"], metadata=result["coverage"])
