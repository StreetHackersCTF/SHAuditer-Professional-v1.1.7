"""Generate a shareable ZIP of report outputs, not raw scan data or secrets."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ALLOWED_REPORTS = (
    "assessment.pdf", "assessment.html", "assessment.json", "assessment-quality.json",
    "findings.json", "findings.csv", "mitigation-plan.csv", "recon-services.csv",
    "docx/executive-report.docx", "docx/technical-report.docx", "docx/complete-assessment.docx",
)


def bundle_reports(workspace: Path) -> Path:
    reports = Path(workspace).resolve() / "reports"
    archive = reports / "assessment-bundle.zip"
    records = []
    with ZipFile(archive, "w", compression=ZIP_DEFLATED, compresslevel=6) as out:
        for name in ALLOWED_REPORTS:
            path = reports / name
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 20_000_000:
                continue
            data = path.read_bytes()
            out.writestr(name, data)
            records.append({"file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        out.writestr("SHA256-MANIFEST.json", json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
                                                           "files": records}, indent=2))
    return archive
