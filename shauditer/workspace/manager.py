from __future__ import annotations
from pathlib import Path
import os


SUBDIRS = (
    "target", "recon", "enumeration", "scans", "vulnerabilities",
    "exploit-intelligence", "validation", "post-exploitation", "evidence",
    "reports", "logs", "metadata",
)


class WorkspaceManager:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            self.root.chmod(0o700)

    def create(self, audit_id: str) -> Path:
        workspace = self.root / audit_id
        workspace.mkdir(parents=False, exist_ok=False, mode=0o700)
        for subdir in SUBDIRS:
            (workspace / subdir).mkdir(mode=0o700)
        return workspace

    def get(self, audit_id: str) -> Path:
        workspace = self.root / audit_id
        if not workspace.is_dir():
            raise FileNotFoundError(f"workspace not found: {workspace}")
        return workspace
