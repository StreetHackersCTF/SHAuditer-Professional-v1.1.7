from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import shutil
from typing import Any


@dataclass(slots=True)
class ModuleResult:
    module: str
    status: str
    assets: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Integration:
    name = "integration"
    executable = ""

    def available(self) -> bool:
        return bool(self.executable and shutil.which(self.executable))

    async def run(self, context) -> ModuleResult:
        raise NotImplementedError
