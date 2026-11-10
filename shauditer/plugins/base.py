from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(slots=True)
class PluginManifest:
    name: str
    version: str
    author: str
    category: str
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    configuration: dict = field(default_factory=dict)
