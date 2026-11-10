from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(slots=True)
class ScopePolicy:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allowed_ports: set[int] = field(default_factory=set)
    excluded_ports: set[int] = field(default_factory=set)
    allowed_domains: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    mode: str = "authorized-security-assessment"


@dataclass(slots=True)
class ScopeDecision:
    allowed: bool
    reason: str
