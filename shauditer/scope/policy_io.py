"""Validated, explicit scope configuration for authorized assessments."""
from __future__ import annotations

import json
from pathlib import Path
from shauditer.models.target import Target
from shauditer.scope.models import ScopePolicy
from shauditer.scope.validator import ScopeValidator

_RULE_KEYS = ("in_scope", "out_of_scope", "allowed_domains", "excluded_domains")
_PORT_KEYS = ("allowed_ports", "excluded_ports")


def _rules(value, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 200:
        raise ValueError(f"{key} must be a list with at most 200 rules")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > 255:
            raise ValueError(f"invalid {key} entry")
        item = item.strip()
        if item in {"*", "*.*"} or "*" in item and not item.startswith("*."):
            raise ValueError("scope wildcards are only allowed as the *.example.com prefix")
        result.append(item)
    return result


def _ports(value, key: str) -> set[int]:
    if value is None:
        return set()
    if not isinstance(value, list) or len(value) > 65535:
        raise ValueError(f"{key} must be a list of TCP port numbers")
    result = set()
    for p in value:
        if isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535:
            raise ValueError(f"invalid port number in {key}: {p!r}")
        result.add(p)
    return result


def scope_from_dict(data: dict, *, default_target: Target | None = None) -> ScopePolicy:
    if not isinstance(data, dict):
        raise ValueError("scope must be a JSON object")
    unexpected = set(data) - set(_RULE_KEYS + _PORT_KEYS + ("mode",))
    if unexpected:
        raise ValueError(f"unsupported scope properties: {', '.join(sorted(unexpected))}")
    entries = {k: _rules(data.get(k), k) for k in _RULE_KEYS}
    if default_target is not None:
        entries["in_scope"] = [default_target.network or default_target.hostname, *entries["in_scope"]]
    ports = {k: _ports(data.get(k), k) for k in _PORT_KEYS}
    if not entries["in_scope"] and not entries["allowed_domains"]:
        raise ValueError("at least one positive scope rule is required")
    policy = ScopePolicy(**entries, **ports, mode="authorized-security-assessment")
    if default_target and not ScopeValidator(policy).authorize(default_target, action="new audit").allowed:
        raise ValueError("target is excluded from the provided scope policy")
    return policy


def load_scope_file(path: str | Path, *, default_target: Target | None = None) -> ScopePolicy:
    data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    return scope_from_dict(data, default_target=default_target)
