"""Local, offline cloud-IaC, Kubernetes, container and AI config review.

Static rules flag review candidates, not guaranteed vulnerabilities. No credentials
are loaded and no cloud API or model endpoint is called by this module.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

MAX_FILES = 1200
MAX_FILE_BYTES = 1_000_000
ACCEPTED = {".tf", ".tfvars", ".json", ".yaml", ".yml", ".dockerfile"}
IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", "dist", "build", ".next"}


def _finding(path: Path, rule: str, title: str, severity: str, recommendation: str, *, category: str, cwe: str, line: int | None = None) -> dict:
    return {
        "title": title, "asset": path.as_posix(), "endpoint": f"{path.as_posix()}{':' + str(line) if line else ''}",
        "category": category, "rule_id": rule, "severity": severity, "confidence": 0.8,
        "cves": [], "cwes": [cwe], "sources": ["offline_artifact_review"],
        "description": f"Static configuration rule {rule} matched. Review surrounding context before treating this as an exploitable vulnerability.",
        "remediation": recommendation, "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
        "poc_type": None,
    }


def _walk(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk(value)


def _ai_check(path: Path, obj: Any) -> list[dict]:
    findings = []
    if not isinstance(obj, (dict, list)):
        return findings
    for node in _walk(obj):
        if node.get("allow_remote_code") is True or node.get("trust_remote_code") is True:
            findings.append(_finding(path, "AI-001", "AI model loading allows remote code", "HIGH",
                    "Disable trust_remote_code/allow_remote_code and pin reviewed model revisions.", category="AI", cwe="CWE-829"))
        tool = node.get("tools") or node.get("tool_permissions")
        if isinstance(tool, dict) and (tool.get("allow_all") is True or tool.get("allowlist") == "*"):
            findings.append(_finding(path, "AI-002", "AI agent tool permissions are unrestricted", "HIGH",
                    "Apply least privilege, enforce a tool allowlist and require approvals for sensitive actions.", category="AI", cwe="CWE-269"))
        if (node.get("log_prompts") is True or node.get("prompt_logging") is True) and node.get("redact_pii") is False:
            findings.append(_finding(path, "AI-003", "AI prompt logging without PII redaction", "MEDIUM",
                    "Disable raw prompt retention or redact sensitive fields before logging; restrict access and retention.", category="AI", cwe="CWE-532"))
        if node.get("guardrails_enabled") is False or node.get("human_approval_for_tools") is False:
            findings.append(_finding(path, "AI-004", "AI agent guardrails or action approval disabled", "MEDIUM",
                    "Implement prompt-injection defenses and human approval for external or sensitive tool actions.", category="AI", cwe="CWE-284"))
    return findings


def _cloud_json(path: Path, obj: Any) -> list[dict]:
    findings = []
    for node in _walk(obj):
        if node.get("Effect") == "Allow" and isinstance(node.get("Action"), str) and node.get("Action") in {"*", "iam:*"} and node.get("Resource") == "*":
            findings.append(_finding(path, "CLOUD-001", "Overly broad IAM permissions", "HIGH",
                    "Scope IAM actions and resources to necessary operations only; use permission boundaries and review policies.", category="CLOUD", cwe="CWE-732"))
        if node.get("Effect") == "Allow" and node.get("Principal") == "*":
            findings.append(_finding(path, "CLOUD-002", "Public principal in resource policy", "HIGH",
                    "Restrict the resource policy Principal to explicitly required roles/accounts and add conditions.", category="CLOUD", cwe="CWE-732"))
    return findings


def _containers_from_pod(path: Path, spec: dict) -> list[dict]:
    findings = []
    for kind, rule, title in (("hostNetwork", "K8S-001", "Kubernetes host network enabled"),
                               ("hostPID", "K8S-002", "Kubernetes host PID namespace enabled")):
        if spec.get(kind) is True:
            findings.append(_finding(path, rule, title, "HIGH", f"Disable {kind} unless a documented exception is required.", category="CONTAINER", cwe="CWE-269"))
    for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        if not isinstance(container, dict):
            continue
        sec = container.get("securityContext") or {}
        if sec.get("privileged") is True:
            findings.append(_finding(path, "K8S-003", "Privileged Kubernetes container", "HIGH",
                    "Remove privileged mode, drop Linux capabilities and enable seccomp/Pod Security admission.", category="CONTAINER", cwe="CWE-250"))
        if sec.get("allowPrivilegeEscalation") is True or sec.get("runAsUser") == 0:
            findings.append(_finding(path, "K8S-004", "Container permits privilege escalation or runs as root", "MEDIUM",
                    "Set runAsNonRoot and allowPrivilegeEscalation: false; use a non-root UID and minimal capabilities.", category="CONTAINER", cwe="CWE-250"))
        image = str(container.get("image") or "")
        if image.lower().endswith(":latest") or (image and ":" not in image and "@sha256:" not in image):
            findings.append(_finding(path, "K8S-005", "Unpinned container image", "LOW",
                    "Use an approved immutable image digest and automate vulnerability scans and updates.", category="CONTAINER", cwe="CWE-1104"))
    return findings


def _openapi(path: Path, obj: dict) -> tuple[list[dict], list[dict]]:
    """Inventory declared endpoints and flag review candidates, without live requests."""
    if not isinstance(obj, dict) or not (obj.get("openapi") or obj.get("swagger")) or not isinstance(obj.get("paths"), dict):
        return [], []
    findings, operations = [], []
    global_sec = obj.get("security")
    for route, methods in list(obj["paths"].items())[:2000]:
        if not isinstance(methods, dict):
            continue
        for verb, operation in methods.items():
            if verb.lower() not in {"get", "put", "post", "delete", "options", "head", "patch"} or not isinstance(operation, dict):
                continue
            operations.append({"file": path.as_posix(), "method": verb.upper(), "path": str(route)[:500],
                               "auth_declared": bool(operation.get("security", global_sec))})
            if operation.get("security", global_sec) == []:
                findings.append(_finding(path, "API-001", "OpenAPI operation declares no authentication", "INFORMATIONAL",
                    "Confirm the endpoint is intentionally public and enforce server-side authorization for private data and operations.", category="API", cwe="CWE-306"))
    servers = obj.get("servers") or []
    if any(isinstance(x, dict) and str(x.get("url", "")).lower().startswith("http://") for x in servers):
        findings.append(_finding(path, "API-002", "OpenAPI specifies an unencrypted HTTP server", "LOW",
                    "Serve production APIs over HTTPS with valid certificates; avoid transmitting credentials over HTTP.", category="API", cwe="CWE-319"))
    return findings, operations


def _structured(path: Path, obj: Any) -> list[dict]:
    findings = []
    if not isinstance(obj, dict):
        return findings
    kind = obj.get("kind")
    if kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}:
        spec = obj.get("spec") or {}
        if kind == "CronJob":
            spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
        if kind != "Pod":
            spec = ((spec.get("template") or {}).get("spec") or {})
        findings.extend(_containers_from_pod(path, spec))
    if "services" in obj and isinstance(obj["services"], dict):
        for service in obj["services"].values():
            if not isinstance(service, dict):
                continue
            if service.get("privileged") is True:
                findings.append(_finding(path, "COMPOSE-001", "Privileged Compose service", "HIGH",
                    "Avoid privileged containers and remove excess capabilities.", category="CONTAINER", cwe="CWE-250"))
            if service.get("network_mode") == "host":
                findings.append(_finding(path, "COMPOSE-002", "Docker Compose host network", "MEDIUM",
                    "Use isolated service networks and publish only needed ports.", category="CONTAINER", cwe="CWE-269"))
    findings.extend(_cloud_json(path, obj))
    name = path.name.lower()
    if any(marker in name for marker in ("ai", "llm", "agent", "model", "genai")):
        findings.extend(_ai_check(path, obj))
    return findings


def _text(path: Path, content: str) -> list[dict]:
    findings = []
    name = path.name.lower()
    if name == "dockerfile" or name.endswith(".dockerfile"):
        lines = content.splitlines()
        from_lines = [line.strip() for line in lines if re.match(r"^\s*FROM\b", line, re.I)]
        if any(re.search(r":latest\b", line, re.I) for line in from_lines):
            findings.append(_finding(path, "DOCKER-001", "Docker base image uses :latest", "LOW",
                    "Pin the base image digest, continuously scan and rebuild on security updates.", category="CONTAINER", cwe="CWE-1104"))
        if not any(re.match(r"^\s*USER\s+[^\s#]+", line, re.I) and not re.search(r"\b(?:root|0)\b", line, re.I) for line in lines):
            findings.append(_finding(path, "DOCKER-002", "Dockerfile lacks a non-root USER", "MEDIUM",
                    "Create a dedicated non-root user and set USER before runtime.", category="CONTAINER", cwe="CWE-250"))
        for index, line in enumerate(lines, 1):
            if re.search(r"\b(?:curl|wget)\b.+\|\s*(?:sh|bash)\b", line, re.I):
                findings.append(_finding(path, "DOCKER-003", "Remote script executed directly in Docker build", "MEDIUM",
                        "Fetch version-pinned artifacts, verify integrity, and avoid piping network responses to a shell.", category="CONTAINER", cwe="CWE-494", line=index))
    if path.suffix.lower() in {".tf", ".tfvars"}:
        if re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', content) and re.search(r'(from_port|to_port)\s*=\s*(22|3389)\b', content):
            findings.append(_finding(path, "IAC-001", "Cloud firewall may expose administrative ports publicly", "HIGH",
                    "Restrict SSH/RDP access to a private management network or authorized CIDRs; verify the Terraform resource context.", category="CLOUD", cwe="CWE-284"))
        if re.search(r'\bacl\s*=\s*"public-read(?:-write)?"', content):
            findings.append(_finding(path, "IAC-002", "Cloud storage ACL permits public access", "HIGH",
                    "Block public access and use narrowly scoped identities for object retrieval.", category="CLOUD", cwe="CWE-732"))
        if re.search(r'\bskip_credentials_validation\s*=\s*true', content):
            findings.append(_finding(path, "IAC-003", "Cloud provider credentials validation disabled", "LOW",
                    "Confirm whether this is deliberate for a local emulator; enable credential checks in production.", category="CLOUD", cwe="CWE-693"))
    return findings


def scan_directory(root: str | Path) -> dict:
    path = Path(root).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError("artifacts location must be a local directory")
    inspected = []
    skipped = []
    findings = []
    api_endpoints = []
    # Bounded filesystem walk: do not first materialize a potentially huge tree.
    # Never follow symlinked directories. Prune dependency/build trees early.
    candidates = 0
    all_paths = []
    for base, directories, files in os.walk(path, followlinks=False):
        directories[:] = sorted(d for d in directories if d not in IGNORE_DIRS and not (Path(base) / d).is_symlink())
        for name in sorted(files):
            candidates += 1
            if candidates > MAX_FILES * 10:
                skipped.append({"reason": "filesystem traversal limit reached"})
                break
            all_paths.append(Path(base) / name)
        if candidates > MAX_FILES * 10:
            break
    for file in all_paths:
        if any(segment in IGNORE_DIRS for segment in file.relative_to(path).parts):
            continue
        if file.is_symlink() or not file.is_file():
            continue
        if len(inspected) >= MAX_FILES:
            skipped.append({"reason": "file limit reached"})
            break
        if file.stat().st_size > MAX_FILE_BYTES:
            skipped.append({"path": file.relative_to(path).as_posix(), "reason": "oversized"})
            continue
        lower = file.name.lower()
        if file.suffix.lower() not in ACCEPTED and lower not in {"dockerfile", "containerfile"}:
            continue
        relative = file.relative_to(path)
        try:
            content = file.read_text(encoding="utf-8")
        except UnicodeError:
            skipped.append({"path": str(relative), "reason": "not UTF-8"})
            continue
        inspected.append(str(relative))
        findings.extend(_text(relative, content))
        if file.suffix.lower() == ".json":
            try:
                document = json.loads(content)
                findings.extend(_structured(relative, document))
                api_findings, endpoints = _openapi(relative, document)
                findings.extend(api_findings)
                api_endpoints.extend(endpoints)
            except (ValueError, TypeError):
                skipped.append({"path": str(relative), "reason": "invalid JSON"})
        elif file.suffix.lower() in {".yaml", ".yml"}:
            if yaml is None:
                skipped.append({"path": str(relative), "reason": "PyYAML unavailable"})
            else:
                try:
                    for obj in yaml.safe_load_all(content):
                        findings.extend(_structured(relative, obj))
                        api_findings, endpoints = _openapi(relative, obj)
                        findings.extend(api_findings)
                        api_endpoints.extend(endpoints)
                except yaml.YAMLError:
                    skipped.append({"path": str(relative), "reason": "invalid YAML"})
    # Deduplicate observations at a file+rule level, preserving independent rules.
    deduped = {(f["asset"], f["rule_id"], f["endpoint"]): f for f in findings}
    return {"findings": list(deduped.values()), "inspected": inspected, "skipped": skipped,
            "api_endpoints": api_endpoints[:5000],
            "coverage": {"files_inspected": len(inspected), "files_skipped": len(skipped),
                         "mode": "offline_static_review", "api_operations_discovered": len(api_endpoints), "cloud_api_connected": False,
                         "image_runtime_inspected": False, "ai_endpoint_probed": False}}
