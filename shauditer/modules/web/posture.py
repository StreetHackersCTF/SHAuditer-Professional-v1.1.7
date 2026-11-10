"""Bounded read-only HTTP posture observations (not exploit execution).

Connections are pinned to the DNS address checked at scope verification. Redirects
are never followed, credentials and response bodies are never collected.
"""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit

from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


SECURITY_CONTROLS = {
    "content-security-policy": ("Content Security Policy is missing", "MEDIUM", "Define a restrictive Content-Security-Policy and test it in report-only mode first.", "CWE-693"),
    "x-content-type-options": ("MIME sniffing protection is missing", "LOW", "Set X-Content-Type-Options: nosniff on relevant responses.", "CWE-693"),
    "referrer-policy": ("Referrer Policy is missing", "LOW", "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter policy.", "CWE-200"),
    "strict-transport-security": ("HTTP Strict Transport Security is missing", "LOW", "On HTTPS, set a tested Strict-Transport-Security policy after verifying all subdomains and TLS support.", "CWE-319"),
}


def review_response_headers(url: str, headers: list[tuple[str, str]]) -> list[dict]:
    """Produce transparent control observations, not unverified compromise claims."""
    parsed = urlsplit(url)
    host = parsed.hostname or "unknown"
    normalized: dict[str, list[str]] = {}
    for key, value in headers:
        normalized.setdefault(key.lower(), []).append(value)
    result = []
    for name, (title, severity, remedy, cwe) in SECURITY_CONTROLS.items():
        if name == "strict-transport-security" and parsed.scheme != "https":
            continue
        if name == "content-security-policy" and any("frame-ancestors" in v.lower() for v in normalized.get(name, [])):
            continue
        if name in normalized:
            continue
        result.append({
            "title": title, "asset": host, "endpoint": url, "category": "WEB_HEADERS",
            "severity": severity, "confidence": 0.9, "cves": [], "cwes": [cwe],
            "sources": ["web_posture"], "description": f"Response to a bounded read-only request did not include {name}. This alone does not prove exploitability.",
            "remediation": remedy, "references": ["https://owasp.org/www-project-secure-headers/"],
            "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
            "poc_type": "HTTP_HEADER", "poc_parameter": name,
        })
    for cookie in normalized.get("set-cookie", []):
        pieces = [x.strip().lower() for x in cookie.split(";")]
        if parsed.scheme == "https" and "secure" not in pieces[1:]:
            result.append({
                "title": "Cookie missing Secure attribute", "asset": host, "endpoint": url,
                "category": "WEB_SESSION", "severity": "MEDIUM", "confidence": 0.85,
                "cves": [], "cwes": ["CWE-614"], "sources": ["web_posture"],
                "description": "A cookie lacks the Secure attribute. Its name and value are intentionally not stored.",
                "remediation": "Apply Secure to session cookies and use HTTPS throughout.",
                "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
                "poc_type": "COOKIE_ATTRIBUTE", "poc_parameter": "secure",
            })
        if "httponly" not in pieces[1:]:
            result.append({
                "title": "Cookie missing HttpOnly attribute", "asset": host, "endpoint": url,
                "category": "WEB_SESSION", "severity": "LOW", "confidence": 0.85,
                "cves": [], "cwes": ["CWE-1004"], "sources": ["web_posture"],
                "description": "A cookie lacks HttpOnly. For non-session cookies this may be intentional; review context.",
                "remediation": "Apply HttpOnly to session cookies that do not need JavaScript access.",
                "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
                "poc_type": "COOKIE_ATTRIBUTE", "poc_parameter": "httponly",
            })
    return result


def _resolve_pinned(host: str, port: int, scope) -> str:
    try:
        direct = ipaddress.ip_address(host)
    except ValueError:
        direct = None
    if direct is not None:
        return str(direct)
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for item in infos:
        address = ipaddress.ip_address(item[4][0])
        # A DNS name that resolves to local/private/link-local infrastructure must
        # also have that *address* explicitly authorized in the scope policy.
        if not address.is_global and not scope.authorize(str(address), port=port, action="private DNS address").allowed:
            continue
        return str(address)
    raise PermissionError("DNS resolved only to non-public addresses not explicitly present in scope")


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, hostname, port, pinned_ip, timeout):
        super().__init__(hostname, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname, port, pinned_ip, timeout):
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self.pinned_ip = pinned_ip

    def connect(self):
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def probe(url: str, scope, *, timeout: float = 6.0) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ValueError("only HTTP(S) URLs without credentials may be probed")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    decision = scope.authorize(parts.hostname, port=port, action="bounded HTTP posture check")
    if not decision.allowed:
        raise PermissionError(decision.reason)
    address = _resolve_pinned(parts.hostname, port, scope)
    klass = _PinnedHTTPS if parts.scheme == "https" else _PinnedHTTP
    connection = klass(parts.hostname, port, address, timeout)
    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    if len(path) > 8192:
        raise ValueError("request path exceeds configured maximum")
    try:
        connection.request("HEAD", path, headers={"User-Agent": "SHAuditer/1.0 (authorized audit)", "Accept": "*/*", "Connection": "close"})
        response = connection.getresponse()
        headers = response.getheaders()
        status = response.status
    finally:
        connection.close()
    # Only property names and a few booleans may leave this function's caller.
    return {"url": url, "status": status, "headers": headers, "observed_at": datetime.now(timezone.utc).isoformat()}


def sanitized_probe(result: dict) -> dict:
    return {"url": result["url"], "status": result["status"], "observed_at": result["observed_at"],
            "header_names": sorted({k.lower() for k, _ in result["headers"]}),
            "cookie_count": sum(k.lower() == "set-cookie" for k, _ in result["headers"])}


class WebPostureIntegration(Integration):
    name = "web_posture"
    executable = ""

    def available(self):
        return True

    async def run(self, context) -> ModuleResult:
        target = context.target
        if target.network:
            return ModuleResult(self.name, "NOT_APPLICABLE", metadata={"reason": "CIDR is not an HTTP URL"})
        if target.scheme:
            urls = [target.original]
        else:
            host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
            urls = [f"https://{host}/", f"http://{host}/"]
        approved = []
        for url in urls:
            parts = urlsplit(url)
            if context.scope.authorize(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)).allowed:
                approved.append(url)
        if not approved:
            return ModuleResult(self.name, "BLOCKED", metadata={"reason": "No permitted HTTP ports"})
        if context.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"urls": approved})
        errors = []
        for url in approved:
            try:
                outcome = await __import__("asyncio").to_thread(probe, url, context.scope, timeout=float(context.config.get("timeouts", {}).get("web_posture", 6)))
                findings = review_response_headers(url, outcome["headers"])
                safe = sanitized_probe(outcome)
                evidence_id = f"EV-{context.audit_id}-WEBPOSTURE"
                dest = context.workspace / "recon" / "web_posture.json"
                dest.write_text(json.dumps(safe, indent=2), encoding="utf-8")
                context.db.add_evidence(evidence_id, context.audit_id, self.name, "sanitized_headers", str(dest), sha256_file(dest))
                for finding in findings:
                    finding["evidence_ids"] = [evidence_id]
                return ModuleResult(self.name, "SUCCESS", findings=findings,
                                    services=[{"url": url, "status_code": outcome["status"]}], metadata=safe)
            except (OSError, ValueError, PermissionError, ssl.SSLError, http.client.HTTPException) as exc:
                errors.append({"url": url, "error": type(exc).__name__})
        return ModuleResult(self.name, "FAILED", metadata={"attempts": errors})
