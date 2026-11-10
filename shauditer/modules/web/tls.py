"""Low-impact TLS certificate posture check (one TLS handshake, no payload)."""
from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlsplit

from shauditer.integrations.base import Integration, ModuleResult
from shauditer.modules.web.posture import _resolve_pinned


def tls_certificate_check(host: str, port: int, scope, *, timeout: float = 6.0) -> dict:
    allowed = scope.authorize(host, port=port, action="one TLS handshake")
    if not allowed.allowed:
        raise PermissionError(allowed.reason)
    address = _resolve_pinned(host, port, scope)
    context = ssl.create_default_context()
    with socket.create_connection((address, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as stream:
            return {"certificate": stream.getpeercert(), "protocol": stream.version()}


class TLSPostureIntegration(Integration):
    name = "tls_posture"
    executable = ""

    def available(self):
        return True

    async def run(self, context) -> ModuleResult:
        target = context.target
        if target.network:
            return ModuleResult(self.name, "NOT_APPLICABLE", metadata={"reason": "one named TLS endpoint required"})
        if target.scheme == "http":
            return ModuleResult(self.name, "NOT_APPLICABLE", metadata={"reason": "HTTP target; no TLS scheme specified"})
        host = target.hostname
        port = 443
        if target.scheme == "https":
            port = urlsplit(target.original).port or 443
        if not context.scope.authorize(host, port=port).allowed:
            return ModuleResult(self.name, "BLOCKED", metadata={"reason": "TLS port out of scope"})
        if context.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"host": host, "port": port})
        try:
            info = await asyncio.to_thread(tls_certificate_check, host, port, context.scope,
                                           timeout=float(context.config.get("timeouts", {}).get("web_posture", 6)))
        except ssl.SSLCertVerificationError as exc:
            return ModuleResult(self.name, "SUCCESS", findings=[{
                "title": "TLS certificate validation failed", "asset": host, "port": port,
                "endpoint": f"https://{host}:{port}/", "severity": "MEDIUM", "confidence": 0.75,
                "cves": [], "cwes": ["CWE-295"], "sources": ["tls_posture"],
                "description": f"TLS certificate validation was rejected by the standard trust store ({type(exc).__name__}). Check trust chain, domain and expiry in an approved browser.",
                "remediation": "Deploy a valid certificate with correct hostname and chain from a trusted issuer; verify automatic renewal and retest.",
                "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
            }], metadata={"host": host, "port": port, "certificate_verified": False})
        except (OSError, ValueError, PermissionError, ssl.SSLError) as exc:
            return ModuleResult(self.name, "FAILED", metadata={"reason": type(exc).__name__, "host": host, "port": port})
        findings = []
        cert = info["certificate"]
        not_after = cert.get("notAfter")
        if not_after:
            try:
                remaining = (datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc) - datetime.now(timezone.utc)).days
            except ValueError:
                remaining = None
            if remaining is not None and remaining < 30:
                findings.append({
                    "title": "TLS certificate expires soon" if remaining >= 0 else "TLS certificate has expired",
                    "asset": host, "port": port, "endpoint": f"https://{host}:{port}/",
                    "severity": "LOW" if remaining >= 0 else "MEDIUM", "confidence": 0.95,
                    "cves": [], "cwes": ["CWE-295"], "sources": ["tls_posture"],
                    "description": f"Trusted TLS certificate expiry is {remaining} day(s) away; verify renewal before the expiry date.",
                    "remediation": "Renew certificate with a trusted CA, use automated rotation, and monitor certificate expiration.",
                    "validation_status": "UNVALIDATED", "exploitability": "UNKNOWN",
                })
        return ModuleResult(self.name, "SUCCESS", findings=findings,
                            metadata={"host": host, "port": port, "certificate_verified": True,
                                      "tls_protocol": info.get("protocol"), "days_to_expiration": remaining if not_after else None})
