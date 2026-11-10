"""Conservative public vulnerability research.

This module resolves authoritative CVE/likelihood sources and creates links to
public research indexes. Search links are NOT claims of a known matching exploit.
Third-party PoC code is never downloaded or executed by this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import shlex
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
MAX_FEED_BYTES = 8_000_000


def cve_ids(finding: dict) -> list[str]:
    raw = finding.get("cves") or []
    if isinstance(raw, str):
        raw = [raw]
    return list(dict.fromkeys(str(x).upper() for x in raw if CVE_PATTERN.fullmatch(str(x).strip())))[:12]


def research_references(finding: dict) -> list[dict[str, str]]:
    """Return trusted entry points, explicitly distinguishing search from evidence."""
    cves = cve_ids(finding)
    out: list[dict[str, str]] = []
    for cve in cves:
        out.extend([
            {"label": f"NVD advisory · {cve}", "provider": "NIST NVD", "kind": "advisory", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
            {"label": f"CISA KEV search · {cve}", "provider": "CISA", "kind": "search", "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"},
            {"label": f"GitHub public PoC research · {cve}", "provider": "GitHub", "kind": "search", "url": f"https://github.com/search?q={quote(cve)}&type=repositories"},
            {"label": f"Exploit-DB research · {cve}", "provider": "Exploit Database", "kind": "search", "url": f"https://www.exploit-db.com/search?cve={quote(cve)}"},
            {"label": f"Rapid7 vulnerability research · {cve}", "provider": "Rapid7", "kind": "search", "url": f"https://www.rapid7.com/db/?q={quote(cve)}"},
        ])
    for url in finding.get("references") or []:
        if isinstance(url, str) and url.startswith("https://") and len(url) <= 2048:
            out.append({"label": "Scanner or vendor reference", "provider": "Finding reference", "kind": "unverified_reference", "url": url})
    return out[:65]


def read_json(url: str, *, timeout: int = 12, limit: int = MAX_FEED_BYTES) -> dict:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "SHAuditer/1.1.7 defensive-assessment"})
    with urlopen(request, timeout=timeout) as response:
        content = response.read(limit + 1)
    if len(content) > limit:
        raise ValueError("intelligence response exceeds configured size limit")
    obj = json.loads(content.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("intelligence service did not return a JSON object")
    return obj


@dataclass(slots=True)
class ThreatContext:
    timeout: int = 12

    def fetch(self, identifiers: list[str]) -> dict[str, Any]:
        identifiers = list(dict.fromkeys(c.upper() for c in identifiers if CVE_PATTERN.fullmatch(c.upper())))[:12]
        info: dict[str, Any] = {"retrieved_at": datetime.now(timezone.utc).isoformat(), "epss": {}, "kev": {}, "errors": {}, "sources": {"epss": EPSS_API, "kev": KEV_FEED}}
        if not identifiers:
            return info
        try:
            url = EPSS_API + "?" + urlencode({"cve": ",".join(identifiers)})
            obj = read_json(url, timeout=self.timeout, limit=250_000)
            for entry in obj.get("data") or []:
                cve = str(entry.get("cve") or "").upper()
                if cve in identifiers:
                    info["epss"][cve] = {"score": float(entry["epss"]), "percentile": float(entry["percentile"]), "date": entry.get("date")}
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            info["errors"]["epss"] = type(exc).__name__
        try:
            obj = read_json(KEV_FEED, timeout=self.timeout)
            for entry in obj.get("vulnerabilities") or []:
                cve = str(entry.get("cveID") or "").upper()
                if cve in identifiers:
                    info["kev"][cve] = {
                        "date_added": entry.get("dateAdded"), "vendor": entry.get("vendorProject"),
                        "product": entry.get("product"), "required_action": entry.get("requiredAction"),
                        "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                    }
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            info["errors"]["kev"] = type(exc).__name__
        return info


def priority_context(feed: dict) -> str:
    kev = feed.get("kev") or {}
    epss = feed.get("epss") or {}
    if kev:
        return "KNOWN EXPLOITED: One or more reported CVEs appear in the CISA KEV catalog; confirm applicability and prioritize remediation."
    if any(float(x.get("score") or 0) >= 0.5 for x in epss.values()):
        return "ELEVATED LIKELIHOOD: EPSS indicates increased exploitation probability; verify asset exposure and business impact."
    return "Review vendor advisory and local applicability. Search hits or exploit references are not validation of the target."


def safe_check_code(finding: dict) -> str | None:
    """Read-only example; never automatically executed or used as an exploit."""
    if finding.get("poc_type") not in {"HTTP_HEADER", "COOKIE_ATTRIBUTE"}:
        return None
    url = str(finding.get("endpoint") or "")
    if not (url.startswith("https://") or url.startswith("http://")) or len(url) > 2048:
        return None
    return ("# Manual operator review and authorized target only\n"
            "# Observe response headers; do not treat as exploit verification\n"
            "curl --head --max-time 6 --max-redirs 0 -- " + shlex.quote(url))
