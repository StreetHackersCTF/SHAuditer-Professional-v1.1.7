from __future__ import annotations

from copy import deepcopy
from urllib.parse import quote_plus
from shauditer.intelligence.public_sources import research_references, safe_check_code


def _norm(value) -> str:
    return str(value or "").strip()


def _pct(value) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    return v if v <= 1 else v / 100.0


def technical_impact(finding: dict) -> str:
    """Return conservative, report-safe impact language derived from the finding title.

    The wording is deliberately conditional unless an evidence-backed validation record
    already confirms the finding. This fills the report without inventing exploitation.
    """
    title = _norm(finding.get("title")).lower()
    confirmed = finding.get("validation_status") == "VALIDATED"
    prefix = "Confirmed impact may include" if confirmed else "If the condition is confirmed, potential impact includes"

    if any(x in title for x in ("remote code execution", " rce", "command injection", "code execution")):
        return f"{prefix} execution of attacker-controlled commands in the security context of the affected service, with follow-on impact determined by service privileges and segmentation."
    if any(x in title for x in ("authentication bypass", "auth bypass", "unauthenticated access")):
        return f"{prefix} access to protected application functionality without the intended authentication control, potentially exposing privileged operations or sensitive data."
    if "sql injection" in title or "sqli" in title:
        return f"{prefix} unauthorized database queries, disclosure or modification of application data, and in some configurations broader compromise of the application tier."
    if any(x in title for x in ("cross-site scripting", " xss")):
        return f"{prefix} execution of attacker-controlled browser script in a victim context, which can affect session integrity, user actions, or sensitive browser-accessible data."
    if any(x in title for x in ("path traversal", "directory traversal", "arbitrary file read", "file disclosure")):
        return f"{prefix} access to files outside the intended application path, potentially exposing configuration, credentials, keys, or other sensitive material."
    if any(x in title for x in ("default credential", "weak password", "anonymous login")):
        return f"{prefix} unauthorized access using weak, default, or unauthenticated credentials, with impact determined by the permissions of the exposed account or service."
    if any(x in title for x in ("information disclosure", "sensitive data", "exposure")):
        return f"{prefix} disclosure of implementation details or sensitive information that can support further attack planning or directly affect confidentiality."
    if any(x in title for x in ("denial of service", " dos")):
        return f"{prefix} loss or degradation of service availability. SHAuditer does not perform destructive availability validation by default."
    return f"{prefix} compromise of confidentiality, integrity, or availability consistent with the finding severity and the privileges of the affected component."


def safe_validation_procedure(finding: dict, intelligence: dict | None = None) -> list[str]:
    """Create a non-destructive validation plan suitable for the report.

    This intentionally stops before payload delivery, shell creation, destructive actions,
    credential dumping, persistence, or other intrusive exploitation steps.
    """
    asset = _norm(finding.get("asset") or finding.get("host") or finding.get("matched_at")) or "the affected asset"
    port = finding.get("port")
    service = _norm(finding.get("service") or finding.get("product")) or "affected service"
    endpoint = _norm(finding.get("endpoint") or finding.get("matched_at"))
    cves = [str(x).upper() for x in finding.get("cves") or []]
    app = (intelligence or {}).get("applicability") or {}

    steps = [
        f"Confirm the in-scope asset and attack surface: {asset}{f' on port {port}' if port else ''}; verify the observed {service} fingerprint from reconnaissance evidence.",
    ]
    if cves:
        steps.append(
            f"Compare the exact product/version/configuration against authoritative advisory data for {', '.join(cves)}; record whether the observed version is inside or outside the affected range."
        )
    else:
        steps.append("Confirm the vulnerable configuration or application behavior against the scanner/template description and vendor documentation.")
    if app.get("status"):
        steps.append(
            f"Review SHAuditer applicability analysis ({app.get('status')}, confidence {round(_pct(app.get('confidence')) * 100)}%) and resolve any product/version ambiguity before claiming validation."
        )
    if endpoint:
        steps.append(f"Repeat a non-destructive request/check against {endpoint} that demonstrates the vulnerable condition without modifying target state or delivering a payload.")
    else:
        steps.append("Repeat an appropriate non-destructive protocol/application check that demonstrates the vulnerable condition without modifying target state or delivering a payload.")
    steps.extend([
        "Capture the exact request/response, command output, timestamp, target identity, and relevant service/version evidence; import the artifact into SHAuditer so it receives a SHA-256 integrity hash.",
        "Mark the finding VALIDATED only when the collected evidence directly demonstrates the reported condition. Otherwise record NOT_VALIDATED or INCONCLUSIVE with the reason.",
    ])
    return steps


def research_links(finding: dict, intelligence: dict | None = None) -> list[dict[str, str]]:
    """Build safe public research references for a finding.

    Links point to advisory/search/module-information pages. SHAuditer intentionally does
    not embed runnable exploit or payload code in generated reports.
    """
    links: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(label: str, url: str, source: str) -> None:
        if not url or url in seen:
            return
        seen.add(url)
        links.append({"label": label, "url": url, "source": source})

    cves = [str(x).upper() for x in finding.get("cves") or [] if str(x).strip()]
    for cve in cves:
        add(f"NVD — {cve}", f"https://nvd.nist.gov/vuln/detail/{quote_plus(cve)}", "NVD")
        add(f"Rapid7 database search — {cve}", f"https://www.rapid7.com/db/?q={quote_plus(cve)}", "Rapid7")
        add(f"GitHub repository search — {cve}", f"https://github.com/search?q={quote_plus(cve)}&type=repositories", "GitHub")

    for ref in finding.get("references") or []:
        ref = _norm(ref)
        if ref.startswith(("https://", "http://")):
            add(ref, ref, "Finding reference")

    intel = intelligence or {}
    for cve, record in (intel.get("nvd") or {}).items():
        for ref in record.get("references") or []:
            ref = _norm(ref)
            if ref.startswith(("https://", "http://")):
                add(f"Advisory reference — {cve}", ref, "NVD reference")

    for cve, modules in (intel.get("metasploit_modules") or {}).items():
        for module in modules:
            path = _norm(module.get("module"))
            if not path:
                continue
            add(
                f"Rapid7 Metasploit module — {path}",
                f"https://www.rapid7.com/db/modules/{path}/",
                "Rapid7 Metasploit",
            )

    return links[:30]


def assurance_for_finding(
    finding: dict,
    *,
    intelligence: dict | None = None,
    validations: list[dict] | None = None,
    evidence: list[dict] | None = None,
) -> dict[str, str | float]:
    validations = validations or []
    evidence = evidence or []
    intel = intelligence or {}

    validated = [v for v in validations if v.get("status") == "VALIDATED"]
    rejected = [v for v in validations if v.get("status") == "NOT_VALIDATED"]
    inconclusive = [v for v in validations if v.get("status") == "INCONCLUSIVE"]

    if validated:
        last = validated[-1]
        evidence_id = last.get("evidence_id")
        evidence_ok = any(e.get("evidence_id") == evidence_id and e.get("sha256") for e in evidence) if evidence_id else False
        return {
            "level": "CONFIRMED",
            "score": 1.0 if evidence_ok else 0.95,
            "display": "CONFIRMED — operator validated with evidence" if evidence_ok else "CONFIRMED — validation record present",
            "basis": f"Validation {last.get('validation_id') or ''} recorded as VALIDATED by {last.get('operator') or 'operator'}" + (f" and linked to hashed evidence {evidence_id}." if evidence_ok else "."),
        }
    if rejected:
        last = rejected[-1]
        return {
            "level": "NOT_CONFIRMED",
            "score": 0.9,
            "display": "NOT CONFIRMED — validation did not reproduce the condition",
            "basis": f"Validation {last.get('validation_id') or ''} is NOT_VALIDATED; see the validation note/evidence for the reason.",
        }
    if inconclusive:
        last = inconclusive[-1]
        return {
            "level": "INCONCLUSIVE",
            "score": 0.5,
            "display": "INCONCLUSIVE — validation attempted but evidence is insufficient",
            "basis": f"Validation {last.get('validation_id') or ''} is INCONCLUSIVE and requires additional non-destructive evidence.",
        }

    app = intel.get("applicability") or {}
    app_status = _norm(app.get("status")).upper()
    app_conf = _pct(app.get("confidence"))
    finding_conf = _pct(finding.get("confidence"))
    module_count = int(intel.get("module_count") or 0)

    if app_status == "LIKELY" and app_conf >= 0.8 and finding_conf >= 0.75:
        return {
            "level": "CORROBORATED",
            "score": min(0.89, (app_conf + finding_conf) / 2),
            "display": "CORROBORATED — scanner evidence plus version/applicability match",
            "basis": f"Scanner confidence is {round(finding_conf * 100)}% and exploit-intelligence applicability is LIKELY at {round(app_conf * 100)}%. This is strong corroboration but is not an operator validation.",
        }
    if app_status == "UNLIKELY" and app_conf >= 0.7:
        return {
            "level": "LIKELY_FALSE_POSITIVE",
            "score": 0.25,
            "display": "LIKELY FALSE POSITIVE — observed version/applicability does not align",
            "basis": f"Exploit-intelligence applicability is UNLIKELY at {round(app_conf * 100)}% confidence. Retain the scanner evidence but do not treat the finding as confirmed.",
        }

    extra = f" A local Metasploit candidate exists ({module_count} candidate{'s' if module_count != 1 else ''}), but module availability is not proof of exploitability." if module_count else ""
    return {
        "level": "DETECTED",
        "score": max(0.2, min(0.7, finding_conf or 0.4)),
        "display": "DETECTED — scanner evidence only; operator validation not recorded",
        "basis": f"The condition was detected by assessment tooling with reported confidence {round(finding_conf * 100)}%. No evidence-backed operator validation record exists.{extra}",
    }


def enrich_findings(
    findings: list[dict],
    *,
    exploit_intelligence: list[dict],
    validations: list[dict],
    evidence: list[dict],
) -> list[dict]:
    intel_map = {i.get("finding_id"): i for i in exploit_intelligence}
    validation_map: dict[str, list[dict]] = {}
    for val in validations:
        validation_map.setdefault(val.get("finding_id"), []).append(val)

    enriched: list[dict] = []
    for raw in findings:
        finding = deepcopy(raw)
        fid = finding.get("finding_id")
        intel = intel_map.get(fid) or {}
        assurance = assurance_for_finding(
            finding,
            intelligence=intel,
            validations=validation_map.get(fid, []),
            evidence=evidence,
        )
        finding["assessment_assurance"] = assurance
        finding["technical_impact"] = technical_impact(finding)
        finding["safe_validation_procedure"] = safe_validation_procedure(finding, intel)
        finding["research_links"] = research_links(finding, intel)
        finding["public_references"] = intel.get("public_references") or research_references(finding)
        finding["safe_check_code"] = safe_check_code(finding)
        finding["threat_context"] = intel.get("threat_context") or {}
        finding["priority_context"] = intel.get("priority_context") or "Not enriched yet; verify affected version and review public sources."
        finding["validation_display"] = assurance["display"]
        finding["validation_basis"] = assurance["basis"]
        enriched.append(finding)
    return enriched
