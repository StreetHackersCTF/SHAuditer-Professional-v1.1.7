"""Explicit, branded, TLS-only, single-client assessment report delivery.

Industry-style subject/body templates contain no finding details unless the operator
adds and reviews them. No message is sent during preview or without per-send consent.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from pathlib import Path
from string import Template
import json
import os
import re
import smtplib
import ssl

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$")
DEFAULT_STREET_HACKERS_EMAIL = "streethackers03012026@gmail.com"
DEFAULT_GMAIL_SMTP_HOST = "smtp.gmail.com"


def sender_address(environ=None) -> str:
    """Visible team sender; may be overridden for a future organization mailbox."""
    env = os.environ if environ is None else environ
    return str(env.get("SHAUDITER_SMTP_FROM") or DEFAULT_STREET_HACKERS_EMAIL).strip()


def smtp_status(environ=None) -> dict:
    """Report readiness without showing secrets or claiming untested connectivity."""
    env = os.environ if environ is None else environ
    sender = sender_address(env)
    host = str(env.get("SHAUDITER_SMTP_HOST") or
               (DEFAULT_GMAIL_SMTP_HOST if sender == DEFAULT_STREET_HACKERS_EMAIL else "")).strip()
    username = str(env.get("SHAUDITER_SMTP_USER") or
                   (sender if host == DEFAULT_GMAIL_SMTP_HOST else "")).strip()
    password_present = bool(env.get("SHAUDITER_SMTP_PASSWORD"))
    # Gmail SMTP requires authentication, but other team-owned relays may use IP allowlists.
    ready = bool(host and sender and (host != DEFAULT_GMAIL_SMTP_HOST or (username and password_present)))
    if not host:
        hint = "Configure your SMTP relay host and verify the FROM identity."
    elif host == DEFAULT_GMAIL_SMTP_HOST and not password_present:
        hint = "Gmail sender selected. Set SHAUDITER_SMTP_PASSWORD using a Google App Password (if eligible)."
    else:
        hint = "SMTP settings provided; connectivity and recipient delivery are not yet verified."
    return {"sender": sender,
            "display_name": str(env.get("SHAUDITER_SMTP_DISPLAY_NAME") or "Street_Hackers Security Team"),
            "reply_to": str(env.get("SHAUDITER_SMTP_REPLY_TO") or ""),
            "ready": ready, "hint": hint}


FILES = {
    "bundle": ("assessment-bundle.zip", "application", "zip", False),
    "pdf": ("assessment.pdf", "application", "pdf", False),
    "html": ("assessment.html", "text", "html", False),
    "executive": ("executive-report.docx", "application", "vnd.openxmlformats-officedocument.wordprocessingml.document", True),
    "technical": ("technical-report.docx", "application", "vnd.openxmlformats-officedocument.wordprocessingml.document", True),
    "complete": ("complete-assessment.docx", "application", "vnd.openxmlformats-officedocument.wordprocessingml.document", True),
}

# Do not state findings are verified or fixed automatically; the attachments contain
# the assessment result, evidence status, caveats, and detailed recommendations.
EMAIL_TEMPLATES = {
    "final_delivery": {
        "label": "Final VAPT assessment report",
        "description": "Comprehensive formal handover: scope, results, coverage limits and next steps.",
        "subject": "[CONFIDENTIAL] VAPT Assessment & Remediation Report | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

Greetings from Street_Hackers Security Team.

Please find attached our Vulnerability Assessment and Penetration Testing (VAPT) deliverable prepared for ${organization} in accordance with the agreed authorization and scope.

ENGAGEMENT DETAILS
- Reference: ${audit_id}
- Assessed target / scope: ${target}
- Report issued (UTC): ${date}
- Document attached: ${attachment}
- Classification: CONFIDENTIAL - Client Authorized Personnel Only

ASSESSMENT OVERVIEW
${assessment_snapshot}

The attached report includes the testing approach and coverage limitations, observed security findings, available evidence and validation status, affected assets, recommended mitigations, and priorities for remediation. Automated detections should not be treated as proven exploitation unless the report explicitly documents validation.

REQUESTED CLIENT ACTIONS
1. Acknowledge safe receipt of this report and confirm that you can access the attachment.
2. Review the executive summary, technical findings and any scope or scanner limitations.
3. Triage verified Critical/High issues based on business impact and exposure; implement compensating controls when required.
4. Assign a remediation owner and target date to each applicable finding, recording risk acceptance where justified.
5. Schedule an agreed remediation review and evidence-based retest after corrective changes.

Please do not forward this assessment outside the agreed distribution list. For sensitive proofs or supporting evidence, request a client-approved secure exchange channel. Please do not send credentials or sensitive production data by reply email.

We are available for a technical walkthrough, clarification of findings, remediation planning and verification testing within the agreed engagement terms.

Regards,
Street_Hackers Security Team
Security Assessment & Research
${sender_email}
""",
    },
    "executive_delivery": {
        "label": "Executive / CISO report delivery",
        "description": "Leadership-facing summary of assessment risks, decisions and ownership.",
        "subject": "[CONFIDENTIAL] Executive Security Risk Review | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

Street_Hackers Security Team is sharing the attached security assessment deliverable for executive review at ${organization}.

Assessment reference: ${audit_id}
Authorized scope: ${target}
Attachment: ${attachment}
Report date (UTC): ${date}

MANAGEMENT SNAPSHOT
${assessment_snapshot}

The document outlines the risk context, principal observations, validation confidence, coverage limitations and corrective actions. These results are a time-bound assessment of tested assets, not an assurance that all risks are absent.

DECISIONS REQUESTED
- Confirm the executive sponsor and operational remediation owners.
- Prioritize verified material risks and agree on business-appropriate target dates.
- Document any exceptions and compensating controls in the organization's risk register.
- Arrange a short leadership debrief with the technical owner and schedule subsequent verification.

Please acknowledge receipt and restrict circulation to approved stakeholders. Technical exploit details and evidence should be handled through an approved confidential channel.

Best regards,
Street_Hackers Security Team
${sender_email}
""",
    },
    "urgent_findings": {
        "label": "Priority / urgent security notification",
        "description": "Escalation for a reviewer-confirmed priority issue; does not presume a breach.",
        "subject": "[ACTION REQUESTED][CONFIDENTIAL] Priority Finding Review | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

This is a priority security notification relating to the authorized assessment for ${organization}.

Reference: ${audit_id}
Affected assessment scope: ${target}
Evidence/report attached: ${attachment}

CURRENT RECORDED SUMMARY
${assessment_snapshot}

Please review the attached finding details promptly, including evidence, validation status and real-world applicability. This notice does not by itself establish compromise, exploitation in the wild, or an incident.

RECOMMENDED RESPONSE
1. Appoint an incident-response or application/infrastructure owner for triage.
2. Confirm asset exposure, severity, exploitability and potential business impact.
3. Apply approved containment or temporary compensating controls if warranted.
4. Agree on remediation action, responsible owner, and a target timeline under your established SLA.
5. Share a status acknowledgment by the agreed escalation channel and arrange a retest.

Do not reply with credentials, customer data, or unredacted exploit artifacts. For sensitive evidence, use a pre-approved secure channel.

Regards,
Street_Hackers Security Team
${sender_email}
""",
    },
    "remediation_followup": {
        "label": "Remediation status follow-up",
        "description": "Asks for owners, action dates, compensating controls and retest readiness.",
        "subject": "[FOLLOW-UP][CONFIDENTIAL] Remediation Tracking | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

We are following up on the security assessment provided to ${organization}.

Assessment: ${audit_id}
Scope: ${target}
Attached reference: ${attachment}

RECORDED REPORT SNAPSHOT
${assessment_snapshot}

For each agreed finding, please provide the remediation status (open / in progress / mitigated / accepted risk), assigned owner, expected completion date, change ticket, and any applied compensating controls. Please flag issues requiring vendor assistance or planned maintenance windows.

Once changes are complete, we recommend a focused retest with evidence of effective remediation. An implementation claim should not be treated as security verification until the affected control is reassessed.

Please acknowledge this follow-up and provide a proposed date for review. Sensitive proof material and credentials should not be transmitted by ordinary email.

Kind regards,
Street_Hackers Security Team
${sender_email}
""",
    },
    "retest_results": {
        "label": "Remediation retest results",
        "description": "Follow-up validation handoff without automatically claiming issues are fixed.",
        "subject": "[CONFIDENTIAL] Retest / Remediation Verification | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

Please find attached the available security verification / retest results for ${organization}.

Reference: ${audit_id}
Scope retested: ${target}
Report: ${attachment}
Date (UTC): ${date}

CURRENT ASSESSMENT SNAPSHOT
${assessment_snapshot}

The report documents checks performed, associated evidence, validation and remediation statuses, remaining risks, and exclusions. A finding must only be described as resolved when verification evidence supports it.

Please review unresolved items and update remediation or risk-acceptance records. Where changes are pending, agree on a subsequent validation window. We can arrange a technical review to explain residual exposure and recommended actions.

Please acknowledge receipt and limit forwarding to the authorized engagement stakeholders.

Regards,
Street_Hackers Security Team
${sender_email}
""",
    },
    "engagement_closure": {
        "label": "Engagement closure / formal handover",
        "description": "Administrative closure after the operator has independently confirmed handover.",
        "subject": "[CONFIDENTIAL] Security Assessment Handover | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

As part of the authorized security assessment engagement for ${organization}, Street_Hackers Security Team is providing the attached deliverable for your records.

Reference: ${audit_id}
Assessment scope: ${target}
Attached file: ${attachment}

REPORT RECORDS
${assessment_snapshot}

Please ensure that the report and evidence have been reviewed, remediation owners are identified, any risk acceptances have been documented, and outstanding action items have been assigned. Administrative handover does not mean all vulnerabilities have been remediated.

Please confirm receipt and advise whether any report clarifications remain. Any future testing or expanded scope requires appropriate authorization and scheduling. Handle report archives according to the agreed confidentiality and retention terms.

Thank you for your cooperation.

Kind regards,
Street_Hackers Security Team
${sender_email}
""",
    },
    "report_revision": {
        "label": "Updated / corrected assessment report",
        "description": "Send a revised report and ask recipients to supersede the prior copy.",
        "subject": "[REVISED][CONFIDENTIAL] Security Assessment Report | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

Street_Hackers Security Team is sharing an updated assessment deliverable for ${organization}.

Assessment reference: ${audit_id}
Scope: ${target}
Replacement attachment: ${attachment}
Report delivery date (UTC): ${date}

The attached file is intended to supersede the previously shared edition of this assessment. Please review the report's revision and change notes; do not assume that a particular finding has changed status unless the evidence supports that change.

CURRENT RECORDED SUMMARY
${assessment_snapshot}

Please confirm receipt of the revised document, replace prior working copies according to your organization's document-control procedure, and notify stakeholders who received the earlier version. We are available to explain specific corrections through an approved channel.

Classification: CONFIDENTIAL - authorized recipients only.

Regards,
Street_Hackers Security Team
${sender_email}
""",
    },
    "technical_debrief": {
        "label": "Technical debrief / remediation workshop",
        "description": "Invites a client technical team to review evidence and plan actions.",
        "subject": "[CONFIDENTIAL] Technical Security Debrief | ${organization} | ${audit_id}",
        "body": """Dear ${client_name},

We would like to arrange a technical walkthrough of the assessment completed for ${organization}.

Engagement: ${audit_id}
Target/scope: ${target}
Reference report: ${attachment}

FINDINGS AND COVERAGE CONTEXT
${assessment_snapshot}

PROPOSED DEBRIEF AGENDA
1. Confirm scope, assessment limitations and validation confidence.
2. Walk through prioritized findings, supporting evidence and realistic impact.
3. Review recommended fixes, compensating controls and implementation dependencies.
4. Assign remediation owners and agree on target dates.
5. Plan focused retesting and acceptance criteria for issue closure.

Please nominate a technical point of contact and suggest suitable meeting times using your approved coordination channel. Share any relevant change references securely; no passwords or production secrets are needed by email.

Kind regards,
Street_Hackers Security Team
${sender_email}
""",
    },
}


def validate_recipient(raw: str) -> str:
    addr = str(raw).strip()
    if len(addr) > 254 or any(c in addr for c in "\r\n,;<>") or not EMAIL_PATTERN.fullmatch(addr):
        raise ValueError("enter one valid recipient email address")
    if parseaddr(addr)[1] != addr:
        raise ValueError("invalid recipient email address")
    return addr


def _single_line(value: str, label: str, max_length: int = 180) -> str:
    value = str(value or "").strip()
    if len(value) > max_length or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"invalid {label}: provide one line up to {max_length} characters")
    return value


def _body(value: str) -> str:
    value = str(value or "").replace("\r\n", "\n").strip()
    if not value or len(value) > 15000 or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError("message must contain 1-15000 valid plain-text characters")
    return value + "\n"


def templates_catalog() -> list[dict]:
    return [{"id": key, "label": t["label"], "description": t["description"]}
            for key, t in EMAIL_TEMPLATES.items()]


def smtp_settings(environ=None) -> dict:
    env = environ if environ is not None else os.environ
    sender = sender_address(env)
    host = str(env.get("SHAUDITER_SMTP_HOST") or
               (DEFAULT_GMAIL_SMTP_HOST if sender == DEFAULT_STREET_HACKERS_EMAIL else "")).strip()
    try:
        port = int(env.get("SHAUDITER_SMTP_PORT") or "587")
    except ValueError as exc:
        raise ValueError("invalid SMTP port") from exc
    if not host or not sender:
        raise RuntimeError("SMTP server is not configured")
    if any(c in host for c in "/\\:\r\n") or not 1 <= port <= 65535:
        raise ValueError("invalid SMTP server configuration")
    validate_recipient(sender)
    name = _single_line(env.get("SHAUDITER_SMTP_DISPLAY_NAME") or "Street_Hackers Security Team", "sender display name", 80)
    reply_to = str(env.get("SHAUDITER_SMTP_REPLY_TO") or "").strip()
    if reply_to:
        validate_recipient(reply_to)
    ssl_mode = str(env.get("SHAUDITER_SMTP_SSL") or "").lower() in {"1", "true", "yes"}
    username = env.get("SHAUDITER_SMTP_USER") or (sender if host == DEFAULT_GMAIL_SMTP_HOST else "")
    password = env.get("SHAUDITER_SMTP_PASSWORD") or ""
    if host == DEFAULT_GMAIL_SMTP_HOST and (not username or not password):
        raise RuntimeError("Gmail SMTP requires an app credential: set SHAUDITER_SMTP_PASSWORD")
    return {"host": host, "port": port, "sender": sender, "display_name": name,
            "reply_to": reply_to, "username": username,
            "password": password, "ssl_mode": ssl_mode}



def assessment_snapshot_from_records(findings: list[dict], quality: dict | None = None) -> str:
    """Factual summary from the stored assessment; avoids unsupported risk claims.

    This is an excerpt for human review, never a substitute for technical evidence.
    """
    quality = quality or {}
    counts = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")}
    for finding in findings:
        level = str(finding.get("severity") or "INFORMATIONAL").upper()
        if level == "INFO":
            level = "INFORMATIONAL"
        counts[level if level in counts else "INFORMATIONAL"] += 1
    status = str(quality.get("status") or "NOT_ASSESSED").upper()
    if status not in {"INSUFFICIENT_COVERAGE", "REVIEW_REQUIRED", "VALIDATION_PENDING", "READY_FOR_HUMAN_REVIEW"}:
        status = "NOT_ASSESSED"
    unvalidated = quality.get("unvalidated_findings")
    unvalidated = int(unvalidated) if isinstance(unvalidated, int) and unvalidated >= 0 else "not evaluated"
    return (f"- Recorded findings: {len(findings)} (Critical {counts['CRITICAL']}, High {counts['HIGH']}, "
            f"Medium {counts['MEDIUM']}, Low {counts['LOW']}, Informational {counts['INFORMATIONAL']})\n"
            f"- Findings awaiting manual validation: {unvalidated}\n"
            f"- Assessment coverage/quality: {status}\n"
            "- Interpretation: scanner detections and coverage are not proof of compromise or a clean system. "
            "Refer to the report for evidence and exclusions.")


def compose_client_email(audit_id: str, *, target: str = "", format_name: str = "pdf",
                         template_name: str = "final_delivery", client_name: str = "",
                         client_organization: str = "", sender_email: str = "",
                         subject: str | None = None, body: str | None = None,
                         date: str | None = None, assessment_snapshot: str | None = None) -> dict:
    if format_name not in FILES:
        raise ValueError("unsupported report type")
    if template_name not in EMAIL_TEMPLATES:
        raise ValueError("unsupported email template")
    values = {
        "audit_id": _single_line(audit_id, "audit reference", 120),
        "target": _single_line(target, "assessment target", 250) or "scope defined in the attached report",
        "client_name": _single_line(client_name, "client contact name") or "Security Team",
        "organization": _single_line(client_organization, "client organization") or "Your Organization",
        "sender_email": _single_line(sender_email or sender_address(), "sender email", 254),
        "attachment": FILES[format_name][0],
        "date": date or datetime.now(timezone.utc).strftime("%d %B %Y"),
        "assessment_snapshot": (assessment_snapshot or
            "Refer to the attached report for the complete findings, validation confidence, and coverage limitations."),
    }
    template = EMAIL_TEMPLATES[template_name]
    # Text placeholders are only expanded once; client-entered text is never interpreted as a template.
    rendered_subject = _single_line(subject if subject is not None else Template(template["subject"]).substitute(values), "subject", 240)
    if not rendered_subject:
        raise ValueError("email subject is required")
    rendered_body = _body(body if body is not None else Template(template["body"]).substitute(values))
    return {"template": template_name, "subject": rendered_subject, "body": rendered_body,
            "client_name": values["client_name"], "client_organization": values["organization"],
            "attachment": values["attachment"], "audit_id": values["audit_id"]}


def mail_report(workspace: Path, audit_id: str, recipient: str, format_name: str, *,
                config: dict | None = None, consent: bool = False, target: str = "",
                template_name: str = "final_delivery", client_name: str = "",
                client_organization: str = "", subject: str | None = None,
                body: str | None = None, assessment_snapshot: str | None = None) -> dict:
    if consent is not True:
        raise PermissionError("explicit approval is required before each report email")
    recipient = validate_recipient(recipient)
    if format_name not in FILES:
        raise ValueError("unsupported report type")
    filename, major, minor, docx = FILES[format_name]
    workspace = Path(workspace).resolve()
    reports_dir = (workspace / "reports" / ("docx" if docx else "")).resolve()
    path = reports_dir / filename
    if not path.is_file() or path.is_symlink() or path.resolve().parent != reports_dir:
        raise FileNotFoundError("generate the requested report first")
    if path.stat().st_size > 15 * 1024 * 1024:
        raise ValueError("report exceeds safe 15 MiB attachment limit")
    settings = config if config is not None else smtp_settings()
    sender = validate_recipient(settings["sender"])
    display_name = _single_line(settings.get("display_name", "Street_Hackers Security Team"), "sender display name", 80)
    reply_to = settings.get("reply_to") or ""
    if reply_to:
        validate_recipient(reply_to)
    composed = compose_client_email(audit_id, target=target, format_name=format_name, template_name=template_name,
                                    client_name=client_name, client_organization=client_organization,
                                    sender_email=sender, subject=subject, body=body,
                                    assessment_snapshot=assessment_snapshot)
    message = EmailMessage()
    message["From"] = formataddr((display_name, sender))
    message["To"] = recipient
    if reply_to:
        message["Reply-To"] = reply_to
    message["Subject"] = composed["subject"]
    message["X-SHAuditer-Assessment"] = _single_line(audit_id, "assessment ID", 120)
    message.set_content(composed["body"])
    message.add_attachment(path.read_bytes(), maintype=major, subtype=minor, filename=filename)
    context = ssl.create_default_context()
    server_class = smtplib.SMTP_SSL if settings.get("ssl_mode") else smtplib.SMTP
    with server_class(settings["host"], settings["port"], timeout=18,
                      **({"context": context} if settings.get("ssl_mode") else {})) as conn:
        if not settings.get("ssl_mode"):
            conn.ehlo()
            conn.starttls(context=context)  # Mandatory: never downgrade to plaintext.
            conn.ehlo()
        if settings.get("username"):
            conn.login(
                settings["username"],
                settings.get("password") or "",
                initial_response_ok=False,
            )
        conn.send_message(message)
    record = {"audit_id": audit_id, "recipient": recipient, "sender": sender, "template": template_name,
              "report": filename, "sent_at": datetime.now(timezone.utc).isoformat(), "status": "SENT", "delivery_stage": "SMTP_ACCEPTED"}
    journal = workspace / "metadata" / "email-delivery.jsonl"
    journal.parent.mkdir(parents=True, exist_ok=True)
    with journal.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record
