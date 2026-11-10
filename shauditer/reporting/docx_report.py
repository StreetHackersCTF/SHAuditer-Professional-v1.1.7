from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Iterable

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.shared import Inches, Pt, RGBColor


PRODUCT = "SHAuditer"
FULL_NAME = "Smart Hybrid Automated Security Auditor"
VERSION = "1.1.7"
QUOTE = "We don't trust security. We test it."
TEAM_NAME = "Street_Hackers"
AUDITED_BY = "Team Street_Hackers"
REPORT_LOGO = Path(__file__).resolve().parents[1] / "gui" / "static" / "assets" / "street_hackers_logo.png"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "INFO": 4}
SEVERITY_FILL = {
    "CRITICAL": "7F1D1D",
    "HIGH": "9A3412",
    "MEDIUM": "854D0E",
    "LOW": "365314",
    "INFORMATIONAL": "1E3A5F",
    "INFO": "1E3A5F",
}


def _text(value, default="—") -> str:
    if value is None:
        return default
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(x) for x in value) or default
    value = str(value).strip()
    return value or default




def _add_hyperlink(paragraph, text: str, url: str) -> None:
    """Add a clickable external hyperlink to a paragraph."""
    r_id = paragraph.part.relate_to(url, RT.HYPERLINK, is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), r_id)
    run = OxmlElement("w:r")
    props = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "2563EB")
    props.append(color)
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    props.append(underline)
    run.append(props)
    text_node = OxmlElement("w:t")
    text_node.text = text
    run.append(text_node)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


def _research_links(doc: Document, finding: dict) -> None:
    links = finding.get("research_links") or finding.get("public_references") or []
    if not links:
        doc.add_paragraph("No public research references were derived from the available finding data.")
        return
    for link in links:
        p = doc.add_paragraph(style="List Bullet")
        source = str(link.get("source") or "Reference")
        p.add_run(f"{source}: ").bold = True
        _add_hyperlink(p, str(link.get("label") or link.get("url")), str(link.get("url") or ""))


def _assurance_label(finding: dict) -> str:
    assurance = finding.get("assessment_assurance") or {}
    raw = str(assurance.get("level") or finding.get("validation_status") or "DETECTED").upper()
    labels = {
        "CONFIRMED": "Confirmed",
        "CORROBORATED": "Corroborated",
        "DETECTED": "Detected",
        "INCONCLUSIVE": "Inconclusive",
        "NOT_CONFIRMED": "Not confirmed",
        "LIKELY_FALSE_POSITIVE": "Likely false positive",
    }
    return labels.get(raw, raw.replace("_", " ").title())


def _validation_record_label(finding: dict) -> str:
    status = str(finding.get("validation_status") or "").upper()
    return {
        "VALIDATED": "VALIDATED — evidence-backed validation record",
        "NOT_VALIDATED": "NOT VALIDATED — validation did not reproduce the condition",
        "INCONCLUSIVE": "INCONCLUSIVE — validation evidence is insufficient",
        "UNVALIDATED": "NOT YET OPERATOR-VALIDATED",
        "": "NO VALIDATION RECORD",
    }.get(status, status.replace("_", " "))


def _exploitability_label(finding: dict) -> str:
    explicit = str(finding.get("exploitability") or "").upper()
    if finding.get("access_status") == "CONFIRMED":
        return f"ACCESS CONFIRMED — {finding.get('access_type') or 'validated access'}"
    if explicit == "CONFIRMED":
        return "VULNERABLE CONDITION CONFIRMED; EXPLOITATION NOT NECESSARILY PERFORMED"
    if explicit and explicit != "UNKNOWN":
        return explicit.replace("_", " ")
    level = str((finding.get("assessment_assurance") or {}).get("level") or "").upper()
    if level == "CONFIRMED":
        return "VULNERABLE CONDITION CONFIRMED; EXPLOITATION NOT NECESSARILY PERFORMED"
    if level == "CORROBORATED":
        return "POTENTIALLY EXPLOITABLE — APPLICABILITY CORROBORATED, NOT DEMONSTRATED"
    if level == "LIKELY_FALSE_POSITIVE":
        return "UNLIKELY BASED ON CURRENT APPLICABILITY EVIDENCE"
    return "NOT DEMONSTRATED"

def _pct(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "—"
    if v <= 1:
        v *= 100
    return f"{v:.0f}%"


def _set_cell_fill(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def _set_cell_text_color(cell, color: str) -> None:
    for paragraph in cell.paragraphs:
        for run in paragraph.runs:
            run.font.color.rgb = __import__("docx").shared.RGBColor.from_string(color)


def _repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def _prevent_row_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def _set_cell_margins(cell, top=80, start=90, bottom=80, end=90):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcMar = tcPr.first_child_found_in("w:tcMar")
    if tcMar is None:
        tcMar = OxmlElement("w:tcMar")
        tcPr.append(tcMar)
    for m, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tcMar.find(qn(f"w:{m}"))
        if node is None:
            node = OxmlElement(f"w:{m}")
            tcMar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def _configure_document(doc: Document, *, title: str, audit_id: str, target: str) -> None:
    section = doc.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)

    styles = doc.styles
    styles["Normal"].font.name = "Aptos"
    styles["Normal"].font.size = Pt(9.5)
    styles["Title"].font.name = "Aptos Display"
    styles["Title"].font.size = Pt(30)
    styles["Heading 1"].font.name = "Aptos Display"
    styles["Heading 1"].font.size = Pt(19)
    styles["Heading 2"].font.name = "Aptos Display"
    styles["Heading 2"].font.size = Pt(14)
    styles["Heading 3"].font.name = "Aptos Display"
    styles["Heading 3"].font.size = Pt(11.5)

    core = doc.core_properties
    core.title = title
    core.subject = f"Authorized security assessment {audit_id}"
    core.author = AUDITED_BY
    core.keywords = "SHAuditer, VA/PT, security assessment, vulnerability assessment"
    core.comments = "Generated by SHAuditer for Team Street_Hackers. Evidence-backed validation is distinguished from scanner detection."

    header = section.header
    p = header.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run(f"{PRODUCT}  |  {audit_id}  |  {target}  |  Audited by {TEAM_NAME}")
    r.font.size = Pt(7.5)

    footer = section.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(f"{FULL_NAME} · v{VERSION} · Team {TEAM_NAME} · Confidential assessment output")
    r.font.size = Pt(7.5)


def _cover(doc: Document, report: dict, report_type: str) -> None:
    audit = report["audit"]

    if REPORT_LOGO.is_file():
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        try:
            p.add_run().add_picture(str(REPORT_LOGO), width=Inches(1.45))
        except Exception:
            pass

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.space_after = Pt(4)
    r = p.add_run("SHAuditer")
    r.bold = True
    r.font.size = Pt(38)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(FULL_NAME)
    r.font.size = Pt(14)

    doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(report_type.upper())
    r.bold = True
    r.font.size = Pt(20)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(_text(audit.get("target")))
    r.bold = True
    r.font.size = Pt(16)

    doc.add_paragraph()
    table = doc.add_table(rows=0, cols=2)
    table.style = "Light Shading Accent 1"
    for label, value in (
        ("Audit ID", audit.get("audit_id")),
        ("Target", audit.get("target")),
        ("Profile", audit.get("profile")),
        ("Assessment state", audit.get("state")),
        ("Created", audit.get("created_at")),
        ("Updated", audit.get("updated_at")),
        ("Report generated", report.get("generated_at")),
        ("Framework", f"{FULL_NAME} v{VERSION}"),
        ("Audited by", AUDITED_BY),
        ("Classification", (report.get("nist_profile") or {}).get("classification", "CONFIDENTIAL")),
        ("Client", (report.get("nist_profile") or {}).get("client_organization", "Not provided")),
        ("Guidance", "NIST SP 800-115-aligned; not NIST-certified"),
        ("Audit identity", f"{audit.get('audit_id')} · {TEAM_NAME}"),
    ):
        cells = table.add_row().cells
        cells[0].text = _text(label)
        cells[1].text = _text(value)
        cells[0].paragraphs[0].runs[0].bold = True
        for c in cells:
            c.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            _set_cell_margins(c)

    doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(f'“{QUOTE}”')
    r.italic = True
    r.font.size = Pt(10.5)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(f"Audited by {AUDITED_BY} · Developed by {TEAM_NAME}")
    r.font.size = Pt(9)
    # Start the executive section on a new page via page_break_before on its heading.
    # Avoid a trailing page-break paragraph spilling into an otherwise blank page.


def _heading(doc: Document, text: str, level: int = 1):
    return doc.add_heading(text, level=level)


def _bullets(doc: Document, items: Iterable[str]) -> None:
    for item in items:
        p = doc.add_paragraph(style="List Bullet")
        p.add_run(str(item))


def _table(doc: Document, headers: list[str], rows: Iterable[Iterable], widths: list[float] | None = None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Light Shading Accent 1"
    if widths:
        table.autofit = False
    hdr = table.rows[0]
    _repeat_table_header(hdr)
    _prevent_row_split(hdr)
    for idx, header in enumerate(headers):
        hdr.cells[idx].text = str(header)
        _set_cell_fill(hdr.cells[idx], "1F2937")
        _set_cell_text_color(hdr.cells[idx], "FFFFFF")
        hdr.cells[idx].paragraphs[0].runs[0].bold = True
        if widths:
            hdr.cells[idx].width = Inches(widths[idx])
        _set_cell_margins(hdr.cells[idx])

    for values in rows:
        row = table.add_row()
        _prevent_row_split(row)
        cells = row.cells
        values = list(values)
        for idx in range(len(headers)):
            cells[idx].text = _text(values[idx] if idx < len(values) else "")
            cells[idx].vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
            if widths:
                cells[idx].width = Inches(widths[idx])
            _set_cell_margins(cells[idx])
    return table


def _severity_summary(doc: Document, report: dict) -> None:
    s = report["summary"]
    rows = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        rows.append((sev, s["severity"].get(sev, 0)))
    table = _table(doc, ["Severity", "Count"], rows, [2.2, 1.2])
    for row in table.rows[1:]:
        sev = row.cells[0].text.upper()
        fill = SEVERITY_FILL.get(sev)
        if fill:
            _set_cell_fill(row.cells[0], fill)
            _set_cell_text_color(row.cells[0], "FFFFFF")
            row.cells[0].paragraphs[0].runs[0].bold = True


def _risk_statement(report: dict) -> str:
    sev = report["summary"]["severity"]
    if sev.get("CRITICAL", 0):
        return "Critical risk: at least one critical-severity finding requires immediate triage and validation."
    if sev.get("HIGH", 0):
        return "High risk: high-severity findings should be prioritized for remediation and evidence-backed validation."
    if sev.get("MEDIUM", 0):
        return "Moderate risk: the assessment identified medium-severity weaknesses requiring planned remediation."
    if report["findings"]:
        return "Low observed risk: only low/informational findings were recorded in this assessment."
    return "No normalized vulnerability findings were recorded. This does not prove that the target is vulnerability-free."


def _top_findings(report: dict, n=8) -> list[dict]:
    return sorted(
        report["findings"],
        key=lambda f: (SEVERITY_ORDER.get(str(f.get("severity", "INFO")).upper(), 9), -float(f.get("priority_score") or 0)),
    )[:n]


def _generic_mitigation(finding: dict) -> str:
    sev = str(finding.get("severity") or "INFORMATIONAL").upper()
    title = str(finding.get("title") or "the affected component")
    if sev in {"CRITICAL", "HIGH"}:
        return (
            f"Prioritize {title}: confirm the affected version/configuration, apply the vendor fix or supported upgrade, "
            "reduce external exposure until remediation is complete, and re-test after the change."
        )
    if sev == "MEDIUM":
        return (
            f"Schedule remediation for {title}: harden the affected configuration, apply available updates, restrict unnecessary "
            "network/application exposure, and verify the control with a targeted re-test."
        )
    return (
        f"Review {title} as part of normal hardening: remove unnecessary exposure, apply supported configuration guidance, "
        "and confirm the issue is no longer observable during the next assessment."
    )


def _finding_mitigation(finding: dict) -> tuple[str, str]:
    remediation = str(finding.get("remediation") or "").strip()
    if remediation:
        return remediation, "Finding-specific guidance"
    return _generic_mitigation(finding), "Generic SHAuditer guidance (scanner did not provide remediation text)"


def _executive_body(doc: Document, report: dict) -> None:
    audit = report["audit"]
    s = report["summary"]
    first_heading = _heading(doc, "1. Executive Summary")
    first_heading.paragraph_format.page_break_before = True
    doc.add_paragraph(
        f"SHAuditer assessed {audit['target']} under the '{audit['profile']}' profile. "
        f"The assessment recorded {len(report['findings'])} normalized findings, including "
        f"{s['severity'].get('CRITICAL', 0)} critical and {s['severity'].get('HIGH', 0)} high-severity findings. "
        f"{s['validated']} finding(s) have evidence-backed validation records."
    )
    p = doc.add_paragraph()
    r = p.add_run(_risk_statement(report))
    r.bold = True

    _heading(doc, "2. Risk Snapshot")
    _severity_summary(doc, report)
    _bullets(doc, [
        f"Confirmed findings (evidence-backed validation): {s.get('confirmed', s['validated'])}",
        f"Corroborated findings (scanner + applicability evidence): {s.get('corroborated', 0)}",
        f"Detected-only findings awaiting operator validation: {s.get('detected_only', s['unvalidated'])}",
        f"Likely false positives / applicability mismatch: {s.get('likely_false_positive', 0)}",
        f"Findings with exploit intelligence: {s['intelligence_analyzed']}",
        f"Read-only local exploit candidates: {s['metasploit_candidates']}",
        f"Evidence-backed recorded access: {s['access_confirmed']}",
    ])

    _heading(doc, "2.1 Validation Coverage and Assurance", 2)
    total = max(1, len(report.get("findings") or []))
    confirmed = int(s.get("confirmed", 0))
    corroborated = int(s.get("corroborated", 0))
    detected = int(s.get("detected_only", 0))
    doc.add_paragraph(
        f"Validation coverage: {confirmed}/{len(report.get('findings') or [])} findings are evidence-backed CONFIRMED. "
        f"{corroborated} additional finding(s) are CORROBORATED by scanner evidence and version/applicability analysis. "
        f"{detected} finding(s) remain DETECTED only. SHAuditer does not convert scanner detections into CONFIRMED findings without supporting evidence."
    )

    _heading(doc, "2.2 Assessment Quality and Limitations", 2)
    quality = report.get("assessment_quality") or {}
    doc.add_paragraph(
        f"Assessment readiness: {quality.get('status', 'NOT_EVALUATED')}. "
        f"Core scanner coverage: {quality.get('core_scanners_successful', 0)}/"
        f"{quality.get('core_scanners_expected', 3)}. "
        "Scanner errors or unavailable modules must not be interpreted as a clean result."
    )
    limitations = quality.get("limitations") or []
    _bullets(doc, limitations[:12] if limitations else [
        "Automated coverage does not replace human review, threat modeling, and targeted validation."
    ])

    _heading(doc, "3. Highest-Priority Findings")
    rows = []
    for f in _top_findings(report, 10):
        rows.append((
            f.get("finding_id"), f.get("severity"), f.get("priority_score"), f.get("title"),
            _assurance_label(f),
        ))
    _table(doc, ["ID", "Severity", "Priority", "Finding", "Assessment assurance"], rows, [0.8, 0.9, 0.7, 3.0, 1.8])

    _heading(doc, "4. Remediation Priorities")
    for f in _top_findings(report, 8):
        mitigation, source = _finding_mitigation(f)
        p = doc.add_paragraph(style="List Number")
        r = p.add_run(f"{f.get('finding_id')} — {f.get('title')}: ")
        r.bold = True
        p.add_run(mitigation)
        p.add_run(f" [{source}]").italic = True

    _heading(doc, "5. Management Conclusion")
    doc.add_paragraph(
        "Prioritize remediation by demonstrated impact, exposure, validation status, and business criticality rather than CVSS alone. "
        "After fixes are deployed, run a focused re-test and retain evidence of closure for each critical/high finding."
    )


def _recon_body(doc: Document, report: dict) -> None:
    recon = report["recon"]
    _heading(doc, "3. Reconnaissance and Attack Surface")
    doc.add_paragraph(
        "Reconnaissance establishes the observable attack surface used by later vulnerability and applicability decisions. "
        "The tables below reflect normalized scanner output; raw evidence remains stored in the audit workspace."
    )

    assets = recon.get("assets") or []
    _heading(doc, "3.1 Asset Inventory", 2)
    asset_rows = []
    for a in assets:
        if isinstance(a, str):
            asset_rows.append((a, "—"))
        else:
            asset_rows.append((_text(a.get("addresses") or a.get("address") or a.get("host")), _text(a.get("hostnames") or a.get("hostname"))))
    _table(doc, ["Address / Asset", "Hostnames"], asset_rows or [("No normalized assets recorded", "—")], [3.2, 3.4])

    _heading(doc, "3.2 Discovered Services", 2)
    service_rows = []
    for s in recon.get("services") or []:
        service_rows.append((
            s.get("address") or s.get("host") or report["audit"].get("target"),
            s.get("port"), s.get("protocol") or "tcp", s.get("service") or s.get("name"),
            " ".join(str(x) for x in (s.get("product"), s.get("version"), s.get("extrainfo")) if x),
            s.get("url") or (f"HTTP {s.get('status_code')} · {s.get('title') or ''}" if s.get("status_code") else ""),
        ))
    _table(doc, ["Host", "Port", "Proto", "Service", "Product / Version", "Web / Notes"], service_rows or [("No normalized services recorded", "—", "—", "—", "—", "—")], [1.35, 0.6, 0.55, 1.0, 2.05, 1.7])

    _heading(doc, "3.3 Technology Fingerprints", 2)
    tech_rows = []
    for t in recon.get("technologies") or []:
        if isinstance(t, str):
            tech_rows.append((report["audit"].get("target"), t))
        else:
            tech_rows.append((t.get("host") or t.get("asset") or report["audit"].get("target"), t.get("technology") or t.get("name")))
    _table(doc, ["Host", "Technology"], tech_rows or [("—", "No normalized technology fingerprints recorded")], [3.0, 3.6])

    _heading(doc, "3.4 Module Execution Health", 2)
    module_rows = []
    for run in report.get("module_runs") or []:
        module_rows.append((run.get("module"), run.get("status"), run.get("started_at") or run.get("created_at"), run.get("finished_at") or run.get("updated_at"), run.get("error") or run.get("message") or ""))
    _table(doc, ["Module", "Status", "Started", "Finished", "Notes"], module_rows or [("—", "—", "—", "—", "No module-run records")], [1.1, 0.9, 1.25, 1.25, 2.4])


def _vulnerability_body(doc: Document, report: dict) -> None:
    _heading(doc, "4. Vulnerability Assessment")
    _severity_summary(doc, report)
    doc.add_paragraph(
        "Findings are normalized and prioritized using severity, confidence, exposure, evidence quality and exploitability context. "
        "The report distinguishes scanner DETECTION from CORROBORATION and evidence-backed CONFIRMATION so that every field is explained without overstating validation."
    )

    _heading(doc, "4.1 Finding Register", 2)
    rows = []
    for f in _top_findings(report, 1000):
        rows.append((f.get("finding_id"), f.get("severity"), f.get("priority_score"), f.get("title"), f.get("asset") or report["audit"].get("target"), _assurance_label(f)))
    _table(doc, ["ID", "Severity", "Priority", "Title", "Asset", "Assessment assurance"], rows or [("—", "—", "—", "No findings recorded", "—", "—")], [0.6, 0.75, 0.6, 2.3, 1.0, 1.55])

    _heading(doc, "4.2 Detailed Findings", 2)
    intel_by_finding = {i.get("finding_id"): i for i in report.get("exploit_intelligence") or []}
    val_by_finding: dict[str, list[dict]] = {}
    for v in report.get("validations") or []:
        val_by_finding.setdefault(v.get("finding_id"), []).append(v)
    sessions_by_finding: dict[str, list[dict]] = {}
    for s in report.get("sessions") or []:
        sessions_by_finding.setdefault(s.get("finding_id"), []).append(s)

    for f in _top_findings(report, 1000):
        _heading(doc, f"{f.get('finding_id')} — {f.get('title')}", 3)
        summary_table = _table(doc, ["Attribute", "Value"], [
            ("Severity", f.get("severity")),
            ("Priority", f"{f.get('priority_score', 0)} / 10"),
            ("Confidence", _pct(f.get("confidence"))),
            ("Asset", f.get("asset") or f.get("host") or f.get("matched_at")),
            ("Endpoint", f.get("endpoint") or f.get("matched_at")),
            ("CVE", _text(f.get("cves"))),
            ("CWE", _text(f.get("cwes"))),
            ("Scanner / template", f.get("template_id") or _text(f.get("sources") or f.get("source"))),
            ("Assessment assurance", _assurance_label(f)),
            ("Validation record state", _validation_record_label(f)),
            ("Exploitability", _exploitability_label(f)),
        ], [1.9, 4.95])
        sev = str(f.get("severity") or "INFO").upper()
        if sev in SEVERITY_FILL:
            _set_cell_fill(summary_table.rows[1].cells[1], SEVERITY_FILL[sev])
            _set_cell_text_color(summary_table.rows[1].cells[1], "FFFFFF")

        _heading(doc, "Description", 3)
        doc.add_paragraph(_text(f.get("description") or f.get("info"), "The scanner did not supply a narrative description; the finding metadata, affected surface, evidence, and validation plan are documented below."))

        _heading(doc, "Technical impact", 3)
        doc.add_paragraph(_text(f.get("technical_impact"), "Impact requires assessment against the affected component and business context."))

        _heading(doc, "Validation basis", 3)
        doc.add_paragraph(_text(f.get("validation_basis"), "No validation basis was recorded."))

        _heading(doc, "Safe validation procedure", 3)
        _bullets(doc, f.get("safe_validation_procedure") or ["Collect evidence that directly demonstrates the vulnerable condition without modifying target state."])

        _heading(doc, "Public research references", 3)
        _research_links(doc, f)

        intel = intel_by_finding.get(f.get("finding_id"))
        if intel:
            _heading(doc, "Exploit intelligence and applicability", 3)
            app = intel.get("applicability") or {}
            _table(doc, ["Attribute", "Value"], [
                ("Applicability", app.get("status", "UNKNOWN")),
                ("Applicability confidence", _pct(app.get("confidence"))),
                ("CVE intelligence", _text(intel.get("cves"))),
                ("Local candidate count", intel.get("module_count", 0)),
                ("Execution policy", "READ_ONLY_INTELLIGENCE_ONLY"),
            ], [2.2, 4.7])
            candidate_rows = []
            for cve, modules in (intel.get("metasploit_modules") or {}).items():
                for mod in modules:
                    candidate_rows.append((cve, mod.get("module"), mod.get("rank"), mod.get("check_supported"), mod.get("disclosure_date")))
            if candidate_rows:
                _table(doc, ["CVE", "Local module", "Rank", "Check", "Disclosure"], candidate_rows, [1.2, 3.4, 0.8, 0.7, 1.0])
            doc.add_paragraph(
                "Module discovery is exploit intelligence only. Review the linked Rapid7/GitHub/advisory references under operator control; SHAuditer does not embed runnable exploit or payload code in this report."
            )

        if val_by_finding.get(f.get("finding_id")):
            _heading(doc, "Validation history", 3)
            _table(doc, ["Status", "Method", "Operator", "Evidence", "Time"], [
                (v.get("status"), v.get("method"), v.get("operator"), v.get("evidence_id"), v.get("created_at"))
                for v in val_by_finding[f.get("finding_id")]
            ], [1.05, 2.5, 1.1, 1.5, 1.2])

        if sessions_by_finding.get(f.get("finding_id")):
            _heading(doc, "Recorded access", 3)
            _table(doc, ["Session", "Type", "Privilege", "Status", "Evidence"], [
                (s.get("session_id"), s.get("session_type"), s.get("privilege"), s.get("status"), s.get("evidence_id"))
                for s in sessions_by_finding[f.get("finding_id")]
            ], [1.2, 1.45, 1.2, 1.0, 1.9])

        mitigation, source = _finding_mitigation(f)
        _heading(doc, "Mitigation", 3)
        doc.add_paragraph(mitigation)
        p = doc.add_paragraph()
        r = p.add_run(source)
        r.italic = True
        r.font.size = Pt(8)


def _exploitation_body(doc: Document, report: dict) -> None:
    _heading(doc, "5. Exploit Intelligence, Validation and Access")
    doc.add_paragraph(
        "This section documents exploit research and validation state. Local Metasploit module discovery is read-only. "
        "SHAuditer does not treat a module match as successful exploitation and does not automatically execute payloads or create shells."
    )

    _heading(doc, "5.1 Exploit Intelligence", 2)
    intel_rows = []
    for i in report.get("exploit_intelligence") or []:
        app = i.get("applicability") or {}
        intel_rows.append((i.get("finding_id"), _text(i.get("cves")), app.get("status", "UNKNOWN"), _pct(app.get("confidence")), i.get("module_count", 0)))
    _table(doc, ["Finding", "CVEs", "Applicability", "Confidence", "Candidates"], intel_rows or [("—", "—", "—", "—", "No intelligence records")], [1.0, 2.1, 1.2, 1.0, 1.0])

    _heading(doc, "5.1.1 Per-Finding Intelligence Procedure", 3)
    if report.get("exploit_intelligence"):
        for i in report.get("exploit_intelligence") or []:
            playbook = i.get("operator_playbook") or {}
            p = doc.add_paragraph()
            r = p.add_run(f"{i.get('finding_id')} — {playbook.get('title') or 'Exploit intelligence'}")
            r.bold = True
            if playbook.get("validation_steps"):
                doc.add_paragraph("Assessment and safe-validation procedure:")
                _bullets(doc, playbook.get("validation_steps") or [])
            commands = playbook.get("metasploit_read_only_commands") or []
            if commands:
                doc.add_paragraph("Read-only Metasploit research commands (module discovery/metadata only):")
                for command in commands:
                    cp = doc.add_paragraph()
                    cr = cp.add_run(str(command))
                    cr.font.name = "Liberation Mono"
                    cr.font.size = Pt(8)
            fallback = playbook.get("no_module_research_plan") or []
            if fallback:
                doc.add_paragraph("No local module found — research plan:")
                _bullets(doc, fallback)
            refs = playbook.get("references") or []
            if refs:
                doc.add_paragraph("Public research references:")
                for ref in refs:
                    doc.add_paragraph(f"{ref.get('label')}: {ref.get('url')}")
            doc.add_paragraph(
                "Execution boundary: " + str(playbook.get("execution_boundary") or "NO_EXPLOIT_EXECUTION_OR_PAYLOAD_GENERATION")
            )
    else:
        doc.add_paragraph("Run exploit intelligence to generate per-finding research and validation procedures.")

    _heading(doc, "5.2 Operator Research Reviews", 2)
    _table(doc, ["Review", "Finding", "Decision", "Operator", "Module / Note"], [
        (r.get("review_id"), r.get("finding_id"), r.get("decision"), r.get("operator"), r.get("module") or r.get("note"))
        for r in report.get("exploit_reviews") or []
    ] or [("—", "—", "—", "—", "No reviews recorded")], [1.1, 1.0, 1.25, 1.0, 2.6])

    _heading(doc, "5.3 Validation Approvals", 2)
    _table(doc, ["Approval", "Finding", "Action", "Decision", "Operator", "Note"], [
        (a.get("approval_id"), a.get("finding_id"), str(a.get("action") or "").replace("_", " "), "APPROVED" if a.get("approved") else "DENIED", a.get("operator"), a.get("note"))
        for a in report.get("approvals") or []
    ] or [("—", "—", "—", "—", "—", "No approval records")], [0.9, 0.8, 1.35, 0.9, 1.0, 1.8])

    _heading(doc, "5.4 Validation Results", 2)
    _table(doc, ["Validation", "Finding", "Result", "Method", "Operator", "Evidence"], [
        (v.get("validation_id"), v.get("finding_id"), v.get("status"), v.get("method"), v.get("operator"), v.get("evidence_id"))
        for v in report.get("validations") or []
    ] or [("—", "—", "—", "—", "—", "No validation records")], [1.1, 0.9, 1.0, 2.3, 0.9, 1.4])

    _heading(doc, "5.5 Evidence-Backed Access Records", 2)
    _table(doc, ["Session", "Finding", "Type", "Privilege", "Status", "Operator", "Evidence"], [
        (s.get("session_id"), s.get("finding_id"), s.get("session_type"), s.get("privilege"), s.get("status"), s.get("operator"), s.get("evidence_id"))
        for s in report.get("sessions") or []
    ] or [("—", "—", "—", "—", "—", "—", "None recorded")], [0.9, 0.75, 1.15, 0.9, 0.8, 0.95, 1.35])

    _heading(doc, "5.6 Operator-Controlled Exploit Research Procedure", 2)
    doc.add_paragraph(
        "The following procedure is included for documentation and authorized operator review. It is intentionally non-operational: "
        "the report links to public advisory/module information but does not embed runnable exploit code, payloads, shell commands, or target-specific execution instructions."
    )
    _bullets(doc, [
        "Confirm written authorization, in-scope asset, allowed service/port, and any engagement limitations before validation activity.",
        "Confirm the exact product/version/configuration and compare it with vendor/NVD affected ranges before relying on a public exploit reference.",
        "Review public exploit/module metadata, reliability, prerequisites, authentication requirements, and stability warnings from authoritative sources.",
        "Prefer a non-destructive check or safe validation method when available; capture evidence before considering more intrusive manual testing.",
        "If the engagement separately authorizes manual exploitation, conduct it under the operator's established testing procedure outside SHAuditer's automatic execution path and preserve the resulting evidence.",
        "Import validation output/evidence into SHAuditer, record the operator decision, and regenerate the report so the finding changes from DETECTED/CORROBORATED to CONFIRMED only when evidence supports it.",
    ])

    _heading(doc, "5.7 Public Exploit and Advisory References", 2)
    any_refs = False
    for finding in _top_findings(report, 1000):
        if not (finding.get("research_links") or []):
            continue
        any_refs = True
        p = doc.add_paragraph()
        r = p.add_run(f"{finding.get('finding_id')} — {finding.get('title')}")
        r.bold = True
        _research_links(doc, finding)
    if not any_refs:
        doc.add_paragraph("No CVE/advisory/exploit-research links were available for the recorded findings.")


def _mitigation_body(doc: Document, report: dict) -> None:
    _heading(doc, "6. Mitigation and Remediation Plan")
    doc.add_paragraph(
        "Remediation should be sequenced by demonstrated exploitability, exposure, severity, confidence, and asset importance. "
        "Finding-specific scanner guidance is preserved when available; otherwise SHAuditer labels its generic hardening guidance explicitly."
    )
    rows = []
    for f in _top_findings(report, 1000):
        mitigation, source = _finding_mitigation(f)
        priority = "Immediate" if str(f.get("severity")).upper() == "CRITICAL" else "High" if str(f.get("severity")).upper() == "HIGH" else "Planned"
        rows.append((f.get("finding_id"), f.get("severity"), priority, f.get("title"), mitigation, source))
    _table(doc, ["ID", "Severity", "Remediation priority", "Finding", "Recommended action", "Guidance source"], rows or [("—", "—", "—", "No findings", "—", "—")], [0.7, 0.8, 1.1, 2.1, 3.0, 1.2])

    _heading(doc, "6.1 Verification of Remediation", 2)
    _bullets(doc, [
        "Re-scan the affected service or endpoint after the fix is deployed.",
        "Repeat the specific validation procedure used to confirm the original issue when it is safe and authorized to do so.",
        "Preserve closure evidence and link it to the original finding ID.",
        "Confirm compensating controls remain in place when full remediation cannot be completed immediately.",
        "Close the finding only after the observed vulnerable condition is no longer reproducible."
    ])


def _evidence_body(doc: Document, report: dict) -> None:
    _heading(doc, "7. Evidence and Audit Trail")
    _table(doc, ["Evidence ID", "Source", "Kind", "SHA-256", "Path / Timestamp"], [
        (e.get("evidence_id"), e.get("module"), e.get("kind"), e.get("sha256"), f"{e.get('path') or ''}\n{e.get('created_at') or ''}")
        for e in report.get("evidence") or []
    ] or [("—", "—", "—", "—", "No evidence records")], [1.4, 1.0, 1.2, 2.7, 2.1])


def _methodology_body(doc: Document, report: dict) -> None:
    _heading(doc, "2. Scope and Methodology")
    audit = report["audit"]
    _table(doc, ["Item", "Assessment value"], [
        ("Target", audit.get("target")),
        ("Profile", audit.get("profile")),
        ("Assessment state", audit.get("state")),
        ("Authorization model", "Operator-confirmed authorized security assessment"),
        ("Primary workflow", "Scope → Recon → Vulnerability Discovery → Correlation → Prioritization → Exploit Intelligence → Validation → Evidence → Mitigation → Report"),
    ], [2.0, 4.8])
    doc.add_paragraph(
        "The framework uses normalized data from reconnaissance and vulnerability tools, correlates duplicate observations, "
        "prioritizes findings using practical risk context, and separates exploit intelligence from evidence-backed validation."
    )


def _nist_engagement_body(doc: Document, report: dict) -> None:
    """NIST SP 800-115-aligned assessment record, not a compliance assertion."""
    profile = report.get("nist_profile") or {}
    scope = profile.get("scope") or {}
    engagement = profile.get("engagement") or {}
    _heading(doc, "NIST-Aligned Engagement Record")
    doc.add_paragraph(profile.get("label") or "NIST-aligned security assessment (not certified)")
    doc.add_paragraph(
        "NIST SP 800-115 is guidance on planning, conducting, analysing and reporting technical "
        "security assessments. It does not certify this report, the tooling, or the assessed system. "
        "Only completed actions with recorded evidence should be interpreted as tested."
    )
    _table(doc, ["Engagement attribute", "Documented value"], [
        ("Client organization", profile.get("client_organization", "Not provided")),
        ("Engagement reference", engagement.get("engagement_id", report["audit"]["audit_id"])),
        ("Authorized by / authorization", engagement.get("authorization_reference", "Not provided; confirm signed authorization")),
        ("Assessment lead", engagement.get("assessment_lead", profile.get("assessor", "Street_Hackers"))),
        ("Testing window", engagement.get("assessment_window", "Not provided")),
        ("Assessment type", engagement.get("assessment_type", "Authorized hybrid VA/PT")),
        ("Information classification", profile.get("classification", "CONFIDENTIAL")),
        ("Test environment", engagement.get("test_environment", "Not provided")),
        ("Rules of engagement", engagement.get("rules_of_engagement", "As agreed with the client; not supplied")),
        ("Constraints / exclusions", engagement.get("constraints", "See declared scope and limitations")),
    ], [2.1, 4.7])
    _heading(doc, "Authorized Scope and Exclusions", 2)
    doc.add_paragraph("In scope: " + _text(scope.get("in_scope") or report["audit"].get("target")))
    doc.add_paragraph("Out of scope: " + _text(scope.get("out_of_scope") or "Not specified"))
    doc.add_paragraph("Allowed ports: " + _text(scope.get("allowed_ports") or "Not further restricted"))
    doc.add_paragraph("Explicitly excluded ports: " + _text(scope.get("excluded_ports") or "Not specified"))
    _heading(doc, "Methodology and Assessment Procedures", 2)
    _table(doc, ["Stage", "Approach"], [(x.get("stage"), x.get("description")) for x in profile.get("methodology") or []], [1.65, 5.15])
    _heading(doc, "Tool Execution and Assessment Completeness", 2)
    statuses = profile.get("tool_execution") or {}
    _table(doc, ["Module execution result", "Count"], [(k, v) for k, v in sorted(statuses.items())] or [("No scanner runs", "0")], [3.2, 1.1])
    doc.add_paragraph("Assessment quality: " + _text(profile.get("coverage_status") or "Not determined"))
    for issue in (profile.get("limitations") or [])[:20]:
        doc.add_paragraph(str(issue), style="List Bullet")
    if not profile.get("limitations"):
        doc.add_paragraph("No automated coverage warnings; independent assurance and review are still required.")


def _nist_risk_register_body(doc: Document, report: dict) -> None:
    profile = report.get("nist_profile") or {}
    rows = profile.get("risk_register") or []
    _heading(doc, "Risk Register and Plan of Action & Milestones")
    doc.add_paragraph(
        "POA&M-style tracking worksheet. Proposed remediation items are not confirmed as assigned, "
        "implemented, accepted or closed. Client owners and deadlines must be agreed separately."
    )
    _table(doc, ["ID / severity", "Affected asset / weakness", "Validation", "Priority / owner", "Corrective action"], [
        (f"{r.get('finding_id')} / {r.get('severity')}",
         str(r.get("asset")) + "\n" + str(r.get("title")),
         r.get("validation"),
         str(r.get("priority")) + "\n" + str(r.get("owner")),
         r.get("recommended_action"))
        for r in rows[:300]
    ] or [("—", "No recorded findings", "Not applicable", "—", "Review scope and scanner coverage")], [1.1, 1.75, 1.05, 1.0, 2.0])
    if len(rows) > 300:
        doc.add_paragraph("Register abbreviated to 300 records; use the full JSON/CSV export for all records.")
    _heading(doc, "Remediation Ownership, Retest and Sign-off", 2)
    _bullets(doc, [
        "For each finding: agree system owner, corrective action, risk acceptance decision and target date.",
        "Retest using the same authorized scope; record testing date, result, evidence ID and residual risk.",
        "Do not mark an item remediated or validated based solely on a scanner rerun.",
        "Report approval: " + str(profile.get("report_approval") or "Pending review"),
    ])
    _heading(doc, "Standards and Supporting References", 2)
    for ref in profile.get("references") or []:
        p = doc.add_paragraph(style="List Bullet")
        p.add_run(str(ref.get("name") or "Reference") + " — ")
        _add_hyperlink(p, str(ref.get("url") or ""), str(ref.get("url") or ""))


def _conclusion(doc: Document, report: dict) -> None:
    _heading(doc, "8. Conclusion")
    doc.add_paragraph(report.get("note") or "")
    doc.add_paragraph(
        "This report should be interpreted together with the defined scope and assessment limitations. Absence of a finding does not prove absence of a vulnerability."
    )


def _save_with_mirror(doc: Document, workspace_docx: Path, mirror_docx: Path | None) -> None:
    workspace_docx.parent.mkdir(parents=True, exist_ok=True)
    doc.save(workspace_docx)
    workspace_docx.chmod(0o600)
    if mirror_docx is not None:
        try:
            mirror_docx.parent.mkdir(parents=True, exist_ok=True)
            mirror_docx.write_bytes(workspace_docx.read_bytes())
            mirror_docx.chmod(0o600)
        except OSError:
            # Source-tree mirror is convenience only; workspace copy remains authoritative.
            pass


def _new_doc(report: dict, report_type: str) -> Document:
    doc = Document()
    audit = report["audit"]
    _configure_document(doc, title=f"{PRODUCT} {report_type} — {audit['audit_id']}", audit_id=audit["audit_id"], target=audit["target"])
    _cover(doc, report, report_type)
    return doc


def generate_docx_reports(report: dict, workspace: Path, *, project_reports_root: Path | None = None) -> dict[str, str]:
    audit_id = report["audit"]["audit_id"]
    workspace_dir = workspace / "reports" / "docx"
    mirror_dir = (project_reports_root / audit_id) if project_reports_root else None

    # Executive report
    executive = _new_doc(report, "Executive Report")
    _executive_body(executive, report)
    _heading(executive, "Assessment Basis and Qualification")
    executive.add_paragraph((report.get("nist_profile") or {}).get("caveat") or "Risk conclusions require evidence and scope review.")
    executive.add_paragraph("NIST SP 800-115-aligned format; no assertion of NIST certification or exhaustive testing.")
    executive_path = workspace_dir / "executive-report.docx"
    _save_with_mirror(executive, executive_path, mirror_dir / executive_path.name if mirror_dir else None)

    # Technical report
    technical = _new_doc(report, "Technical Report")
    _executive_body(technical, report)
    _methodology_body(technical, report)
    _nist_engagement_body(technical, report)
    _recon_body(technical, report)
    _vulnerability_body(technical, report)
    _exploitation_body(technical, report)
    _mitigation_body(technical, report)
    _nist_risk_register_body(technical, report)
    _evidence_body(technical, report)
    _conclusion(technical, report)
    technical_path = workspace_dir / "technical-report.docx"
    _save_with_mirror(technical, technical_path, mirror_dir / technical_path.name if mirror_dir else None)

    # Complete assessment: deliberately comprehensive and appendices-friendly.
    complete = _new_doc(report, "Complete Assessment")
    _executive_body(complete, report)
    _methodology_body(complete, report)
    _nist_engagement_body(complete, report)
    _recon_body(complete, report)
    _vulnerability_body(complete, report)
    _exploitation_body(complete, report)
    _mitigation_body(complete, report)
    _nist_risk_register_body(complete, report)
    _evidence_body(complete, report)
    _heading(complete, "8. Appendix — Raw Record Counts")
    _table(complete, ["Record type", "Count"], [
        ("Assets", len(report.get("recon", {}).get("assets") or [])),
        ("Services", len(report.get("recon", {}).get("services") or [])),
        ("Technologies", len(report.get("recon", {}).get("technologies") or [])),
        ("Findings", len(report.get("findings") or [])),
        ("Exploit intelligence records", len(report.get("exploit_intelligence") or [])),
        ("Approvals", len(report.get("approvals") or [])),
        ("Validations", len(report.get("validations") or [])),
        ("Recorded sessions", len(report.get("sessions") or [])),
        ("Evidence artifacts", len(report.get("evidence") or [])),
    ], [3.5, 1.5])
    _heading(complete, "9. Conclusion")
    complete.add_paragraph(report.get("note") or "")
    complete_path = workspace_dir / "complete-assessment.docx"
    _save_with_mirror(complete, complete_path, mirror_dir / complete_path.name if mirror_dir else None)

    return {
        "executive": str(executive_path),
        "technical": str(technical_path),
        "complete": str(complete_path),
        "mirror_dir": str(mirror_dir) if mirror_dir else "",
    }
