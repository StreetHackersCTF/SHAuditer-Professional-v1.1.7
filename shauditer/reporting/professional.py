"""Self-contained HTML and print-ready PDF assessment exports."""
from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
import json


def _e(value):
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    return escape(str(value if value is not None else ""), quote=True)


def build_workflow(report: dict) -> list[dict]:
    latest = {x.get("module"): x.get("status") for x in report.get("module_runs", [])}
    def status(names):
        matched = [latest[n] for n in names if n in latest]
        if not matched:
            return "NOT RUN"
        if all(x == "SUCCESS" for x in matched):
            return "COMPLETE"
        if "SUCCESS" in matched:
            return "PARTIAL"
        if all(x in {"DRY_RUN", "NOT_APPLICABLE"} for x in matched):
            return "NOT ASSESSED"
        return "INCOMPLETE"
    validations = report.get("validations") or []
    return [
        {"phase": 1, "title": "Reconnaissance & asset discovery", "status": status(["subfinder", "httpx"]), "details": "Passive asset and HTTP discovery; strict target scope"},
        {"phase": 2, "title": "Service enumeration & attack-surface mapping", "status": status(["nmap", "httpx"]), "details": "Service versions, exposed ports, HTTP metadata"},
        {"phase": 3, "title": "Vulnerability & configuration review", "status": status(["nuclei", "web_posture", "tls_posture", "artifact_review", "trivy_offline", "semgrep_local", "checkov_local", "gitleaks_local"]), "details": "Network/web checks and optional local IaC, container and AI artifact review"},
        {"phase": 4, "title": "Approved proof-of-control & evidence", "status": "PARTIAL" if validations else "AWAITING OPERATOR", "details": f"{len(validations)} validation record(s); each active PoC requires one bound operator approval"},
        {"phase": 5, "title": "Reporting, mitigation & retest", "status": "GENERATED", "details": "DOCX, searchable PDF, offline HTML, JSON and CSV; mitigations for every finding"},
    ]




def _nist_html_sections(report: dict) -> str:
    profile = report.get("nist_profile") or {}
    engagement = profile.get("engagement") or {}
    scope = profile.get("scope") or {}
    fields = [
        ("Client organization", profile.get("client_organization")),
        ("Assessment lead", profile.get("assessor")),
        ("Engagement reference", engagement.get("engagement_id") or report["audit"]["audit_id"]),
        ("Written authorization", engagement.get("authorization_reference") or "Not provided"),
        ("Rules of engagement", engagement.get("rules_of_engagement") or "Not provided"),
        ("Testing window", engagement.get("assessment_window") or "Not provided"),
        ("Classification", profile.get("classification")),
        ("Assessment quality", profile.get("coverage_status")),
        ("In scope", scope.get("in_scope") or [report["audit"]["target"]]),
        ("Out of scope", scope.get("out_of_scope") or "Not provided"),
    ]
    info = "".join(f"<tr><th>{_e(label)}</th><td>{_e(value)}</td></tr>" for label,value in fields)
    phases = "".join(f"<tr><td>{_e(row.get('stage'))}</td><td>{_e(row.get('description'))}</td></tr>"
                     for row in (profile.get("methodology") or []))
    tools = "".join(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k,v in (profile.get("tool_execution") or {}).items())
    risk_rows = "".join(f"<tr><td>{_e(r.get('finding_id'))}</td><td>{_e(r.get('severity'))}</td><td>{_e(r.get('title'))}<br><small>{_e(r.get('asset'))}</small></td>"
                        f"<td>{_e(r.get('validation'))}</td><td>{_e(r.get('priority'))}</td><td>{_e(r.get('recommended_action'))}</td><td>{_e(r.get('owner'))}</td>"
                        f"<td>{_e(r.get('status'))}</td></tr>" for r in (profile.get("risk_register") or [])[:500])
    ref_list = "".join(f"<li><a href='{_e(ref.get('url'))}' rel='noopener noreferrer'>{_e(ref.get('name'))}</a></li>"
                       for ref in (profile.get("references") or []))
    return f"""<section class='nist-section'>
<h2>Engagement and Rules of Engagement</h2><p class='section-caption'>NIST SP 800-115-aligned assessment record. This is not NIST accreditation or certification.</p>
<table class='engagement-grid'><tbody>{info}</tbody></table>
<h2>Assessment Methodology</h2><table><thead><tr><th>Assessment stage</th><th>Testing / reporting procedure</th></tr></thead><tbody>{phases}</tbody></table>
<h2>Scanner Execution and Coverage</h2><table><thead><tr><th>Execution status</th><th>Recorded runs</th></tr></thead><tbody>{tools or '<tr><td>Not run</td><td>0</td></tr>'}</tbody></table>
<h2>Risk Register and Remediation Plan</h2><p class='section-caption'>POA&amp;M-style worksheet. Owners and completion dates are not assumed to be agreed.</p>
<div class='wide-table'><table><thead><tr><th>Finding</th><th>Severity</th><th>Weakness / asset</th><th>Validation</th><th>Priority</th><th>Recommended action</th><th>Owner</th><th>State</th></tr></thead><tbody>{risk_rows or '<tr><td colspan="8">No findings recorded; review assessment coverage.</td></tr>'}</tbody></table></div>
<h2>Retest, Sign-off and Residual Risk</h2><p>Assign a client owner, remediation due date and change reference for each accepted finding. Verify remediation with a scoped retest; retain new evidence IDs and document residual risk or formal risk acceptance. Report sign-off: {_e(profile.get('report_approval'))}.</p>
<h2>Applicable References</h2><ul>{ref_list}</ul></section>"""

def write_html(report: dict, output: Path) -> Path:
    a = report["audit"]
    issues = (report.get("assessment_quality") or {}).get("limitations") or []
    sev = report["summary"]["severity"]
    phases = report.get("workflow") or build_workflow(report)
    rows = "".join(f"<tr><td>{p['phase']}</td><td>{_e(p['title'])}</td><td><strong>{_e(p['status'])}</strong></td><td>{_e(p['details'])}</td></tr>" for p in phases)
    findings = "".join(
        f"<article class='finding'><div class='finding-head'><h3>{_e(f.get('finding_id'))} &nbsp; {_e(f.get('title'))}</h3>"
        f"<span class='severity'>{_e(f.get('severity'))}</span></div>"
        f"<div class='detail'><b>Asset:</b> {_e(f.get('asset'))} &nbsp;&nbsp; <b>Endpoint:</b> {_e(f.get('endpoint'))}</div>"
        f"<div class='detail'><b>Assurance:</b> {_e(f.get('validation_status', 'UNVALIDATED'))} &nbsp;&nbsp;"
        f"<b>Source:</b> {_e(f.get('sources'))} &nbsp;&nbsp; <b>CWE:</b> {_e(f.get('cwes'))}</div>"
        f"<p>{_e(f.get('description', 'No scanner-specific description supplied.'))}</p>"
        f"<div class='remedy'><b>Mitigation</b><p>{_e(f.get('remediation') or next((m['recommendation'] for m in report['mitigation'] if m['finding_id']==f.get('finding_id')), 'Review vendor guidance and re-test after fixing.'))}</p></div>"
        f"<div class='research'><b>Public advisory and PoC research:</b><ul>{''.join('<li><a href=\"'+_e(r.get('url'))+'\" rel=\"noopener noreferrer\">'+_e(r.get('label'))+'</a> <small>('+_e(r.get('kind'))+')</small></li>' for r in (f.get('public_references') or [])[:10]) or '<li>No exact CVE research references.</li>'}</ul></div>"
        f"<div class='detail'><b>Risk context:</b> {_e(f.get('priority_context'))}</div></article>"
        for f in report.get("findings", []))
    if not findings:
        findings = "<p>No findings were recorded. This is <b>not</b> a security-clearance statement; review scanner coverage.</p>"
    issues_html = "".join(f"<li>{_e(issue)}</li>" for issue in issues) or "<li>No automated coverage warning; review methodology and evidence independently.</li>"
    html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SHAuditer Security Assessment — {_e(a['audit_id'])}</title>
<style>
:root{{--navy:#14253d;--aqua:#1c8795;--ink:#243449;--light:#f1f5f8}}*{{box-sizing:border-box}}body{{font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:var(--ink);margin:0;background:#e9eff3}}main{{background:white;max-width:1020px;margin:26px auto;padding:55px 66px;box-shadow:0 6px 28px #23324a1a}}.brand{{color:var(--aqua);font-size:12px;font-weight:800;letter-spacing:.22em;text-transform:uppercase}}h1{{font-size:36px;line-height:1.2;color:var(--navy);margin:10px 0}}h2{{color:var(--navy);font-size:21px;border-bottom:2px solid #dce8ee;padding-bottom:9px;margin-top:36px}}h3{{color:var(--navy);font-size:16px;margin:0}}.subtitle{{color:#64748b}}.metadata{{background:var(--light);border-left:4px solid var(--aqua);padding:17px 20px;margin:24px 0}}.cards{{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0}}.metric{{background:var(--light);padding:13px 15px;min-width:130px;flex:1}}.metric strong{{display:block;color:var(--navy);font-size:24px}}.metric small{{color:#64748b}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #e0e7ed;vertical-align:top}}th{{background:#e8f1f5;color:var(--navy)}}.finding{{margin:16px 0 22px;padding:18px;border:1px solid #d6e1e8;border-radius:8px;break-inside:avoid}}.finding-head{{display:flex;justify-content:space-between;gap:12px}}.severity{{font-weight:800;color:#b45309}}.detail{{font-size:13px;margin:6px 0;color:#475569;overflow-wrap:anywhere}}.remedy{{padding:12px;background:#edf7f5;border-left:3px solid var(--aqua)}}.remedy p{{margin:6px 0}}.research{{margin-top:12px}}.research a{{color:var(--aqua);overflow-wrap:anywhere}}.notice{{padding:14px;background:#fff8e9;border-left:4px solid #ca8a04}}footer{{margin-top:44px;color:#64748b;font-size:12px}}@media print{{body{{background:#fff}}main{{box-shadow:none;max-width:none;margin:0;padding:0}}h2{{break-after:avoid}}.finding{{break-inside:avoid}}@page{{size:A4;margin:20mm}}}}
.classification{{display:inline-block;margin-top:8px;border:1px solid #b7cbd5;border-radius:6px;padding:5px 9px;color:#8a303f;font-size:11px;font-weight:800}}.section-caption{{color:#607b8d;font-size:13px}}.engagement-grid th{{width:32%}}.wide-table{{overflow-x:auto}}.wide-table table{{font-size:12px;min-width:780px}}.nist-section{{border-top:2px solid #d8ebeb;margin-top:25px}}.nist-section h2{{scroll-margin-top:15px}}@media print{{.wide-table table{{min-width:0;font-size:10px}}.wide-table{{overflow:visible}}}}
</style></head><body><main>
<div class="brand">Street_Hackers / SHAuditer Professional 1.1.7</div>
<div class="classification">{_e((report.get("nist_profile") or {}).get("classification", "CONFIDENTIAL"))}</div>
<h1>Security Assessment Report</h1><div class="subtitle">Professional reconnaissance, control validation and prioritized remediation</div>
<div class="metadata"><b>Audit ID:</b> {_e(a['audit_id'])}<br><b>Target:</b> {_e(a['target'])}<br><b>State:</b> {_e(a['state'])}<br><b>Generated (UTC):</b> {_e(report['generated_at'])}</div>
<div class="notice"><b>Assessment boundaries:</b> Findings are observations or scanner detections unless independently validated. A missing scanner or module is not proof of safety. Proof-of-control checks do not demonstrate compromise or privilege escalation.</div>
<h2>Executive summary</h2><div class="cards">{''.join(f'<div class="metric"><strong>{int(sev.get(k,0))}</strong><small>{k}</small></div>' for k in ('CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'))}</div>
<p>Discovered {_e(report['summary'].get('assets',0))} assets and {_e(report['summary'].get('services',0))} service entries. {_e(report['summary'].get('validated',0))} finding validation record(s) indicate a reproduced condition; review the stated validation method to understand what was demonstrated.</p>
<h2>Five-phase assessment workflow</h2><table><thead><tr><th>Phase</th><th>Activity</th><th>Status</th><th>Basis</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Coverage and limitations</h2><ul>{issues_html}</ul>
{_nist_html_sections(report)}
<h2>Detailed findings and remediation</h2>{findings}
<h2>Proof-of-control log</h2><p>{_e(len(report.get('poc_executions',[])))} single-use approved probe execution(s); see JSON for individual evidence IDs and hashes.</p>
<h2>Recommended follow-up</h2><p>Prioritize confirmed critical/high risks, review flagged configuration patterns in context, assign remediation owners, and re-test affected components. Do not interpret unknown or blocked scanner coverage as a clean assessment.</p>
<footer>Street_Hackers &middot; SHAuditer Professional &middot; Confidential authorized assessment output &middot; Generated {_e(datetime.now().year)}</footer>
</main></body></html>'''
    output.write_text(html, encoding="utf-8")
    return output


def write_pdf(report: dict, output: Path) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SHTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=23, leading=28, textColor=colors.HexColor("#132a44"), spaceAfter=20))
    styles.add(ParagraphStyle(name="SHSection", parent=styles["Heading2"], fontSize=13, leading=17, spaceBefore=17, spaceAfter=9, textColor=colors.HexColor("#156776")))
    styles.add(ParagraphStyle(name="SHBody", parent=styles["BodyText"], fontSize=9, leading=14, spaceAfter=7))
    styles.add(ParagraphStyle(name="SHSmall", parent=styles["BodyText"], fontSize=8, leading=11))
    doc = SimpleDocTemplate(str(output), pagesize=(210*mm,297*mm), rightMargin=18*mm, leftMargin=18*mm, topMargin=17*mm, bottomMargin=17*mm,
                            title=f"SHAuditer Assessment {report['audit']['audit_id']}", author="Street_Hackers")
    story = []
    def par(text, style="SHBody"):
        return Paragraph(_e(text).replace("\n", "<br/>"), styles[style])
    def sec(text):
        story.append(Paragraph(_e(text), styles["SHSection"]))
    story.append(Paragraph("SHAuditer Professional", styles["SHSmall"]))
    story.append(Paragraph("VA &amp; PT Assessment Report", styles["SHTitle"]))
    story.append(Paragraph("NIST SP 800-115-aligned format / CONFIDENTIAL", styles["SHSmall"]))
    a = report["audit"]
    for label, val in (("Audit", a["audit_id"]), ("Target", a["target"]), ("Status", a["state"]), ("Generated", report["generated_at"])):
        story.append(Paragraph(f"<b>{_e(label)}:</b> {_e(val)}", styles["SHBody"]))
    story.append(Spacer(1, 6*mm))
    story.append(par("Only authorized, scoped testing is permitted. Scanner detections do not demonstrate exploitation; gaps in coverage are not evidence of absence of vulnerabilities."))
    sec("Executive summary")
    counts = report["summary"]["severity"]
    data = [["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], [str(counts.get(k,0)) for k in ("CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL")]]
    table = Table(data, colWidths=[34*mm]*5)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e8f2f5")),("TEXTCOLOR",(0,0),(-1,0),colors.HexColor("#19384b")),("ALIGN",(0,0),(-1,-1),"CENTER"),("BOTTOMPADDING",(0,0),(-1,-1),10),("TOPPADDING",(0,0),(-1,-1),10),("GRID",(0,0),(-1,-1),.2,colors.HexColor("#bdcfd7"))]))
    story.append(table)
    profile = report.get("nist_profile") or {}
    engagement = profile.get("engagement") or {}
    scope = profile.get("scope") or {}
    sec("Engagement details and authorized scope")
    for label, val in (
        ("Client", profile.get("client_organization", "Not supplied")),
        ("Assessment lead", profile.get("assessor", "Street_Hackers")),
        ("Authorization reference", engagement.get("authorization_reference", "Not supplied")),
        ("Testing window", engagement.get("assessment_window", "Not supplied")),
        ("Rules of engagement", engagement.get("rules_of_engagement", "Not supplied")),
        ("Classification", profile.get("classification", "CONFIDENTIAL")),
        ("In scope", scope.get("in_scope") or [a["target"]]),
        ("Out of scope", scope.get("out_of_scope") or "Not supplied"),
    ):
        story.append(Paragraph(f"<b>{_e(label)}:</b> {_e(val)}", styles["SHSmall"]))
    sec("Assessment methodology — NIST SP 800-115 aligned")
    story.append(par("This assessment uses NIST testing guidance for planning, examination, evidence, analysis, and remediation. It is not NIST-certified or a claim of full NIST control assessment.", "SHSmall"))
    for row in profile.get("methodology") or []:
        story.append(Paragraph(f"<b>{_e(row['stage'])}:</b> {_e(row['description'])}", styles["SHSmall"]))
    sec("Scanner execution coverage")
    for key, num in (profile.get("tool_execution") or {}).items():
        story.append(par(f"{key}: {num}", "SHSmall"))
    story.append(par(f"Coverage result: {profile.get('coverage_status', 'NOT ASSESSED')}", "SHBody"))
    sec("Five phases and coverage")
    for p in report.get("workflow") or build_workflow(report):
        story.append(Paragraph(f"<b>{p['phase']}. {_e(p['title'])} — {_e(p['status'])}</b>", styles["SHBody"]))
        story.append(par(p["details"], "SHSmall"))
    sec("Coverage limitations")
    issues = report.get("assessment_quality",{}).get("limitations") or ["No automatic warnings; confirm manually."]
    for issue in issues[:15]: story.append(par("• " + str(issue), "SHSmall"))
    sec("Prioritized risk register and remediation tracking")
    story.append(par("POA&M-style tracking: asset owners, due dates and closure statuses must be agreed with the client. Unknown fields are not assumed to be completed.", "SHSmall"))
    register = (profile.get("risk_register") or [])[:120]
    if register:
        tbl_rows = [["ID / Risk", "Asset and weakness", "Validation", "Priority"]]
        for item in register:
            tbl_rows.append([_e(item.get("finding_id"))+" / "+_e(item.get("severity")),
                             Paragraph(_e(item.get("asset"))+"<br/>"+_e(item.get("title")),styles["SHSmall"]),
                             _e(item.get("validation")),_e(item.get("priority"))])
        tbl = Table(tbl_rows, colWidths=[28*mm,79*mm,35*mm,28*mm], repeatRows=1, hAlign="LEFT")
        tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e9f4f5")),
           ("GRID",(0,0),(-1,-1),.25,colors.HexColor("#d6e4e8")),("VALIGN",(0,0),(-1,-1),"TOP"),
           ("FONTSIZE",(0,0),(-1,-1),7),("LEFTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),6)]))
        story.append(tbl)
    else:
        story.append(par("No recorded findings; coverage and scanner failures still require review.", "SHSmall"))
    sec("Findings and mitigation")
    findings = report.get("findings") or []
    if not findings:
        story.append(par("No reported findings. This does not establish a clean target or adequate assessment coverage."))
    for finding_index, f in enumerate(findings[:400]):
        title = f"{f.get('finding_id','')} | {f.get('title','Untitled')} [{f.get('severity','INFORMATIONAL')}]"
        detail = f"Asset: {f.get('asset','')} | Validation: {f.get('validation_status','UNVALIDATED')}"
        remedy = f.get('remediation') or next((m['recommendation'] for m in report['mitigation'] if m['finding_id']==f.get('finding_id')), 'Review vendor guidance and retest.')
        elems = [Paragraph("<b>" + _e(title) + "</b>", styles["SHBody"]), par(detail,"SHSmall"), par("Observation: " + str(f.get('description') or 'Static/dynamic finding; context required.'),"SHSmall"), par("Mitigation: " + str(remedy),"SHSmall"), Spacer(1,2*mm)]
        refs = (f.get("public_references") or [])[:5]
        if refs:
            elems.append(par("Public research: " + "; ".join(str(r.get("label")) + " (" + str(r.get("url")) + ")" for r in refs),"SHSmall"))
        if finding_index == 0:
            # Keep the section heading and the first finding together on one page.
            section_heading = story.pop()
            story.append(KeepTogether([section_heading, *elems[:2]]))
            story.extend(elems[2:])
        else:
            story.extend(elems)
    if len(findings)>400:
        story.append(par("Report limited to 400 findings in PDF; JSON/DOCX exports contain all findings."))
    sec("Retesting, residual risk and reference standards")
    story.append(par("Assign each issue to a client remediation owner, agree the planned resolution date and retest using scoped procedures. Confirm closure only after recorded verification; document accepted residual risk and the client sign-off decision.", "SHSmall"))
    story.append(par("Report approval: " + str(profile.get("report_approval") or "Pending"), "SHSmall"))
    for reference in profile.get("references") or []:
        story.append(par(f"{reference.get('name')}: {reference.get('url')}", "SHSmall"))
    sec("Approval & proof-of-control evidence")
    story.append(par(f"{len(report.get('poc_executions',[]))} approved single-use request(s). See exported JSON and hashed evidence for details. Non-destructive control observations are not compromise claims."))
    def footer(canvas, doc):
        canvas.saveState();canvas.setFont("Helvetica",8);canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18*mm, 12*mm, "Street_Hackers  |  Confidential authorized assessment")
        canvas.drawRightString(192*mm, 12*mm, str(doc.page))
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output


def generate_professional_exports(report: dict, reports_dir: Path) -> dict:
    result = {"html": str(write_html(report, reports_dir / "assessment.html"))}
    try:
        result["pdf"] = str(write_pdf(report, reports_dir / "assessment.pdf"))
    except ImportError:
        result["pdf"] = None
        result["pdf_warning"] = "Install reportlab to enable searchable PDF generation"
    return result
