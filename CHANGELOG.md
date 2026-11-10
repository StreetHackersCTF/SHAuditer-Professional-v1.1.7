## v1.1.7 SMTP compatibility hotfix (2026-11-04)

- Explicitly set `initial_response_ok=False` for SMTP authentication to match successful Gmail SMTP_SSL tests on port 465.
- Added regression coverage for Gmail SMTP over SSL/TLS on port 465, without sending a real email.
- Preserve existing Street_Hackers sender and client mail templates.
- For an existing installation, replace `shauditer/reporting/mail.py` or use the corrected source archive, then stop the old dashboard and restart it with the SMTP environment variables set.

# SHAuditer Release History

## 1.1.7 — NIST-aligned reporting, themed dashboard and expanded tool hub (2026-11-03)

- Modernized responsive Street_Hackers web console with persisted dark/light theme, improved status and severity chart, accessibility enhancements, and per-engagement report metadata editor.
- Added explicit engagement, methodology, scope, approval/ROE reference, testing limitations, scanner quality, and POA&M-style remediation register sections to PDF, HTML, and Word reporting. Report language is **NIST SP 800-115-aligned**, not NIST-certified.
- Expanded curated official-source catalog to 57 entries: 8 actual integrations, 2 read-only lookups, 47 catalog-only recommendations.
- Integrated optional Checkov IaC and Gitleaks secret-pattern scanners for local approved artifacts, redacting code snippets and secret material from report evidence. Both need separate local installation.
- Retained v1.1.6 Gmail SMTP/SSL sending, per-client recipients, consent, eight templates, downloads and report ZIP manifest. No secrets are shipped.
- Added tests for client engagement data isolation, input checks, reporting model, new integrations, frontend features and backward compatibility.

## v1.1.6 — Street_Hackers Gmail Sender & Expanded Client Correspondence

- Set `streethackers03012026@gmail.com` as the default team sender using Gmail SMTP STARTTLS on port 587; no credential is bundled.
- Require a private Gmail App Password for Gmail delivery and show honest readiness messaging; the client recipient remains unique per engagement.
- Expanded the six client communication templates to eight, including report revision and technical debrief.
- All default templates now include stronger engagement, confidentiality, remediation, ownership, acknowledgment and risk-context language.
- Email previews insert a factual per-engagement severity/validation/coverage snapshot; unvalidated detections are clearly distinguished from proven exploitation.
- Updated GUI, CLI, environment example and documentation; no real emails sent during automated testing.

## v1.1.6 — Client Delivery Edition (optional revision)

- Team-owned Street_Hackers sender identity with configurable display name and Reply-To.
- Per-engagement client contact, organization, and recipient; UI resets recipient on audit switch.
- Six professional message templates, editable subject/body, and no-send email preview.
- Explicit sending confirmation, TLS SMTP-only transport and metadata-only delivery journal.
- CLI template choices, preview mode, client fields and editable message file support.
- Added test coverage for header injection, multi-client isolation, consent and sender identity.

# Changelog

## 1.1.6 — Professional security operations upgrade

- Fixed NVD 2.0 CVE lookup query parameter and exact CVE response filtering; bounded JSON response size.
- Added CISA KEV and FIRST EPSS intelligence enrichment, CVE-specific public advisory/search links (GitHub, Exploit-DB, Rapid7, NVD, CISA) and optional read-only local SearchSploit index lookup.
- Added built-in TLS certificate posture and optional packaged-local Semgrep checks for authorized artifact directories.
- Added 25-tool official-source catalog with integrated-vs-catalog-only labels and platform-specific setup instructions; no blind GitHub code downloads or exploit execution.
- Added dashboard scan health ring, module status rail and precise zero-finding explanations, tool hub, finding references, and SMTP email form.
- Added PDF/DOCX/HTML/JSON/CSV report ZIP bundle, SHA-256 content manifest, CSRF-protected download/send routes and explicit TLS SMTP delivery.
- Maintained existing signed scope policy, one-use PoC approvals, evidence integrity, mitigation plan, local dashboard and original five-phase workflow.
- Added v1.1.6 regression tests for NVD, public research, threat feeds, SearchSploit metadata, mail, ZIP integrity, UI and tool catalog.

## 1.0.0 — Five-phase platform foundation

Includes original Nmap/Subfinder/HTTPX/Nuclei connectors, optional offline cloud/AI/container review, single-use HTTP control recheck, DOCX/PDF/HTML reports and secure local dashboard.
