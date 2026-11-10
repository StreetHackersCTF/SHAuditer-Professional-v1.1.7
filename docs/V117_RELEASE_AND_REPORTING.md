# SHAuditer Professional v1.1.7 — Release and VA&PT reporting guide

Release date: 2026-11-03. Brand: Street_Hackers. Scope: authorized local-first VA/PT with human approval for supported proof-of-control rechecks.

## Console: dark/light and assessment health

- Open `./SHAuditer gui` from the source folder. Visit `http://127.0.0.1:8765` locally.
- Select the **Dark/Light** toggle in the top bar. The browser remembers this preference with local storage, including after refresh; it does not send theme preference to the backend.
- Dashboard panels emphasize scan coverage, scanner failures/unavailable status, findings severity distribution, evidence/verification, and incomplete coverage. Light and dark use different semantic color variables. Reduced-motion OS preferences are respected.
- `Reports` includes the **NIST-aligned client & assessment details** form. Save verified names, engagement/ROE reference, assessment dates, classification, constraints and actual lead. Each assessment has separate metadata, under `~/.local/share/SHAuditer/workspaces/<AUDIT-ID>/metadata/engagement.json` by default. Saving does not automatically regenerate old exports: select **Generate / refresh reports**.
- Client Mail Desk retains changeable recipients, preflight preview and explicit per-send confirmation. Sender remains `streethackers03012026@gmail.com` unless overridden by your own SMTP environment.

## NIST-aligned VA&PT assessment methodology

The generated deliverables use the structure and concepts of **NIST SP 800-115, Technical Guide to Information Security Testing and Assessment**. They also reference NIST SP 800-53A Rev. 5, OWASP WSTG and OWASP Top 10:2025 as appropriate. This is **not a NIST certification, attestation of controls, accreditation, or substitute for an assessor's professional judgment**. Standards: https://csrc.nist.gov/pubs/sp/800/115/final and https://csrc.nist.gov/pubs/sp/800/53/a/r5/final .

Documents record:

1. Client and assessor engagement record, authorization / rules-of-engagement identifier, classification, and assessment window **when supplied by the operator**.
2. In-scope/excluded assets and configured restrictions where captured in the audit.
3. Planning, discovery, vulnerability examination, controlled proof-of-control validation, reporting and remediation methodology.
4. A factual executive summary, severity distribution, per-finding affected asset and evidence/validation context.
5. Scanner execution coverage, unavailable/failed modules, and assessment limitations. Missing scanner output is NOT a clean target result.
6. Risk register and **POA&M-style** corrective actions: finding ID, description, severity, recommended action, suggested priority, and **unassigned** owner/due date/retest evidence until verified.
7. Retesting guidance, client handover and primary testing-framework references.

### Supported file formats

- `assessment.pdf` — readable print-ready report
- `assessment.html` — offline interactive-friendly static HTML
- `docx/executive-report.docx` — management summary
- `docx/technical-report.docx` — detailed findings and methodology
- `docx/complete-assessment.docx` — combined deliverable
- `assessment.json`, `findings.csv`, `mitigation-plan.csv` — technical analysis and import/export
- `assessment-bundle.zip` — downloadable report archive with SHA-256 manifest

Raw secrets, scanner logs, database files and SMTP credentials are **not** packaged in generated report bundles. You must still manually review and redact customer-specific content before sending.

## Tool architecture and honest coverage

The GUI Tool Hub contains **57** official-source entries, with explicit labels: **8 INTEGRATED**, **2 READ_ONLY_LOOKUP**, **47 CATALOG_ONLY**. Catalog-only entries are not operational integrations and do not install or execute by themselves. The original Nmap/HTTPX/Nuclei/Subfinder/Trivy/Semgrep etc. remain supported when properly installed. Some checks require binaries/templates or optional configurations. `./SHAuditer doctor` and the dashboard show whether they are available.

The two additions in v1.1.7 are **Checkov** and **Gitleaks**. Both are executed only when provided an explicitly approved local project directory via `--artifacts`; the project does not require any live cloud account connection. Checkov is invoked with `--skip-download` to avoid fetching rules at execution time. Gitleaks requests complete output redaction, deletes temporary raw result files and writes only rule-and-path metadata (never the discovered secret). Review false positives and verify tool compatibility/version locally.

Install scanner tools through pinned versions and their verified official repositories. `./SHAuditer tools --instructions` provides curated catalog suggestions; the release will not auto-pull every GitHub repository, clone exploits, or run arbitrary unreviewed code.

## Street_Hackers Gmail setup — known working option

The operator previously confirmed SMTP authentication/delivery using Gmail **port 465**, implicit SSL. Under Kali's Zsh shell:

```zsh
export SHAUDITER_SMTP_HOST='smtp.gmail.com'
export SHAUDITER_SMTP_PORT='465'
export SHAUDITER_SMTP_SSL='true'
export SHAUDITER_SMTP_FROM='streethackers03012026@gmail.com'
export SHAUDITER_SMTP_USER='streethackers03012026@gmail.com'
export SHAUDITER_SMTP_DISPLAY_NAME='Street_Hackers Security Team'
read -rs 'SHAUDITER_SMTP_PASSWORD?Gmail App Password: '
echo
export SHAUDITER_SMTP_PASSWORD
./SHAuditer gui
```

Use a fresh, private Google App Password (not your normal password), never enter it into the source code, and revoke any previously exposed credential. Starting a second GUI while port 8765 is occupied raises `Address already in use`; stop the old process before starting this one. SMTP acceptance is not proof of inbox delivery. Use a secure client-approved transfer channel for especially sensitive reports.

## Test and security limitations

Run `python3 -m pytest -q`, `python3 -m compileall -q shauditer`, `node --check shauditer/gui/static/app.js`. Offline tests cover the engagement editor, static theme assets, scanner parsing/redaction, NIST report structure and existing email paths. Actual installed scanner behavior and inbox delivery need independent validation on the operator's authorized lab and configured Gmail credentials. Browser screenshot automation is environment restricted in this build; the static UI, JavaScript syntax and local API paths have been checked, but no automated visual screenshot assertion was made.

**Not implemented:** unrestricted automated exploitation, compromise persistence, hosted RBAC, live AWS/Azure/GCP credentialed assessment, guaranteed detection of all vulnerabilities, and automated credential handling. Proof-of-control testing remains bounded, per-finding and explicitly approved.
