# SHAuditer v1.1.7 Graphical Dashboard

The dashboard is a local browser application backed by the exact same SQLite database and workspaces as the CLI.

## Start

```bash
./SHAuditer gui
```

Default URL:

```text
http://127.0.0.1:8765
```

Alternative:

```bash
./SHAuditer gui --no-browser --port 8877
```

## Main views

### Overview

Shows the Street_Hackers visual identity, audit identity, current state, risk distribution, assets/services/findings/evidence metrics, detailed phase coverage, recent audits and an audit-event timeline. The supplied Street_Hackers logo and scene artwork are served locally from `shauditer/gui/static/assets/`.

### Assessment quality

The Overview shows a conservative completeness indicator with core scanner status, findings awaiting manual validation, evidence hash verification and explicit scope/coverage limitations. Zero findings with missing scanner modules is shown as incomplete coverage, **not** a clean assessment.

### Recon

Shows normalized asset and service inventory, discovered ports, product/version information, web metadata, technology fingerprints, and module execution health.

### Vulnerabilities

Shows severity totals, priority-ranked normalized findings, CVEs, affected assets and current validation state. Selecting a finding opens a deeper technical review panel.

### Exploitation & Validation

Shows CVE applicability, local read-only exploit candidates, operator research reviews, validation approvals, evidence-backed validation outcomes and recorded access/session metadata.

Candidate discovery is intelligence only. The dashboard does not automatically execute payloads or create shells.

### Mitigation

Builds a prioritized remediation plan. Finding-specific scanner remediation is preserved. If a scanner did not provide remediation, the UI clearly labels the displayed fallback as generic SHAuditer guidance. The view also shows the recommended closure workflow: fix, reduce exposure, re-scan, re-validate, attach closure evidence and close.

### Evidence

Shows evidence source, kind, hash, path and timestamp. GUI-imported evidence is copied into the audit workspace and hashed with SHA-256.

### DOCX Reports

Generates and downloads three formal Word reports:

```text
executive-report.docx
technical-report.docx
complete-assessment.docx
```

Each report is saved in the audit workspace and mirrored into the project `reports/<AUDIT-ID>/` folder.


### Audit deletion

The **Audits** table and selected-audit toolbar expose a permanent delete action. The confirmation dialog requires the exact audit ID. The backend refuses deletion when an in-memory audit/intelligence job is still running and constrains recursive filesystem removal to the configured SHAuditer `workspaces/` root and report-mirror root. Confirmed deletion removes:

```text
SQLite audit + child rows
audit workspace
raw scanner output
evidence files
workspace reports
mirrored DOCX reports
```

There is no undo operation.

## Local web-security controls

- Default bind address: `127.0.0.1`
- Loopback-only host options
- Host header check to mitigate DNS rebinding
- Exact scheme/host/port validation of browser Origin headers
- Random per-launch action token
- Origin validation for write requests
- Content Security Policy
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- no remote JavaScript/CSS dependencies
- evidence upload size limit
- scanner-controlled values escaped before DOM insertion

## CLI and GUI interoperability

An audit created in the CLI appears in the GUI. An audit created in the GUI is available to all CLI commands because both interfaces share the same data model, database and workspace layout.


## v1.1 controls

- Enter an HTTP(S) website, IP address, hostname or bounded CIDR in **New Audit**. Local IaC, Docker/Kubernetes, OpenAPI and AI artifacts can optionally be selected via a directory path (they are not uploaded to the server).
- Open a finding. If it has `poc_type` and `poc_parameter`, enter an operator identity and use **Approve one PoC**. The next button executes exactly one bounded HTTP HEAD control recheck using that one-hour, single-use approval; it does not execute an exploit payload.
- The Reports tab now provides downloadable **PDF** and **offline HTML** in addition to the original three DOCX reports.
- The dashboard is for localhost/one operator. It does not implement hosted SSO or RBAC.

## v1.1.7 additions

- Local dashboard supports persisted dark/light theme, a severity-donut chart and clearer tool health indicators.
- Reports view provides a per-audit engagement editor; complete it, save, and regenerate the assessment package to include client, assessment window, authorization reference, constraints and classification.
- PDF, offline HTML and three DOCX outputs include NIST SP 800-115-aligned methodology, scope/limitations, quality warnings and a POA&M-style remediation register (owner/due date remain unassigned until the client agrees them).
- 57 official-source tools are catalogued; only 8 show INTEGRATED and 2 READ_ONLY_LOOKUP. Checkov and Gitleaks are separately installed optional local-artifact integrations, not network exploitation modules.
- The Street_Hackers SMTP sender, explicit recipient confirmation and client communication templates are preserved from v1.1.6.

See [`V117_RELEASE_AND_REPORTING.md`](V117_RELEASE_AND_REPORTING.md).
