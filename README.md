# SHAuditer Professional v1.1.7

**SHAuditor> Street_Hackers_Auditor** — developed and maintained by the Street_Hackers security team. The historical command and Python package names remain `SHAuditer` / `shauditer` for compatibility.

**Street_Hackers** | Local-first, evidence-focused security auditing for authorized engagements.

> SHAuditer is **not** an autonomous intrusion system. Target entry starts an authorized assessment but never grants permission to run exploits. CVE search results, publicly indexed PoCs, and static findings are **not confirmation** that a target is vulnerable. An explicit single-use approval is required for each supported non-destructive HTTP proof-of-control check. This release does not run third-party exploit code.

## What's new in v1.1.7 — 3 November 2026

- **Redesigned responsive local console** with persistent light/dark theme switching, modern status indicators, an interactive severity-donut visualization, improved typography and reduced-motion accessibility rules. Theme choices stay in browser local storage, not on the server.
- **Professional NIST SP 800-115-aligned VA&PT reports** covering documented engagement scope, authorization references, assessment approach, scanner execution and coverage quality, confidence/verification status, prioritized findings, actionable remediation, POA&M-style action register, retest guidance, and references. Includes PDF, HTML, executive/technical/comprehensive DOCX, machine-readable outputs and an integrity-manifest ZIP. **NIST does not certify this report.**
- **Client engagement editor** in Reports: enter verified customer/assessor names, engagement ID, signed rules-of-engagement reference, test window, classification and constraints. Save, then regenerate the reports. Optional metadata is stored separately per audit in `metadata/engagement.json`; unknown values remain explicitly unverified, not fabricated.
- **57-tool cross-platform catalog**: 8 marked integrated, 2 read-only intelligence lookups and 47 discovery/catalog-only tools; these are **not** 57 automatically operational scanners. New *optional and local-artifact-only* adapters for **Checkov** (IaC checks, no online policy downloads) and **Gitleaks** (redacted secret-pattern metadata). Review official distribution and installation instructions before enabling tools. No arbitrary GitHub exploit code is auto-downloaded or executed.
- **Preserved client mail delivery**, including the Street_Hackers Gmail sender `streethackers03012026@gmail.com`, eight editable industry-style templates and per-audit recipient confirmation. SMTP passwords are **never** included in this source ZIP.

For detailed changes, supported tools, report methodology, setup, testing and limitations see [`docs/V117_RELEASE_AND_REPORTING.md`](docs/V117_RELEASE_AND_REPORTING.md).

## Changes in 1.1.6 (inherited features)

- **More meaningful outcomes:** fixed the NVD CVE API parameter (`cveId`, singular) so CVE lookups return exact records; added TLS certificate posture, and optional local Semgrep with packaged rules. The existing Nmap, Subfinder, ProjectDiscovery HTTPX, Nuclei, Trivy, web posture, cloud/IaC, container, API, and AI config assessment functionality remains.
- **Exploit research workspace:** CVE-specific NVD advisories and dedicated GitHub, Exploit-DB, Rapid7 and CISA KEV search links. Optional online intelligence from NVD, FIRST EPSS and the CISA KEV catalog. Local SearchSploit metadata matching (when installed) and read-only Metasploit discovery (when installed). Each entry distinguishes direct advisories, search suggestions, actual indexed candidates and proof status. Safe read-only control verification snippets are available where appropriate.
- **Clearer dashboard:** responsive scan-health meter, module-by-module health status and failure explanations, research cards, visual risk distribution and live job updates. **No findings** is never silently promoted to **no vulnerabilities**.
- **Cross-platform tool hub:** initial v1.1.6 catalog of 25 upstream tools (now 57 in v1.1.7) across Kali/Ubuntu/Debian, macOS, and Windows/WSL. Search, availability, upstream URL, integration status and installation plan. Third-party software is not cloned or blindly installed on behalf of the operator.
- **Reports + secure delivery:** PDF, three DOCX variants, offline HTML, JSON, CSV, and a report ZIP bundle containing a SHA-256 manifest. Download from the dashboard or send an existing report through **explicitly configured TLS/SSL SMTP** with one confirmation per send and an audit journal.
- **Regression tests:** deterministic offline tests cover the existing five-phase workflow and new intelligence, email, catalog and archive safeguards.

## Supported targets

Websites (`https://staging.example.org/`), hostnames (`app.internal.example`), individual IPv4/IPv6 addresses and servers (`192.168.56.11`), and limited CIDR targets (`192.168.56.0/28`) are supported. Only HTTP(S) URL schemes are accepted as URL inputs. For SSH/FTP/database servers, enter the host/IP and use service enumeration. Network reachability, DNS, correct scanner binaries, and explicit scope determine what can actually be observed. Static cloud/container/AI reviews take **local authorized artifact directories**, not live credentialed cloud accounts.

## Install — Kali Linux, Ubuntu or Debian

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip
unzip SHAuditer-Professional-v1.1.7.zip
cd SHAuditer-Professional-v1.1.7
chmod +x install.sh SHAuditer SHAuditer-gui
./install.sh
./SHAuditer doctor
./SHAuditer tools --instructions
./SHAuditer gui
```

Open **http://127.0.0.1:8765**. The GUI is loopback-only; it is not a remotely hosted enterprise application. Install any desired third-party scanner from its verified official repository or trusted package manager, then run `doctor` and re-scan. The `tools` command shows the catalog and supported platforms; **CATALOG_ONLY is not a claim of integration**. Don't mix ProjectDiscovery `httpx` with the unrelated Python `httpx` CLI.

To install without editable mode for Python package development: `python3 -m pip install .` in an isolated virtual environment. For a clean machine, the initial Python dependencies require package-index access or an internally approved wheelhouse. No scanner payloads, unreviewed GitHub scripts or exploit packages are fetched by `install.sh`.

## Run an authorized assessment

```bash
./SHAuditer audit https://staging.example.org --authorized
./SHAuditer audit 192.168.56.10 --authorized
./SHAuditer audit server.internal.example --authorized
./SHAuditer audit 192.168.56.0/28 --authorized --scope-file examples/scope.example.json
./SHAuditer audit https://staging.example.org --authorized --artifacts ./examples/fixtures
./SHAuditer audit https://staging.example.org --authorized --dry-run
```

Replace placeholders with assets expressly included in the engagement's written rules of engagement. Example fixture and addresses are illustrative, not an implicit permission to test a public website.

In the dashboard, enter the target in **New Audit**, accept the scope acknowledgment, and monitor **Live Assessment Health**. Modules report `SUCCESS`, `UNAVAILABLE`, `FAILED`, `BLOCKED`, `NOT_APPLICABLE` or `DRY_RUN`. Any failed/unavailable core scanner means coverage remains incomplete. A zero-findings result does not certify security.

## Prepare the professional client report

After choosing an audit in **Reports → NIST-aligned client & assessment details**, enter the actual client organization, assessor/lead, engagement reference, signed authorization or ROE reference, approved test window, classification and testing constraints. Save the engagement information, then select **Generate / refresh reports**. Incomplete or missing facts are never converted into claims of authorization, validation, control compliance or successful exploitation. Use the same assessment record with PDF, DOCX and HTML reports.

For an offline review, supply your own *authorized local* project tree using `--artifacts /path/to/project`. Checkov and Gitleaks are optional; absent tools are shown as unavailable/not assessed, not as zero security findings. Gitleaks only persists sanitized rule/file metadata, not matching secret values.

## Finding and public-exploit research workflow

1. Open a finding. The panel shows severity, observed asset, confidence, CVEs, mitigation, public advisory/search references and non-destructive check guidance where applicable.
2. For CVE-tagged findings, choose **Run intelligence**, or for the highest-priority CVE findings choose **Analyze top 5**. Network-based public intelligence queries go only to the configured fixed NVD/FIRST/CISA endpoints, not arbitrary URLs from scanner output.
3. Assess the CISA KEV and EPSS entries **with affected product/version applicability** before prioritizing. A search result or published module is not proof your asset is vulnerable.
4. Supported header/cookie control rechecks require one-time **Approve one PoC** and **Execute approved control check** per finding and operator. For other vulnerability categories, import redacted evidence and record manual validation.
5. Review fixes, rerun the relevant check and update validation status. Reports record evidence, severity, mitigation, CVE sources and limitations.

Existing CLI: `intel`, `intel-all`, `finding`, `approve`, `poc-approve`, `poc-run`, `evidence`, `validate`, `quality`, `verify-evidence`, `report`, `status`, `list`.

### Why am I seeing no vulnerabilities?

Run `./SHAuditer doctor` and `./SHAuditer tools`; inspect the **Live Assessment Health** panel and **Diagnostics**. Confirm that external scanner binaries and templates exist, the target resolves, the allowed ports include the target port, and scan jobs completed. For public targets, service/tool coverage depends on permissions, network access and environment. The built-in HTTP/TLS checks are meaningful observations but are not a substitute for authenticated web/API VAPT, dynamic analysis and manual testing.

## Report output and downloads

Reports for each audit are written under `~/.local/share/SHAuditer/workspaces/<AUDIT-ID>/reports/`, or under a custom `--home`.

| Output | Filename |
|---|---|
| Searchable assessment PDF | `assessment.pdf` |
| Complete offline HTML | `assessment.html` |
| Executive DOCX | `docx/executive-report.docx` |
| Technical DOCX | `docx/technical-report.docx` |
| Comprehensive DOCX | `docx/complete-assessment.docx` |
| Machine-readable data | `assessment.json`, `findings.json`, `findings.csv`, `mitigation-plan.csv` |
| Confidential shareable bundle | `assessment-bundle.zip` including `SHA256-MANIFEST.json` |

Generate or refresh via `./SHAuditer report AUDIT_ID` or the console's **Reports** section. The bundle excludes raw logs, arbitrary evidence files, credentials, local source code and databases. Check PDF/DOCX/HTML report accuracy and redact sensitive details before sharing outside the engagement.

## Configure secure Street_Hackers Gmail client delivery

The default **Street_Hackers sender** is `streethackers03012026@gmail.com` via `smtp.gmail.com:587` (mandatory STARTTLS), with display name `Street_Hackers Security Team`. The **client recipient is entered afresh for each audit** and must be authorized to receive the report. You can override the sender/provider with `SHAUDITER_SMTP_*` environment variables if your team switches to a managed domain.

Gmail still requires a private SMTP credential; the project **does not** contain a password and cannot send until you configure one. For eligible accounts with two-step verification enabled, create a dedicated Google App Password:

Kali Linux typically uses Zsh. This supported **port 465 SSL/TLS configuration** is the one successfully authenticated by the Street_Hackers operator; it is also compatible with SHAuditer's SMTP_SSL transport:

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

Use a new private App Password, **never the actual Google account password**. A previously exposed App Password must be revoked. Stop a previously-running dashboard before restarting (otherwise port 8765 may remain occupied). If you prefer port 587, select `SHAUDITER_SMTP_SSL=false` and STARTTLS. A reachable port is not proof of successful authentication or report delivery.

Select an audit under **Reports → Client Delivery Desk**, enter the current client's name, organization and email, choose one of **eight** editable industry-style templates, preview, confirm authorization and submit. The message contains a factual risk snapshot from the current database and the chosen PDF/DOCX/ZIP attachment. CLI preview and confirmed send are also available:

```bash
./SHAuditer mail AUDIT-ID --to security@client.example \
  --client-organization 'Example Client Ltd' --template final_delivery --format pdf --preview
./SHAuditer mail AUDIT-ID --to security@client.example \
  --client-organization 'Example Client Ltd' --template final_delivery --format pdf --confirm-send
```

Do not use the account's normal password or include credentials in the ZIP. Google may not offer App Passwords for all security configurations; in those cases the current SMTP login feature requires an alternate approved relay or future OAuth2 support. A successful send indicates SMTP acceptance, **not verified inbox delivery**. Sensitive evidence should be transmitted by a client-approved secure method. See [`docs/CLIENT_DELIVERY_AND_EMAIL_TEMPLATES.md`](docs/CLIENT_DELIVERY_AND_EMAIL_TEMPLATES.md).

## Verification and build

```bash
python3 -m pytest -q
python3 -m compileall -q shauditer
node --check shauditer/gui/static/app.js
python3 -m pip wheel --no-deps --no-build-isolation . -w dist
```

See `docs/V116_FEATURES_AND_LIMITATIONS.md` for scope and implementation notes, `docs/BUILD_FROM_SOURCE.md` for reproducible steps, and `SECURITY.md` for authorization and privacy.

**Release limitations:** Live AWS/Azure/GCP accounts, deep AI red-teaming, authenticated BOLA/IDOR, arbitrary PoC execution, payload delivery, broad remote exploitation, continuous daemonized scanning, and cloud hosted multi-user RBAC **are not implemented**. Tool hub catalog entries are **recommendations, not all native integrations**. Run external tools only with verified authorization and review their scan profile/settings first.


## Street_Hackers client delivery edition (v1.1.6)

The **Reports → Client Delivery Desk** supports a different client email and organization for every engagement, while using a configurable team-controlled Street_Hackers sender identity. Eight professionally written and editable message templates are provided: final report, executive handoff, priority finding notification, remediation follow-up, retest, and closure. Preview, explicit one-send consent, TLS-only SMTP, a client-delivery journal and recipient reset between audits are built in.

For complete sender setup, security precautions, real usage, and sample industry messages, read **[`docs/CLIENT_DELIVERY_AND_EMAIL_TEMPLATES.md`](docs/CLIENT_DELIVERY_AND_EMAIL_TEMPLATES.md)**. The user-provided team Gmail sender is the default; a private Google App Password is still required before sending. No credential is included in the package. Never send a confidential report to a client without verifying report content and authorizing the recipient.
