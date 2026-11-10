# SHAuditer Professional v1.1.7

**Professional VA&PT and security auditing platform by Street_Hackers**

SHAuditer is a Python-based platform for **authorized** security assessments of websites, servers, IP addresses and infrastructure. It brings reconnaissance, scanning, vulnerability research, controlled validation, NIST-aligned reporting and client email delivery into a single workflow.

> **Repository setup:** The project source still needs to be pushed from the local release folder. Do not assume the application is installable from this repository until the source files appear.

## Capabilities

- Five phases: reconnaissance, scanning/enumeration, vulnerability analysis, approved proof-of-control validation, and remediation/reporting.
- Configurable scope: domains, URLs, IP addresses, CIDRs, allow/exclude rules.
- Nmap, HTTPX, Nuclei and optional security tools, with a broader reference catalog.
- CVE/CWE intelligence, CISA KEV, EPSS and public exploit research references.
- Dark/light web dashboard, scanner health and assessment coverage tracking.
- PDF, DOCX, HTML, JSON and CSV reports, plus POA&M-style remediation register.
- Report delivery with editable emails and per-client recipients via SMTP.
- Operator approvals for active verification; no automatic third-party exploit execution.

## Quick start (after source upload)

```bash
git clone https://github.com/StreetHackersCTF/SHAuditer-Professional-v1.1.7.git
cd SHAuditer-Professional-v1.1.7
chmod +x install.sh SHAuditer SHAuditer-gui
./install.sh
./SHAuditer doctor
./SHAuditer gui
```

Run only against systems you own or have written permission to assess.

## Gmail report delivery

Default Street_Hackers sender: `streethackers03012026@gmail.com`

```bash
export SHAUDITER_SMTP_HOST=smtp.gmail.com
export SHAUDITER_SMTP_PORT=465
export SHAUDITER_SMTP_SSL=true
export SHAUDITER_SMTP_USER=streethackers03012026@gmail.com
export SHAUDITER_SMTP_FROM=streethackers03012026@gmail.com
```

Provide the Gmail App Password at runtime, never in source control. The successful Kali configuration used SSL/TLS on port 465 and `initial_response_ok=False` for SMTP login.

## Important limitations

External scanners require installation and authorization. The tool catalog is not a list of fully integrated scanners. CVE references and static-analysis leads are not proof of exploitability. NIST-aligned refers to documentation conventions, not a NIST certification.

## Maintainers

**Street_Hackers Security Team** — Security Assessment & Research

[Report a security concern privately](mailto:streethackers03012026@gmail.com)
