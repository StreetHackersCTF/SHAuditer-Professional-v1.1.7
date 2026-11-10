<!-- SHAuditor = Street_Hackers_Auditor -->
# SHAuditer v1.1.7 security guidance

SHAuditer must be run only against assets covered by explicit authorization and written rules of engagement. Entering a URL, host, or IP is **not permission to exploit it**. The scanner enforces scope allowlists, excluded networks/ports, bounded CIDRs, execution timeouts and evidence integrity. Nuclei excludes intrusive, fuzz and DoS tags, but third-party templates must still be reviewed for safety.

Supported proof-of-control checks require one approval per finding, action and operator; approvals are bound, single use and expire. Other validations are manually recorded with hashed evidence. This release does not create shells, deliver exploit payloads, enable persistence or automatically run third-party PoC scripts. Search links do not prove applicability.

The GUI binds to loopback only, validates Host and same-origin controls, and uses a random token for state-changing actions. Don't expose it through a reverse proxy or bind it to public interfaces without independent authentication, TLS and access control engineering. SHAuditer is not a certified multi-user SaaS application.

Email delivery requires TLS/SSL and operator confirmation. SMTP passwords are read from environment variables and should be provided via a secret manager or interactive shell prompt, not pasted into code, logs or committed `.env` files. Confidential report ZIPs can reveal vulnerability details; use only approved recipients, data retention controls and secure channels. UI responses intentionally avoid exposing SMTP credential-related server diagnostics.

The public intelligence client connects only to hard-coded HTTPS advisory feeds and parses JSON with bounded response sizes. The tools hub displays official installation references and does not download or execute arbitrary GitHub repositories. Local Semgrep rules are packaged; project review files should be located in an explicitly authorized, isolated directory. Pin and verify third-party dependencies/releases before production use.

No scanner can guarantee discovery of every vulnerability. Reports identify false-positive uncertainty, scope and missing-tool limitations, and distinguish scanner detections from operator-confirmed exploitable conditions.


### Client report delivery

Use only a team-owned SMTP sender, keep passwords in a runtime secret manager, verify authorized client recipients per engagement and ensure correct reports are attached. Street_Hackers client-delivery emails require explicit per-send approval. SMTP TLS protects transport to the relay but does **not** encrypt mail end-to-end or prove arrival in the inbox; use a secure client portal or separately encrypted attachment for especially sensitive findings. Never store credentials, PII, or vulnerability exploit secrets in the email message or project repository.


### Street_Hackers Gmail report delivery

The configured team sender is `streethackers03012026@gmail.com`. It is not a client recipient and must never be automatically used as the client destination. Gmail SMTP is disabled until you provide a private app credential. Never include a Gmail password, app password, OAuth token, or sensitive client report in a public repository. The sender domain may use Gmail authentication; this app does not implement OAuth2. All emails require a distinct authorized recipient and single-send operator consent. Assessment summaries are derived from recorded findings and include coverage limitations, not a claim of full compromise or safety.

### v1.1.7 reporting and local scans

NIST SP 800-115 alignment denotes a report structure based on published assessment guidance, not NIST certification or verified compliance with any NIST control set. Review, correct and approve all engagement metadata and findings before sharing. The client engagement editor stores details per audit with bounded fields and atomic file replacement; do not enter secrets.

The optional Checkov and Gitleaks adapters must only run on local files that belong to the authorized engagement. Their output is treated as untrusted, potentially false-positive evidence; secret values and matched source excerpts are stripped. Run source inspection with least privilege and in an isolated environment. No third-party tool is automatically installed by this project.
