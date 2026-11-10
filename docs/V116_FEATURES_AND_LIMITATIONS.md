# SHAuditer Professional 1.1.6 — implementation and boundaries

## Modules really invoked by the scan engine

| Engine | Network / local | Execution behavior |
|---|---|---|
| Subfinder | Passive recon, when installed | External scanner run with scope rules |
| Nmap | Network enumeration, when installed | Bounded ports/timeouts; operator-authorized scope |
| HTTPX (ProjectDiscovery) | HTTP fingerprint, when installed | External scanner with bounded execution |
| Nuclei | Web templates, when installed | Intrusive/fuzz/DoS tags excluded; no OOB interactions |
| `web_posture` | Built in, HTTP(S) | One bounded read-only HEAD, pinned DNS, no body |
| `tls_posture` | Built in, HTTPS | One TLS handshake; expiry / trust observation |
| `artifact_review` | Built in, local files | Bounded offline check for cloud/containers/APIs/AI config |
| Trivy | Local filesystem, when installed | Offline DB reuse; no network database updater |
| Semgrep | Local source, when installed | Packaged local reviewed rule set; no cloud registry/telemetry |

`SearchSploit` and `Metasploit` are **research lookup** tools, not active exploit engines. The 25-item hub also includes catalog-only installation recommendations for tools that are not invoked by an assessment. All network or active validation checks require appropriate legal authorization. Each supported PoC additionally requires a *distinct* one-time approval.

## Public exploit references

- The NVD API uses `?cveId=` for exact CVE lookups. CVE records are not automatically attached to unrelated findings.
- FIRST EPSS answers exploitation likelihood, not local reachability or impact. CISA KEV is a historical exploited-in-the-wild catalog, not proof that a given server is affected.
- GitHub, Rapid7, Exploit-DB and CISA links created from a CVE identifier are **search entry points**. A result list is not automatically scraped and no result is silently treated as verified.
- If locally installed, `searchsploit --cve ... --json` is parsed for indexed EDB IDs/titles and safe reference links. Local Metasploit matching uses console search/info, never exploit execution.
- Optional safe check snippets only show a read-only HTTP HEAD command. No third-party exploit scripts are automatically fetched or executed.

## Explainable status

The dashboard separates job state, scan module status, quality gates, observed findings and confirmed findings. `COMPLETE` means the scheduled workflow reached report generation, not that all scanners succeeded. Missing/failed tools and network errors are reported separately. The combined coverage meter is a module completion indicator, **not a vulnerability risk score**.

## Report delivery safeguards

Reports are generated locally. ZIP bundle includes only allowlisted report exports and a SHA-256 manifest. SMTP credentials are environment-only; network delivery uses verified TLS, never plaintext downgrade. UI has same-origin token, loopback Host binding and explicit per-send consent. Successful SMTP acceptance is logged to the workspace. A delivered report may still be held/rejected by a downstream email system.

## Security and accuracy limitations

SHAuditer cannot find *all* vulnerabilities, and false positives/negatives are possible. Real-world completeness requires authenticated assessments, specialist tools and an analyst. Third-party software may have incompatible versions or new flags; the tool hub provides official upstream links rather than quietly fetching and executing GitHub code. Keep customer-specific DBs, reports, `.env` and credentials outside shared source control. Review the risk of false positives before promising a customer that their system has been compromised.
