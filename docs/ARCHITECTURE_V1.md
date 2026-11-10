# SHAuditer Professional v1.0.0 — Architecture

## Components

```text
         CLI / Local Browser UI
                  |
         Authorized Target + ROE
                  |
           Target normalizer
                  |
           ScopeValidator  <----------- JSON in/out of scope + port policy
                  |
             AuditEngine
        __________|____________________
       |                |             |
 Recon / Enumerate   Discovery     Offline Evidence
       |                |             |
 Subfinder, HTTPX,  Nuclei, HEAD   IaC, OpenAPI,
 Nmap                posture       K8s/Compose, AI
       |                |            optional Trivy
       |________________|_____________|
                        |
             Correlation + Priority
                        |
                SQLite + Evidence
                        |
           [WAIT FOR OPERATOR]
                        |
           Single-use PoC Approval
                        |
         Bound HTTP HEAD recheck / Manual validation
                        |
                 Evidence SHA-256
                        |
         HTML / PDF / DOCX / JSON / CSV
                        |
              Mitigation & Retest
```

## Data stores

- `audits`, `events`, `module_runs`, `evidence`, `findings`: assessment foundation.
- `approvals`, `validations`, `sessions`, `exploit_intelligence`, `exploit_reviews`: legacy operator history retained.
- `poc_executions` (v1): `execution_id`, UNIQUE `approval_id`, audit/finding/operator, status, timestamps, evidence. Atomic insertion prevents replay.
- `workspaces/<audit-id>/`: restricted audit-specific directories. Reports and sanitized evidence reference database records.

## Trust boundaries

1. User-supplied targets are untrusted; parse only HTTPS/HTTP URLs, IPs, hostnames and bounded CIDRs.
2. User-supplied scope is explicit and may *restrict* the target. Refuse out-of-scope web hosts/ports, even if discovered by scanners.
3. Third-party scanners are trusted local binaries but not sandboxed; review and install separately. Outputs are untrusted and evidence-backed.
4. Built-in HTTP probe pins the resolved address; private DNS responses require explicit resolved-IP scope. A proxy is not used and redirect locations are not followed.
5. Local artifacts are not remotely fetched; size/file-count bounded; symlinks skipped. Analysis is heuristic, not credentialed cloud API evaluation.
6. Single-use PoC approval is verified inside a database transaction before any network request, with 1-hour expiry; completion is recorded separately.
7. HTML escapes data; CSV export neutralizes spreadsheet formulas; reports warn about missing scanners and control observations that do not prove exploitation.

## Coverage truth table

- `SUCCESS`: module completed without runner/parse error; does NOT mean all vulnerabilities were found.
- `PARTIAL`: some offline source files could not be parsed/inspected.
- `UNAVAILABLE`: optional scanner is absent.
- `FAILED`: execution, response, output bound or parsing failed.
- `BLOCKED`: scope did not authorize that module/target/port.
- `NOT_APPLICABLE`/`SKIPPED`: target type does not support the module.
- `DRY_RUN`: attempted commands previewed; **no scan evidence**.

## Phases

1. Recon: asset and HTTP metadata inventory.
2. Enumeration: host service and version inventory.
3. Discovery: scanner output, posture observations, static artifact review, prioritization.
4. Validation: operator decision and single-use approved safe checks; manual evidence for other finding types.
5. Reporting: professional exports and remediation recommendations. Report generation does not remove the phase-4 approval requirement.

## Areas reserved for a future independently reviewed release

Authentic cloud-account read-only API credential adapters, ZAP authenticated scanning, package SBOM generation, repository CI/CD continuous monitoring, API authorization test harness, full AI agent/model prompt-injection methodology, multi-user OIDC/RBAC, remote secure workers and distributed scheduling, report signing/immutable evidence storage. None is falsely labeled complete in v1.0.
