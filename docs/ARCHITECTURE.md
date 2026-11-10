# Legacy v0.6 architecture — see [ARCHITECTURE_V1.md](ARCHITECTURE_V1.md) for the current architecture.

# SHAuditer v0.6.0 Architecture

## Product workflow

```text
TARGET_CREATED
    ↓
SCOPE_VERIFIED
    ↓
RECONNAISSANCE
    ├── host / DNS discovery
    ├── port and service discovery
    ├── HTTP probing
    ├── technology fingerprinting
    └── normalized attack-surface model
    ↓
VULNERABILITY_DISCOVERY
    ├── relevant scanner selection
    ├── normalized findings
    ├── correlation / deduplication
    └── priority scoring
    ↓
EXPLOIT_INTELLIGENCE
    ├── CVE extraction
    ├── observed product/version correlation
    ├── NVD applicability
    ├── read-only local Metasploit candidate lookup
    └── operator research review
    ↓
VALIDATION
    ├── explicit approval
    ├── validation method
    ├── evidence attachment
    └── VALIDATED / NOT_VALIDATED / INCONCLUSIVE
    ↓
ACCESS_RECORDING
    ├── existing authorized access metadata
    ├── privilege
    ├── evidence link
    └── session lifecycle record
    ↓
MITIGATION
    ├── finding-specific remediation when available
    ├── explicitly labeled generic fallback guidance
    ├── remediation priority
    └── re-test / closure workflow
    ↓
REPORTING
    ├── executive-report.docx
    ├── technical-report.docx
    ├── complete-assessment.docx
    └── JSON / CSV support exports
```

## Core components

- `shauditer/core/engine.py`: assessment orchestration and state transitions.
- `shauditer/core/scheduler.py`: module scheduling and scanner failure isolation.
- `shauditer/scope/`: centralized target/port/action authorization decisions.
- `shauditer/integrations/`: scanner adapters that return normalized `ModuleResult` objects.
- `shauditer/database/db.py`: SQLite persistence for audits, events, findings, evidence, validation, sessions and intelligence.
- `shauditer/intelligence/`: finding correlation, risk prioritization, CVE/applicability and read-only exploit intelligence.
- `shauditer/validation/`: operator approval, evidence-backed validation and existing-access/session records.
- `shauditer/reporting/summary.py`: report data model and structured exports.
- `shauditer/reporting/docx_report.py`: formal Word report generation.
- `shauditer/gui/`: loopback-only graphical console backed by the same database/workspaces as CLI.

## Reporting storage

Authoritative audit copy:

```text
~/.local/share/SHAuditer/workspaces/<AUDIT-ID>/reports/docx/
```

Convenience mirror in a source checkout:

```text
SHAuditer-Professional-v0.6.0/reports/<AUDIT-ID>/
```

The source-tree mirror can be overridden by setting `SHAUDITER_PROJECT_REPORTS`.

## Trust boundary

AI or exploit-intelligence output is advisory. Scope restrictions, authorization, operator approval and evidence requirements remain enforced by application code. Exploit candidate discovery is not treated as exploit execution or successful access.


## v0.6.0 additions

- `shauditer/scope/policy_io.py` validates authorized scope policies from JSON / GUI fields.
- `shauditer/reporting/quality.py` evaluates scanner completeness, validation status and SHA-256 evidence integrity.
- `shauditer/security/runner.py` bounds scanner timeout/output and terminates subprocess groups on POSIX.
- GUI has a loopback Host/Origin protection check and a dedicated assessment quality panel.
- Source and installed-wheel execution both have packaged default configuration and local image assets.
- Manual authorization is required. DNS pinning and egress sandboxing are future work and not assumed to exist.
