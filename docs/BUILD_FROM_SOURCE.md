# SHAuditer v1.1.7 — Build, Run, Extend, Verify

This describes how to reproduce the project **from this ZIP's source code**. No original developer workstation is required.

## Step 1 — Inspect the tree

The original modules remain under `shauditer/cli`, `core`, `integrations`, `database`, `scope`, `validation` and `reporting`. The added v1 code lives in `modules/artifacts.py`, `modules/web/posture.py`, `integrations/artifact_review.py`, `integrations/trivy_fs.py`, `poc/runner.py`, and `reporting/professional.py`.

## Step 2 — Prepare the Python environment

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -q
```

Python dependencies: `python-docx` for Word reports, `reportlab` for PDF, `PyYAML` for Kubernetes/AI configs; `pytest` for tests. External scanners are independent and optional.

## Step 3 — Configure authorized engagement scope

Copy `examples/scope.example.json`, replace target CIDRs/domains, and remove every sample network not in the actual rules of engagement. Use the included JSON schema format: `in_scope`, `out_of_scope`, `allowed_domains`, `excluded_domains`, `allowed_ports`, `excluded_ports`.

## Step 4 — Run a non-network smoke test

```bash
./SHAuditer --home /tmp/shauditer-v116-demo audit https://staging.example.org --authorized --dry-run --artifacts examples/fixtures
./SHAuditer --home /tmp/shauditer-v116-demo list
```

**DRY_RUN** does not inspect the fixture files and does not produce real vulnerability measurements; use this only to test commands, states and report generation.

## Step 5 — Conduct an authorized local assessment

Use a server you administer or the isolated loopback test fixture. For the loopback test, run `python -m pytest tests/test_v1_platform.py -k live_local_http -q`; the test starts its own HTTP server and shuts it down.

In an approved client lab, run `./SHAuditer audit <TARGET> --authorized --artifacts ./path/to/approved-source` or enter the target from the GUI. Open the vulnerability table, prioritize findings and corroborate context.

## Step 6 — Verify vulnerabilities deliberately

For a built-in header/cookie observation, require a separate `poc-approve` call with explicit `--acknowledge` then a `poc-run` with the exact approval ID and same operator. No automatically selected exploit code is executed. For any other issue, import redacted manual evidence and record a reasoned validation result using the existing `approve`, `evidence` and `validate` commands.

## Step 7 — Generate and review reports

`./SHAuditer report AUDIT_ID` writes PDF, HTML, three DOCX files, JSON and CSV, all traceable to audit ID. Read `assessment-quality.json` and verify hashes with `verify-evidence --strict`. Reject any "no vulnerabilities" conclusion if core scanners failed or coverage is insufficient.

## Step 8 — Extend safely

An adapter subclass of `Integration` returns a `ModuleResult` with `status`, `findings`, `evidence` and `metadata`. Register it in `AuditEngine.run_recon` or `AuditEngine.run_vulnerability_discovery`. Gate every network target with `ScopeValidator.authorize`; use `SafeProcessRunner` for subprocesses; record hashed evidence. Do **not** enable unbounded external commands or exploit templates from untrusted output. Add a deterministic test for each feature, error path, scope denial and report rendering.

## Step 9 — Build a distributable package

```bash
python -m compileall -q shauditer
python -m pip wheel --no-deps --no-build-isolation . -w dist
```

For isolated professional use, pin/verify third-party dependencies and scanner binary versions, segregate customer data by OS account, and run an independent code review before deploying outside a lab.

## Step 10 — Review the v1.1.6 additions

The new public CVE intelligence functions are in `intelligence/public_sources.py`, while `intelligence/searchsploit.py` only reads local exploit index metadata. `tools/catalog.py` contains official upstream installation references. The email sender is `reporting/mail.py` and report archive builder is `reporting/bundle.py`. Local source scanner and TLS posture scanner are `integrations/semgrep_fs.py` and `modules/web/tls.py`.

Run `./SHAuditer tools --instructions` to inspect install plans. Use `./SHAuditer mail --help` and the SMTP environment variables documented in the README for email delivery. Test against the loopback fixture first.

## v1.1.7 additions

- Local dashboard supports persisted dark/light theme, a severity-donut chart and clearer tool health indicators.
- Reports view provides a per-audit engagement editor; complete it, save, and regenerate the assessment package to include client, assessment window, authorization reference, constraints and classification.
- PDF, offline HTML and three DOCX outputs include NIST SP 800-115-aligned methodology, scope/limitations, quality warnings and a POA&M-style remediation register (owner/due date remain unassigned until the client agrees them).
- 57 official-source tools are catalogued; only 8 show INTEGRATED and 2 READ_ONLY_LOOKUP. Checkov and Gitleaks are separately installed optional local-artifact integrations, not network exploitation modules.
- The Street_Hackers SMTP sender, explicit recipient confirmation and client communication templates are preserved from v1.1.6.

See [`V117_RELEASE_AND_REPORTING.md`](V117_RELEASE_AND_REPORTING.md).
