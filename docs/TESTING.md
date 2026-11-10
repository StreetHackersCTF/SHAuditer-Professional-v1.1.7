# Development and QA Checks

Run from the repository root:

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
./SHAuditer doctor
./SHAuditer audit 127.0.0.1 --authorized --dry-run
```

The 44-test suite includes existing feature tests and professional-hardening regression tests for CIDR containment, explicit exclusions, allowed ports, oversized networks, output limits, process timeout, dashboard Host validation, CSV formula protection, and evidence hash mismatch.

**Manual acceptance tests still needed before customer use:** install in a fresh Kali VM; check GUI visually; verify wheel configuration and images; run isolated authorized lab scans with genuine nmap/httpx/subfinder/nuclei; test interrupted scans and long-running tasks; validate DOCX contents and client-specific export redaction; exercise backup and restore; review real DNS/redirect containment. Automated tests alone do not prove production readiness.
