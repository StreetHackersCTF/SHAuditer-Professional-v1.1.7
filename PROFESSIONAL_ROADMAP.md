# SHAuditer Professional — Roadmap after v1.0.0

## Implemented now

- Reuse original v0.5.3 CLI/GUI and v0.6 hardened scope and scanner integrations.
- Safe HTTP posture, optional Trivy offline, offline Terraform/IAM/Docker/K8s/OpenAPI/AI config review.
- Bounded five-phase workflow, one-time operator approvals for supported proof-of-control checks.
- PDF/HTML plus existing Word/JSON/CSV reporting, evidence hashes and scanner quality warnings.

## Next phase (not implemented in this ZIP)

1. Authenticated, read-only AWS/Azure/GCP configuration APIs with per-account role boundaries.
2. Authenticated OWASP ZAP crawling, API spec-driven authorization matrix checks and false-positive workflows.
3. Container registry SBOM/OCI-image scans and safe Kubernetes cluster read-only audits.
4. Controlled AI red-team evaluation with synthetic data, human review and no autonomous external tool calls.
5. CI/CD SAST/SCA/SBOM, continuously updated CISA KEV and FIRST EPSS feeds with recorded timestamps.
6. OIDC/SSO, enterprise RBAC, multi-client isolation, encrypted evidence at rest and independently signed audit logs.
7. Plugin sandboxing, distributed workers, deployment guides, integration tests against maintained authorized labs, load testing and external audit.

**Do not describe roadmap items as available features.** The v1.0 code is a tested professional starting platform, not a universal exploitation engine.
