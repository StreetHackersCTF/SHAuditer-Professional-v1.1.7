# v1.0 testing strategy

Automated: `pytest -q` executes inherited v0.6 coverage and new v1.0 tests. Test groups include database migration, scope denials, CIDR/port limits, subprocess time/output bounds, normalization, scanner parsing, HTML escaping, PDF/DOCX outputs, single-use approval expiration/replay checks, DNS-private-address blocking, static IaC/K8s/Docker/AI/OpenAPI rule detection, Trivy fixture normalization and **a real loopback-only HTTP server** for the integrated probe → finding → approval → evidence → report path.

Package: `python -m compileall -q shauditer` and `python -m pip wheel --no-deps --no-build-isolation . -w dist`.

Manual acceptance remaining for production use: version-specific external scanner execution on approved lab targets, GUI interactive browser QA, full cloud provider credentialed read-only API testing, Trivy offline DB availability, performance/capacity under realistic data, threat model against local malicious users, third-party dependency/software supply-chain audit, PDF accessibility, independent penetration test and client report signoff. These are not claimed done.
