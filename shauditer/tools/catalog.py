"""Cross-platform scanner inventory. No arbitrary code is cloned or executed.

Installation commands are suggestions for a human to review, NOT executable app
endpoints. Official upstream links, version verification, and package managers
are safer than unreviewed GitHub scripts. Extra tools are catalogued rather
than falsely presented as integrated scan engines.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str
    category: str
    repo: str
    integration: str = "CATALOG_ONLY"
    linux: str = "See the official project's installation documentation."
    macos: str = "See official releases and Homebrew, when supported."
    windows: str = "See official releases, WSL2, or a supported Windows package manager."


TOOLS = (
    Tool("Nmap", "nmap", "Network", "https://github.com/nmap/nmap", "INTEGRATED", "sudo apt install nmap", "brew install nmap", "winget install Insecure.Nmap"),
    Tool("Subfinder", "subfinder", "Recon", "https://github.com/projectdiscovery/subfinder", "INTEGRATED", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    Tool("HTTPX (ProjectDiscovery)", "httpx", "Recon", "https://github.com/projectdiscovery/httpx", "INTEGRATED", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    Tool("Nuclei", "nuclei", "Web/API", "https://github.com/projectdiscovery/nuclei", "INTEGRATED", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    Tool("Trivy", "trivy", "Cloud/Container", "https://github.com/aquasecurity/trivy", "INTEGRATED", "Use vendor APT repository or pinned signed GitHub release."),
    Tool("Metasploit", "msfconsole", "Exploit intelligence", "https://github.com/rapid7/metasploit-framework", "READ_ONLY_LOOKUP", "Use official Kali package or Rapid7 installer."),
    Tool("SearchSploit", "searchsploit", "Exploit intelligence", "https://github.com/offensive-security/exploitdb", "READ_ONLY_LOOKUP", "Install exploitdb from your distribution's trusted package source."),
    Tool("Katana", "katana", "Web/API", "https://github.com/projectdiscovery/katana", "CATALOG_ONLY", "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    Tool("DNSX", "dnsx", "Recon", "https://github.com/projectdiscovery/dnsx", "CATALOG_ONLY", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    Tool("Naabu", "naabu", "Network", "https://github.com/projectdiscovery/naabu", "CATALOG_ONLY", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    Tool("OWASP ZAP", "zap.sh", "Web/API", "https://github.com/zaproxy/zaproxy", "CATALOG_ONLY", "Use official ZAP packages or stable Docker images."),
    Tool("Semgrep", "semgrep", "Source code", "https://github.com/semgrep/semgrep", "INTEGRATED", "python3 -m pip install --user semgrep"),
    Tool("Checkov", "checkov", "Cloud/IaC", "https://github.com/bridgecrewio/checkov", "INTEGRATED", "python3 -m pip install --user checkov"),
    Tool("Gitleaks", "gitleaks", "Secrets", "https://github.com/gitleaks/gitleaks", "INTEGRATED", "Use pinned official GitHub release or distribution package."),
    Tool("Grype", "grype", "SBOM", "https://github.com/anchore/grype", "CATALOG_ONLY", "Use pinned official release and verify checksum."),
    Tool("Syft", "syft", "SBOM", "https://github.com/anchore/syft", "CATALOG_ONLY", "Use pinned official release and verify checksum."),
    Tool("OSV-Scanner", "osv-scanner", "Dependencies", "https://github.com/google/osv-scanner", "CATALOG_ONLY", "See official OSV-Scanner release instructions."),
    Tool("testssl.sh", "testssl.sh", "TLS", "https://github.com/testssl/testssl.sh", "CATALOG_ONLY", "Download a reviewed, pinned release of testssl.sh."),
    Tool("SSLyze", "sslyze", "TLS", "https://github.com/nabla-c0d3/sslyze", "CATALOG_ONLY", "python3 -m pip install --user sslyze"),
    Tool("ffuf", "ffuf", "Web/API", "https://github.com/ffuf/ffuf", "CATALOG_ONLY", "go install github.com/ffuf/ffuf/v2@latest"),
    Tool("Gobuster", "gobuster", "Web/API", "https://github.com/OJ/gobuster", "CATALOG_ONLY", "go install github.com/OJ/gobuster/v3@latest"),
    Tool("Amass", "amass", "Recon", "https://github.com/owasp-amass/amass", "CATALOG_ONLY", "Use official OWASP Amass release."),
    Tool("Prowler", "prowler", "Cloud", "https://github.com/prowler-cloud/prowler", "CATALOG_ONLY", "pipx install prowler"),
    Tool("Kube-bench", "kube-bench", "Kubernetes", "https://github.com/aquasecurity/kube-bench", "CATALOG_ONLY", "Use pinned official release."),
    Tool("Nikto", "nikto", "Web/API", "https://github.com/sullo/nikto", "CATALOG_ONLY", "sudo apt install nikto"),
    # Official upstream resources. These are CATALOG_ONLY unless explicitly noted.
    Tool("RustScan", "rustscan", "Network", "https://github.com/bee-san/RustScan", linux="Install a pinned RustScan release via apt or vendor packaging."),
    Tool("Masscan", "masscan", "Network", "https://github.com/robertdavidgraham/masscan", linux="sudo apt install masscan (only within written authorization and rate limits)"),
    Tool("ZMap", "zmap", "Network", "https://github.com/zmap/zmap", linux="Use your distribution package or verified upstream release."),
    Tool("ZGrab2", "zgrab2", "Network", "https://github.com/zmap/zgrab2", linux="Review official Go build and release guidance."),
    Tool("DNSRecon", "dnsrecon", "Recon", "https://github.com/darkoperator/dnsrecon", linux="sudo apt install dnsrecon"),
    Tool("Shuffledns", "shuffledns", "Recon", "https://github.com/projectdiscovery/shuffledns", linux="Review pinned upstream release and resolvers configuration."),
    Tool("AlterX", "alterx", "Recon", "https://github.com/projectdiscovery/alterx", linux="go install github.com/projectdiscovery/alterx/cmd/alterx@latest"),
    Tool("Uncover", "uncover", "Recon", "https://github.com/projectdiscovery/uncover", linux="Review official GitHub releases and API key requirements."),
    Tool("Gau", "gau", "Recon", "https://github.com/lc/gau", linux="go install github.com/lc/gau/v2/cmd/gau@latest"),
    Tool("Waybackurls", "waybackurls", "Recon", "https://github.com/tomnomnom/waybackurls", linux="go install github.com/tomnomnom/waybackurls@latest"),
    Tool("Hakrawler", "hakrawler", "Web/API", "https://github.com/hakluke/hakrawler", linux="Review official releases and build instructions."),
    Tool("WhatWeb", "whatweb", "Web/API", "https://github.com/urbanadventurer/WhatWeb", linux="sudo apt install whatweb"),
    Tool("Wapiti", "wapiti", "Web/API", "https://github.com/wapiti-scanner/wapiti", linux="sudo apt install wapiti"),
    Tool("Wfuzz", "wfuzz", "Web/API", "https://github.com/xmendez/wfuzz", linux="sudo apt install wfuzz"),
    Tool("Arjun", "arjun", "Web/API", "https://github.com/s0md3v/Arjun", linux="pipx install arjun"),
    Tool("Kiterunner", "kr", "Web/API", "https://github.com/assetnote/kiterunner", linux="Install verified official binary release."),
    Tool("ScoutSuite", "scout", "Cloud", "https://github.com/nccgroup/ScoutSuite", linux="pipx install scoutsuite; only with approved cloud credentials"),
    Tool("CloudFox", "cloudfox", "Cloud", "https://github.com/BishopFox/cloudfox", linux="Review official upstream release; needs approved cloud credentials."),
    Tool("Steampipe", "steampipe", "Cloud", "https://github.com/turbot/steampipe", linux="Install supported official package and approved plugins."),
    Tool("Kubescape", "kubescape", "Kubernetes", "https://github.com/kubescape/kubescape", linux="Use pinned verified upstream release."),
    Tool("Kube-hunter", "kube-hunter", "Kubernetes", "https://github.com/aquasecurity/kube-hunter", linux="Review upstream usage and permission requirements."),
    Tool("Docker Bench Security", "docker-bench-security", "Container", "https://github.com/docker/docker-bench-security", linux="Run only with authorized Docker host access after reviewing scripts."),
    Tool("Hadolint", "hadolint", "Container", "https://github.com/hadolint/hadolint", linux="Use pinned verified release or trusted package manager."),
    Tool("Dockle", "dockle", "Container", "https://github.com/goodwithtech/dockle", linux="Use official verified release for local image hardening."),
    Tool("TruffleHog", "trufflehog", "Secrets", "https://github.com/trufflesecurity/trufflehog", linux="Install verified upstream release; protect raw secret matches."),
    Tool("Detect Secrets", "detect-secrets", "Secrets", "https://github.com/Yelp/detect-secrets", linux="pipx install detect-secrets"),
    Tool("Lynis", "lynis", "Host Hardening", "https://github.com/CISOfy/lynis", linux="sudo apt install lynis"),
    Tool("Falco", "falco", "Runtime Security", "https://github.com/falcosecurity/falco", linux="Use official package/install docs; requires host permissions."),
    Tool("CycloneDX CLI", "cyclonedx", "SBOM", "https://github.com/CycloneDX/cyclonedx-cli", linux="Install verified official binary release."),
    Tool("Garak", "garak", "AI Security", "https://github.com/NVIDIA/garak", linux="Create isolated environment; review model/API data handling."),
    Tool("Promptfoo", "promptfoo", "AI Security", "https://github.com/promptfoo/promptfoo", linux="npm install -g promptfoo; requires authorized LLM application targets."),
    Tool("modelaudit", "modelaudit", "AI Security", "https://github.com/promptfoo/modelaudit", linux="Review official release for offline model scanning."),
)


def inventory() -> list[dict]:
    items = []
    for tool in TOOLS:
        executable = shutil.which(tool.binary)
        items.append({"name": tool.name, "binary": tool.binary, "category": tool.category,
                      "status": "INSTALLED" if executable else "MISSING",
                      "path": executable, "integration": tool.integration, "repo": tool.repo,
                      "linux": tool.linux, "macos": tool.macos, "windows": tool.windows})
    return items
