from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path
import ipaddress

from shauditer.integrations.base import Integration, ModuleResult
from shauditer.security.evidence import sha256_file


class NmapIntegration(Integration):
    name = "nmap"
    executable = "nmap"

    async def run(self, context) -> ModuleResult:
        decision = context.scope.authorize(context.target, action="nmap reconnaissance")
        if not decision.allowed:
            return ModuleResult(self.name, "BLOCKED", metadata={"reason": decision.reason})

        recon_cfg = context.config.get("recon", {})
        top_ports = int(recon_cfg.get("nmap_top_ports", 1000))
        if not 1 <= top_ports <= 65535:
            raise ValueError("nmap_top_ports must be between 1 and 65535")
        if context.target.network:
            network = ipaddress.ip_network(context.target.network, strict=False)
            max_hosts = int(recon_cfg.get("max_cidr_addresses", 256))
            if max_hosts < 1 or network.num_addresses > max_hosts:
                return ModuleResult(self.name, "BLOCKED", metadata={
                    "reason": f"CIDR contains {network.num_addresses} addresses; configured maximum is {max_hosts}. "
                              "Narrow the scope or explicitly increase max_cidr_addresses."
                })
            # A network range may include exclusions not represented by nmap flags.
            # Fail closed rather than scan an excluded host.
            if context.scope.policy.out_of_scope or context.scope.policy.excluded_domains:
                if not context.scope.authorize(context.target, action="CIDR with exclusions").allowed:
                    return ModuleResult(self.name, "BLOCKED", metadata={"reason": "CIDR overlaps an exclusion"})

        args = ["-sT", "-sV", "--version-light", "--open"]
        permitted_ports = set(context.scope.policy.allowed_ports)
        excluded_ports = set(context.scope.policy.excluded_ports)
        if permitted_ports:
            final_ports = sorted(permitted_ports - excluded_ports)
            if not final_ports:
                return ModuleResult(self.name, "BLOCKED", metadata={"reason": "no permitted ports remain"})
            args += ["-p", ",".join(str(port) for port in final_ports)]
        else:
            args += ["--top-ports", str(top_ports)]
            if excluded_ports:
                args += ["--exclude-ports", ",".join(str(port) for port in sorted(excluded_ports))]
        args += ["-oX", "-", context.target.scan_host]
        result = await context.runner.execute(self.executable, args, timeout=int(context.config.get("timeouts", {}).get("nmap", 900)), cwd=context.workspace, dry_run=context.dry_run)

        if result.dry_run:
            return ModuleResult(self.name, "DRY_RUN", metadata={"command": result.command_display})

        raw_path = context.workspace / "recon" / "nmap.xml"
        err_path = context.workspace / "logs" / "nmap.stderr.txt"
        raw_path.write_bytes(result.stdout)
        err_path.write_bytes(result.stderr)
        context.db.add_evidence(f"EV-{context.audit_id}-NMAP", context.audit_id, self.name, "raw_scanner_output", str(raw_path), sha256_file(raw_path))

        assets, services = [], []
        parse_error = None
        if result.stdout.strip():
            try:
                root = ET.fromstring(result.stdout)
                for host in root.findall("host"):
                    addresses = [a.attrib.get("addr") for a in host.findall("address") if a.attrib.get("addr")]
                    hostnames = [h.attrib.get("name") for h in host.findall("hostnames/hostname") if h.attrib.get("name")]
                    assets.append({"addresses": addresses, "hostnames": hostnames})
                    for port in host.findall("ports/port"):
                        state = port.find("state")
                        if state is None or state.attrib.get("state") != "open":
                            continue
                        service = port.find("service")
                        services.append({
                            "address": addresses[0] if addresses else context.target.hostname,
                            "port": int(port.attrib.get("portid", "0")),
                            "protocol": port.attrib.get("protocol"),
                            "service": service.attrib.get("name") if service is not None else None,
                            "product": service.attrib.get("product") if service is not None else None,
                            "version": service.attrib.get("version") if service is not None else None,
                            "extrainfo": service.attrib.get("extrainfo") if service is not None else None,
                        })
            except ET.ParseError as exc:
                parse_error = str(exc)

        status = "SUCCESS" if result.exit_code == 0 and not result.timed_out and not result.output_truncated and parse_error is None else "FAILED"
        return ModuleResult(self.name, status, assets=assets, services=services, metadata={
            "exit_code": result.exit_code,
            "timed_out": result.timed_out, "output_truncated": result.output_truncated,
            "command": result.command_display,
            "parse_error": parse_error,
            "stderr": str(err_path),
        })
