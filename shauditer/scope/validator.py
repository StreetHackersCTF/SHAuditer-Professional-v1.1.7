from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from shauditer.models.target import Target
from shauditer.scope.models import ScopeDecision, ScopePolicy


def _parse_candidate(value: str) -> tuple[str, int | None, ipaddress._BaseNetwork | None]:
    """Normalize an explicit host, URL or CIDR without string-prefix scope matches."""
    value = value.strip()
    port = None
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("unsupported URL in scope decision")
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    else:
        host = value.rstrip(".")
        if not host:
            raise ValueError("empty host")
    try:
        net = ipaddress.ip_network(host, strict=False) if "/" in host else None
        if net is not None:
            return str(net.network_address), port, net
        return str(ipaddress.ip_address(host)), port, None
    except ValueError:
        if not host or any(c in host for c in " /?#@\\"):
            raise ValueError("invalid hostname")
        # An IDNA canonical form permits comparison of international hostnames.
        return host.encode("idna").decode("ascii").lower(), port, None


def _match(candidate: str, rule: str) -> bool:
    """CIDR rules must cover the *entire* candidate range, not its first IP."""
    try:
        host, _port, candidate_network = _parse_candidate(candidate)
        rule = rule.strip()
        if rule.startswith("*."):
            suffix, _, _ = _parse_candidate(rule[2:])
            return host.endswith("." + suffix) and host != suffix
        rule_host, _rule_port, rule_network = _parse_candidate(rule)
        if rule_network is not None:
            try:
                if candidate_network is not None:
                    return candidate_network.subnet_of(rule_network)
                return ipaddress.ip_address(host) in rule_network
            except (ValueError, TypeError):
                return False
        if candidate_network is not None:
            # A host rule never authorizes an entire network range.
            return False
        return host == rule_host
    except (ValueError, UnicodeError):
        return False


class ScopeValidator:
    def __init__(self, policy: ScopePolicy):
        self.policy = policy

    def authorize(self, target: Target | str, port: int | None = None, action: str = "network") -> ScopeDecision:
        candidate = (target.network or target.hostname) if isinstance(target, Target) else target
        try:
            host, implied_port, _ = _parse_candidate(candidate)
        except (ValueError, UnicodeError) as exc:
            return ScopeDecision(False, f"invalid target for {action}: {exc}")
        if port is None:
            port = implied_port if implied_port is not None else (target.port if isinstance(target, Target) else None)
        if port is not None and not (1 <= port <= 65535):
            return ScopeDecision(False, "invalid network port")

        # An explicit exclusion of a single host inside a CIDR blocks that
        # entire CIDR request; no partial-scope scanning is performed.
        if any(_match(candidate, rule) or
               ("/" in candidate and _network_overlaps_rule(candidate, rule))
               for rule in self.policy.out_of_scope):
            return ScopeDecision(False, f"target is explicitly out of scope for {action}")
        if any(_match(candidate, rule) or
               ("/" in candidate and _network_overlaps_rule(candidate, rule))
               for rule in self.policy.excluded_domains):
            return ScopeDecision(False, f"domain is explicitly excluded for {action}")

        positive = [*self.policy.in_scope, *self.policy.allowed_domains]
        if not positive:
            return ScopeDecision(False, "no positive scope rules configured; refusing to run")
        if not any(_match(candidate, rule) for rule in positive):
            return ScopeDecision(False, f"target does not match configured in-scope rules for {action}")

        if port is not None:
            if port in self.policy.excluded_ports:
                return ScopeDecision(False, f"port {port} is excluded")
            if self.policy.allowed_ports and port not in self.policy.allowed_ports:
                return ScopeDecision(False, f"port {port} is not in the allowed-port set")
        return ScopeDecision(True, f"scope permits {action}")


def _network_overlaps_rule(candidate: str, rule: str) -> bool:
    try:
        _host, _port, network = _parse_candidate(candidate)
        if network is None:
            return False
        rule_host, _rule_port, rule_network = _parse_candidate(rule)
        if rule_network is not None:
            return network.overlaps(rule_network)
        return ipaddress.ip_address(rule_host) in network
    except (ValueError, TypeError, UnicodeError):
        return False
