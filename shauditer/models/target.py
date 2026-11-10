from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import ipaddress
import re
from urllib.parse import urlparse


class TargetType(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    CIDR = "CIDR"
    DOMAIN = "Domain"
    URL = "URL"
    HOST = "Host"


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$"
)
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


@dataclass(slots=True)
class Target:
    original: str
    type: TargetType
    hostname: str
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    network: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["type"] = self.type.value
        return data

    @property
    def display(self) -> str:
        return self.original

    @property
    def scan_host(self) -> str:
        return self.network or self.hostname


def normalize_target(raw: str) -> Target:
    value = raw.strip()
    if not value:
        raise ValueError("target cannot be empty")
    if any(ch.isspace() for ch in value):
        raise ValueError("target cannot contain whitespace")

    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("only HTTP/HTTPS URLs are accepted")
        if not parsed.hostname:
            raise ValueError("URL is missing a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("target URLs must not contain embedded credentials")
        if parsed.fragment:
            raise ValueError("URL fragments are not valid scan targets")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid URL port") from exc
        return Target(
            original=value,
            type=TargetType.URL,
            hostname=parsed.hostname.lower(),
            scheme=parsed.scheme.lower(),
            port=port or (443 if parsed.scheme.lower() == "https" else 80),
            path=parsed.path or "/",
        )

    try:
        network = ipaddress.ip_network(value, strict=False)
        if "/" in value:
            return Target(
                original=value,
                type=TargetType.CIDR,
                hostname=str(network.network_address),
                network=str(network),
            )
    except ValueError:
        pass

    try:
        address = ipaddress.ip_address(value)
        return Target(
            original=value,
            type=TargetType.IPV4 if address.version == 4 else TargetType.IPV6,
            hostname=str(address),
        )
    except ValueError:
        pass

    hostname = value.rstrip(".").lower()
    if _DOMAIN_RE.fullmatch(hostname):
        return Target(original=value, type=TargetType.DOMAIN, hostname=hostname)
    if _HOST_RE.fullmatch(hostname):
        return Target(original=value, type=TargetType.HOST, hostname=hostname)
    raise ValueError(f"unsupported or invalid target: {raw!r}")
