"""Configuration defaults, YAML/JSON loading and validation."""

from __future__ import annotations

import json
import ipaddress
import socket
from dataclasses import dataclass, field, fields
from functools import lru_cache
from pathlib import Path
from typing import Any

from .storage import default_report_dir

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465,
                 502, 636, 993, 995, 1433, 1883, 3306, 3389, 5432, 6379,
                 8080, 8443, 8883, 27017]
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def is_private_target(value: str | ipaddress.IPv4Address) -> bool:
    address = ipaddress.ip_address(value)
    return address.version == 4 and any(address in network for network in PRIVATE_NETWORKS)


@lru_cache(maxsize=1)
def detect_local_ipv4() -> str:
    """Return the preferred private IPv4 without sending application data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        address = sock.getsockname()[0]
        return address if is_private_target(address) else "192.168.0.1"
    except OSError:
        return "192.168.0.1"
    finally:
        sock.close()


def default_local_subnet() -> str:
    return str(ipaddress.ip_network(f"{detect_local_ipv4()}/24", strict=False))


@dataclass
class Config:
    subnet: str = field(default_factory=default_local_subnet)
    scan_type: str = "arp"
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    max_concurrent: int = 100
    timeout: float = 1.0
    retries: int = 1
    output_dir: str = field(default_factory=default_report_dir)
    formats: list[str] = field(default_factory=lambda: ["console"])
    security_audit_enabled: bool = False
    audit_depth: str = "standard"
    risk_threshold: int = 30
    credential_testing_enabled: bool = False
    allow_public_targets: bool = False
    oui_file: str = ""
    compliance: list[str] = field(
        default_factory=lambda: ["pci_dss", "iso_27001", "bsi_grundschutz"]
    )

    @classmethod
    def from_file(cls, path: str) -> "Config":
        source = Path(path)
        text = source.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(text) or {}
            except ImportError as exc:
                raise ValueError(
                    "YAML configuration requires PyYAML; JSON is always supported."
                ) from exc
        if not isinstance(data, dict):
            raise ValueError("Configuration root must be an object.")
        allowed = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in allowed})

    def merge(self, values: dict[str, Any]) -> "Config":
        data = {item.name: getattr(self, item.name) for item in fields(self)}
        data.update({key: value for key, value in values.items()
                     if value is not None and key in data})
        return Config(**data)

    def validate(self) -> None:
        network = ipaddress.ip_network(self.subnet, strict=False)
        if network.version != 4:
            raise ValueError("Only IPv4 networks are supported.")
        if not self.allow_public_targets and not any(
            network.subnet_of(private) for private in PRIVATE_NETWORKS
        ):
            raise ValueError(
                "Standardmäßig sind nur private IPv4-Netze (10/8, 172.16/12, "
                "192.168/16) erlaubt. Externe Ziele benötigen eine explizite "
                "Expertenfreigabe in der Konfiguration."
            )
        if self.scan_type not in {"arp", "icmp", "full", "custom"}:
            raise ValueError(f"Unknown scan type: {self.scan_type}")
        if not 1 <= self.max_concurrent <= 500:
            raise ValueError("max_concurrent must be between 1 and 500")
        if not 0.05 <= self.timeout <= 30:
            raise ValueError("timeout must be between 0.05 and 30 seconds")
        if any(not 1 <= int(port) <= 65535 for port in self.ports):
            raise ValueError("Ports must be in the range 1..65535")
