"""Configuration defaults, YAML/JSON loading and validation."""

from __future__ import annotations

import json
import ipaddress
import socket
from dataclasses import dataclass, field, fields
from functools import lru_cache
from pathlib import Path
from typing import Any

from .storage import application_data_dir, default_report_dir

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
    """Return a real private IPv4 of this host, or an empty string.

    No placeholder address is returned: callers can therefore distinguish a
    failed adapter detection from an actual local address.
    """
    candidates: list[str] = []
    try:
        candidates.extend(
            item[4][0] for item in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM
            )
        )
    except OSError:
        pass
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        candidates.insert(0, sock.getsockname()[0])
    except OSError:
        pass
    finally:
        sock.close()
    return next((address for address in candidates if is_private_target(address)), "")


def default_local_subnet() -> str:
    address = detect_local_ipv4()
    return str(ipaddress.ip_network(f"{address}/24", strict=False)) if address else ""


@dataclass
class Config:
    subnet: str = field(default_factory=default_local_subnet)
    scan_type: str = "full"
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    max_concurrent: int = 100
    timeout: float = 1.0
    retries: int = 1
    output_dir: str = field(default_factory=default_report_dir)
    formats: list[str] = field(default_factory=lambda: ["console"])
    security_audit_enabled: bool = True
    credential_testing_enabled: bool = False
    allow_public_targets: bool = False
    oui_file: str = ""

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
                    "Für YAML-Konfigurationsdateien wird PyYAML benötigt; JSON wird ohne Zusatzpaket unterstützt."
                ) from exc
        if not isinstance(data, dict):
            raise ValueError("Die Konfigurationsdatei muss ein Objekt mit Schlüssel-Wert-Paaren enthalten.")
        allowed = {item.name for item in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in allowed})

    def merge(self, values: dict[str, Any]) -> "Config":
        data = {item.name: getattr(self, item.name) for item in fields(self)}
        data.update({key: value for key, value in values.items()
                     if value is not None and key in data})
        return Config(**data)

    def validate(self) -> None:
        if not self.subnet.strip():
            raise ValueError(
                "Es wurde keine private lokale IPv4-Adresse erkannt. "
                "Bitte einen autorisierten privaten IPv4-Bereich in CIDR-Schreibweise angeben."
            )
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
        except ValueError:
            raise ValueError(
                f"„{self.subnet}“ ist kein gültiger IPv4-Bereich in "
                "CIDR-Schreibweise (Beispiel: 192.168.0.0/24)."
            ) from None
        if network.version != 4:
            raise ValueError("Es werden ausschließlich IPv4-Netze unterstützt.")
        if not self.allow_public_targets and not any(
            network.subnet_of(private) for private in PRIVATE_NETWORKS
        ):
            raise ValueError(
                "Standardmäßig sind nur private IPv4-Netze (10/8, 172.16/12, "
                "192.168/16) erlaubt. Externe Ziele benötigen eine explizite "
                "Expertenfreigabe in der Konfiguration."
            )
        if self.scan_type not in {"arp", "icmp", "full", "custom"}:
            raise ValueError(f"Unbekannter Scan-Modus: {self.scan_type}")
        if not 1 <= self.max_concurrent <= 500:
            raise ValueError("Die Anzahl gleichzeitiger Prüfungen muss zwischen 1 und 500 liegen.")
        if not 0.05 <= self.timeout <= 30:
            raise ValueError("Der Timeout pro Ziel muss zwischen 0,05 und 30 Sekunden liegen.")
        if any(not 1 <= int(port) <= 65535 for port in self.ports):
            raise ValueError("TCP-Ports müssen im Bereich von 1 bis 65535 liegen.")


PERSISTED_SETTING_FIELDS = (
    "subnet", "scan_type", "ports", "timeout", "security_audit_enabled",
)


def settings_path() -> Path:
    """Return the private, per-user path for persistent scan settings."""
    return application_data_dir() / "settings.json"


def load_persisted_config(path: str | Path | None = None) -> Config:
    """Load the local settings profile, falling back safely to defaults."""
    source = Path(path) if path is not None else settings_path()
    config = Config()
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return config
        loaded = config.merge({key: data.get(key) for key in PERSISTED_SETTING_FIELDS})
        loaded.validate()
        return loaded
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return config


def save_persisted_config(config: Config, path: str | Path | None = None) -> Path:
    """Atomically save user-editable settings in the private app data folder."""
    config.validate()
    target = Path(path) if path is not None else settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {key: getattr(config, key) for key in PERSISTED_SETTING_FIELDS}
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(target)
    return target
