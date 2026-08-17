"""Data models shared by scanners, auditors and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    code: str
    title: str
    severity: str
    points: int
    description: str
    recommendation: str
    evidence: str = ""
    cve: str = ""
    confidence: str = "medium"
    finding_type: str = "exposure"


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    status: str = "online"
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    banners: dict[int, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_category: str = "Sicher"
    compliance: dict[str, bool] = field(default_factory=dict)
    audit_coverage: dict[str, str] = field(default_factory=dict)
    audit_log: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    subnet: str
    started_at: str
    finished_at: str = ""
    scanner_version: str = "1.0.0"
    scanned_hosts: int = 0
    devices: list[Device] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    security_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
