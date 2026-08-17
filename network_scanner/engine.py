"""Scan orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .config import Config, is_private_target
from .assessment import network_assessment
from .models import Device, ScanResult, utc_now
from .scanners import discover, expand_targets, scan_ports
from .security import audit_device
from .version import get_build_info


def run_scan(config: Config, target_values: list[str] | None = None,
             on_device: Callable[[Device], None] | None = None,
             on_progress: Callable[[str, int], None] | None = None) -> ScanResult:
    config.validate()
    targets = expand_targets(config.subnet, target_values)
    if not config.allow_public_targets and any(not is_private_target(value) for value in targets):
        raise ValueError("Explizite Ziele außerhalb privater IPv4-Netze sind gesperrt.")
    result = ScanResult(subnet=config.subnet, started_at=utc_now(),
                        scanner_version=get_build_info()["version"],
                        scanned_hosts=len(targets))
    try:
        if on_progress:
            on_progress("discovery", 8)
        devices = discover(config, targets, on_device)
        if config.scan_type in {"full", "custom"} or config.security_audit_enabled:
            if on_progress:
                on_progress("ports", 42)
            with ThreadPoolExecutor(max_workers=min(50, config.max_concurrent)) as executor:
                futures = [executor.submit(scan_ports, item, config.ports, config)
                           for item in devices]
                devices = [future.result() for future in as_completed(futures)]
        if config.security_audit_enabled:
            if on_progress:
                on_progress("audit", 72)
            devices = [audit_device(item) for item in devices]
        if on_progress:
            on_progress("assessment", 94)
        result.devices = sorted(devices, key=lambda item: tuple(map(int, item.ip.split("."))))
        result.security_summary = network_assessment(result.devices)
    except (OSError, ValueError, RuntimeError) as exc:
        result.errors.append(str(exc))
    result.finished_at = utc_now()
    return result
