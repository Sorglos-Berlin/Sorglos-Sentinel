"""Private, local scan archive and trend statistics."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import ScanResult

HISTORY_VERSION = 1
SAFE_ID = re.compile(r"^[a-zA-Z0-9_-]{8,80}$")


def _canonical_subnet(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value


def _archive_dir(output_dir: str) -> Path:
    return Path(output_dir) / "history" / "scans"


def _summary(result: dict[str, Any], scan_id: str) -> dict[str, Any]:
    devices = result.get("devices", [])
    findings = [finding for device in devices for finding in device.get("findings", [])]
    assessed_devices = [device for device in devices
                        if device.get("risk_category") != "Nicht bewertet"]
    risks = [int(device.get("risk_score", 0)) for device in assessed_devices]
    security = result.get("security_summary", {})
    started = result.get("started_at", "")
    finished = result.get("finished_at", "")
    duration = 0
    try:
        duration = max(0, round((datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds()))
    except (TypeError, ValueError):
        pass
    assessment_available = bool(security.get(
        "assessment_available",
        bool(devices) and any(device.get("risk_category") != "Nicht bewertet"
                              for device in devices),
    ))
    overall_risk = security.get("overall_risk")
    health_score = security.get("health_score")
    return {
        "id": scan_id,
        "timestamp": finished or started,
        "subnet": _canonical_subnet(result.get("subnet", "")),
        "duration_seconds": duration,
        "scanned_hosts": int(result.get("scanned_hosts", 0)),
        "devices": len(devices),
        "open_ports": sum(len(device.get("open_ports", [])) for device in devices),
        "findings": len(findings),
        "critical_findings": sum(f.get("severity") == "critical" for f in findings),
        "high_findings": sum(f.get("severity") == "high" for f in findings),
        "assessed_devices": len(assessed_devices),
        "unassessed_devices": len(devices) - len(assessed_devices),
        "risky_devices": sum(int(device.get("risk_score", 0)) >= 31
                             for device in assessed_devices),
        "average_risk": round(sum(risks) / len(risks), 1) if risks else None,
        "assessment_available": assessment_available,
        "overall_risk": int(overall_risk) if assessment_available and overall_risk is not None else None,
        "health_score": int(health_score) if assessment_available and health_score is not None else None,
        "coverage_percent": int(security.get("coverage_percent", 0)),
        "confidence_label": security.get("confidence_label", "Keine Daten"),
        "errors": len(result.get("errors", [])),
    }


def save_history(result: ScanResult, output_dir: str) -> Path:
    """Persist a complete result locally and return its archive path."""
    directory = _archive_dir(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    raw = result.to_dict()
    seed = f"{result.started_at}|{result.finished_at}|{result.subnet}"
    scan_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    path = directory / f"{scan_id}.json"
    payload = {"schema_version": HISTORY_VERSION, "summary": _summary(raw, scan_id), "result": raw}
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
    return path


def load_history(output_dir: str, limit: int = 250) -> list[dict[str, Any]]:
    """Load newest archive summaries, skipping corrupt records safely."""
    records: list[dict[str, Any]] = []
    for path in _archive_dir(output_dir).glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload.get("summary"), dict):
                summary = dict(payload["summary"])
                summary["subnet"] = _canonical_subnet(summary.get("subnet", ""))
                records.append(summary)
        except (OSError, json.JSONDecodeError, TypeError):
            continue
    records.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
    return records[:max(1, min(limit, 1000))]


def load_scan(output_dir: str, scan_id: str) -> dict[str, Any] | None:
    if not SAFE_ID.fullmatch(scan_id):
        return None
    path = _archive_dir(output_dir) / f"{scan_id}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def history_statistics(output_dir: str, subnet: str | None = None) -> dict[str, Any]:
    all_scans = load_history(output_dir, limit=1000)
    selected_subnet = _canonical_subnet(subnet) if subnet else (
        all_scans[0].get("subnet", "") if all_scans else ""
    )
    scans = [scan for scan in all_scans if scan.get("subnet") == selected_subnet]
    network_map: dict[str, list[dict[str, Any]]] = {}
    for scan in all_scans:
        subnet_name = scan.get("subnet") or "Nicht zugeordnet"
        network_map.setdefault(subnet_name, []).append(scan)
    networks = [{
        "subnet": name,
        "scan_count": len(items),
        "latest_timestamp": items[0].get("timestamp", ""),
        "latest_health": items[0].get("health_score"),
        "latest_risk": items[0].get("overall_risk"),
    } for name, items in network_map.items()]
    chronological = list(reversed(scans))
    assessed_scans = [scan for scan in scans if scan.get(
        "assessment_available", scan.get("devices", 0) > 0)]
    latest = scans[0] if scans else None
    previous = scans[1] if len(scans) > 1 else None
    changes = {}
    if latest and previous:
        for key in ("devices", "open_ports", "findings"):
            changes[key] = latest[key] - previous[key]
        if latest.get("assessment_available") and previous.get("assessment_available"):
            for key in ("overall_risk", "health_score"):
                changes[key] = latest[key] - previous[key]
    return {
        "total_scans": len(scans),
        "selected_subnet": selected_subnet,
        "networks": networks,
        "latest": latest,
        "changes": changes,
        "averages": {
            **{
                key: round(sum(scan[key] for scan in scans) / len(scans), 1) if scans else None
                for key in ("devices", "open_ports", "findings")
            },
            **{
                key: round(sum(scan[key] for scan in assessed_scans) / len(assessed_scans), 1)
                if assessed_scans else None
                for key in ("overall_risk", "health_score")
            },
        },
        "best_health": max((scan["health_score"] for scan in assessed_scans), default=None),
        "worst_risk": max((scan["overall_risk"] for scan in assessed_scans), default=None),
        "trend": [scan for scan in chronological if scan.get(
            "assessment_available", scan.get("devices", 0) > 0)][-30:],
        "scans": scans,
    }


def purge_history(output_dir: str) -> int:
    """Delete only archived scan records, leaving exported reports intact."""
    directory = _archive_dir(output_dir)
    if not directory.exists():
        return 0
    count = 0
    for path in directory.glob("*.json"):
        path.unlink()
        count += 1
    return count


def purge_data(output_dir: str) -> int:
    directory = Path(output_dir).resolve()
    if not directory.exists():
        return 0
    count = 0
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".csv", ".html", ".pdf", ".log"}:
            path.unlink()
            count += 1
    return count
