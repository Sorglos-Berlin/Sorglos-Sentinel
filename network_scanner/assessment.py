"""Aggregate device findings without hiding a critical host in an average."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .models import Device


def network_assessment(devices: list[Device]) -> dict[str, Any]:
    """Build a transparent network-level assessment.

    The highest-risk host carries most weight, followed by the three riskiest
    hosts and the network average. This prevents many clean hosts from masking
    one urgent device.
    """
    if not devices:
        return {
            "overall_risk": 0, "health_score": 100, "highest_risk": 0,
            "highest_risk_device": "", "coverage_percent": 0,
            "confidence_percent": 0, "confidence_label": "Keine Daten",
            "device_count": 0, "open_port_count": 0, "finding_counts": {},
            "inconclusive_checks": 0, "limited_checks": 0, "limitations": {},
        }
    ordered = sorted(devices, key=lambda item: item.risk_score, reverse=True)
    scores = [item.risk_score for item in ordered]
    highest = scores[0]
    top_average = sum(scores[:3]) / min(3, len(scores))
    average = sum(scores) / len(scores)
    overall = round(0.55 * highest + 0.25 * top_average + 0.20 * average)

    measurable = {"completed", "passed", "inconclusive"}
    applicable: list[str] = []
    limitation_statuses: list[str] = []
    for device in devices:
        for value in device.audit_coverage.values():
            if value in measurable:
                applicable.append(value)
            elif value != "not_applicable":
                limitation_statuses.append(value)
    completed = sum(value in {"completed", "passed"} for value in applicable)
    inconclusive = sum(value == "inconclusive" for value in applicable)
    coverage = round(100 * completed / len(applicable)) if applicable else 0

    findings = [item for device in devices for item in device.findings]
    confidence_weight = {"high": 1.0, "medium": 0.6, "low": 0.3}
    confidence = round(
        100 * sum(confidence_weight.get(item.confidence, 0.5) for item in findings)
        / len(findings)
    ) if findings else (100 if applicable and coverage == 100 else 0)
    confidence_label = (
        "Hoch" if confidence >= 80 else "Mittel" if confidence >= 50
        else "Niedrig" if confidence > 0 else "Keine Daten"
    )
    type_counts = Counter(item.finding_type for item in findings)
    severity_counts = Counter(item.severity for item in findings)
    return {
        "overall_risk": min(100, overall),
        "health_score": max(0, 100 - overall),
        "highest_risk": highest,
        "highest_risk_device": ordered[0].hostname or ordered[0].ip,
        "coverage_percent": coverage,
        "confidence_percent": confidence,
        "confidence_label": confidence_label,
        "device_count": len(devices),
        "open_port_count": sum(len(item.open_ports) for item in devices),
        "finding_counts": {
            "confirmed": type_counts["confirmed"],
            "exposure": type_counts["exposure"],
            "inconclusive": type_counts["inconclusive"],
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
        },
        "inconclusive_checks": inconclusive,
        "limited_checks": len(limitation_statuses),
        "limitations": dict(Counter(limitation_statuses)),
    }
