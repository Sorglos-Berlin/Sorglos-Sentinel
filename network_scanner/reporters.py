"""Console, CSV, JSON and self-contained HTML reports."""

from __future__ import annotations

import csv
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ScanResult

REPORT_FILENAME = re.compile(
    r"^(scan-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}|statistikbericht-[0-9a-f]{8})"
    r"\.(json|csv|html)$"
)

RISK_COLORS = {
    "Nicht bewertet": "#8e8e93",
    "Sicher": "#34c759", "Niedrig": "#ffd60a", "Mittel": "#ff9500",
    "Hoch": "#ff3b30", "Kritisch": "#bf0000",
}
FINDING_TYPES = {"confirmed": "Bestätigter Befund", "exposure": "Erreichbarer Dienst",
                 "inconclusive": "Nicht abschließend prüfbar"}
CONFIDENCE = {"high": "hoch", "medium": "mittel", "low": "niedrig"}
AUDIT_STATUS = {"completed": "ausgeführt", "passed": "ohne Befund",
                "inconclusive": "nicht abschließend", "not_applicable": "nicht anwendbar",
                "disabled": "deaktiviert", "limited": "technisch begrenzt",
                "skipped": "übersprungen"}


def export_statistics_html(statistics: dict, path: Path) -> Path:
    """Create a self-contained local trend report from history summaries."""
    scans = statistics.get("scans", [])
    def assessment_value(scan: dict, key: str) -> str:
        value = scan.get(key)
        return f"{value}/100" if scan.get("assessment_available") and value is not None else "Nicht bewertbar"

    rows = "".join(
        f"<tr><td>{html.escape(str(scan.get('timestamp', '—')))}</td>"
        f"<td>{html.escape(str(scan.get('subnet', '—')))}</td>"
        f"<td>{scan.get('devices', 0)}</td><td>{scan.get('open_ports', 0)}</td>"
        f"<td>{scan.get('findings', 0)}</td><td>{assessment_value(scan, 'overall_risk')}</td>"
        f"<td>{assessment_value(scan, 'health_score')}</td></tr>" for scan in scans
    ) or '<tr><td colspan="7">Noch keine gespeicherten Scans.</td></tr>'
    latest = statistics.get("latest") or {}
    latest_assessed = bool(latest.get("devices")) and latest.get("assessment_available", True)
    latest_health = latest.get("health_score") if latest_assessed else "Nicht bewertbar"
    best_health = statistics.get("best_health")
    best_health = best_health if best_health is not None else "Noch nicht ermittelt"
    document = f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Sorglos Sentinel – Statistikbericht</title>
<style>:root{{--bg:#f2f2f7;--card:#fff;--text:#1c1c1e;--muted:#6e6e73;--blue:#007aff}}
@media(prefers-color-scheme:dark){{:root{{--bg:#000;--card:#1c1c1e;--text:#fff;--muted:#aaa;--blue:#0a84ff}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px system-ui,sans-serif}}
main{{max-width:1100px;margin:auto;padding:32px}}h1{{font-size:32px;margin-bottom:4px}}.muted{{color:var(--muted)}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}}.card,.table{{background:var(--card);border-radius:16px;padding:18px}}
.card strong{{display:block;font-size:28px;color:var(--blue)}}.card span{{color:var(--muted)}}.table{{overflow:auto}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #8883}}th{{color:var(--muted)}}
@media(max-width:700px){{.stats{{grid-template-columns:1fr 1fr}}}}</style></head><body><main>
<h1>Statistikbericht</h1><p class="muted">Netzwerk {html.escape(str(statistics.get('selected_subnet') or 'Noch kein Netzwerk gescannt'))} · Lokal erzeugt · {html.escape(str(latest.get('timestamp') or 'Noch kein Scan gespeichert'))}</p>
<div class="stats"><div class="card"><strong>{statistics.get('total_scans', 0)}</strong><span>Gespeicherte Scans</span></div>
<div class="card"><strong>{latest_health}</strong><span>Aktueller Zustand</span></div>
<div class="card"><strong>{best_health}</strong><span>Bester bewertbarer Zustand</span></div>
<div class="card"><strong>{statistics.get('worst_risk') if statistics.get('worst_risk') is not None else 'Noch nicht ermittelt'}</strong><span>Höchstes bewertbares Risiko</span></div></div>
<div class="table"><h2>Scanverlauf</h2><table><thead><tr><th>Zeitpunkt</th><th>Netz</th><th>Geräte</th><th>Ports</th><th>Befunde</th><th>Risiko</th><th>Zustand</th></tr></thead><tbody>{rows}</tbody></table></div>
</main></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path


def console_report(result: ScanResult) -> None:
    print(f"\nScan beendet: {len(result.devices)} aktive Geräte / "
          f"{result.scanned_hosts} Ziele")
    print(f"{'IP':<16} {'Hostname':<28} {'Ports':<24} {'Risiko':<12}")
    print("-" * 84)
    for device in result.devices:
        ports = ",".join(map(str, device.open_ports)) or "-"
        risk = (f"{device.risk_score:>3} {device.risk_category}"
                if device.risk_category != "Nicht bewertet" else "Nicht bewertet")
        print(f"{device.ip:<16} {device.hostname[:27]:<28} "
              f"{ports[:23]:<24} {risk}")
    for error in result.errors:
        print(f"Fehler: {error}")


def export_json(result: ScanResult, path: Path) -> Path:
    path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return path


def export_csv(result: ScanResult, path: Path) -> Path:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["IP", "MAC", "Hostname", "Hersteller", "Status",
                         "Offene Ports", "Risiko", "Kategorie", "Befunde",
                         "Compliance", "Audit-Abdeckung",
                         "Erstentdeckung", "Letzte Aktivität"])
        for device in result.devices:
            writer.writerow([
                device.ip, device.mac, device.hostname, device.vendor, device.status,
                ",".join(map(str, device.open_ports)),
                device.risk_score if device.risk_category != "Nicht bewertet" else "",
                device.risk_category, "; ".join(item.title for item in device.findings),
                "; ".join(f"{key}={'OK' if value else 'FAIL'}"
                          for key, value in device.compliance.items()),
                "; ".join(f"{key}={value}"
                          for key, value in device.audit_coverage.items()),
                device.first_seen, device.last_seen,
            ])
    return path


def export_html(result: ScanResult, path: Path) -> Path:
    counts = {name: 0 for name in RISK_COLORS}
    for device in result.devices:
        counts[device.risk_category] = counts.get(device.risk_category, 0) + 1
    summary = result.security_summary
    assessed = bool(result.devices) and summary.get("assessment_available", True)
    summary_cards = "".join([
        f'<div class="stat"><b>{summary.get("health_score") if assessed else "Nicht bewertbar"}</b>'
        f'<span>Netzwerkzustand</span></div>',
        f'<div class="stat"><b>{summary.get("highest_risk") if assessed else "Nicht bewertbar"}</b>'
        f'<span>Höchstes Geräterisiko</span></div>',
        f'<div class="stat"><b>{str(summary.get("coverage_percent", 0)) + "%" if assessed else "Nicht geprüft"}</b>'
        f'<span>Prüfabdeckung</span></div>',
        f'<div class="stat"><b>{html.escape(str(summary.get("confidence_label", "Keine Daten")))}</b>'
        f'<span>Ergebnisvertrauen</span></div>',
    ])
    risk_cards = "".join(
        f'<div class="stat"><b>{value}</b><span>{html.escape(name)}</span></div>'
        for name, value in counts.items()
    )
    cards = summary_cards + risk_cards
    rows = []
    details = []
    for index, device in enumerate(result.devices):
        color = RISK_COLORS.get(device.risk_category, "#8e8e93")
        rows.append(
            f'<tr data-text="{html.escape((device.ip + " " + device.hostname + " " + device.vendor).lower())}">'
            f"<td>{html.escape(device.ip)}</td><td>{html.escape(device.hostname or 'Nicht ermittelt')}</td>"
            f"<td>{html.escape(device.mac or 'Nicht ermittelt')}</td><td>{html.escape(device.vendor or 'Nicht bestimmbar')}</td>"
            f"<td>{html.escape(', '.join(map(str, device.open_ports)) or 'Keine geprüften Ports erreichbar')}</td>"
            f'<td><span class="badge" style="background:{color}">'
            f"{(str(device.risk_score) + '/100 · ') if device.risk_category != 'Nicht bewertet' else ''}"
            f"{html.escape(device.risk_category)}</span></td>"
            f'<td><a href="#device-{index}">{len(device.findings)} Befunde</a></td></tr>'
        )
        finding_rows = "".join(
            f'<li class="{item.severity}"><b>{html.escape(item.title)}</b>'
            f"<p><small>{html.escape(FINDING_TYPES.get(item.finding_type, 'Nicht klassifiziert'))} · "
            f"Aussagekraft {html.escape(CONFIDENCE.get(item.confidence, 'nicht bewertet'))}</small><br>"
            f"{html.escape(item.description)}"
            f"{'<br><strong>Nachweis:</strong> ' + html.escape(item.evidence) if item.evidence else ''} "
            f"<strong>Empfehlung:</strong> "
            f"{html.escape(item.recommendation)}</p></li>"
            for item in device.findings
        ) or "<li>Die ausgeführten Prüfungen ergaben keine Sicherheitsbefunde. Dies ist kein vollständiger Sicherheitsnachweis.</li>"
        compliance = " · ".join(
            f"{html.escape(name.upper())}: {'✓' if passed else '✗'}"
            for name, passed in device.compliance.items()
        )
        details.append(
            f'<section id="device-{index}"><h2>{html.escape(device.hostname or device.ip)}</h2>'
            f"<p>{html.escape(device.ip)} · "
            f"{('Risiko ' + str(device.risk_score) + '/100') if device.risk_category != 'Nicht bewertet' else 'Keine Risikobewertung durchgeführt'}"
            f"{(' · ' + compliance) if compliance else ''}</p>"
            f"<p><strong>Audit-Abdeckung:</strong> "
            f"{html.escape(', '.join(f'{key}: {AUDIT_STATUS.get(value, value)}' for key, value in device.audit_coverage.items()) or 'Kein Sicherheits-Audit ausgeführt')}</p>"
            f"<ul>{finding_rows}</ul></section>"
        )
    document = f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Netzwerk-Sicherheitsbericht</title><style>
:root{{--bg:#f2f2f7;--card:#fff;--text:#1c1c1e;--muted:#636366}}
@media(prefers-color-scheme:dark){{:root{{--bg:#000;--card:#1c1c1e;--text:#fff;--muted:#aeaeb2}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}}
main{{max-width:1180px;margin:auto;padding:32px}}header{{padding:24px 0}}h1{{font-size:34px;margin:0 0 8px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:20px 0}}
.stat,section,.table-wrap{{background:var(--card);border-radius:16px;padding:18px;box-shadow:0 5px 20px #0001}}
.stat b{{font-size:28px;display:block}}.stat span,.muted{{color:var(--muted)}}
input{{width:100%;padding:12px;border:1px solid #8e8e9355;border-radius:10px;background:var(--card);color:var(--text)}}
.table-wrap{{overflow:auto;margin-top:12px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #8e8e9333;white-space:nowrap}}
.badge{{color:white;padding:5px 9px;border-radius:99px}}section{{margin-top:20px}}li{{margin:10px 0}}li p{{margin:5px 0;color:var(--muted)}}a{{color:#007aff}}.critical,.high{{border-left:4px solid #ff3b30;padding-left:10px}}
</style></head><body><main><header><h1>Netzwerk-Sicherheitsbericht</h1>
<div class="muted">{html.escape(result.subnet)} · {html.escape(result.finished_at)}</div></header>
<p><strong>Gesamtrisiko:</strong> {str(summary.get("overall_risk", 0)) + '/100' if assessed else 'Nicht bewertbar'} ·
<strong>Höchstes Geräterisiko:</strong> {html.escape(str(summary.get("highest_risk_device") or "Kein Gerät bewertbar"))} ·
<strong>Unklare Prüfungen:</strong> {summary.get("inconclusive_checks", 0)}</p>
<div class="stats">{cards}</div><input id="search" aria-label="Geräte suchen" placeholder="Geräte durchsuchen …">
<div class="table-wrap"><table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th>
<th>Hersteller</th><th>Ports</th><th>Risiko</th><th>Details</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>{''.join(details)}</main>
<script>const q=document.querySelector('#search');q.addEventListener('input',()=>{{for(const r of document.querySelectorAll('tbody tr'))r.hidden=!r.dataset.text.includes(q.value.toLowerCase())}});</script>
</body></html>"""
    path.write_text(document, encoding="utf-8")
    return path


def list_reports(output_dir: str) -> list[dict[str, Any]]:
    """List previously exported report files for the local dashboard."""
    directory = Path(output_dir)
    if not directory.exists():
        return []
    reports = []
    for path in directory.iterdir():
        if path.is_file() and REPORT_FILENAME.fullmatch(path.name):
            stat = path.stat()
            reports.append({
                "name": path.name,
                "format": path.suffix.lstrip("."),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
    reports.sort(key=lambda item: item["modified"], reverse=True)
    return reports


def resolve_report_path(output_dir: str, filename: str) -> Path | None:
    """Resolve a report filename to a path strictly inside output_dir, or None."""
    if not REPORT_FILENAME.fullmatch(filename):
        return None
    directory = Path(output_dir).resolve()
    target = (directory / filename).resolve()
    if target.parent != directory or not target.is_file():
        return None
    return target


def export_reports(result: ScanResult, formats: list[str], output_dir: str) -> list[Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = result.started_at[:19].replace(":", "-")
    written: list[Path] = []
    for output_format in formats:
        name = output_format.lower().strip()
        if name == "json":
            written.append(export_json(result, directory / f"scan-{stamp}.json"))
        elif name == "csv":
            written.append(export_csv(result, directory / f"scan-{stamp}.csv"))
        elif name == "html":
            written.append(export_html(result, directory / f"scan-{stamp}.html"))
        elif name == "pdf":
            html_path = export_html(result, directory / f"scan-{stamp}.html")
            try:
                from weasyprint import HTML  # type: ignore
                pdf_path = directory / f"scan-{stamp}.pdf"
                HTML(filename=str(html_path)).write_pdf(str(pdf_path))
                written.append(pdf_path)
            except ImportError:
                if html_path not in written:
                    written.append(html_path)
    return written
