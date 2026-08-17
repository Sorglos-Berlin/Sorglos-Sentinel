"""Command line entry point for Network Sentinel."""

from __future__ import annotations

import argparse
import logging
import sys

from network_scanner.config import Config
from network_scanner.engine import run_scan
from network_scanner.history import purge_data, save_history
from network_scanner.reporters import console_report, export_reports

DISCLAIMER = (
    "RECHTLICHER HINWEIS: Scannen Sie ausschließlich eigene Netzwerke oder Ziele, "
    "für die Ihnen eine ausdrückliche Genehmigung vorliegt. Das Programm führt "
    "keine Exploits und standardmäßig keine Zugangsdaten-Tests aus."
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Lokaler, nicht-invasiver IPv4-Netzwerk- und Sicherheitsscanner."
    )
    result.add_argument("--config", help="JSON- oder YAML-Konfiguration")
    result.add_argument("--subnet")
    result.add_argument("--targets", help="Kommagetrennte IPv4-Adressen")
    result.add_argument("--scan-type", choices=["arp", "icmp", "full", "custom"])
    result.add_argument("--ports", help="Kommagetrennte TCP-Ports")
    result.add_argument("--timeout", type=float)
    result.add_argument("--retries", type=int)
    result.add_argument("--max-concurrent", type=int)
    result.add_argument("--format", dest="formats", help="console,csv,json,html,pdf")
    result.add_argument("--output", dest="output_dir")
    result.add_argument("--security-audit", action="store_true", default=None)
    result.add_argument("--audit-depth", choices=["basic", "standard", "deep", "comprehensive"])
    result.add_argument("--risk-threshold", type=int)
    result.add_argument("--compliance", choices=["pci_dss", "iso_27001", "bsi_grundschutz"])
    result.add_argument("--trend-analysis", action="store_true")
    result.add_argument("--gui", action="store_true",
                        help="Lokale HTML-Oberfläche öffnen")
    result.add_argument("--web", action="store_true",
                        help="Lokale HTML-Oberfläche öffnen")
    result.add_argument("--web-port", type=int, default=8765)
    result.add_argument("--cli", action="store_true",
                        help="Kommandozeilenmodus erzwingen (ohne GUI)")
    result.add_argument("--auto-scan", action="store_true")
    result.add_argument("--theme", choices=["system", "light", "dark"], default="system")
    result.add_argument("--purge-data", action="store_true")
    result.add_argument("--update-cve-db", action="store_true",
                        help="Nicht verfügbar: externe Datenbank bewusst nicht gebündelt")
    result.add_argument("--yes", action="store_true", help="Autorisierungshinweis bestätigen")
    result.add_argument("-v", "--verbose", action="count", default=0)
    return result


def build_config(args: argparse.Namespace) -> Config:
    config = Config.from_file(args.config) if args.config else Config()
    values = vars(args).copy()
    values["security_audit_enabled"] = values.pop("security_audit")
    if args.ports:
        values["ports"] = [int(item.strip()) for item in args.ports.split(",") if item.strip()]
    if args.formats:
        values["formats"] = [item.strip() for item in args.formats.split(",") if item.strip()]
    if args.compliance:
        values["compliance"] = [args.compliance]
    return config.merge(values)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose > 1 else logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        config = build_config(args)
        if args.purge_data:
            print(f"{purge_data(config.output_dir)} gespeicherte Reportdateien gelöscht.")
            return 0
        if args.update_cve_db:
            print("CVE-Update ist nicht eingerichtet. Nutzen Sie eine geprüfte interne Datenquelle.")
            return 2
        no_scan_arguments = not any([
            args.config, args.subnet, args.targets, args.scan_type, args.ports,
            args.formats, args.security_audit, args.purge_data, args.update_cve_db,
        ])
        if args.gui or args.web or (no_scan_arguments and not args.cli):
            if not 1024 <= args.web_port <= 65535:
                raise ValueError("web-port must be between 1024 and 65535")
            from network_scanner.webapp import launch_web
            launch_web(config, args.web_port)
            return 0
        print(DISCLAIMER)
        if not args.yes:
            answer = input("Sind Sie zum Scan autorisiert? [j/N] ").strip().lower()
            if answer not in {"j", "ja", "y", "yes"}:
                print("Scan abgebrochen.")
                return 1
        target_values = args.targets.split(",") if args.targets else None
        result = run_scan(config, target_values)
        console_report(result)
        formats = [item for item in config.formats if item != "console"]
        paths = export_reports(result, formats, config.output_dir)
        save_history(result, config.output_dir)
        for path in paths:
            print(f"Erstellt: {path}")
        return 0 if not result.errors else 2
    except (ValueError, OSError) as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
