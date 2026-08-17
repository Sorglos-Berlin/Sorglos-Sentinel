from __future__ import annotations

import csv
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from network_scanner.config import (
    Config, default_local_subnet, detect_local_ipv4, is_private_target,
    load_persisted_config, save_persisted_config,
)
from network_scanner.assessment import network_assessment
from network_scanner.history import (
    history_statistics, load_history, load_scan, purge_data, save_history,
)
from network_scanner.models import Device, Finding, ScanResult
from network_scanner.oui import OuiDatabase
from network_scanner.reporters import (
    export_csv, export_html, export_json, export_statistics_html,
)
from network_scanner.scanners import (
    enrich_devices, expand_targets, parse_neighbor_cache, resolve_hostname,
    resolve_netbios_name, scan_ports,
)
from network_scanner.security import (
    audit_device, audit_exposed_services, audit_ssh, audit_starttls, audit_web,
    evaluate, record_audit_boundaries,
)
from network_scanner.webapp import AppState, DashboardHandler
from network_scanner.version import get_build_info


class ConfigTests(unittest.TestCase):
    def test_defaults_validate(self):
        Config(subnet="192.168.1.0/24").validate()

    def test_complete_scan_and_security_audit_are_defaults(self):
        config = Config(subnet="192.168.1.0/24")
        self.assertEqual(config.scan_type, "full")
        self.assertTrue(config.security_audit_enabled)

    def test_settings_survive_local_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            expected = Config(
                subnet="10.20.30.0/24", scan_type="custom", ports=[22, 443],
                timeout=2.5, security_audit_enabled=False,
            )
            save_persisted_config(expected, path)
            loaded = load_persisted_config(path)
            self.assertEqual(loaded.subnet, expected.subnet)
            self.assertEqual(loaded.scan_type, expected.scan_type)
            self.assertEqual(loaded.ports, expected.ports)
            self.assertEqual(loaded.timeout, expected.timeout)
            self.assertFalse(loaded.security_audit_enabled)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_invalid_settings_fall_back_to_safe_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text("{invalid", encoding="utf-8")
            loaded = load_persisted_config(path)
            self.assertEqual(loaded.scan_type, "full")
            self.assertTrue(loaded.security_audit_enabled)

    @patch("network_scanner.config.socket.getaddrinfo", side_effect=OSError)
    @patch("network_scanner.config.socket.socket")
    def test_failed_adapter_detection_returns_no_fabricated_address(self, socket_factory, _lookup):
        socket_factory.return_value.connect.side_effect = OSError
        detect_local_ipv4.cache_clear()
        try:
            self.assertEqual(detect_local_ipv4(), "")
            self.assertEqual(default_local_subnet(), "")
        finally:
            detect_local_ipv4.cache_clear()

    def test_missing_scan_scope_has_clear_validation_error(self):
        with self.assertRaisesRegex(ValueError, "keine private lokale IPv4-Adresse"):
            Config(subnet="").validate()

    def test_bad_concurrency_rejected(self):
        with self.assertRaises(ValueError):
            Config(max_concurrent=0).validate()

    def test_bad_port_rejected(self):
        with self.assertRaises(ValueError):
            Config(ports=[0]).validate()

    def test_json_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"subnet":"10.0.0.0/30","timeout":2}', encoding="utf-8")
            config = Config.from_file(str(path))
            self.assertEqual(config.timeout, 2)

    def test_merge_ignores_none(self):
        self.assertEqual(Config(timeout=2).merge({"timeout": None}).timeout, 2)

    def test_default_scan_scope_is_private(self):
        network = default_local_subnet()
        if not network:
            self.skipTest("Keine private IPv4-Adresse auf dem Testsystem erkannt")
        self.assertTrue(is_private_target(network.split("/", 1)[0]))
        Config(subnet=network).validate()

    def test_public_network_rejected_by_default(self):
        with self.assertRaisesRegex(ValueError, "private IPv4"):
            Config(subnet="8.8.8.0/24").validate()

    def test_public_network_requires_explicit_expert_opt_in(self):
        Config(subnet="8.8.8.0/24", allow_public_targets=True).validate()


class VersionTests(unittest.TestCase):
    def tearDown(self):
        get_build_info.cache_clear()

    @patch("network_scanner.version.subprocess.run")
    def test_git_build_version_contains_commit(self, run):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".git").mkdir()
            run.side_effect = [
                MagicMock(stdout="abc12345-dirty\n"),
                MagicMock(stdout="abc12345\n"),
            ]
            get_build_info.cache_clear()
            info = get_build_info(directory)
            self.assertEqual(info["commit"], "abc12345")
            self.assertTrue(info["dirty"])
            self.assertIn("lokal geändert", info["display"])

    @patch("network_scanner.version.subprocess.run", side_effect=OSError)
    def test_git_metadata_fallback_reads_head(self, _run):
        with tempfile.TemporaryDirectory() as directory:
            git = Path(directory) / ".git"
            (git / "refs" / "heads").mkdir(parents=True)
            (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (git / "refs" / "heads" / "main").write_text("1234567890abcdef\n", encoding="utf-8")
            get_build_info.cache_clear()
            info = get_build_info(directory)
            self.assertEqual(info["commit"], "12345678")
            self.assertEqual(info["source"], "git-metadata")


class ScannerTests(unittest.TestCase):
    def test_expand_subnet(self):
        self.assertEqual(expand_targets("192.0.2.0/30"), ["192.0.2.1", "192.0.2.2"])

    def test_explicit_targets_are_sorted(self):
        self.assertEqual(expand_targets("192.0.2.0/24", ["192.0.2.9", "192.0.2.1"]),
                         ["192.0.2.1", "192.0.2.9"])

    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):
            expand_targets("2001:db8::/126")

    def test_large_network_rejected(self):
        with self.assertRaises(ValueError):
            expand_targets("10.0.0.0/8")

    def test_oui_lookup(self):
        self.assertEqual(
            OuiDatabase(include_system=False).lookup("00:50:56:aa:bb:cc"),
            "VMware",
        )

    def test_unknown_oui(self):
        self.assertEqual(
            OuiDatabase(include_system=False).lookup("00:00:00:00:00:01"),
            "Unbekannt",
        )

    def test_private_mac_vendor(self):
        self.assertEqual(
            OuiDatabase(include_system=False).lookup("86:c3:2c:54:8d:32"),
            "Private/zufällige MAC",
        )

    def test_custom_oui_file_has_final_priority(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vendors.txt"
            path.write_text("005056 Custom VMware Name\n", encoding="utf-8")
            database = OuiDatabase(str(path), include_system=False)
        self.assertEqual(database.lookup("00:50:56:aa:bb:cc"),
                         "Custom VMware Name")

    @patch("network_scanner.oui.OuiDatabase._system_candidates")
    def test_builtin_names_override_system_database(self, candidates):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "system-vendors.txt"
            path.write_text("005056 Inc.\n", encoding="utf-8")
            candidates.return_value = [path]
            database = OuiDatabase()
        self.assertEqual(database.lookup("00:50:56:aa:bb:cc"), "VMware")

    def test_parse_windows_arp_cache(self):
        output = """
          Internetadresse       Physische Adresse     Typ
          192.168.0.1           b0-0a-d5-bc-43-ed     dynamisch
          192.168.0.255         ff-ff-ff-ff-ff-ff     statisch
        """
        self.assertEqual(
            parse_neighbor_cache(output),
            {"192.168.0.1": "b0:0a:d5:bc:43:ed"},
        )

    @patch("network_scanner.scanners.read_neighbor_cache",
           return_value={"192.0.2.1": "00:50:56:aa:bb:cc"})
    @patch("network_scanner.scanners.resolve_hostname", return_value="server.local")
    def test_enrich_device(self, _hostname, _neighbors):
        devices = enrich_devices([Device("192.0.2.1")], Config())
        self.assertEqual(devices[0].mac, "00:50:56:aa:bb:cc")
        self.assertEqual(devices[0].vendor, "VMware")
        self.assertEqual(devices[0].hostname, "server.local")

    @patch("network_scanner.scanners.subprocess.run")
    def test_netbios_name(self, run):
        run.return_value.stdout = "  OFFICE-PC      <00>  EINDEUTIG Registriert"
        self.assertEqual(resolve_netbios_name("192.0.2.1"), "OFFICE-PC")

    @patch("network_scanner.scanners.socket.gethostbyaddr", side_effect=OSError)
    def test_dns_failure_is_empty(self, _mock):
        self.assertEqual(resolve_hostname("192.0.2.1"), "")


class SecurityTests(unittest.TestCase):
    def test_telnet_is_critical(self):
        findings = audit_exposed_services(Device("192.0.2.1", open_ports=[23]))
        self.assertEqual(findings[0].points, 25)

    def test_database_exposure(self):
        codes = {item.code for item in audit_exposed_services(
            Device("192.0.2.1", open_ports=[6379])
        )}
        self.assertIn("DATABASE_EXPOSED", codes)

    def test_ssh_banner(self):
        findings = audit_ssh(Device("192.0.2.1", open_ports=[22],
                                    banners={22: "SSH-1.5-old"}))
        self.assertTrue(any(item.code == "SSH_LEGACY_PROTOCOL" for item in findings))

    def test_risk_caps_at_100(self):
        device = Device("192.0.2.1", findings=[
            Finding("X", "x", "critical", 80, "x", "x"),
            Finding("Y", "y", "critical", 80, "y", "y"),
        ])
        self.assertEqual(evaluate(device).risk_score, 100)

    def test_risk_category_boundaries(self):
        device = Device("192.0.2.1", findings=[
            Finding("X", "x", "medium", 31, "x", "x")
        ])
        self.assertEqual(evaluate(device).risk_category, "Mittel")

    def test_clean_device_is_compliant(self):
        self.assertTrue(all(evaluate(Device("192.0.2.1")).compliance.values()))

    def test_cleartext_ftp_is_high_risk(self):
        findings = audit_exposed_services(Device("192.0.2.1", open_ports=[21]))
        self.assertEqual(findings[0].code, "FTP_CLEARTEXT")
        self.assertEqual(findings[0].confidence, "high")

    def test_duplicate_finding_does_not_double_score(self):
        duplicate = Finding("SAME", "x", "high", 20, "x", "x")
        device = Device("192.0.2.1", findings=[duplicate, duplicate])
        self.assertEqual(evaluate(device).risk_score, 20)

    def test_audit_records_coverage_and_log(self):
        device = audit_device(Device("192.0.2.1"))
        self.assertEqual(device.audit_coverage["service_exposure"], "completed")
        self.assertEqual(device.audit_coverage["ssh_banner"], "not_applicable")
        self.assertTrue(device.audit_log)

    def test_critical_device_is_not_hidden_by_average(self):
        devices = [Device("192.0.2.1", risk_score=100, risk_category="Kritisch")]
        devices.extend(Device(f"192.0.2.{index}", risk_score=0, risk_category="Sicher")
                       for index in range(2, 11))
        summary = network_assessment(devices)
        self.assertGreaterEqual(summary["overall_risk"], 60)
        self.assertEqual(summary["highest_risk_device"], "192.0.2.1")

    def test_coverage_ignores_not_applicable_checks(self):
        device = Device("192.0.2.1", audit_coverage={
            "web": "not_applicable", "services": "completed",
            "tls": "inconclusive",
        }, risk_category="Sicher")
        summary = network_assessment([device])
        self.assertEqual(summary["coverage_percent"], 50)
        self.assertEqual(summary["inconclusive_checks"], 1)

    def test_confidence_uses_evidence_quality(self):
        device = Device("192.0.2.1", findings=[
            Finding("A", "a", "high", 10, "a", "a", confidence="high"),
            Finding("B", "b", "low", 1, "b", "b", confidence="low"),
        ], risk_category="Niedrig")
        summary = network_assessment([device])
        self.assertEqual(summary["confidence_percent"], 65)
        self.assertEqual(summary["confidence_label"], "Mittel")

    def test_empty_assessment_has_no_fake_confidence(self):
        summary = network_assessment([])
        self.assertEqual(summary["confidence_label"], "Keine Daten")
        self.assertEqual(summary["coverage_percent"], 0)
        self.assertFalse(summary["assessment_available"])

    def test_discovered_but_unaudited_device_is_not_rated_safe(self):
        device = Device("192.0.2.1")
        summary = network_assessment([device])
        self.assertEqual(device.risk_category, "Nicht bewertet")
        self.assertFalse(summary["assessment_available"])
        self.assertIsNone(summary["health_score"])
        self.assertEqual(summary["unassessed_device_count"], 1)

    @patch("network_scanner.security._read_protocol",
           side_effect=[b"220 mail", b"250-STARTTLS\r\n250 OK"])
    @patch("network_scanner.security.socket.create_connection")
    def test_smtp_starttls_capability_passes(self, connection, _read):
        connection.return_value.__enter__.return_value = MagicMock()
        self.assertEqual(audit_starttls(Device("192.0.2.1", open_ports=[25]), 25), [])

    @patch("network_scanner.security._read_protocol",
           side_effect=[b"220 mail", b"250 AUTH PLAIN"])
    @patch("network_scanner.security.socket.create_connection")
    def test_missing_starttls_is_confirmed(self, connection, _read):
        connection.return_value.__enter__.return_value = MagicMock()
        result = audit_starttls(Device("192.0.2.1", open_ports=[25]), 25)
        self.assertEqual(result[0].code, "STARTTLS_MISSING")
        self.assertEqual(result[0].finding_type, "confirmed")

    def test_audit_boundaries_are_explicit(self):
        device = Device("192.0.2.1")
        record_audit_boundaries(device)
        self.assertEqual(device.audit_coverage["credential_testing"],
                         "disabled_by_policy")
        self.assertEqual(device.audit_coverage["wifi_wps"],
                         "not_remotely_testable")


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.result = ScanResult("192.0.2.0/24", "2026-01-01T00:00:00+00:00",
                                 "2026-01-01T00:00:01+00:00",
                                 devices=[Device("192.0.2.1", hostname="<router>")])

    def test_json_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = export_json(self.result, Path(directory) / "x.json")
            self.assertEqual(json.loads(path.read_text())["devices"][0]["ip"], "192.0.2.1")

    def test_csv_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = export_csv(self.result, Path(directory) / "x.csv")
            with path.open(encoding="utf-8-sig") as handle:
                self.assertEqual(list(csv.reader(handle))[1][0], "192.0.2.1")

    def test_html_escapes_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = export_html(self.result, Path(directory) / "x.html")
            text = path.read_text(encoding="utf-8")
            self.assertIn("&lt;router&gt;", text)
            self.assertNotIn("<router>", text)

    def test_purge_only_known_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scan.json").write_text("{}")
            (root / "keep.txt").write_text("keep")
            self.assertEqual(purge_data(directory), 1)
            self.assertTrue((root / "keep.txt").exists())

    def test_statistics_html_escapes_subnet(self):
        with tempfile.TemporaryDirectory() as directory:
            statistics = {"total_scans": 1, "best_health": 90, "worst_risk": 10,
                          "latest": {"timestamp": "2026-01-01"}, "scans": [{
                              "timestamp": "2026-01-01", "subnet": "<private>",
                              "devices": 1, "open_ports": 2, "findings": 3,
                              "overall_risk": 10, "health_score": 90,
                          }]}
            path = export_statistics_html(statistics, Path(directory) / "stats.html")
            self.assertIn("&lt;private&gt;", path.read_text(encoding="utf-8"))


class HistoryTests(unittest.TestCase):
    def result(self, started: str, risk: int = 20) -> ScanResult:
        device = Device("192.0.2.1", open_ports=[22, 443], risk_score=risk,
                        risk_category="Niedrig")
        return ScanResult("192.0.2.0/24", started,
                          started.replace("00+00:00", "05+00:00"),
                          scanned_hosts=254, devices=[device], security_summary={
                              "overall_risk": risk, "health_score": 100-risk,
                              "coverage_percent": 100, "confidence_label": "Hoch",
                          })

    def test_complete_scan_is_saved_and_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_history(self.result("2026-01-01T10:00:00+00:00"), directory)
            records = load_history(directory)
            self.assertTrue(path.exists())
            self.assertEqual(records[0]["open_ports"], 2)
            self.assertEqual(load_scan(directory, records[0]["id"])["result"]["devices"][0]["ip"], "192.0.2.1")

    def test_statistics_compare_latest_scans(self):
        with tempfile.TemporaryDirectory() as directory:
            save_history(self.result("2026-01-01T10:00:00+00:00", 10), directory)
            save_history(self.result("2026-01-02T10:00:00+00:00", 30), directory)
            stats = history_statistics(directory)
            self.assertEqual(stats["total_scans"], 2)
            self.assertEqual(stats["changes"]["overall_risk"], 20)
            self.assertEqual(stats["changes"]["health_score"], -20)

    def test_unassessed_scan_does_not_create_fake_health_statistics(self):
        with tempfile.TemporaryDirectory() as directory:
            result = ScanResult(
                "192.0.2.0/24", "2026-01-01T10:00:00+00:00",
                "2026-01-01T10:00:05+00:00", scanned_hosts=254,
                devices=[Device("192.0.2.1")],
                security_summary=network_assessment([Device("192.0.2.1")]),
            )
            save_history(result, directory)
            stats = history_statistics(directory)
            self.assertFalse(stats["latest"]["assessment_available"])
            self.assertIsNone(stats["latest"]["health_score"])
            self.assertIsNone(stats["best_health"])
            self.assertEqual(stats["averages"]["devices"], 1.0)
            self.assertIsNone(stats["averages"]["health_score"])

    def test_statistics_are_isolated_by_subnet(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.result("2026-01-01T10:00:00+00:00", 10)
            second = self.result("2026-01-02T10:00:00+00:00", 80)
            second.subnet = "10.20.30.0/24"
            save_history(first, directory)
            save_history(second, directory)
            first_stats = history_statistics(directory, "192.0.2.99/24")
            second_stats = history_statistics(directory, "10.20.30.4/24")
            self.assertEqual(first_stats["total_scans"], 1)
            self.assertEqual(first_stats["latest"]["overall_risk"], 10)
            self.assertEqual(second_stats["total_scans"], 1)
            self.assertEqual(second_stats["latest"]["overall_risk"], 80)
            self.assertEqual(len(second_stats["networks"]), 2)

    def test_history_rejects_path_traversal_and_corrupt_records(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "history" / "scans"
            archive.mkdir(parents=True)
            (archive / "broken.json").write_text("{", encoding="utf-8")
            self.assertEqual(load_history(directory), [])
            self.assertIsNone(load_scan(directory, "../../secret"))


class LocalApiSecurityTests(unittest.TestCase):
    def setUp(self):
        self.state = AppState(Config())
        handler = type("ApiSecurityTestHandler", (DashboardHandler,),
                       {"state": self.state})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_status_returns_session_token_and_security_headers(self):
        self.state.last_scan_summary = {"subnet": "10.0.0.0/24", "devices": 3}
        with urllib.request.urlopen(self.base + "/api/status") as response:
            data = json.load(response)
            self.assertEqual(data["session_token"], self.state.session_token)
            self.assertEqual(data["last_scan_summary"]["devices"], 3)
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_post_without_session_token_is_rejected(self):
        request = urllib.request.Request(
            self.base + "/api/export", data=b"{}", method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request)
        self.assertEqual(context.exception.code, 403)

    @patch("network_scanner.webapp.save_persisted_config")
    @patch("network_scanner.webapp._scan")
    def test_scan_target_is_published_as_active_before_worker_starts(self, scan_worker, _save):
        payload = json.dumps({
            "authorized": True,
            "subnet": "10.42.0.0/24",
            "scan_type": "arp",
            "security_audit": False,
        }).encode("utf-8")
        request = urllib.request.Request(
            self.base + "/api/scan", data=payload, method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Sorglos-Sentinel-Token": self.state.session_token,
            },
        )
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 202)
        self.assertEqual(self.state.config.subnet, "10.42.0.0/24")
        self.assertTrue(self.state.scanning)
        for _ in range(20):
            if scan_worker.called:
                break
            threading.Event().wait(0.01)
        scan_worker.assert_called_once()

    def test_dns_rebinding_host_is_rejected(self):
        request = urllib.request.Request(
            self.base + "/api/status", headers={"Host": "attacker.example"}
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request)
        self.assertEqual(context.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
