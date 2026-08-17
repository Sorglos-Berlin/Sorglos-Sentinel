"""Rate-limited, non-destructive security checks with explicit evidence."""

from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
import time
import warnings
from datetime import datetime, timezone
from typing import Callable

from .models import Device, Finding, utc_now

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def finding(code: str, title: str, severity: str, points: int,
            description: str, recommendation: str, evidence: str = "",
            confidence: str = "medium",
            finding_type: str = "exposure") -> Finding:
    return Finding(code, title, severity, points, description, recommendation,
                   evidence, "", confidence, finding_type)


class AuditRunner:
    """Run checks with a per-host rate limit and an immutable-style audit trail."""

    def __init__(self, device: Device, max_rate: float = 10.0) -> None:
        self.device = device
        self.interval = 1.0 / max(1.0, max_rate)
        self.last_check = 0.0

    def run(self, name: str, check: Callable[[], list[Finding]]) -> list[Finding]:
        wait = self.interval - (time.monotonic() - self.last_check)
        if wait > 0:
            time.sleep(wait)
        started = utc_now()
        status, detail = "completed", ""
        try:
            results = check()
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
            results, status, detail = [], "inconclusive", str(exc)
        self.last_check = time.monotonic()
        self.device.audit_coverage[name] = status
        self.device.audit_log.append({
            "check": name, "timestamp": started, "status": status,
            "findings": len(results), "detail": detail[:200],
        })
        return results


def audit_exposed_services(device: Device) -> list[Finding]:
    """Classify reachable services without claiming an unverified CVE."""
    results: list[Finding] = []
    ports = set(device.open_ports)
    rules = [
        (21, "FTP_CLEARTEXT", "FTP ist erreichbar", "high", 12,
         "FTP schützt Zugangsdaten und Nutzdaten nicht durch Transportverschlüsselung.",
         "SFTP oder FTPS einsetzen."),
        (23, "TELNET_ENABLED", "Telnet ist erreichbar", "critical", 25,
         "Telnet überträgt Zugangsdaten unverschlüsselt.",
         "Telnet deaktivieren und SSH verwenden."),
        (110, "POP3_CLEARTEXT", "Unverschlüsseltes POP3", "medium", 8,
         "POP3 auf Port 110 bietet standardmäßig keine Transportverschlüsselung.",
         "POP3S oder verpflichtendes STARTTLS verwenden."),
        (143, "IMAP_CLEARTEXT", "Unverschlüsseltes IMAP", "medium", 8,
         "IMAP auf Port 143 kann ohne STARTTLS verwendet werden.",
         "IMAPS oder verpflichtendes STARTTLS einsetzen."),
        (389, "LDAP_PLAINTEXT", "Unverschlüsseltes LDAP", "high", 15,
         "LDAP auf Port 389 kann Daten unverschlüsselt übertragen.",
         "LDAPS oder verpflichtendes StartTLS erzwingen."),
        (445, "SMB_EXPOSED", "SMB ist erreichbar", "medium", 8,
         "SMB ist aus dem geprüften Segment erreichbar. Das bestätigt kein SMBv1.",
         "SMB segmentieren, Signierung erzwingen und SMBv1 separat deaktivieren."),
        (502, "MODBUS_EXPOSED", "Modbus/TCP ist erreichbar", "critical", 25,
         "Ein Industrieprotokoll ohne native Authentisierung ist erreichbar.",
         "Modbus durch industrielle Firewall und VLAN isolieren."),
        (1883, "MQTT_CLEARTEXT", "Unverschlüsseltes MQTT", "high", 12,
         "MQTT ist ohne TLS erreichbar; eine fehlende Authentisierung ist damit nicht bestätigt.",
         "MQTTS, Client-Zertifikate und ACLs einsetzen."),
        (3389, "RDP_EXPOSED", "RDP ist erreichbar", "medium", 8,
         "RDP ist erreichbar. Daraus folgt keine bestätigte BlueKeep-Anfälligkeit.",
         "NLA, MFA, Patches und Netzwerksegmentierung einsetzen."),
    ]
    for port, code, title, severity, points, description, recommendation in rules:
        if port in ports:
            results.append(finding(
                code, title, severity, points, description, recommendation,
                f"TCP-Verbindung zu Port {port} erfolgreich", "high", "exposure"))
    for port, service in [(1433, "MSSQL"), (3306, "MySQL"),
                          (5432, "PostgreSQL"), (6379, "Redis"),
                          (27017, "MongoDB")]:
        if port in ports:
            results.append(finding(
                "DATABASE_EXPOSED", f"{service}-Port ist erreichbar", "high", 12,
                "Ein Datenbankdienst ist aus dem geprüften Segment erreichbar; "
                "fehlende Authentisierung wurde nicht unterstellt.",
                "Zugriff auf benötigte Anwendungsserver beschränken und TLS erzwingen.",
                f"TCP-Verbindung zu Port {port} erfolgreich", "high", "exposure"))
    return results


def audit_ssh(device: Device) -> list[Finding]:
    if 22 not in device.open_ports:
        return []
    banner = device.banners.get(22, "")
    results: list[Finding] = []
    if banner and not banner.startswith("SSH-2.0"):
        results.append(finding(
            "SSH_LEGACY_PROTOCOL", "Veraltetes SSH-Protokoll", "critical", 20,
            "Der Server kündigt nicht ausschließlich SSHv2 an.",
            "Nur SSHv2 erlauben.", banner, "high", "confirmed"))
    if banner:
        results.append(finding(
            "SSH_BANNER_DISCLOSURE", "SSH-Produktversion offengelegt", "low", 3,
            "Der SSH-Banner enthält möglicherweise Produkt- und Versionsinformationen.",
            "Software aktuell halten und detaillierte Zusatztexte im Banner minimieren.",
            banner, "high", "confirmed"))
    else:
        results.append(finding(
            "SSH_BANNER_UNAVAILABLE", "SSH-Konfiguration nicht vollständig prüfbar",
            "info", 0, "Der Dienst antwortete nicht mit einem auswertbaren Banner.",
            "Algorithmen und Host-Schlüssel lokal mit einem autorisierten SSH-Audit prüfen.",
            "TCP-Port 22 offen, kein Banner", "high", "inconclusive"))
    return results


def _tls_connect(device: Device, port: int, context: ssl.SSLContext) -> tuple[str, str, bytes]:
    with socket.create_connection((device.ip, port), timeout=2.5) as raw:
        with context.wrap_socket(raw, server_hostname=device.hostname or device.ip) as tls:
            cipher = tls.cipher()
            return tls.version() or "unknown", cipher[0] if cipher else "", tls.getpeercert(True)


def _supported_tls_versions(device: Device, port: int) -> list[str]:
    supported: list[str] = []
    versions = [
        ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for label, version in versions:
        if version is None:
            continue
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                context.minimum_version = version
                context.maximum_version = version
                _tls_connect(device, port, context)
                supported.append(label)
            except (OSError, ssl.SSLError, ValueError):
                continue
    return supported


def audit_tls(device: Device, port: int) -> list[Finding]:
    """Inspect negotiated TLS, protocol support, trust and certificate fingerprint."""
    results: list[Finding] = []
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        version, cipher, certificate = _tls_connect(device, port, unverified)
    except (OSError, ssl.SSLError) as exc:
        return [finding(
            "TLS_HANDSHAKE_FAILED", "TLS-Prüfung nicht vollständig möglich", "info", 0,
            "Der TLS-Handshake konnte nicht abgeschlossen werden.",
            "Dienstkonfiguration lokal prüfen.", str(exc), "medium", "inconclusive")]
    fingerprint = hashlib.sha256(certificate).hexdigest() if certificate else ""
    device.banners[port] = f"{version} {cipher}".strip()
    supported = _supported_tls_versions(device, port)
    legacy = [item for item in supported if item in {"TLS 1.0", "TLS 1.1"}]
    if legacy:
        results.append(finding(
            "TLS_LEGACY", "Veraltete TLS-Version akzeptiert", "critical", 15,
            "Der Dienst akzeptiert eine nicht mehr zeitgemäße TLS-Version.",
            "TLS 1.0/1.1 deaktivieren und mindestens TLS 1.2 erzwingen.",
            ", ".join(supported), "high", "confirmed"))
    weak_tokens = ("RC4", "3DES", "DES", "NULL", "EXPORT")
    if any(token in cipher.upper() for token in weak_tokens):
        results.append(finding(
            "TLS_WEAK_CIPHER", "Schwache Cipher ausgehandelt", "high", 15,
            "Die ausgehandelte Cipher enthält einen bekannten schwachen Baustein.",
            "Nur moderne AEAD-Cipher zulassen.", cipher, "high", "confirmed"))
    try:
        _tls_connect(device, port, ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        results.append(finding(
            "CERT_UNTRUSTED", "TLS-Zertifikat nicht vertrauenswürdig", "high", 12,
            "Zertifikatskette oder Hostname konnte nicht validiert werden.",
            "Gültiges Zertifikat mit korrekter SAN-Kennung installieren.",
            f"{exc}; SHA-256 {fingerprint}", "high", "confirmed"))
    except (OSError, ssl.SSLError):
        pass
    if not results:
        device.audit_log.append({
            "check": f"tls:{port}:evidence", "timestamp": utc_now(),
            "status": "passed", "findings": 0,
            "detail": f"{version}; {cipher}; {', '.join(supported)}; SHA-256 {fingerprint}",
        })
    return results


def audit_web(device: Device, port: int) -> list[Finding]:
    results: list[Finding] = []
    is_tls = port in {443, 8443}
    connection_cls = http.client.HTTPSConnection if is_tls else http.client.HTTPConnection
    kwargs: dict[str, object] = {"timeout": 2.5}
    if is_tls:
        kwargs["context"] = ssl._create_unverified_context()
    connection = connection_cls(device.ip, port, **kwargs)
    try:
        connection.request("HEAD", "/", headers={
            "Host": device.hostname or device.ip,
            "User-Agent": "NetworkSentinel/1.0 SecurityAudit",
            "Connection": "close",
        })
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
    finally:
        connection.close()
    if not is_tls:
        results.append(finding(
            "HTTP_PLAINTEXT", "HTTP ohne TLS erreichbar", "medium", 7,
            "Der Webdienst ist unverschlüsselt erreichbar.",
            "HTTPS erzwingen und HTTP dauerhaft auf HTTPS umleiten.",
            f"HTTP {response.status} auf Port {port}", "high", "exposure"))
    checks = [
        ("strict-transport-security", "HSTS_MISSING", "HSTS fehlt", "medium", 5,
         "Strict-Transport-Security mit angemessener max-age setzen.", is_tls),
        ("content-security-policy", "CSP_MISSING", "Content-Security-Policy fehlt",
         "low", 2, "Eine anwendungsspezifische CSP definieren.", True),
        ("x-content-type-options", "NOSNIFF_MISSING", "MIME-Sniffing-Schutz fehlt",
         "low", 2, "X-Content-Type-Options: nosniff setzen.", True),
        ("x-frame-options", "XFO_MISSING", "Clickjacking-Schutz fehlt", "low", 2,
         "frame-ancestors in CSP oder X-Frame-Options setzen.", True),
        ("referrer-policy", "REFERRER_POLICY_MISSING", "Referrer-Policy fehlt",
         "low", 1, "Eine restriktive Referrer-Policy setzen.", True),
        ("permissions-policy", "PERMISSIONS_POLICY_MISSING", "Permissions-Policy fehlt",
         "low", 1, "Nicht benötigte Browserfunktionen einschränken.", True),
    ]
    for header, code, title, severity, points, recommendation, applicable in checks:
        if applicable and header not in headers:
            results.append(finding(
                code, title, severity, points, f"HTTP-Header {header} fehlt.",
                recommendation, f"HTTP {response.status}; Header nicht vorhanden",
                "high", "confirmed"))
    if headers.get("access-control-allow-origin") == "*":
        results.append(finding(
            "CORS_WILDCARD", "Wildcard-CORS aktiv", "medium", 7,
            "Jede Origin ist zugelassen. Das ist bei öffentlichen, anonymen APIs "
            "nicht automatisch unsicher, bei sensitiven Antworten aber riskant.",
            "Nur benötigte Origins erlauben oder die öffentliche Absicht dokumentieren.",
            "Access-Control-Allow-Origin: *", "high", "confirmed"))
    server = headers.get("server", "")
    if server:
        device.banners[port] = server
        if any(char.isdigit() for char in server):
            results.append(finding(
                "SERVER_VERSION_DISCLOSURE", "Webserver-Version offengelegt", "low", 2,
                "Der Server-Header enthält Versionsinformationen.",
                "Detaillierte Versionsangabe unterdrücken und Patchstand überwachen.",
                server, "high", "confirmed"))
    return results


def audit_redis_noauth(device: Device) -> list[Finding]:
    """Use only Redis PING; never read or modify application data."""
    if 6379 not in device.open_ports:
        return []
    try:
        with socket.create_connection((device.ip, 6379), timeout=2.0) as sock:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            reply = sock.recv(128)
    except (OSError, socket.timeout):
        return []
    if reply.startswith(b"+PONG"):
        return [finding(
            "REDIS_NOAUTH", "Redis antwortet ohne Authentisierung", "critical", 25,
            "Der Server beantwortet PING ohne vorherige Authentisierung.",
            "Authentisierung/ACLs aktivieren, TLS einsetzen und Zugriff segmentieren.",
            "Antwort auf PING: +PONG", "high", "confirmed")]
    return []


def _read_protocol(sock: socket.socket, limit: int = 4096) -> bytes:
    """Read a bounded protocol response without collecting application data."""
    sock.settimeout(1.0)
    chunks = bytearray()
    while len(chunks) < limit:
        try:
            block = sock.recv(min(1024, limit - len(chunks)))
        except socket.timeout:
            break
        if not block:
            break
        chunks.extend(block)
        if len(block) < 1024:
            break
    return bytes(chunks)


def audit_starttls(device: Device, port: int) -> list[Finding]:
    """Check whether a cleartext protocol advertises a TLS upgrade.

    Only capability commands are sent. No login, mailbox, file or message data
    is requested.
    """
    protocol = {21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP"}.get(port)
    if not protocol or port not in device.open_ports:
        return []
    commands = {
        21: (b"AUTH TLS\r\n", (b"234",)),
        25: (b"EHLO network-sentinel.local\r\n", (b"STARTTLS",)),
        110: (b"CAPA\r\n", (b"STLS",)),
        143: (b"a1 CAPABILITY\r\n", (b"STARTTLS",)),
    }
    try:
        with socket.create_connection((device.ip, port), timeout=2.0) as sock:
            banner = _read_protocol(sock, 1024)
            command, markers = commands[port]
            sock.sendall(command)
            response = _read_protocol(sock).upper()
    except (OSError, socket.timeout):
        return [finding(
            "STARTTLS_INCONCLUSIVE", f"{protocol}-TLS-Upgrade nicht prüfbar",
            "info", 0, "Die Capability-Abfrage lieferte keine auswertbare Antwort.",
            "STARTTLS-Konfiguration serverseitig kontrollieren.",
            f"Banner: {banner[:120].decode('utf-8', 'replace') if 'banner' in locals() else 'keiner'}",
            "medium", "inconclusive")]
    if any(marker in response for marker in markers):
        return []
    return [finding(
        "STARTTLS_MISSING", f"{protocol} bietet keinen TLS-Upgrade an", "high", 10,
        f"Der {protocol}-Dienst kündigt bei der Capability-Prüfung kein STARTTLS an.",
        "TLS-Upgrade verpflichtend aktivieren oder ausschließlich den TLS-Port bereitstellen.",
        response[:240].decode("utf-8", "replace"), "high", "confirmed")]


def record_audit_boundaries(device: Device) -> None:
    """Document important checks that cannot be safely inferred from a port."""
    boundaries = {
        "credential_testing": ("disabled_by_policy",
            "Keine Anmeldeversuche ohne gesonderte ausdrückliche Freigabe."),
        "exploit_validation": ("prohibited",
            "Keine Exploits oder schadensgeeigneten Payloads."),
        "cve_patch_validation": ("requires_inventory",
            "Benötigt exakte Produktversion und aktuellen Patch-/CVE-Bestand."),
        "os_fingerprinting": ("requires_specialized_tool",
            "Passives TCP-Fingerprinting ist ohne Spezialwerkzeug nicht belastbar."),
        "snmp_community": ("requires_opt_in",
            "Community-String-Tests gelten als Authentisierungsversuch."),
        "smb_vulnerability": ("requires_specialized_tool",
            "Ein offener SMB-Port bestätigt weder SMBv1 noch EternalBlue."),
        "rdp_vulnerability": ("requires_specialized_tool",
            "Ein offener RDP-Port bestätigt weder fehlendes NLA noch BlueKeep."),
        "wifi_wps": ("not_remotely_testable",
            "WPS ist über einen gewöhnlichen IPv4-LAN-Scan nicht prüfbar."),
    }
    for name, (status, detail) in boundaries.items():
        device.audit_coverage.setdefault(name, status)
        device.audit_log.append({
            "check": name, "timestamp": utc_now(), "status": status,
            "findings": 0, "detail": detail,
        })


def evaluate(device: Device) -> Device:
    """Score unique findings with a cap to avoid duplicated inflation."""
    unique: dict[str, Finding] = {}
    for item in device.findings:
        previous = unique.get(item.code)
        if previous is None or item.points > previous.points:
            unique[item.code] = item
    score = min(100, sum(max(0, item.points) for item in unique.values()))
    device.risk_score = score
    device.risk_category = (
        "Sicher" if score <= 10 else "Niedrig" if score <= 30 else
        "Mittel" if score <= 50 else "Hoch" if score <= 70 else "Kritisch")
    codes = set(unique)
    device.compliance = {
        "pci_dss": not bool(codes & {
            "TELNET_ENABLED", "FTP_CLEARTEXT", "TLS_LEGACY", "CERT_UNTRUSTED",
            "DATABASE_EXPOSED", "REDIS_NOAUTH"}),
        "iso_27001": score <= 30 and not bool(codes & {
            "DATABASE_EXPOSED", "REDIS_NOAUTH", "MODBUS_EXPOSED"}),
        "bsi_grundschutz": score <= 30 and not bool(codes & {
            "TELNET_ENABLED", "FTP_CLEARTEXT", "LDAP_PLAINTEXT",
            "HTTP_PLAINTEXT", "MQTT_CLEARTEXT"}),
    }
    return device


def audit_device(device: Device) -> Device:
    """Run all applicable safe checks and record their coverage."""
    runner = AuditRunner(device)
    device.findings.extend(runner.run(
        "service_exposure", lambda: audit_exposed_services(device)))
    if 22 in device.open_ports:
        device.findings.extend(runner.run("ssh_banner", lambda: audit_ssh(device)))
    else:
        device.audit_coverage["ssh_banner"] = "not_applicable"
    web_ports = set(device.open_ports) & {80, 443, 8080, 8443}
    for port in sorted(web_ports):
        if port in {443, 8443}:
            device.findings.extend(runner.run(
                f"tls:{port}", lambda port=port: audit_tls(device, port)))
        device.findings.extend(runner.run(
            f"http:{port}", lambda port=port: audit_web(device, port)))
    for port in sorted(set(device.open_ports) & {465, 636, 993, 995, 8883}):
        device.findings.extend(runner.run(
            f"tls:{port}", lambda port=port: audit_tls(device, port)))
    if not web_ports:
        device.audit_coverage["web_tls"] = "not_applicable"
    if 6379 in device.open_ports:
        device.findings.extend(runner.run(
            "redis_auth", lambda: audit_redis_noauth(device)))
    else:
        device.audit_coverage["redis_auth"] = "not_applicable"
    for port in sorted(set(device.open_ports) & {21, 25, 110, 143}):
        device.findings.extend(runner.run(
            f"starttls:{port}", lambda port=port: audit_starttls(device, port)))
    record_audit_boundaries(device)
    device.findings.sort(
        key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), item.code))
    return evaluate(device)
