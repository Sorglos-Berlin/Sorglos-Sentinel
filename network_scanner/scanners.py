"""Host discovery, DNS resolution and conservative TCP port scanning."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

from .config import Config
from .models import Device
from .oui import OuiDatabase

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    389: "ldap", 465: "smtps", 502: "modbus", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1883: "mqtt",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 8883: "mqtts", 27017: "mongodb",
}


def expand_targets(subnet: str, targets: Iterable[str] | None = None) -> list[str]:
    if targets:
        return sorted({str(ipaddress.ip_address(item.strip())) for item in targets},
                      key=ipaddress.ip_address)
    network = ipaddress.ip_network(subnet, strict=False)
    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported.")
    if network.num_addresses > 65536:
        raise ValueError("Networks larger than /16 require explicit --targets.")
    return [str(ip) for ip in network.hosts()]


def icmp_ping(ip: str, timeout: float) -> bool:
    flag = "-n" if platform.system() == "Windows" else "-c"
    wait_flag = "-w" if platform.system() == "Windows" else "-W"
    wait = str(max(1, int(timeout * (1000 if platform.system() == "Windows" else 1))))
    try:
        result = subprocess.run(
            ["ping", flag, "1", wait_flag, wait, ip],
            capture_output=True, timeout=timeout + 1.5, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def arp_scan(subnet: str, timeout: float, oui: OuiDatabase) -> list[Device]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=timeout, retry=0, verbose=False,
        )
        return [Device(ip=reply.psrc, mac=reply.hwsrc,
                       vendor=oui.lookup(reply.hwsrc)) for _, reply in answered]
    except (ImportError, OSError, PermissionError, RuntimeError):
        return []


def resolve_hostname(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except (socket.herror, socket.gaierror, OSError):
        pass
    if platform.system() == "Windows":
        return resolve_netbios_name(ip)
    return ""


def resolve_netbios_name(ip: str) -> str:
    """Resolve a Windows/SMB device name without enumerating shares."""
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=2.5, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    # The <00> UNIQUE workstation entry is the device name. GROUP is a workgroup.
    match = re.search(
        r"^\s*([^\s<][^<]{0,14}?)\s+<00>\s+(?:EINDEUTIG|UNIQUE)\b",
        result.stdout, re.IGNORECASE | re.MULTILINE,
    )
    return match.group(1).strip() if match else ""


def parse_neighbor_cache(output: str) -> dict[str, str]:
    """Parse Windows/Linux/macOS ARP cache output into IP-to-MAC mappings."""
    entries: dict[str, str] = {}
    pattern = re.compile(
        r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}).{1,40}?"
        r"(?P<mac>(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})",
        re.IGNORECASE,
    )
    for match in pattern.finditer(output):
        ip, mac = match.group("ip"), match.group("mac").replace("-", ":").lower()
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not address.is_multicast and mac != "ff:ff:ff:ff:ff:ff":
            entries[ip] = mac
    return entries


def read_neighbor_cache() -> dict[str, str]:
    """Read the operating system neighbor cache after discovery probes."""
    commands = [["arp", "-a"]]
    if platform.system() == "Linux":
        commands.insert(0, ["ip", "neigh", "show"])
    for command in commands:
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=4, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            entries = parse_neighbor_cache(result.stdout)
            if entries:
                return entries
        except (OSError, subprocess.SubprocessError):
            continue
    return {}


def enrich_devices(devices: list[Device], config: Config) -> list[Device]:
    """Attach cached MAC/vendor data and resolve names in parallel."""
    oui = OuiDatabase(config.oui_file)
    neighbors = read_neighbor_cache()
    for device in devices:
        if not device.mac and device.ip in neighbors:
            device.mac = neighbors[device.ip]
        if device.mac and not device.vendor:
            device.vendor = oui.lookup(device.mac)
    unnamed = [device for device in devices if not device.hostname]
    with ThreadPoolExecutor(max_workers=min(config.max_concurrent, 32)) as executor:
        futures = {executor.submit(resolve_hostname, device.ip): device
                   for device in unnamed}
        for future in as_completed(futures):
            futures[future].hostname = future.result()
    return devices


def check_port(ip: str, port: int, timeout: float) -> tuple[int, str] | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = ""
            if port in {21, 22, 23, 25, 110, 143}:
                sock.settimeout(min(timeout, 0.5))
                try:
                    banner = sock.recv(256).decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    pass
            return port, banner[:256]
    except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError):
        return None


def scan_ports(device: Device, ports: list[int], config: Config) -> Device:
    with ThreadPoolExecutor(max_workers=min(32, len(ports) or 1)) as executor:
        futures = [executor.submit(check_port, device.ip, port, config.timeout)
                   for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                port, banner = result
                device.open_ports.append(port)
                device.services[port] = SERVICES.get(port, "unknown")
                if banner:
                    device.banners[port] = banner
    device.open_ports.sort()
    if not device.hostname:
        device.hostname = resolve_hostname(device.ip)
    return device


def discover(config: Config, targets: list[str],
             on_device: Callable[[Device], None] | None = None) -> list[Device]:
    oui = OuiDatabase(config.oui_file)
    devices = arp_scan(config.subnet, config.timeout, oui) if config.scan_type in {"arp", "full"} else []
    known = {device.ip for device in devices}
    remaining = [ip for ip in targets if ip not in known]
    with ThreadPoolExecutor(max_workers=config.max_concurrent) as executor:
        futures = {executor.submit(icmp_ping, ip, config.timeout): ip
                   for ip in remaining}
        for future in as_completed(futures):
            if future.result():
                device = Device(ip=futures[future])
                devices.append(device)
                if on_device:
                    on_device(device)
    for device in devices:
        if on_device and device.ip in known:
            on_device(device)
    return sorted(enrich_devices(devices, config),
                  key=lambda item: ipaddress.ip_address(item.ip))
