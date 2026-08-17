"""OUI vendor database with built-in and locally installed data sources."""

import os
from pathlib import Path

BUILTIN = {
    "001A2B": "Cisco", "001B63": "Apple", "001C42": "Parallels",
    "001D7E": "Cisco", "0024E8": "Dell", "005056": "VMware",
    "080027": "Oracle VirtualBox", "3C5A37": "Samsung",
    "B827EB": "Raspberry Pi", "D850E6": "ASUSTek", "F4F5D8": "Google",
}


class OuiDatabase:
    def __init__(self, path: str = "") -> None:
        self.entries = dict(BUILTIN)
        candidates = [Path(path)] if path else []
        program_files = os.environ.get("ProgramFiles")
        if program_files:
            candidates.extend([
                Path(program_files) / "Nmap" / "nmap-mac-prefixes",
                Path(program_files) / "Wireshark" / "manuf",
            ])
        candidates.extend([
            Path("/usr/share/nmap/nmap-mac-prefixes"),
            Path("/usr/share/wireshark/manuf"),
            Path("/usr/share/ieee-data/oui.txt"),
        ])
        for candidate in candidates:
            if candidate.is_file():
                self._load(candidate)

    def _load(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "," in stripped:
                prefix, vendor = stripped.split(",", 1)
            elif "\t" in stripped:
                prefix, vendor = stripped.split("\t", 1)
            else:
                parts = stripped.split(maxsplit=1)
                if len(parts) != 2:
                    continue
                prefix, vendor = parts
            normalized = self.normalize(prefix)
            if len(normalized) >= 6 and vendor.strip():
                self.entries[normalized[:6]] = vendor.strip()

    @staticmethod
    def normalize(mac: str) -> str:
        return "".join(char for char in mac.upper() if char in "0123456789ABCDEF")

    def lookup(self, mac: str) -> str:
        normalized = self.normalize(mac)
        vendor = self.entries.get(normalized[:6])
        if vendor:
            return vendor
        if len(normalized) >= 2 and int(normalized[:2], 16) & 2:
            return "Private/zufällige MAC"
        return "Unbekannt"
