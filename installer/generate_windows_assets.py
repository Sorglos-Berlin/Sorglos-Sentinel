"""Generate Windows icon and executable version metadata."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image


LOGO_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "network_scanner"
    / "web"
    / "assets"
    / "sorglos-sentinel-logo-light.png"
)


def create_icon(path: Path) -> None:
    """Create a multi-resolution Windows icon from the shared product mark."""
    canvas = Image.open(LOGO_SOURCE).convert("RGBA")
    canvas = canvas.resize((512, 512), Image.Resampling.LANCZOS)
    path.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(
        path,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
               (64, 64), (128, 128), (256, 256)],
    )


def create_version_file(path: Path, version: str) -> None:
    parts = [int(value) for value in version.split(".")[:3] if value.isdigit()]
    numeric = tuple((parts + [0, 0, 0, 0])[:4])
    content = f"""VSVersionInfo(ffi=FixedFileInfo(filevers={numeric}, prodvers={numeric}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)), kids=[StringFileInfo([StringTable('040704B0', [StringStruct('CompanyName', 'Sorglos-Apps'), StringStruct('FileDescription', 'Sorglos Sentinel'), StringStruct('FileVersion', '{version}'), StringStruct('InternalName', 'Sorglos Sentinel'), StringStruct('LegalCopyright', 'Copyright 2026 Sorglos-Apps'), StringStruct('OriginalFilename', 'Sorglos Sentinel.exe'), StringStruct('ProductName', 'Sorglos Sentinel'), StringStruct('ProductVersion', '{version}')])]), VarFileInfo([VarStruct('Translation', [1031, 1200])])])"""
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="1.2.0")
    parser.add_argument("--icon", type=Path, required=True)
    parser.add_argument("--version-file", type=Path, required=True)
    args = parser.parse_args()
    create_icon(args.icon)
    create_version_file(args.version_file, args.version)
