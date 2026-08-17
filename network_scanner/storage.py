"""Platform-appropriate private application data paths."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def application_data_dir() -> Path:
    override = os.environ.get("SORGLOS_SENTINEL_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        current = base / "Sorglos-Apps" / "Sorglos Sentinel"
        legacy = base / "Sorglos-Apps" / "Network Sentinel"
        return _migrate_legacy_data(legacy, current)
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    current = base / "sorglos-apps" / "sorglos-sentinel"
    legacy = base / "sorglos-apps" / "network-sentinel"
    return _migrate_legacy_data(legacy, current)


def _migrate_legacy_data(legacy: Path, current: Path) -> Path:
    """Copy existing local data to the renamed product directory once.

    The old directory is intentionally retained as a recoverable backup.
    """
    if not current.exists() and legacy.is_dir():
        try:
            shutil.copytree(legacy, current)
        except OSError:
            return legacy
    return current


def default_report_dir() -> str:
    return str(application_data_dir() / "reports")
