"""Platform-appropriate private application data paths."""

from __future__ import annotations

import os
from pathlib import Path


def application_data_dir() -> Path:
    override = os.environ.get("SORGLOS_SENTINEL_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "Sorglos-Apps" / "Sorglos Sentinel"
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "sorglos-apps" / "sorglos-sentinel"


def default_report_dir() -> str:
    return str(application_data_dir() / "reports")
