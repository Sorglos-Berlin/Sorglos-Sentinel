"""Convenient HTML dashboard launcher for Sorglos Sentinel."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from network_scanner.config import load_persisted_config
from network_scanner.webapp import launch_web
from network_scanner.storage import application_data_dir


def main() -> int:
    data_dir = application_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    log_path = data_dir / "sorglos-sentinel.log"
    logging.basicConfig(filename=log_path, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        launch_web(load_persisted_config())
        return 0
    except Exception as exc:  # visible boundary for a windowed executable
        logging.exception("Sorglos Sentinel konnte nicht gestartet werden")
        try:
            from tkinter import messagebox
            messagebox.showerror(
                "Sorglos Sentinel",
                f"Die Anwendung konnte nicht gestartet werden.\n\n{exc}\n\n"
                f"Details: {log_path}",
            )
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
