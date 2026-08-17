"""Local-only HTTP server for the HTML dashboard."""

from __future__ import annotations

import json
import hashlib
import os
import secrets
import threading
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .config import Config, detect_local_ipv4, save_persisted_config
from .engine import run_scan
from .history import history_statistics, load_history, load_scan, purge_history, save_history
from .models import ScanResult
from .reporters import export_reports, export_statistics_html
from .version import get_build_info

WEB_ROOT = Path(__file__).with_name("web")
DEFAULT_SPONSOR_URL = "https://buymeacoffee.com/sorglos.apps"


@dataclass
class AppState:
    config: Config
    lock: threading.Lock = field(default_factory=threading.Lock)
    scanning: bool = False
    progress: int = 0
    discovered: int = 0
    phase: str = "idle"
    message: str = "Bereit für einen Scan"
    result: ScanResult | None = None
    last_scan_summary: dict[str, Any] | None = None
    error: str = ""
    session_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    sponsor_url: str = ""

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "scanning": self.scanning,
                "progress": self.progress,
                "discovered": self.discovered,
                "phase": self.phase,
                "message": self.message,
                "error": self.error,
                "session_token": self.session_token,
                "sponsor_url": self.sponsor_url,
                "build": get_build_info(),
                "result": self.result.to_dict() if self.result else None,
                "last_scan_summary": self.last_scan_summary,
                "config": {
                    "subnet": self.config.subnet,
                    "scan_type": self.config.scan_type,
                    "ports": self.config.ports,
                    "timeout": self.config.timeout,
                    "security_audit_enabled": self.config.security_audit_enabled,
                    "local_ip": detect_local_ipv4(),
                    "allow_public_targets": self.config.allow_public_targets,
                },
            }


def _scan(state: AppState, config: Config) -> None:
    def discovered(_device: object) -> None:
        with state.lock:
            state.discovered += 1
            state.message = f"{state.discovered} Geräte erkannt"

    def progress(phase: str, percent: int) -> None:
        with state.lock:
            state.phase = phase
            state.progress = percent

    try:
        result = run_scan(config, on_device=discovered, on_progress=progress)
        try:
            save_history(result, config.output_dir)
        except OSError as exc:
            result.errors.append(f"Scan-Historie konnte nicht gespeichert werden: {exc}")
        with state.lock:
            state.result = result
            latest = load_history(config.output_dir, limit=1)
            state.last_scan_summary = latest[0] if latest else None
            state.scanning = False
            state.progress = 100
            state.phase = "complete"
            state.message = f"Scan abgeschlossen · {len(result.devices)} Geräte"
            state.error = "\n".join(result.errors)
            state.config = config
    except Exception as exc:  # server boundary must remain responsive
        with state.lock:
            state.scanning = False
            state.error = str(exc)
            state.message = "Scan fehlgeschlagen"


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve static assets and a minimal local JSON API."""

    state: AppState
    server_version = "SorglosSentinel/1.1"

    def log_message(self, format_string: str, *args: object) -> None:
        return

    def _json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; "
                         "style-src 'self' 'unsafe-inline'; script-src 'self'")
        self.end_headers()
        self.wfile.write(payload)

    def _allowed_host(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0].strip("[]").lower()
        return host in {"127.0.0.1", "localhost", "::1"}

    def _authorized_post(self) -> bool:
        return secrets.compare_digest(
            self.headers.get("X-Sorglos-Sentinel-Token", ""),
            self.state.session_token,
        )

    def _body(self) -> dict[str, Any]:
        length = min(int(self.headers.get("Content-Length", "0")), 65536)
        if not length:
            return {}
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Die Anfrage muss ein JSON-Objekt enthalten.")
        return value

    def do_GET(self) -> None:  # noqa: N802
        if not self._allowed_host():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        parsed_request = urlparse(self.path)
        path = parsed_request.path
        if path == "/api/status":
            self._json(self.state.snapshot())
            return
        if path == "/api/history":
            requested_subnet = parse_qs(parsed_request.query).get("subnet", [None])[0]
            self._json(history_statistics(self.state.config.output_dir, requested_subnet))
            return
        if path.startswith("/api/history/"):
            payload = load_scan(self.state.config.output_dir, path.rsplit("/", 1)[-1])
            self._json(payload if payload else {"error": "Scan nicht gefunden."},
                       HTTPStatus.OK if payload else HTTPStatus.NOT_FOUND)
            return
        static = {"": "index.html", "/": "index.html",
                  "/app.js": "app.js", "/styles.css": "styles.css",
                  "/logo.png": "assets/sorglos-sentinel-logo-dark.png",
                  "/logo-dark.png": "assets/sorglos-sentinel-logo-dark.png",
                  "/logo-light.png": "assets/sorglos-sentinel-logo-light.png"}
        filename = static.get(path)
        if not filename:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        target = WEB_ROOT / filename
        try:
            payload = target.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = {"html": "text/html", "js": "text/javascript",
                        "css": "text/css", "png": "image/png"}[target.suffix.lstrip(".")]
        self.send_response(HTTPStatus.OK)
        charset = "; charset=utf-8" if target.suffix != ".png" else ""
        self.send_header("Content-Type", f"{content_type}{charset}")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; "
                         "style-src 'self' 'unsafe-inline'; script-src 'self'; "
                         "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; "
                         "base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        if not self._allowed_host() or not self._authorized_post():
            self._json({"error": "Ungültige lokale Sitzung."}, HTTPStatus.FORBIDDEN)
            return
        try:
            data = self._body()
            if self.path == "/api/scan":
                self._start_scan(data)
            elif self.path == "/api/settings":
                self._update_settings(data)
            elif self.path == "/api/export":
                self._export(data)
            elif self.path == "/api/history/export":
                self._export_history(data)
            elif self.path == "/api/history/purge":
                self._purge_history(data)
            else:
                self._json({"error": "Der angeforderte lokale Endpunkt wurde nicht gefunden."}, HTTPStatus.NOT_FOUND)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _start_scan(self, data: dict[str, Any]) -> None:
        if data.get("authorized") is not True:
            self._json({"error": "Autorisierung muss bestätigt werden."},
                       HTTPStatus.FORBIDDEN)
            return
        with self.state.lock:
            if self.state.scanning:
                self._json({"error": "Ein Scan läuft bereits."}, HTTPStatus.CONFLICT)
                return
        config = self._config_from_request(data)
        save_persisted_config(config)
        with self.state.lock:
            # Publish the validated scan configuration before the worker starts,
            # so every status response identifies the actually active target.
            self.state.config = config
            self.state.scanning = True
            self.state.progress = 5
            self.state.phase = "starting"
            self.state.discovered = 0
            self.state.error = ""
            self.state.message = f"Scan von {config.subnet} gestartet"
        threading.Thread(target=_scan, args=(self.state, config), daemon=True).start()
        self._json({"ok": True}, HTTPStatus.ACCEPTED)

    def _config_from_request(self, data: dict[str, Any]) -> Config:
        ports = data.get("ports", self.state.config.ports)
        if isinstance(ports, str):
            ports = [int(value.strip()) for value in ports.split(",") if value.strip()]
        config = self.state.config.merge({
            "subnet": data.get("subnet"),
            "scan_type": data.get("scan_type", "full"),
            "ports": ports,
            "timeout": float(data.get("timeout", self.state.config.timeout)),
            "security_audit_enabled": bool(data.get("security_audit", True)),
        })
        config.validate()
        return config

    def _update_settings(self, data: dict[str, Any]) -> None:
        with self.state.lock:
            if self.state.scanning:
                self._json(
                    {"error": "Einstellungen können während eines laufenden Scans nicht geändert werden."},
                    HTTPStatus.CONFLICT,
                )
                return
        config = self._config_from_request(data)
        save_persisted_config(config)
        with self.state.lock:
            self.state.config = config
        self._json({"ok": True, "message": "Einstellungen lokal gespeichert."})

    def _export(self, data: dict[str, Any]) -> None:
        with self.state.lock:
            result = self.state.result
        if not result:
            self._json({"error": "Noch kein Scanergebnis vorhanden."},
                       HTTPStatus.CONFLICT)
            return
        formats = data.get("formats", ["html", "json", "csv"])
        if not isinstance(formats, list):
                raise ValueError("Die Exportformate müssen als Liste übergeben werden.")
        paths = export_reports(result, [str(value) for value in formats],
                               self.state.config.output_dir)
        self._json({"paths": [str(path.resolve()) for path in paths]})

    def _export_history(self, data: dict[str, Any]) -> None:
        subnet = data.get("subnet")
        statistics = history_statistics(self.state.config.output_dir,
                                        str(subnet) if subnet else None)
        if not statistics["selected_subnet"]:
            self._json({"error": "Noch keine Statistikdaten vorhanden."},
                       HTTPStatus.CONFLICT)
            return
        suffix = hashlib.sha256(statistics["selected_subnet"].encode("utf-8")).hexdigest()[:8]
        path = Path(self.state.config.output_dir) / f"statistikbericht-{suffix}.html"
        export_statistics_html(statistics, path)
        self._json({"path": str(path.resolve())})

    def _purge_history(self, data: dict[str, Any]) -> None:
        if data.get("confirm") != "DELETE_HISTORY":
            self._json({"error": "Löschbestätigung fehlt."}, HTTPStatus.BAD_REQUEST)
            return
        self._json({"deleted": purge_history(self.state.config.output_dir)})


def launch_web(config: Config, port: int = 8765, open_browser: bool = True) -> None:
    """Start the loopback-only web dashboard."""
    sponsor_url = os.environ.get(
        "SORGLOS_SENTINEL_SPONSOR_URL", DEFAULT_SPONSOR_URL
    ).strip()
    parsed_sponsor = urlparse(sponsor_url)
    if sponsor_url and (parsed_sponsor.scheme != "https" or not parsed_sponsor.netloc):
        print("Hinweis: Sponsor-URL ignoriert; nur vollständige HTTPS-URLs sind erlaubt.")
        sponsor_url = ""
    latest = load_history(config.output_dir, limit=1)
    state = AppState(
        config,
        sponsor_url=sponsor_url,
        last_scan_summary=latest[0] if latest else None,
    )
    handler = type("LocalDashboardHandler", (DashboardHandler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"Sorglos Sentinel läuft lokal unter {url}")
    print("Beenden mit Strg+C.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
