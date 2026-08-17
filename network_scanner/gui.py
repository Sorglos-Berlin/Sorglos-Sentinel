"""Modern multi-page desktop dashboard built with Tkinter."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .config import Config, DEFAULT_PORTS
from .engine import run_scan
from .models import Device, ScanResult
from .reporters import export_reports

LIGHT = {"bg": "#F2F2F7", "side": "#FFFFFF", "card": "#FFFFFF",
         "text": "#1C1C1E", "muted": "#6E6E73", "line": "#E5E5EA",
         "blue": "#007AFF", "green": "#34C759", "orange": "#FF9500",
         "red": "#FF3B30", "critical": "#BF0000", "select": "#E8F2FF"}
DARK = {"bg": "#000000", "side": "#151517", "card": "#1C1C1E",
        "text": "#FFFFFF", "muted": "#A1A1A6", "line": "#38383A",
        "blue": "#0A84FF", "green": "#30D158", "orange": "#FF9F0A",
        "red": "#FF453A", "critical": "#FF375F", "select": "#123354"}
RISK_NAMES = ("Sicher", "Niedrig", "Mittel", "Hoch", "Kritisch")


class ScannerApp(tk.Tk):
    """Network scanner dashboard with five navigable pages."""

    def __init__(self, config: Config, auto_scan: bool = False,
                 theme: str = "system") -> None:
        super().__init__()
        self.config_data = config
        self.dark = theme == "dark"
        self.c = DARK if self.dark else LIGHT
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.result: ScanResult | None = None
        self.scanning = False
        self.pages: dict[str, tk.Frame] = {}
        self.nav: dict[str, tk.Button] = {}
        self.title("Network Sentinel")
        self.geometry("1280x780")
        self.minsize(980, 640)
        self._styles()
        self._shell()
        self._pages()
        self.show_page("dashboard")
        self.after(80, self._poll)
        if auto_scan:
            self.after(400, self.start_scan)

    def _styles(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", font=("Segoe UI", 10), background=self.c["bg"],
                    foreground=self.c["text"])
        s.configure("Treeview", background=self.c["card"], foreground=self.c["text"],
                    fieldbackground=self.c["card"], rowheight=38, borderwidth=0)
        s.configure("Treeview.Heading", background=self.c["card"],
                    foreground=self.c["muted"], borderwidth=0,
                    font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", self.c["select"])],
              foreground=[("selected", self.c["text"])])
        s.configure("Horizontal.TProgressbar", background=self.c["blue"],
                    troughcolor=self.c["line"], borderwidth=0)
        s.configure("TCombobox", fieldbackground=self.c["card"], padding=7)
        self.configure(bg=self.c["bg"])

    def _shell(self) -> None:
        self.sidebar = tk.Frame(self, bg=self.c["side"], width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        logo = tk.Frame(self.sidebar, bg=self.c["side"], height=92)
        logo.pack(fill="x")
        tk.Label(logo, text="◉", bg=self.c["side"], fg=self.c["blue"],
                 font=("Segoe UI", 25, "bold")).pack(side="left", padx=(22, 10))
        tk.Label(logo, text="Network\nSentinel", bg=self.c["side"],
                 fg=self.c["text"], justify="left",
                 font=("Segoe UI", 13, "bold")).pack(side="left")
        for key, icon, label in [
            ("dashboard", "▦", "Dashboard"), ("devices", "⌁", "Geräte"),
            ("risks", "△", "Schwachstellen"), ("reports", "▤", "Berichte"),
            ("settings", "⚙", "Einstellungen"),
        ]:
            button = tk.Button(
                self.sidebar, text=f"  {icon}   {label}", anchor="w",
                command=lambda name=key: self.show_page(name), cursor="hand2",
                relief="flat", bd=0, padx=18, pady=13, bg=self.c["side"],
                fg=self.c["muted"], activebackground=self.c["select"],
                activeforeground=self.c["blue"], font=("Segoe UI", 10))
            button.pack(fill="x", padx=10, pady=2)
            self.nav[key] = button
        tk.Label(self.sidebar, text="LOKAL · NICHT-INVASIV", bg=self.c["side"],
                 fg=self.c["muted"], font=("Segoe UI", 8, "bold")).pack(
                     side="bottom", pady=22)

        workspace = tk.Frame(self, bg=self.c["bg"])
        workspace.pack(fill="both", expand=True)
        top = tk.Frame(workspace, bg=self.c["bg"], height=88)
        top.pack(fill="x", padx=28)
        top.pack_propagate(False)
        heading = tk.Frame(top, bg=self.c["bg"])
        heading.pack(side="left", fill="y")
        self.page_title = tk.Label(heading, bg=self.c["bg"], fg=self.c["text"],
                                   font=("Segoe UI", 23, "bold"))
        self.page_title.pack(anchor="w", pady=(16, 0))
        self.page_subtitle = tk.Label(heading, bg=self.c["bg"], fg=self.c["muted"],
                                      font=("Segoe UI", 9))
        self.page_subtitle.pack(anchor="w")
        tk.Button(top, text="◐", command=self.toggle_theme, relief="flat", bd=0,
                  cursor="hand2", bg=self.c["card"], fg=self.c["text"],
                  activebackground=self.c["select"], padx=12, pady=9).pack(
                      side="right", padx=(8, 0), pady=22)
        self.scan_button = tk.Button(
            top, text="▶  Scan starten", command=self.start_scan, relief="flat",
            bd=0, cursor="hand2", bg=self.c["blue"], fg="white",
            activebackground=self.c["blue"], activeforeground="white",
            font=("Segoe UI", 10, "bold"), padx=18, pady=10)
        self.scan_button.pack(side="right", pady=22)
        self.content = tk.Frame(workspace, bg=self.c["bg"])
        self.content.pack(fill="both", expand=True, padx=28, pady=(0, 24))

    def _pages(self) -> None:
        for name in ("dashboard", "devices", "risks", "reports", "settings"):
            self.pages[name] = tk.Frame(self.content, bg=self.c["bg"])
        self._dashboard()
        self._devices()
        self._risks()
        self._reports()
        self._settings()

    def _card(self, parent: tk.Widget) -> tk.Frame:
        return tk.Frame(parent, bg=self.c["card"], highlightthickness=1,
                        highlightbackground=self.c["line"])

    def _dashboard(self) -> None:
        page = self.pages["dashboard"]
        status = self._card(page)
        status.pack(fill="x", pady=(0, 14))
        self.status_dot = tk.Label(status, text="●", bg=self.c["card"],
                                   fg=self.c["green"], font=("Segoe UI", 11))
        self.status_dot.pack(side="left", padx=(16, 8), pady=12)
        self.status_text = tk.Label(status, text="Bereit für einen Scan",
                                    bg=self.c["card"], fg=self.c["text"],
                                    font=("Segoe UI", 9, "bold"))
        self.status_text.pack(side="left")
        self.status_detail = tk.Label(
            status, text="Nur eigene oder autorisierte Netzwerke prüfen",
            bg=self.c["card"], fg=self.c["muted"])
        self.status_detail.pack(side="left", padx=12)
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=170)
        self.progress.pack(side="right", padx=16)

        metrics = tk.Frame(page, bg=self.c["bg"])
        metrics.pack(fill="x")
        self.metrics: dict[str, tk.Label] = {}
        specs = [("health", "Netzwerkzustand", "100", self.c["green"]),
                 ("devices", "Aktive Geräte", "0", self.c["blue"]),
                 ("ports", "Offene Ports", "0", self.c["orange"]),
                 ("critical", "Kritische Geräte", "0", self.c["red"])]
        for i, (key, title, value, color) in enumerate(specs):
            card = self._card(metrics)
            card.grid(row=0, column=i, sticky="nsew",
                      padx=(0 if i == 0 else 6, 0 if i == 3 else 6))
            metrics.grid_columnconfigure(i, weight=1)
            tk.Label(card, text=title, bg=self.c["card"], fg=self.c["muted"]).pack(
                anchor="w", padx=16, pady=(14, 2))
            label = tk.Label(card, text=value, bg=self.c["card"], fg=color,
                             font=("Segoe UI", 25, "bold"))
            label.pack(anchor="w", padx=16)
            tk.Label(card, text="seit letztem Scan", bg=self.c["card"],
                     fg=self.c["muted"], font=("Segoe UI", 8)).pack(
                         anchor="w", padx=16, pady=(0, 13))
            self.metrics[key] = label

        lower = tk.Frame(page, bg=self.c["bg"])
        lower.pack(fill="both", expand=True, pady=14)
        chart_card = self._card(lower)
        chart_card.pack(side="left", fill="both", expand=True, padx=(0, 7))
        tk.Label(chart_card, text="Risikoverteilung", bg=self.c["card"],
                 fg=self.c["text"], font=("Segoe UI", 12, "bold")).pack(
                     anchor="w", padx=18, pady=(16, 0))
        self.chart = tk.Canvas(chart_card, width=220, height=185,
                               bg=self.c["card"], highlightthickness=0)
        self.chart.pack(side="left", padx=10, pady=6)
        self.legend = tk.Frame(chart_card, bg=self.c["card"])
        self.legend.pack(side="left", fill="both", expand=True, pady=20)
        self._draw_chart({})
        feed_card = self._card(lower)
        feed_card.pack(side="left", fill="both", expand=True, padx=(7, 0))
        tk.Label(feed_card, text="Live-Aktivität", bg=self.c["card"],
                 fg=self.c["text"], font=("Segoe UI", 12, "bold")).pack(
                     anchor="w", padx=18, pady=(16, 8))
        self.feed = tk.Frame(feed_card, bg=self.c["card"])
        self.feed.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self._feed("Noch keine Scan-Ereignisse", "Starte einen neuen Scan.")

    def _devices(self) -> None:
        page = self.pages["devices"]
        toolbar = tk.Frame(page, bg=self.c["bg"])
        toolbar.pack(fill="x", pady=(0, 12))
        self.search_var = tk.StringVar()
        search = tk.Entry(toolbar, textvariable=self.search_var, relief="flat",
                          bg=self.c["card"], fg=self.c["text"],
                          insertbackground=self.c["text"], font=("Segoe UI", 10))
        search.pack(side="left", fill="x", expand=True, ipady=10)
        search.bind("<KeyRelease>", lambda _e: self._refresh_devices())
        self.filter_var = tk.StringVar(value="Alle Risiken")
        risk_filter = ttk.Combobox(toolbar, textvariable=self.filter_var,
                                   values=("Alle Risiken",) + RISK_NAMES,
                                   state="readonly", width=16)
        risk_filter.pack(side="left", padx=(10, 0))
        risk_filter.bind("<<ComboboxSelected>>", lambda _e: self._refresh_devices())
        body = tk.Frame(page, bg=self.c["bg"])
        body.pack(fill="both", expand=True)
        table_card = self._card(body)
        table_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        columns = ("ip", "host", "vendor", "ports", "risk")
        self.device_tree = ttk.Treeview(table_card, columns=columns, show="headings")
        for key, title, width in [
            ("ip", "IP-Adresse", 130), ("host", "Gerätename", 180),
            ("vendor", "Hersteller", 140), ("ports", "Offene Ports", 170),
            ("risk", "Risiko", 110)]:
            self.device_tree.heading(key, text=title)
            self.device_tree.column(key, width=width, minwidth=80)
        self.device_tree.pack(fill="both", expand=True, padx=8, pady=8)
        self.device_tree.bind("<<TreeviewSelect>>", self._device_details)
        self.details = self._card(body)
        self.details.configure(width=300)
        self.details.pack(side="left", fill="y", padx=(8, 0))
        self.details.pack_propagate(False)
        self._empty_details()

    def _risks(self) -> None:
        page = self.pages["risks"]
        self.risk_summary = tk.Label(page, text="0 offene Befunde",
                                     bg=self.c["bg"], fg=self.c["text"],
                                     font=("Segoe UI", 13, "bold"))
        self.risk_summary.pack(anchor="w", pady=(0, 12))
        card = self._card(page)
        card.pack(fill="both", expand=True)
        columns = ("severity", "title", "device", "evidence", "recommendation")
        self.risk_tree = ttk.Treeview(card, columns=columns, show="headings")
        for key, title, width in [
            ("severity", "Schweregrad", 100), ("title", "Befund", 210),
            ("device", "Gerät", 130), ("evidence", "Nachweis", 180),
            ("recommendation", "Empfehlung", 360)]:
            self.risk_tree.heading(key, text=title)
            self.risk_tree.column(key, width=width, minwidth=90)
        self.risk_tree.pack(fill="both", expand=True, padx=8, pady=8)

    def _reports(self) -> None:
        page = self.pages["reports"]
        card = self._card(page)
        card.pack(fill="x")
        tk.Label(card, text="Berichte exportieren", bg=self.c["card"],
                 fg=self.c["text"], font=("Segoe UI", 16, "bold")).pack(
                     anchor="w", padx=20, pady=(18, 4))
        tk.Label(card, text="Interaktiver Sicherheitsbericht und strukturierte Daten.",
                 bg=self.c["card"], fg=self.c["muted"]).pack(anchor="w", padx=20)
        self.report_status = tk.Label(card, text="Noch kein Scanergebnis verfügbar.",
                                      bg=self.c["card"], fg=self.c["muted"])
        self.report_status.pack(anchor="w", padx=20, pady=(10, 16))
        actions = tk.Frame(page, bg=self.c["bg"])
        actions.pack(fill="x", pady=14)
        for label, formats in [("HTML-Bericht", ["html"]), ("JSON", ["json"]),
                               ("CSV", ["csv"]),
                               ("Alle Formate", ["html", "json", "csv"])]:
            tk.Button(actions, text=label, command=lambda f=formats: self.export(f),
                      relief="flat", bd=0, cursor="hand2", bg=self.c["card"],
                      fg=self.c["text"], activebackground=self.c["select"],
                      padx=18, pady=14).pack(side="left", padx=(0, 10))

    def _settings(self) -> None:
        page = self.pages["settings"]
        card = self._card(page)
        card.pack(fill="x")
        tk.Label(card, text="Scan-Einstellungen", bg=self.c["card"],
                 fg=self.c["text"], font=("Segoe UI", 15, "bold")).grid(
                     row=0, column=0, columnspan=2, sticky="w",
                     padx=20, pady=(18, 14))
        self.subnet_var = tk.StringVar(value=self.config_data.subnet)
        self.mode_var = tk.StringVar(value="full")
        self.ports_var = tk.StringVar(value=",".join(map(str, self.config_data.ports)))
        self.timeout_var = tk.StringVar(value=str(self.config_data.timeout))
        widgets: list[tuple[str, tk.Widget]] = [
            ("IPv4-Subnetz", tk.Entry(card, textvariable=self.subnet_var)),
            ("Scan-Modus", ttk.Combobox(card, textvariable=self.mode_var,
                                        values=("arp", "icmp", "full", "custom"),
                                        state="readonly")),
            ("TCP-Ports", tk.Entry(card, textvariable=self.ports_var)),
            ("Timeout pro Ziel", tk.Entry(card, textvariable=self.timeout_var))]
        for row, (label, widget) in enumerate(widgets, 1):
            tk.Label(card, text=label, bg=self.c["card"],
                     fg=self.c["muted"]).grid(row=row, column=0, sticky="w",
                                              padx=20, pady=8)
            widget.grid(row=row, column=1, sticky="ew", padx=(10, 20), pady=8,
                        ipady=7)
        card.grid_columnconfigure(1, weight=1)
        self.audit_var = tk.BooleanVar(value=True)
        tk.Checkbutton(card, text="Sicherheits-Audit aktivieren",
                       variable=self.audit_var, bg=self.c["card"],
                       fg=self.c["text"], activebackground=self.c["card"],
                       selectcolor=self.c["card"]).grid(
                           row=5, column=1, sticky="w", padx=10, pady=(10, 20))
        note = self._card(page)
        note.pack(fill="x", pady=14)
        tk.Label(note, text="Sicherheitsprinzip", bg=self.c["card"],
                 fg=self.c["blue"], font=("Segoe UI", 11, "bold")).pack(
                     anchor="w", padx=20, pady=(16, 4))
        tk.Label(note, text="Keine Exploits, Passwortangriffe oder Änderungen.",
                 bg=self.c["card"], fg=self.c["muted"]).pack(
                     anchor="w", padx=20, pady=(0, 16))

    def show_page(self, name: str) -> None:
        texts = {
            "dashboard": ("Dashboard", "Übersicht über dein lokales Netzwerk"),
            "devices": ("Geräte", "Erkannte Hosts durchsuchen und untersuchen"),
            "risks": ("Schwachstellen", "Befunde nach Schweregrad und Gerät"),
            "reports": ("Berichte", "Ergebnisse dokumentieren und exportieren"),
            "settings": ("Einstellungen", "Scan-Bereich und Prüfprofil konfigurieren")}
        for page in self.pages.values():
            page.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        self.page_title.configure(text=texts[name][0])
        self.page_subtitle.configure(text=texts[name][1])
        for key, button in self.nav.items():
            active = key == name
            button.configure(bg=self.c["select"] if active else self.c["side"],
                             fg=self.c["blue"] if active else self.c["muted"],
                             font=("Segoe UI", 10,
                                   "bold" if active else "normal"))

    def toggle_theme(self) -> None:
        config = self._form_config(False) or self.config_data
        theme = "light" if self.dark else "dark"
        self.destroy()
        ScannerApp(config, theme=theme).mainloop()

    def _form_config(self, show_error: bool = True) -> Config | None:
        try:
            ports = [int(value.strip()) for value in self.ports_var.get().split(",")
                     if value.strip()]
            config = self.config_data.merge({
                "subnet": self.subnet_var.get().strip(),
                "scan_type": self.mode_var.get(), "ports": ports or DEFAULT_PORTS,
                "timeout": float(self.timeout_var.get()),
                "security_audit_enabled": self.audit_var.get()})
            config.validate()
            return config
        except ValueError as exc:
            if show_error:
                messagebox.showerror("Ungültige Einstellung", str(exc))
            return None

    def start_scan(self) -> None:
        if self.scanning:
            return
        config = self._form_config()
        if not config:
            self.show_page("settings")
            return
        if not messagebox.askyesno(
                "Autorisierung erforderlich",
                "Bestätigst du, dass du dieses Netzwerk besitzt oder eine "
                "ausdrückliche Scan-Erlaubnis hast?"):
            return
        self.scanning = True
        self.scan_button.configure(text="Scan läuft …", state="disabled")
        self.progress.start(12)
        self.status_dot.configure(fg=self.c["orange"])
        self.status_text.configure(text="Netzwerk wird geprüft")
        self.status_detail.configure(text=config.subnet)
        self._clear_feed()
        self._feed("Scan gestartet", f"Zielbereich {config.subnet}")
        threading.Thread(target=self._worker, args=(config,), daemon=True).start()

    def _worker(self, config: Config) -> None:
        try:
            result = run_scan(
                config, on_device=lambda d: self.events.put(("device", d)))
            self.events.put(("done", result))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def _poll(self) -> None:
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "device" and isinstance(value, Device):
                    self._feed("Gerät erkannt", value.hostname or value.ip)
                elif kind == "done" and isinstance(value, ScanResult):
                    self._finished(value)
                elif kind == "error":
                    self._failed(str(value))
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(80, self._poll)

    def _finished(self, result: ScanResult) -> None:
        self.result, self.scanning = result, False
        self.progress.stop()
        self.scan_button.configure(text="▶  Erneut scannen", state="normal")
        self.status_dot.configure(fg=self.c["green"])
        self.status_text.configure(text="Scan abgeschlossen")
        self.status_detail.configure(
            text=f"{len(result.devices)} Geräte · {result.finished_at[:19]}")
        self._feed("Scan abgeschlossen", f"{len(result.devices)} Geräte gefunden")
        self._refresh()
        if result.errors:
            messagebox.showwarning("Scan mit Hinweisen", "\n".join(result.errors))

    def _failed(self, error: str) -> None:
        self.scanning = False
        self.progress.stop()
        self.scan_button.configure(text="▶  Scan starten", state="normal")
        self.status_dot.configure(fg=self.c["red"])
        self.status_text.configure(text="Scan fehlgeschlagen")
        messagebox.showerror("Scanfehler", error)

    def _refresh(self) -> None:
        if not self.result:
            return
        devices = self.result.devices
        average = sum(d.risk_score for d in devices) / max(1, len(devices))
        self.metrics["health"].configure(text=str(max(0, round(100 - average))))
        self.metrics["devices"].configure(text=str(len(devices)))
        self.metrics["ports"].configure(text=str(sum(len(d.open_ports) for d in devices)))
        self.metrics["critical"].configure(
            text=str(sum(d.risk_category == "Kritisch" for d in devices)))
        self._draw_chart({key: sum(d.risk_category == key for d in devices)
                          for key in RISK_NAMES})
        self._refresh_devices()
        self._refresh_risks()
        self.report_status.configure(
            text=f"Scan vom {self.result.finished_at[:19]} · "
                 f"{len(devices)} Geräte verfügbar.")

    def _draw_chart(self, counts: dict[str, int]) -> None:
        self.chart.delete("all")
        colors = (self.c["green"], "#FFD60A", self.c["orange"],
                  self.c["red"], self.c["critical"])
        total, start = sum(counts.values()), -90.0
        if total:
            for key, color in zip(RISK_NAMES, colors):
                extent = 360 * counts.get(key, 0) / total
                self.chart.create_arc(30, 18, 190, 178, start=start,
                                      extent=extent, fill=color,
                                      outline=self.c["card"], width=2)
                start += extent
        else:
            self.chart.create_oval(30, 18, 190, 178, fill=self.c["line"], outline="")
        self.chart.create_oval(69, 57, 151, 139, fill=self.c["card"], outline="")
        self.chart.create_text(110, 91, text=str(total), fill=self.c["text"],
                               font=("Segoe UI", 20, "bold"))
        self.chart.create_text(110, 115, text="Geräte", fill=self.c["muted"])
        for child in self.legend.winfo_children():
            child.destroy()
        for key, color in zip(RISK_NAMES, colors):
            row = tk.Frame(self.legend, bg=self.c["card"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text="●", fg=color, bg=self.c["card"]).pack(side="left")
            tk.Label(row, text=key, fg=self.c["muted"], bg=self.c["card"]).pack(
                side="left", padx=6)
            tk.Label(row, text=str(counts.get(key, 0)), fg=self.c["text"],
                     bg=self.c["card"], font=("Segoe UI", 9, "bold")).pack(side="right")

    def _refresh_devices(self) -> None:
        self.device_tree.delete(*self.device_tree.get_children())
        if not self.result:
            return
        query, selected_risk = self.search_var.get().lower(), self.filter_var.get()
        for index, device in enumerate(self.result.devices):
            if query and query not in (
                    f"{device.ip} {device.hostname} {device.vendor}".lower()):
                continue
            if selected_risk != "Alle Risiken" and device.risk_category != selected_risk:
                continue
            self.device_tree.insert("", "end", iid=str(index), values=(
                device.ip, device.hostname or "Unbekannt",
                device.vendor or "Unbekannt",
                ", ".join(map(str, device.open_ports)) or "Keine",
                f"{device.risk_score} · {device.risk_category}"))

    def _device_details(self, _event: object = None) -> None:
        selection = self.device_tree.selection()
        if not selection or not self.result:
            return
        device = self.result.devices[int(selection[0])]
        for child in self.details.winfo_children():
            child.destroy()
        tk.Label(self.details, text="◉", bg=self.c["card"], fg=self.c["blue"],
                 font=("Segoe UI", 28)).pack(anchor="w", padx=20, pady=(22, 5))
        tk.Label(self.details, text=device.hostname or "Unbekanntes Gerät",
                 bg=self.c["card"], fg=self.c["text"],
                 font=("Segoe UI", 15, "bold"), wraplength=250,
                 justify="left").pack(anchor="w", padx=20)
        tk.Label(self.details, text=device.ip, bg=self.c["card"],
                 fg=self.c["muted"]).pack(anchor="w", padx=20, pady=(2, 14))
        tk.Label(self.details,
                 text=f" Risiko {device.risk_score}/100 · {device.risk_category} ",
                 bg=self._risk_color(device.risk_category), fg="white",
                 font=("Segoe UI", 9, "bold"), pady=6).pack(anchor="w", padx=20)
        self._detail("MAC & Hersteller",
                     f"{device.mac or 'Nicht ermittelt'}\n"
                     f"{device.vendor or 'Unbekannt'}")
        self._detail("Offene Dienste",
                     ", ".join(f"{p}/{device.services.get(p, 'tcp')}"
                               for p in device.open_ports) or "Keine erkannt")
        self._detail("Sicherheitsbefunde",
                     "\n".join(f"• {f.title}" for f in device.findings[:5])
                     or "Keine relevanten Befunde")

    def _empty_details(self) -> None:
        tk.Label(self.details, text="Gerät auswählen", bg=self.c["card"],
                 fg=self.c["text"], font=("Segoe UI", 13, "bold")).pack(
                     pady=(70, 8))
        tk.Label(self.details, text="Details, Ports und Befunde\nerscheinen hier.",
                 bg=self.c["card"], fg=self.c["muted"], justify="center").pack()

    def _detail(self, title: str, text: str) -> None:
        tk.Label(self.details, text=title.upper(), bg=self.c["card"],
                 fg=self.c["muted"], font=("Segoe UI", 8, "bold")).pack(
                     anchor="w", padx=20, pady=(18, 4))
        tk.Label(self.details, text=text, bg=self.c["card"], fg=self.c["text"],
                 justify="left", wraplength=255).pack(anchor="w", padx=20)

    def _refresh_risks(self) -> None:
        self.risk_tree.delete(*self.risk_tree.get_children())
        if not self.result:
            return
        findings = [(device, finding) for device in self.result.devices
                    for finding in device.findings]
        self.risk_summary.configure(text=f"{len(findings)} offene Befunde")
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for device, finding in sorted(
                findings, key=lambda item: rank.get(item[1].severity, 9)):
            self.risk_tree.insert("", "end", values=(
                finding.severity.upper(), finding.title, device.ip,
                finding.evidence or "—", finding.recommendation))

    def _risk_color(self, risk: str) -> str:
        return {"Sicher": self.c["green"], "Niedrig": "#B28B00",
                "Mittel": self.c["orange"], "Hoch": self.c["red"],
                "Kritisch": self.c["critical"]}.get(risk, self.c["muted"])

    def _clear_feed(self) -> None:
        for child in self.feed.winfo_children():
            child.destroy()

    def _feed(self, title: str, detail: str) -> None:
        row = tk.Frame(self.feed, bg=self.c["card"])
        row.pack(fill="x", pady=5)
        tk.Label(row, text="●", bg=self.c["card"], fg=self.c["blue"]).pack(
            side="left", anchor="n")
        text = tk.Frame(row, bg=self.c["card"])
        text.pack(side="left", padx=8)
        tk.Label(text, text=title, bg=self.c["card"], fg=self.c["text"],
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(text, text=detail, bg=self.c["card"], fg=self.c["muted"],
                 font=("Segoe UI", 8)).pack(anchor="w")

    def export(self, formats: list[str]) -> None:
        if not self.result:
            messagebox.showinfo("Kein Ergebnis", "Starte zuerst einen Netzwerk-Scan.")
            return
        directory = filedialog.askdirectory(title="Ausgabeordner wählen")
        if not directory:
            return
        try:
            paths = export_reports(self.result, formats, directory)
            messagebox.showinfo("Export abgeschlossen",
                                "\n".join(str(path) for path in paths))
        except OSError as exc:
            messagebox.showerror("Export fehlgeschlagen", str(exc))


def launch(config: Config, auto_scan: bool = False, theme: str = "system") -> None:
    """Start the desktop dashboard."""
    ScannerApp(config, auto_scan, theme).mainloop()
