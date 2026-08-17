# Mitwirken

Vielen Dank für dein Interesse an Sorglos Sentinel.

## Voraussetzungen

- Beiträge müssen defensiv, nicht destruktiv und nachvollziehbar sein.
- Tests dürfen nur eigene oder ausdrücklich autorisierte Ziele verwenden.
- Keine echten Scanergebnisse, MAC-Adressen, Tokens oder Zugangsdaten committen.
- Neue Netzwerkprüfungen benötigen Timeout, Rate-Limit, Fehlerbehandlung,
  Evidenzbewertung und Unit-Tests.

## Entwicklung

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
node --check network_scanner/web/app.js
```

## Pull Requests

1. Ein fokussiertes Issue oder eine nachvollziehbare Beschreibung erstellen.
2. Kleine, logisch getrennte Änderungen vornehmen.
3. Tests und Dokumentation aktualisieren.
4. Keine API- oder Datenschutzänderung verschweigen.
5. Bestätigen, dass der Beitrag unter der Projektlizenz veröffentlicht werden
   darf und keine Rechte Dritter verletzt.

Beiträge mit Exploits, heimlichen Anmeldeversuchen, Telemetrie oder externem
Tracking werden nicht akzeptiert.

## Windows-Paket testen

Der Windows-Build benötigt PyInstaller und Pillow aus dem `dev`-Extra sowie
NSIS 3.12 oder neuer:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer/build-installer.ps1
```

Erzeugte Dateien unter `build/`, `dist/`, `installer/output/` und generierte
Build-Metadaten dürfen nicht committed werden.
