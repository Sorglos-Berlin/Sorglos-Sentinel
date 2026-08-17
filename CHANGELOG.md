# Changelog

Alle wesentlichen Änderungen werden in dieser Datei dokumentiert. Das Format
orientiert sich an Keep a Changelog; Versionen folgen Semantic Versioning.

## [Unreleased]

## [1.2.0] - 2026-08-17

### Hinzugefügt

- Scan-Einstellungen werden atomar im privaten lokalen Anwendungsordner gespeichert und beim nächsten Start wiederhergestellt.
- Die Einstellungsansicht zeigt verständlich an, ob Änderungen gespeichert werden oder eine Eingabe korrigiert werden muss.

### Geändert

- „Kompletter Scan“ ist das Standardprofil; das nicht-invasive Sicherheits-Audit ist standardmäßig aktiviert.
- Scan-Modi und ihre Auswirkungen werden in der Oberfläche eindeutig beschrieben.
- Während eines laufenden Scans sind Konfigurationsänderungen gesperrt, damit aktiver Scan und Anzeige konsistent bleiben.

## [1.1.4] - 2026-08-17

### Geändert

- Der zentrale Scan-Button wechselt vor dem Autorisierungsdialog automatisch zum Dashboard.

## [1.1.3] - 2026-08-17

### Behoben

- Das Dashboard zeigt ab Scanstart sofort den tatsächlich aktiven IP-Bereich.
- Der ruhende Radarbereich zeigt die Zusammenfassung des letzten abgeschlossenen Scans statt eines allgemeinen Animationstextes.

## [1.1.2] - 2026-08-17

### Geändert

- Entfernt die erfundene IPv4-Ersatzadresse bei fehlgeschlagener Adaptererkennung.
- Kennzeichnet Geräte ohne Sicherheits-Audit konsistent als „Nicht bewertet“ statt als „Sicher“.
- Vereinheitlicht Leerzustände, Risikobegriffe, Scan-Modi, Portangaben und Statistiktexte in Oberfläche und Berichten.
- Trennt in Verlaufsauswertungen reale Zählwerte von nicht verfügbaren Sicherheitsbewertungen.

## [1.1.1] - 2026-08-17

### Geändert

- Runde, freigestellte Produktlogos für alle App- und Browserdarstellungen.
- Automatisch wechselnde Logo-Variante für helles und dunkles Farbschema.

## [1.1.0] - 2026-08-17

### Changed

- Produkt, Paket, Oberfläche, Installer und Dokumentation von „Network Sentinel“
  auf „Sorglos Sentinel“ umbenannt
- Installations- und lokale Datenpfade an den neuen Produktnamen angepasst
- Bestehende lokale Scan-Historien werden beim ersten Start verlustfrei in den
  neuen Datenordner kopiert; der alte Ordner bleibt als Sicherung erhalten
- MIT-lizenzierten Quellcode klar von Marken- und Logorechten getrennt

### Added

- Neues eigenständiges Sorglos-Sentinel-Logo für Dashboard, App und Installer
- Plattformunabhängige Tests für lokale und benutzerdefinierte OUI-Datenbanken
- Dauerhaft sichtbares, im Ruhezustand dezentes Netzwerk-Radar im Dashboard
- Platzsparender Radar-Ruhezustand mit fließendem Wechsel zur Live-Scanansicht
- Fachlich eindeutige Leerzustände und deutsche Bezeichnungen für Prüfstatus,
  Befundtyp, Schweregrad und Aussagekraft

### Fixed

- Deterministische Herstellererkennung unter Linux, Windows und macOS
- Kuratierte Herstellernamen werden nicht mehr von abweichenden Systemdaten überschrieben
- Veraltete Radarpunkte und Fortschrittszustände nach einem Scanwechsel
- Scheinbarer Netzwerkzustand 100 vor einer belastbaren Messung
- Irreführender Dauerstatus „Online“ für Geräte aus einem abgeschlossenen Scan
- Fest eingetragene alte Versionswerte in neuen Scanergebnissen

### Added

- Lokales HTML-Dashboard mit Geräte-, Befund- und Reportansichten
- Nicht-invasive Netzwerk- und Sicherheitsprüfungen
- Risiko-, Abdeckungs- und Vertrauensbewertung
- CSV-, JSON- und HTML-Export
- Lokale API-Härtung und Sicherheitsdokumentation
- Automatische private Netzwerkbereichserkennung und Sperre öffentlicher Ziele
- Vollständige lokale Scan-Historie mit getrennten Statistiken pro Subnetz
- Interaktive Scan-, Geräte- und Befunddetails sowie Statistikberichte
- Responsive Gerätetabelle mit Touch- und Horizontal-Scrolling
- Automatische Git-Build-Version im Dashboard
- Windows-Anwendung und per NSIS gebauter Benutzer-Installer
- Automatisierter GitHub-Release-Build mit SHA-256-Prüfsummen

## [1.0.0] - 2026-07-31

- Erste geplante öffentliche Version.
