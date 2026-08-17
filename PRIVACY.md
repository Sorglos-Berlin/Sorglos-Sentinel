# Datenschutz

Stand: 31. Juli 2026

## Lokale Verarbeitung

Network Sentinel ist als lokale Anwendung konzipiert:

- Der Webserver bindet ausschließlich an `127.0.0.1`.
- Es gibt keine Telemetrie, Nutzeranalyse oder Cloud-Synchronisierung.
- Scanergebnisse werden nicht an Sorglos-Apps übertragen.
- Das Dashboard lädt keine externen Schriften, Skripte oder Trackingpixel.
- Eine Sponsor-Seite wird nur nach einem bewussten Klick im Browser geöffnet.

## Verarbeitete Daten

Abhängig vom Zielnetz können IP-Adressen, MAC-Adressen, Hostnamen,
Herstellerinformationen, offene Ports, Protokollbanner, Zertifikatsdaten und
Sicherheitsbefunde verarbeitet werden. Diese Angaben können in bestimmten
Kontexten personenbeziehbar oder vertraulich sein.

## Speicherung und Löschung

Erfolgreiche Scans werden für Verlauf und Statistik automatisch und vollständig
im konfigurierten Ausgabeordner unter `history/scans/` archiviert. Dazu können
IP- und MAC-Adressen, Gerätenamen, Hersteller, offene Dienste, technische
Nachweise und Befunde gehören. Es findet keine automatische Übertragung statt.

Weitere Berichte entstehen nur durch einen ausdrücklichen Export. Der Nutzer
entscheidet über Speicherort, Aufbewahrungsdauer, Zugriffsschutz und Löschung.
Mit `--purge-data` können lokale Scan- und Reportdateien entfernt werden.

Beim offiziellen Windows-Installer lautet der Standardordner:
`%LOCALAPPDATA%\Sorglos-Apps\Network Sentinel\reports\`. Programmupdates und
Deinstallation entfernen diesen Datenordner nicht automatisch. Ein Fehlerprotokoll
kann unter `%LOCALAPPDATA%\Sorglos-Apps\Network Sentinel\network-sentinel.log`
entstehen und technische Fehlermeldungen enthalten.

Report- und Konfigurationsdateien sind über `.gitignore` vom Repository
ausgeschlossen. Vor einer Veröffentlichung eines Forks muss trotzdem geprüft
werden, ob sensible Dateien versehentlich aufgenommen wurden.

## Verantwortung des Betreibers

Wer Network Sentinel in einer Organisation einsetzt, ist für eine geeignete
Rechtsgrundlage, Transparenz gegenüber Betroffenen, Zugriffsrechte,
Aufbewahrungsfristen und technische Schutzmaßnahmen verantwortlich.

Diese Beschreibung bezieht sich auf die unveränderte offizielle Software.
Forks oder Erweiterungen können ein anderes Datenschutzverhalten haben.
