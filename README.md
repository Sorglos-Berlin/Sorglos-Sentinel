# Sorglos Sentinel

<p align="center">
  <img src="network_scanner/web/assets/sorglos-sentinel-logo-dark.png" width="220" alt="Rundes Sorglos Sentinel Markenemblem">
</p>

Ein lokaler, nicht-invasiver IPv4-Netzwerk-Scanner für Windows und Python 3.10+.
Er erkennt
Hosts per ARP/ICMP, prüft ausgewählte TCP-Ports, löst DNS-Namen auf, bewertet
sichtbare Sicherheitsrisiken und erzeugt CSV-, JSON- und interaktive HTML-Berichte.

Ein Open-Source-Projekt von [Sorglos-Apps](https://sorglos-apps.de/).

> Nur eigene Netze oder Ziele mit ausdrücklicher Genehmigung scannen. Das Programm
> führt keine Exploits, Konfigurationsänderungen oder Passwortangriffe aus.

Mit Download oder Nutzung bestätigst du nicht automatisch eine Berechtigung zum
Scannen. Nutze das Programm ausschließlich in eigenen oder ausdrücklich
autorisierten Netzen. Siehe [zulässige Nutzung](ACCEPTABLE_USE.md),
[rechtlicher Hinweis](DISCLAIMER.md) und [Datenschutz](PRIVACY.md).

## Installation

Für Windows steht im **Releases**-Bereich ein fertiger
`Sorglos-Sentinel-Setup-<Version>.exe` bereit. Python wird dafür nicht benötigt.
Der Installer richtet Startmenü, optionalen Desktop-Link und Deinstallation ein.

> **Hinweis zum Installer:** Die aktuelle Version ist noch nicht digital
> signiert. Windows kann deshalb „Unbekannter Herausgeber“ oder eine
> SmartScreen-Warnung anzeigen. Lade den Installer nur aus den Releases dieses
> Repositorys, vergleiche die veröffentlichte SHA-256-Prüfsumme und deaktiviere
> weder SmartScreen noch den Virenschutz.

Ausführliche Hinweise stehen in [INSTALL.md](INSTALL.md).

Installation aus dem Quellcode:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
# Alternativ als lokales Paket mit Startbefehl:
python -m pip install .
sorglos-sentinel
```

Scapy ist aus Lizenz- und Installationsgründen keine Pflichtabhängigkeit. Die
optionale Integration kann bewusst mit `python -m pip install .[arp]` oder
`requirements-arp.txt` installiert werden. Dabei gelten zusätzlich die
GPL-2.0-Bedingungen von Scapy; unter Windows können Npcap und erhöhte Rechte
nötig sein. Ohne Scapy bleiben ICMP, Betriebssystem-Neighbor-Cache und TCP-Scan
nutzbar. PDF benötigt optional `python -m pip install .[pdf]`; ansonsten wird
beim Format `pdf` der druckfertige HTML-Bericht erstellt.

## Nutzung

```powershell
# Schneller Discovery-Scan
python main.py --subnet 192.168.0.0/24 --yes

# Vollscan mit sicherem Audit und Reports
python main.py --subnet 192.168.0.0/24 --scan-type full `
  --security-audit --format console,json,csv,html --yes

# Einzelne autorisierte Ziele
python main.py --targets 192.168.0.1,192.168.0.10 `
  --scan-type full --security-audit --yes

# Konfiguration
python main.py --config config.yaml.example --yes

# Lokale HTML-Oberfläche (öffnet den Standardbrowser)
python main.py --web
# Ohne Argumente öffnet sich die HTML-Oberfläche ebenfalls:
python main.py

# Eigene Reportdaten löschen
python main.py --output ./reports --purge-data
```

Scan-Typen:

- `arp`: ARP-Discovery plus paralleler ICMP-Fallback
- `icmp`: parallele ICMP-Erkennung
- `full`: Discovery, DNS und TCP-Ports
- `custom`: wie `full`, mit expliziter Portliste

Der Audit erkennt ausschließlich von außen sichtbare und sicher prüfbare
Indikatoren: exponierte Klartext-, SMB-, RDP-, Datenbank-, Industrie-, MQTT- und
Webdienste, SSH-Banner, tatsächlich akzeptierte TLS-Versionen, ausgehandelte
Cipher, Zertifikatsvertrauen, Redis ohne Authentisierung sowie HTTP-
Sicherheitsheader. Jeder Check wird mit Zeitstempel, Status, Evidenz,
Befundtyp und Konfidenz dokumentiert und auf maximal zehn Prüfungen pro Sekunde
und Host begrenzt.

Die Netzbewertung besteht aus vier getrennten Kennzahlen. Das Gesamtrisiko
gewichtet das kritischste Gerät mit 55 Prozent, den Durchschnitt der drei
riskantesten Geräte mit 25 Prozent und den Netzdurchschnitt mit 20 Prozent.
Dadurch kann ein einzelnes kritisches Gerät nicht durch viele unauffällige Hosts
verdeckt werden. Prüfabdeckung und Ergebnisvertrauen werden separat ausgewiesen
und verändern den Risikowert nicht künstlich.

Für FTP, SMTP, POP3 und IMAP wird zusätzlich per reiner Capability-Abfrage
geprüft, ob ein TLS-Upgrade angeboten wird. Dabei werden keine Zugangsdaten,
Nachrichten, Postfächer oder Dateien angefordert. Nicht sicher aus einem
Netzwerkport ableitbare Prüfungen werden in der Abdeckungsmatrix ausdrücklich
als `requires_inventory`, `requires_specialized_tool`, `requires_opt_in`,
`disabled_by_policy`, `prohibited` oder `not_remotely_testable` ausgewiesen.
Sie erscheinen damit niemals fälschlich als bestanden.

Aussagen wie Heartbleed-, BlueKeep-, EternalBlue- oder eine konkrete CVE-
Verwundbarkeit werden ohne einen verlässlichen Nachweis und aktuellen,
produktgenauen Patchstand nicht behauptet. „Port erreichbar“ bedeutet nicht
automatisch „verwundbar“. Formale PCI-DSS-, ISO-27001- oder BSI-Audits werden
durch die technischen Hinweise nicht ersetzt.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Troubleshooting

- Keine Geräte: ICMP kann durch Firewalls blockiert sein; Scapy/Npcap installieren
  und gegebenenfalls in einer administrativen Konsole starten.
- Langsamer Scan: Timeout oder Portliste reduzieren.
- YAML-Fehler: PyYAML installieren oder JSON als Konfiguration verwenden.
- HTML statt PDF: WeasyPrint samt nativen Abhängigkeiten installieren oder den
  HTML-Bericht über den Browser als PDF drucken.

## Sicherheit und Grenzen

Es gibt kein Credential-Bruteforce. `credential_testing_enabled` bleibt aus
Kompatibilitätsgründen in der Konfiguration, aktiviert aber keine Passworttests.
Der Scanner sendet nur ARP/ICMP, TCP-Verbindungsversuche sowie einzelne
HEAD-/TLS-Anfragen. Compliance-Ergebnisse sind technische Hinweise und ersetzen
kein formales Audit. CVE-Updates werden nicht ungeprüft aus dem Internet geladen.

## Lizenz

MIT, Copyright © 2026 Sorglos-Apps und Mitwirkende. Optionale Komponenten
unterliegen eigenen Lizenzen; siehe [Drittanbieterhinweise](THIRD_PARTY_NOTICES.md).
Die MIT-Lizenz räumt keine Rechte an den Marken oder Produktkennzeichen
„Sorglos-Apps“ und „Sorglos Sentinel“ ein.

Die Markenbilder und Logos unter `network_scanner/web/assets/` sind nicht unter
MIT lizenziert. Für sie gelten die [Branding-Lizenz](BRAND_LICENSE.md) und die
[Markenhinweise](TRADEMARKS.md). Der Quellcode bleibt davon unabhängig Open Source.

## Projekt und Support

- Website: <https://sorglos-apps.de/>
- Support: <https://sorglos-apps.de/Support/>
- Impressum: <https://sorglos-apps.de/Main/Impressum.html>
- Datenschutz Website: <https://sorglos-apps.de/Main/Datenschutz1.html>

## Entwicklung unterstützen

Sorglos Sentinel bleibt freie Software ohne Telemetrie oder Cloud-Zwang. Das
Projekt kann freiwillig über Sorglos-Apps unterstützt werden:

<https://buymeacoffee.com/sorglos.apps>

Die im Dashboard verwendete Adresse lässt sich bei Bedarf lokal überschreiben:

```powershell
$env:SORGLOS_SENTINEL_SPONSOR_URL="https://buymeacoffee.com/sorglos.apps"
python main.py
```

Der Unterstützungsbutton befindet sich unten in der Seitenleiste. Überschriebene
Adressen werden nur akzeptiert, wenn sie vollständige HTTPS-Adressen sind.

## Lokale Scan-Historie und Statistik

Jeder erfolgreich abgeschlossene Scan wird vollständig und ausschließlich lokal
im konfigurierten Berichtsordner unter `history/scans/` gespeichert. Bei der
Windows-Installation liegt dieser standardmäßig unter
`%LOCALAPPDATA%\Sorglos-Apps\Sorglos Sentinel\reports\`. Die Ansicht **Statistik** zeigt
Zeitverläufe, Änderungen gegenüber dem vorherigen Scan, Durchschnittswerte und
anklickbare Scan-Details mit Geräten und Befunden.

Scanbereiche werden dabei strikt getrennt ausgewertet. Für jedes erkannte Subnetz
steht eine eigene Statistikansicht zur Verfügung; Werte aus unterschiedlichen
Netzen werden weder bei Trends noch bei Durchschnitts- oder Vergleichswerten
vermischt.

**Statistikbericht erstellen** erzeugt für den ausgewählten IP-Bereich einen
eigenständigen HTML-Bericht namens `statistikbericht-<netz-id>.html` im
Berichtsordner. Es
werden keine Verlaufsdaten übertragen. Mit
`python main.py --purge-data` lassen sich lokale Scan- und Berichtsdaten löschen.

## Sicherer Standard-Scanbereich

Beim Start erkennt Sorglos Sentinel die bevorzugte private IPv4-Adresse des
Rechners und verwendet deren `/24`-Netz als Voreinstellung. Der aktuelle Bereich
steht im Dashboard und kann unter **Einstellungen → IPv4-Scanbereich** geändert
werden. Ohne ausdrückliche Expertenfreigabe akzeptiert der Scanner ausschließlich
private Netze aus `10.0.0.0/8`, `172.16.0.0/12` und `192.168.0.0/16`.

## Automatische Build-Version

Die Seitenleiste zeigt die Paketversion zusammen mit dem aktuellen kurzen
Git-Commit. Bei einem Release-Tag wird dessen Version verwendet; ein veränderter
Arbeitsstand wird als `lokal geändert` gekennzeichnet. Ist Git nicht ausführbar,
wird der Commit direkt aus den lokalen Repository-Metadaten gelesen. In einer
Installation ohne Git-Verzeichnis dient die Paketversion als Fallback.
