# Sorglos Sentinel installieren

## Empfohlen: Windows-Installer

Für die normale Nutzung wird weder Python noch eine Entwicklungsumgebung
benötigt.

### Voraussetzungen

- Windows 10 oder Windows 11, 64 Bit
- ein aktueller Webbrowser
- ein eigenes oder ausdrücklich zum Scan freigegebenes privates IPv4-Netzwerk

### Installation

1. Im Bereich **Releases** dieses GitHub-Repositorys die neueste Datei
   `Sorglos-Sentinel-Setup-<Version>.exe` herunterladen.
2. Optional die SHA-256-Prüfsumme mit der ebenfalls veröffentlichten Datei
   `SHA256SUMS.txt` vergleichen.
3. Den Installer doppelt anklicken.
4. Sicherheits-, Nutzungs- und Lizenzhinweise lesen und bestätigen.
5. Optional eine Desktop-Verknüpfung auswählen.
6. **Installieren** und anschließend **Sorglos Sentinel starten** wählen.

Der Installer richtet einen Startmenüeintrag und einen normalen Windows-
Deinstaller ein. Standardmäßig wird nur für den aktuellen Benutzer installiert;
Administratorrechte sind dafür nicht erforderlich.

> **Windows-Sicherheitshinweis:** Solange der Installer noch nicht mit einem
> vertrauenswürdigen Code-Signing-Zertifikat signiert ist, kann Microsoft Defender
> SmartScreen bei neuen Releases eine Warnung anzeigen. Lade Installationsdateien
> ausschließlich aus dem offiziellen Repository herunter und vergleiche im
> Zweifel die SHA-256-Prüfsumme. Deaktiviere dafür nicht den Virenschutz.

## Starten

Sorglos Sentinel kann anschließend über das Windows-Startmenü oder die optionale
Desktop-Verknüpfung gestartet werden. Die Anwendung öffnet das Dashboard im
Standardbrowser und stellt es ausschließlich lokal unter
`http://127.0.0.1:8765` bereit.

Es sind keine Portweiterleitung und keine eingehende Firewallfreigabe notwendig.
Die Oberfläche darf nicht über einen öffentlichen Webserver bereitgestellt
werden.

## Lokale Daten

Programmdateien und persönliche Scandaten werden bewusst getrennt gespeichert:

- Programm: `%LOCALAPPDATA%\Programs\Sorglos-Apps\Sorglos Sentinel\`
- Berichte und Scan-Historie:
  `%LOCALAPPDATA%\Sorglos-Apps\Sorglos Sentinel\reports\`
- Fehlerprotokoll:
  `%LOCALAPPDATA%\Sorglos-Apps\Sorglos Sentinel\sorglos-sentinel.log`

Ein Update oder eine normale Deinstallation entfernt die lokale Scan-Historie
nicht automatisch. Dadurch gehen Berichte nicht versehentlich verloren. Die
Daten können manuell beziehungsweise mit `--purge-data` bei einer
Quellcode-Installation bewusst gelöscht werden. Vor dem Weitergeben von
Berichten müssen IP-, MAC- und Gerätenamen auf vertrauliche Angaben geprüft
werden.

## Aktualisieren

Eine neuere `Sorglos-Sentinel-Setup-<Version>.exe` aus dem offiziellen Release-
Bereich herunterladen und ausführen. Der Installer aktualisiert die vorhandenen
Programmdateien. Lokale Einstellungen, Berichte und Statistiken bleiben erhalten.

Die installierte Build-Version steht direkt unter dem Programmnamen in der
Seitenleiste.

## Deinstallieren

Unter **Windows-Einstellungen → Apps → Installierte Apps** den Eintrag
**Sorglos Sentinel** auswählen und **Deinstallieren** anklicken. Alternativ steht
im Startmenü unter **Sorglos-Apps → Sorglos Sentinel** ein Deinstaller bereit.

Gespeicherte Scanberichte bleiben aus Sicherheitsgründen erhalten. Wenn sie
ebenfalls entfernt werden sollen, kann anschließend dieser Ordner manuell
gelöscht werden:

`%LOCALAPPDATA%\Sorglos-Apps\Sorglos Sentinel\`

Vor dem Löschen sollte geprüft werden, ob daraus noch Berichte benötigt werden.

## Prüfsumme unter Windows kontrollieren

PowerShell im Downloadordner öffnen und ausführen:

```powershell
Get-FileHash .\Sorglos-Sentinel-Setup-1.2.0.exe -Algorithm SHA256
```

Der angezeigte Hash muss exakt dem Eintrag in `SHA256SUMS.txt` des jeweiligen
GitHub-Releases entsprechen.

## Automatisierte Installation

Für verwaltete Windows-Arbeitsplätze unterstützt der Installer den stillen
NSIS-Modus:

```powershell
.\Sorglos-Sentinel-Setup-1.2.0.exe /S
```

Die Nutzung und der Scanbereich müssen auch bei einer stillen Installation durch
den Betreiber autorisiert und organisatorisch freigegeben sein.

## Portable Anwendung

Ein Release kann zusätzlich einen portablen Anwendungsordner enthalten. Darin
`Sorglos Sentinel.exe` starten. Auch die portable Variante speichert Berichte
standardmäßig im oben genannten lokalen Sorglos-Apps-Datenordner und nicht neben
der EXE.

## Installation aus dem Quellcode

Für Entwicklung oder Beiträge:

Das Repository über **Code → Download ZIP** herunterladen oder mit der auf der
GitHub-Seite angezeigten Clone-Adresse klonen. Anschließend im Projektordner:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
sorglos-sentinel
```

Alternativ lässt sich die lokale HTML-Oberfläche direkt starten:

```powershell
python start_gui.py
```

### Optionale Entwicklungsfunktionen

```powershell
# Native Layer-2-ARP-Unterstützung; zusätzliche Lizenzbedingungen beachten
python -m pip install ".[arp]"

# Optionaler PDF-Export
python -m pip install ".[pdf]"
```

Scapy kann unter Windows zusätzliche Komponenten wie Npcap und erhöhte Rechte
benötigen. Der offizielle Basis-Installer führt auch ohne diese optionale
Erweiterung sichere Discovery- und TCP-Prüfungen durch.

## Fehlerdiagnose

Wenn das Dashboard nicht startet:

1. Prüfen, ob bereits eine andere Anwendung Port `8765` verwendet.
2. Sorglos Sentinel einmal vollständig schließen und neu starten.
3. Das Fehlerprotokoll unter
   `%LOCALAPPDATA%\Sorglos-Apps\Sorglos Sentinel\sorglos-sentinel.log` öffnen.
4. Keine Firewallfreigabe oder Portweiterleitung für Port `8765` erstellen.
5. Bei einem reproduzierbaren Fehler einen Issue ohne sensible Scan- oder
   Netzwerkdaten melden.
