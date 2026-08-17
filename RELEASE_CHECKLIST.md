# Release-Checkliste

## Recht und Inhalte

- [ ] Rechteinhaber und Jahreszahl korrekt
- [ ] Repository- und Website-URLs ohne Platzhalter
- [ ] MIT-Lizenz, Disclaimer und Drittanbieterhinweise geprüft
- [ ] Keine fremden Logos, Bilder, Datenbanken oder Texte ohne Erlaubnis
- [ ] Sponsor-, Steuer- und Anbieterangaben geprüft

## Datenschutz und Geheimnisse

- [ ] Keine Reports, IP-/MAC-Listen oder Konfigurationen im Git-Verlauf
- [ ] `git grep` und Secret-Scanner ohne Befund
- [ ] Keine Tokens, privaten Schlüssel oder persönlichen E-Mail-Adressen
- [ ] Dashboard bindet nur an Loopback und enthält keine Telemetrie

## Qualität und Sicherheit

- [ ] Alle Unit-Tests bestanden
- [ ] JavaScript-Syntaxprüfung bestanden
- [ ] Abhängigkeiten und Lizenzen geprüft
- [ ] NSIS-Version und verwendetes Kompressionsmodul lizenzrechtlich geprüft
- [ ] Dependency- und Code-Scanning aktiviert
- [ ] Private Vulnerability Reporting aktiviert
- [ ] Release auf sauberer VM getestet

## Paket

- [ ] Git-Tag und Version in `pyproject.toml` identisch
- [ ] `python -m build` erfolgreich
- [ ] `python -m twine check dist/*` erfolgreich
- [ ] Wheel-Inhalt auf sensible oder unnötige Dateien geprüft
- [ ] SHA-256-Prüfsummen veröffentlicht
- [ ] Windows-Installer auf sauberer Windows-VM installiert, gestartet und deinstalliert
- [ ] Installer-Hinweise, Startmenü, optionaler Desktop-Link und App-Eintrag geprüft
- [ ] EXE- und Installer-Signatur geprüft oder fehlende Signatur klar dokumentiert
- [ ] Scan-Historie bleibt bei Update/Deinstallation erwartungsgemäß erhalten
- [ ] Release Notes und Changelog aktualisiert
