# Sicherheitsrichtlinie

## Unterstützte Versionen

Sicherheitskorrekturen werden für die aktuelle veröffentlichte 1.x-Version
bereitgestellt. Ältere Entwicklungsstände und nicht unterstützte Forks erhalten
keine langfristige Supportzusage.

## Schwachstelle vertraulich melden

Bitte veröffentliche Sicherheitsprobleme nicht sofort als öffentliches Issue.
Nutze bevorzugt GitHubs Funktion **Private vulnerability reporting** im Bereich
`Security` des Repositorys. Falls sie noch nicht aktiviert ist, eröffne ein
Issue ohne technische Exploitdetails und bitte um einen privaten Kontaktkanal.

Eine gute Meldung enthält:

- betroffene Version und Plattform,
- reproduzierbare Schritte,
- erwartetes und tatsächliches Verhalten,
- mögliche Auswirkungen,
- einen minimalen, nicht schädlichen Nachweis.

Keine realen Zugangsdaten, personenbezogenen Scanergebnisse oder Daten Dritter
mitsenden.

## Reaktionsziel

Sorglos-Apps bemüht sich um:

- Eingangsbestätigung innerhalb von 7 Tagen,
- erste Bewertung innerhalb von 14 Tagen,
- koordinierte Veröffentlichung nach Verfügbarkeit einer Korrektur.

Dies sind Ziele und keine garantierten Service Level.

## Scope

Zum Scope gehören insbesondere lokale API-Sicherheit, Berichtsexporte,
Eingabevalidierung, ungewollte externe Verbindungen, Datenschutzverletzungen
und Möglichkeiten, die private Zielnetz-, Autorisierungs- oder defensive
Prüfbegrenzung zu umgehen. Auch Manipulationen an Installer, Release-Workflow
oder lokaler Scan-Historie gehören zum Scope.

Nicht zum Scope gehören unautorisierte Tests gegen fremde Netze, Social
Engineering, Denial of Service und Schwachstellen ausschließlich in nicht
unterstützten Drittanbieterkomponenten.
