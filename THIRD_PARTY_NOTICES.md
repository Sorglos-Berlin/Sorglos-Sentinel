# Drittanbieterhinweise

Sorglos Sentinel selbst wird unter der MIT-Lizenz bereitgestellt.

## PyYAML

- Zweck: optionale YAML-Konfiguration
- Lizenz: MIT
- Projekt: <https://github.com/yaml/pyyaml>
- Installation: reguläre Abhängigkeit

## Scapy

- Zweck: optionale Layer-2-ARP-Erkennung
- Lizenz: GPL-2.0
- Projekt: <https://github.com/secdev/scapy>
- Installation: nur über das optionale Extra `arp` oder
  `requirements-arp.txt`
- Scapy wird nicht in diesem Repository gebündelt oder verändert.

Die MIT-Lizenz von Sorglos Sentinel ändert nicht die Lizenzbedingungen von
Scapy. Wer die optionale Integration installiert oder verteilt, muss die
anwendbaren Bedingungen der GPL-2.0 selbst beachten.

## WeasyPrint

- Zweck: optionaler PDF-Export
- Lizenz: BSD-3-Clause
- Projekt: <https://github.com/Kozea/WeasyPrint>
- Installation: optionales Extra `pdf`

## Offizieller Windows-Build

Der Windows-Installer bündelt die für die Ausführung benötigte Python-Laufzeit
unter den Bedingungen der Python Software Foundation License sowie PyYAML unter
der MIT-Lizenz. Die konkreten Versionsstände werden durch den jeweiligen
Release-Build bestimmt.

PyInstaller (GPL-2.0-or-later mit Bootloader-Ausnahme), Pillow (HPND) und NSIS
(zlib/libpng) werden als Build-Werkzeuge eingesetzt. Der offizielle Installer
verwendet ausdrücklich das zlib-Kompressionsmodul. Ihre Nutzung ändert
nicht die MIT-Lizenz des Sorglos-Sentinel-Quellcodes. Scapy und WeasyPrint sind
im offiziellen Basis-Installer nicht enthalten.

## Python und Browser

Bei einer Quellcode-Installation wird die lokale Python-Laufzeit verwendet; im
offiziellen Windows-Build ist sie gebündelt. Der installierte Browser wird nie
gebündelt. Es werden keine extern geladenen Schriftarten, Skripte oder
Trackingbibliotheken ausgeliefert.

Vor einem Binärrelease muss eine Software-Bill-of-Materials beziehungsweise
Lizenzliste der tatsächlich gebündelten Versionen neu erzeugt und geprüft
werden.
