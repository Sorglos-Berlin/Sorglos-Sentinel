@echo off
cd /d "%~dp0"
python start_gui.py
if errorlevel 1 (
  echo.
  echo Die HTML-Benutzeroberflaeche konnte nicht gestartet werden.
  echo Bitte Python 3.10 oder neuer installieren.
  pause
)
