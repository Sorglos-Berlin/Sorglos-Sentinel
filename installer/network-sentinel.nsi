Unicode True
!include "MUI2.nsh"

!ifndef AppVersion
  !define AppVersion "1.0.0"
!endif
!ifndef SourceDir
  !define SourceDir "..\dist\Network Sentinel"
!endif
!ifndef OutputDir
  !define OutputDir "output"
!endif

Name "Network Sentinel ${AppVersion}"
OutFile "${OutputDir}\Network-Sentinel-Setup-${AppVersion}.exe"
InstallDir "$LOCALAPPDATA\Programs\Sorglos-Apps\Network Sentinel"
InstallDirRegKey HKCU "Software\Sorglos-Apps\Network Sentinel" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID zlib
Icon "assets\app.ico"
UninstallIcon "assets\app.ico"
BrandingText "Sorglos-Apps · https://sorglos-apps.de/"
VIProductVersion "${AppVersion}.0"
VIAddVersionKey /LANG=1031 "ProductName" "Network Sentinel"
VIAddVersionKey /LANG=1031 "CompanyName" "Sorglos-Apps"
VIAddVersionKey /LANG=1031 "FileDescription" "Network Sentinel Installer"
VIAddVersionKey /LANG=1031 "FileVersion" "${AppVersion}"
VIAddVersionKey /LANG=1031 "ProductVersion" "${AppVersion}"
VIAddVersionKey /LANG=1031 "LegalCopyright" "Copyright 2026 Sorglos-Apps"

!define MUI_ABORTWARNING
!define MUI_ICON "assets\app.ico"
!define MUI_UNICON "assets\app.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\Network Sentinel.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Network Sentinel starten"
!define MUI_FINISHPAGE_LINK "Sorglos-Apps besuchen"
!define MUI_FINISHPAGE_LINK_LOCATION "https://sorglos-apps.de/"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "INSTALLER_NOTICE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "German"
!insertmacro MUI_LANGUAGE "English"

Section "Network Sentinel (erforderlich)" SEC_MAIN
  SectionIn RO
  SetOutPath "$INSTDIR"
  File /r "${SourceDir}\*"
  File "..\LICENSE"
  File "..\PRIVACY.md"
  File "..\DISCLAIMER.md"
  File "..\THIRD_PARTY_NOTICES.md"
  File "..\ACCEPTABLE_USE.md"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\Sorglos-Apps\Network Sentinel"
  CreateShortcut "$SMPROGRAMS\Sorglos-Apps\Network Sentinel\Network Sentinel.lnk" "$INSTDIR\Network Sentinel.exe" "" "$INSTDIR\Network Sentinel.exe"
  CreateShortcut "$SMPROGRAMS\Sorglos-Apps\Network Sentinel\Datenschutz.lnk" "$INSTDIR\PRIVACY.md"
  CreateShortcut "$SMPROGRAMS\Sorglos-Apps\Network Sentinel\Deinstallieren.lnk" "$INSTDIR\Uninstall.exe"

  WriteRegStr HKCU "Software\Sorglos-Apps\Network Sentinel" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "DisplayName" "Network Sentinel"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "DisplayVersion" "${AppVersion}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "Publisher" "Sorglos-Apps"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "URLInfoAbout" "https://sorglos-apps.de/"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "HelpLink" "https://sorglos-apps.de/Support/"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "DisplayIcon" "$INSTDIR\Network Sentinel.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel" "NoRepair" 1
SectionEnd

Section /o "Desktop-Verknüpfung" SEC_DESKTOP
  CreateShortcut "$DESKTOP\Network Sentinel.lnk" "$INSTDIR\Network Sentinel.exe" "" "$INSTDIR\Network Sentinel.exe"
SectionEnd

LangString DESC_SEC_MAIN ${LANG_GERMAN} "Installiert Network Sentinel für den aktuellen Benutzer."
LangString DESC_SEC_MAIN ${LANG_ENGLISH} "Installs Network Sentinel for the current user."
LangString DESC_SEC_DESKTOP ${LANG_GERMAN} "Erstellt eine Verknüpfung auf dem Desktop."
LangString DESC_SEC_DESKTOP ${LANG_ENGLISH} "Creates a desktop shortcut."
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} $(DESC_SEC_MAIN)
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} $(DESC_SEC_DESKTOP)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  Delete "$DESKTOP\Network Sentinel.lnk"
  RMDir /r "$SMPROGRAMS\Sorglos-Apps\Network Sentinel"
  RMDir "$SMPROGRAMS\Sorglos-Apps"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSentinel"
  DeleteRegKey HKCU "Software\Sorglos-Apps\Network Sentinel"
  RMDir /r "$INSTDIR"
  ; Persönliche Scanberichte unter LOCALAPPDATA\Sorglos-Apps bleiben bewusst erhalten.
SectionEnd
