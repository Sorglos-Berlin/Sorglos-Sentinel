param(
    [string]$Version = "1.1.0",
    [string]$Commit = ""
)
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Icon = Join-Path $PSScriptRoot "assets\app.ico"
$VersionFile = Join-Path $PSScriptRoot "generated-version.txt"
$BuildModule = Join-Path $ProjectRoot "network_scanner\_build.py"
$Output = Join-Path $PSScriptRoot "output"

Set-Content -Path $BuildModule -Encoding UTF8 -Value "BUILD_VERSION = '$Version'`nBUILD_COMMIT = '$Commit'"
python (Join-Path $PSScriptRoot "generate_windows_assets.py") --version $Version --icon $Icon --version-file $VersionFile
python -m PyInstaller --noconfirm --clean (Join-Path $PSScriptRoot "sorglos-sentinel.spec")

$CompilerCandidates = @(
    "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
    "$env:ProgramFiles\NSIS\makensis.exe",
    "$env:LOCALAPPDATA\Programs\NSIS\makensis.exe"
)
$Compiler = $CompilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $Compiler) { throw "NSIS wurde nicht gefunden." }
New-Item -ItemType Directory -Force $Output | Out-Null
& $Compiler "/DAppVersion=$Version" "/DSourceDir=$(Join-Path $ProjectRoot 'dist\Sorglos Sentinel')" "/DOutputDir=$Output" (Join-Path $PSScriptRoot "sorglos-sentinel.nsi")
if ($LASTEXITCODE -ne 0) { throw "NSIS ist mit Code $LASTEXITCODE fehlgeschlagen." }
