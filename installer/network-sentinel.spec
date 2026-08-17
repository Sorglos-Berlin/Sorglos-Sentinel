from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files

project_root = Path(SPECPATH).parent
icon = project_root / "installer" / "assets" / "app.ico"
version_file = project_root / "installer" / "generated-version.txt"

a = Analysis(
    [str(project_root / "start_gui.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=collect_data_files("network_scanner") + [
        (str(project_root / "LICENSE"), "."),
        (str(project_root / "NOTICE"), "."),
        (str(project_root / "PRIVACY.md"), "."),
        (str(project_root / "DISCLAIMER.md"), "."),
        (str(project_root / "THIRD_PARTY_NOTICES.md"), "."),
    ],
    hiddenimports=["yaml"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["weasyprint", "scapy"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True,
    name="Network Sentinel", debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=False, disable_windowed_traceback=False,
    icon=str(icon), version=str(version_file),
)
coll = COLLECT(
    exe, a.binaries, a.datas, strip=False, upx=False,
    name="Network Sentinel",
)
