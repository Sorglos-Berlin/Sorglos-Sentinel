"""Runtime build identity with Git metadata and package fallback."""

from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any

FALLBACK_VERSION = "1.0.0"


def _baked_build() -> dict[str, Any] | None:
    try:
        from ._build import BUILD_COMMIT, BUILD_VERSION  # type: ignore
    except ImportError:
        return None
    if not BUILD_VERSION:
        return None
    commit = str(BUILD_COMMIT or "")[:8]
    return {
        "version": str(BUILD_VERSION),
        "display": f"v{BUILD_VERSION}" + (f" · {commit}" if commit else ""),
        "commit": commit, "dirty": False, "source": "release-build",
    }


def _base_version() -> str:
    try:
        return package_version("network-sentinel")
    except PackageNotFoundError:
        return FALLBACK_VERSION


def _repository_root(start: Path | None = None) -> Path | None:
    current = (start or Path(__file__)).resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, text=True,
        check=True, timeout=1.5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return completed.stdout.strip()


def _head_commit(root: Path) -> str:
    """Read HEAD without executing Git (also works with safe-directory warnings)."""
    git_dir = root / ".git"
    if git_dir.is_file():
        marker = git_dir.read_text(encoding="utf-8").strip()
        if marker.startswith("gitdir:"):
            git_dir = (root / marker.split(":", 1)[1].strip()).resolve()
    head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    if not head.startswith("ref:"):
        return head[:8]
    reference = head.split(":", 1)[1].strip()
    loose = git_dir / reference
    if loose.exists():
        return loose.read_text(encoding="utf-8").strip()[:8]
    packed = git_dir / "packed-refs"
    if packed.exists():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(('#', '^')):
                commit, name = line.split(" ", 1)
                if name == reference:
                    return commit[:8]
    return ""


@lru_cache(maxsize=4)
def get_build_info(repository: str = "") -> dict[str, Any]:
    """Return a display version; never fail when Git is unavailable."""
    base = _base_version()
    root = _repository_root(Path(repository)) if repository else _repository_root()
    info: dict[str, Any] = {
        "version": base, "display": f"v{base}", "commit": "",
        "dirty": False, "source": "package",
    }
    if root is None:
        return _baked_build() or info
    try:
        description = _git(root, "describe", "--tags", "--always", "--dirty")
        commit = _git(root, "rev-parse", "--short=8", "HEAD")
    except (OSError, subprocess.SubprocessError):
        try:
            commit = _head_commit(root)
        except (OSError, ValueError):
            commit = ""
        if commit:
            info.update({"display": f"v{base} · {commit}", "commit": commit,
                         "source": "git-metadata"})
        return info
    dirty = description.endswith("-dirty")
    clean_description = description.removesuffix("-dirty").removeprefix("v")
    tag_match = re.fullmatch(r"\d+\.\d+\.\d+", clean_description)
    display = f"v{clean_description}" if tag_match else f"v{base} · {commit}"
    if dirty:
        display += " · lokal geändert"
    return {
        "version": clean_description if tag_match else base,
        "display": display,
        "commit": commit,
        "dirty": dirty,
        "source": "git",
    }
