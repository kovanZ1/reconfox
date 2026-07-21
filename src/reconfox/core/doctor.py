"""Environment readiness checks powering ``reconfox doctor``.

Recon leans on external tools (nmap, ffuf, searchsploit, nuclei) and a
wordlist; if one is missing that otherwise only surfaces mid-scan. ``doctor``
looks them up once, up front, so the operator knows exactly what is wired up
before a live engagement.
"""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404 — diagnostic tool-version probe, fixed argv, no shell
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

Which = Callable[[str], str | None]
VersionProbe = Callable[[str], str | None]

# (binary, required, install hint)
TOOLS: tuple[tuple[str, bool, str], ...] = (
    ("nmap", True, "sudo apt install nmap"),
    ("ffuf", True, "sudo apt install ffuf"),
    ("searchsploit", False, "sudo apt install exploitdb"),
    ("nuclei", False, "sudo apt install nuclei"),
)


@dataclass(frozen=True)
class ToolStatus:
    name: str
    required: bool
    path: str | None
    version: str | None
    hint: str

    @property
    def ok(self) -> bool:
        return self.path is not None


@dataclass(frozen=True)
class WordlistStatus:
    path: Path
    exists: bool
    hint: str = "sudo apt install seclists  (or dirb)"


def _probe_version(binary: str) -> str | None:
    """Best-effort first line of ``binary --version`` (never raises)."""
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    return text.splitlines()[0][:80] if text else None


def check_tools(
    which: Which | None = None, version: VersionProbe | None = None
) -> list[ToolStatus]:
    """Report presence/path/version for each external tool reconfox can use."""
    which = which or shutil.which
    version = version or _probe_version
    statuses: list[ToolStatus] = []
    for binary, required, hint in TOOLS:
        path = which(binary)
        statuses.append(
            ToolStatus(
                name=binary,
                required=required,
                path=path,
                version=version(binary) if path else None,
                hint=hint,
            )
        )
    return statuses


def check_wordlist(path: Path) -> WordlistStatus:
    return WordlistStatus(path=path, exists=path.exists())


def required_ok(tools: list[ToolStatus]) -> bool:
    """True when every *required* tool is present."""
    return all(t.ok for t in tools if t.required)
