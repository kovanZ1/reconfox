"""Async wrapper around nuclei — active, template-based vulnerability scanning.

Unlike searchsploit (which only string-matches service versions against
Exploit-DB), nuclei actually fires community templates at live URLs and reports
what matched. Results are mapped onto the shared Vulnerability model with
``source="nuclei"``. Scanning is active/intrusive, so it is opt-in (``--nuclei``).
"""

from __future__ import annotations

import json
from typing import Any

from reconfox.core._proc import run_capture
from reconfox.models import Severity, Vulnerability

DEFAULT_TIMEOUT = 1800.0  # nuclei runs many templates — generous anti-hang ceiling

_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class NucleiError(RuntimeError):
    """Raised when the nuclei binary is missing or unusable."""


class NucleiScanner:
    def __init__(self, binary: str = "nuclei", timeout: float | None = None) -> None:
        self.binary = binary
        self.timeout = timeout if timeout is not None else DEFAULT_TIMEOUT

    async def scan(self, urls: list[str]) -> list[Vulnerability]:
        if not urls:
            return []
        args: list[str] = []
        for url in urls:
            args.extend(["-u", url])
        args.extend(["-jsonl", "-silent", "-disable-update-check", "-no-color"])
        try:
            _, stdout, _ = await run_capture(self.binary, *args, timeout=self.timeout)
        except TimeoutError:
            # active scanning is best-effort — a hung run degrades to no findings
            return []
        except FileNotFoundError as exc:
            raise NucleiError(f"nuclei binary not found: {self.binary}") from exc
        return self.parse_jsonl(stdout.decode(errors="replace"))

    @staticmethod
    def parse_jsonl(output: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue  # tolerate non-JSON chatter on the stream
            if isinstance(item, dict):
                vulns.append(_to_vuln(item))
        return vulns


def _to_vuln(item: dict[str, Any]) -> Vulnerability:
    info = item.get("info") or {}
    severity = _SEVERITY_MAP.get(str(info.get("severity", "")).lower(), Severity.INFO)
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or []
    cve = cves[0] if isinstance(cves, list) and cves else None
    title = info.get("name") or item.get("template-id") or "nuclei finding"
    return Vulnerability(
        title=title,
        severity=severity,
        source="nuclei",
        cve=cve,
        description=info.get("description"),
        references=_as_list(info.get("reference")),
    )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []
