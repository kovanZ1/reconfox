"""Orchestrator — runs Resolver, then nmap and ffuf in parallel, aggregates ScanResult.

Exposes a callback-based progress channel so TUI and CLI can render live progress.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from reconfox.core.ffuf_scanner import FfufError
from reconfox.core.nmap_scanner import NmapError
from reconfox.core.resolver import ResolverError
from reconfox.models import (
    PortInfo,
    ScanMode,
    ScanResult,
    ScanStatus,
    Target,
    Vulnerability,
    WebFinding,
)

Phase = Literal["resolve", "nmap", "ffuf", "exploits", "report"]
Status = Literal["started", "info", "completed", "failed"]


@dataclass(frozen=True)
class ProgressEvent:
    phase: Phase
    status: Status
    message: str | None = None
    duration_seconds: float | None = None


# Protocols let tests inject fakes without inheritance.
class ResolverProtocol(Protocol):
    async def resolve(self, target: Target) -> Target: ...


class NmapProtocol(Protocol):
    async def scan(
        self, target: str, mode: ScanMode, ports: str | None = None
    ) -> list[PortInfo]: ...


class FfufProtocol(Protocol):
    async def fuzz(
        self,
        target_url: str,
        wordlist: Path,
        match_codes: list[int] | tuple[int, ...] = ...,
        threads: int = ...,
    ) -> list[WebFinding]: ...


class ExploitFinderProtocol(Protocol):
    async def find_for_ports(self, ports: list[PortInfo]) -> list[Vulnerability]: ...


ProgressCallback = Callable[[ProgressEvent], None]


class Orchestrator:
    def __init__(
        self,
        resolver: ResolverProtocol,
        nmap_scanner: NmapProtocol,
        ffuf_scanner: FfufProtocol,
        wordlist: Path,
        exploit_finder: ExploitFinderProtocol | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.resolver = resolver
        self.nmap = nmap_scanner
        self.ffuf = ffuf_scanner
        self.exploit_finder = exploit_finder
        self.wordlist = wordlist
        self._on_progress = on_progress

    def _emit(
        self,
        phase: Phase,
        status: Status,
        message: str | None = None,
        duration: float | None = None,
    ) -> None:
        if self._on_progress is None:
            return
        # Callback must not break the run — swallow any error it raises.
        with contextlib.suppress(Exception):
            self._on_progress(
                ProgressEvent(
                    phase=phase, status=status, message=message, duration_seconds=duration
                )
            )

    async def run(self, target_url: str, mode: ScanMode) -> ScanResult:
        started_at = datetime.now(UTC)

        try:
            target = Target.from_url(target_url)
        except ValueError as exc:
            return ScanResult(
                target=_placeholder_target(target_url),
                mode=mode,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status=ScanStatus.FAILED,
                errors=[f"target: {exc}"],
            )

        result = ScanResult(
            target=target,
            mode=mode,
            started_at=started_at,
            status=ScanStatus.RUNNING,
        )

        if not await self._do_resolve(target, result):
            result.finished_at = datetime.now(UTC)
            result.status = ScanStatus.FAILED
            return result

        ports, findings = await asyncio.gather(
            self._do_nmap(target, mode, result),
            self._do_ffuf(target, result),
        )
        result.ports = ports
        result.web_findings = findings
        if self.exploit_finder is not None and ports:
            result.vulnerabilities = await self._do_exploits(ports, result)
        result.finished_at = datetime.now(UTC)
        result.status = self._derive_status(result)
        return result

    async def _do_resolve(self, target: Target, result: ScanResult) -> bool:
        self._emit("resolve", "started", f"resolving {target.hostname}")
        start = datetime.now(UTC)
        try:
            await self.resolver.resolve(target)
        except ResolverError as exc:
            self._emit(
                "resolve",
                "failed",
                str(exc),
                (datetime.now(UTC) - start).total_seconds(),
            )
            result.errors.append(f"resolve: {exc}")
            return False
        self._emit("resolve", "info", f"ip: {target.ip}")
        if target.asn is not None and target.asn.asn:
            asn_str = f"AS{target.asn.asn} {target.asn.asn_name or ''}".strip()
            self._emit("resolve", "info", f"asn: {asn_str}")
        if target.geo is not None and (target.geo.city or target.geo.country):
            loc = ", ".join(filter(None, [target.geo.city, target.geo.country]))
            self._emit("resolve", "info", f"location: {loc}")
        self._emit(
            "resolve",
            "completed",
            duration=(datetime.now(UTC) - start).total_seconds(),
        )
        return True

    async def _do_nmap(
        self, target: Target, mode: ScanMode, result: ScanResult
    ) -> list[PortInfo]:
        if target.ip is None:
            return []
        self._emit("nmap", "started", f"scanning {target.ip} (mode={mode.value})")
        start = datetime.now(UTC)
        try:
            ports = await self.nmap.scan(target.ip, mode)
        except NmapError as exc:
            self._emit(
                "nmap", "failed", str(exc), (datetime.now(UTC) - start).total_seconds()
            )
            result.errors.append(f"nmap: {exc}")
            return []
        open_ports = [p for p in ports if p.state == "open"]
        for p in sorted(open_ports, key=lambda x: x.port):
            svc = p.service or "?"
            ver = f"{p.product or ''} {p.version or ''}".strip()
            tail = f" {ver}" if ver else ""
            self._emit("nmap", "info", f"{p.port}/{p.protocol} open {svc}{tail}")
        self._emit(
            "nmap",
            "completed",
            f"{len(open_ports)} open port(s)",
            (datetime.now(UTC) - start).total_seconds(),
        )
        return ports

    async def _do_exploits(
        self, ports: list[PortInfo], result: ScanResult
    ) -> list[Vulnerability]:
        if self.exploit_finder is None:  # guarded by caller, narrow type for mypy
            return []
        relevant = [p for p in ports if p.product]
        self._emit(
            "exploits",
            "started",
            f"querying for {len(relevant)} service(s)",
        )
        start = datetime.now(UTC)
        try:
            vulns = await self.exploit_finder.find_for_ports(ports)
        except Exception as exc:  # noqa: BLE001 — third-party tool may raise anything
            self._emit(
                "exploits",
                "failed",
                str(exc),
                (datetime.now(UTC) - start).total_seconds(),
            )
            result.errors.append(f"exploits: {exc}")
            return []
        for v in vulns[:10]:
            label = f"[{v.severity.value}] {v.title}"
            if v.cve:
                label += f" ({v.cve})"
            self._emit("exploits", "info", label)
        if len(vulns) > 10:
            self._emit("exploits", "info", f"... and {len(vulns) - 10} more")
        self._emit(
            "exploits",
            "completed",
            f"{len(vulns)} potential vuln(s)",
            (datetime.now(UTC) - start).total_seconds(),
        )
        return vulns

    async def _do_ffuf(self, target: Target, result: ScanResult) -> list[WebFinding]:
        self._emit("ffuf", "started", f"fuzzing {target.url} with {self.wordlist.name}")
        start = datetime.now(UTC)
        try:
            findings = await self.ffuf.fuzz(target.url, self.wordlist)
        except FfufError as exc:
            self._emit(
                "ffuf", "failed", str(exc), (datetime.now(UTC) - start).total_seconds()
            )
            result.errors.append(f"ffuf: {exc}")
            return []
        for f in findings[:20]:
            self._emit("ffuf", "info", f"{f.status} {f.url}")
        if len(findings) > 20:
            self._emit("ffuf", "info", f"... and {len(findings) - 20} more")
        self._emit(
            "ffuf",
            "completed",
            f"{len(findings)} finding(s)",
            (datetime.now(UTC) - start).total_seconds(),
        )
        return findings

    @staticmethod
    def _derive_status(result: ScanResult) -> ScanStatus:
        if not result.errors:
            return ScanStatus.COMPLETED
        if result.ports or result.web_findings:
            return ScanStatus.PARTIAL
        return ScanStatus.FAILED


def _placeholder_target(raw: str) -> Target:
    """Stand-in target when URL parsing fails — keeps ScanResult constructable."""
    return Target(url=raw, hostname="unknown", path="/", port=80, is_https=False)
