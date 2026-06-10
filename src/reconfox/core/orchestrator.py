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
    WebFinding,
)

Phase = Literal["resolve", "nmap", "ffuf"]
Status = Literal["started", "completed", "failed"]


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


ProgressCallback = Callable[[ProgressEvent], None]


class Orchestrator:
    def __init__(
        self,
        resolver: ResolverProtocol,
        nmap_scanner: NmapProtocol,
        ffuf_scanner: FfufProtocol,
        wordlist: Path,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.resolver = resolver
        self.nmap = nmap_scanner
        self.ffuf = ffuf_scanner
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
        result.finished_at = datetime.now(UTC)
        result.status = self._derive_status(result)
        return result

    async def _do_resolve(self, target: Target, result: ScanResult) -> bool:
        self._emit("resolve", "started")
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
        self._emit("nmap", "started")
        start = datetime.now(UTC)
        try:
            ports = await self.nmap.scan(target.ip, mode)
        except NmapError as exc:
            self._emit(
                "nmap", "failed", str(exc), (datetime.now(UTC) - start).total_seconds()
            )
            result.errors.append(f"nmap: {exc}")
            return []
        self._emit(
            "nmap", "completed", duration=(datetime.now(UTC) - start).total_seconds()
        )
        return ports

    async def _do_ffuf(self, target: Target, result: ScanResult) -> list[WebFinding]:
        self._emit("ffuf", "started")
        start = datetime.now(UTC)
        try:
            findings = await self.ffuf.fuzz(target.url, self.wordlist)
        except FfufError as exc:
            self._emit(
                "ffuf", "failed", str(exc), (datetime.now(UTC) - start).total_seconds()
            )
            result.errors.append(f"ffuf: {exc}")
            return []
        self._emit(
            "ffuf", "completed", duration=(datetime.now(UTC) - start).total_seconds()
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
