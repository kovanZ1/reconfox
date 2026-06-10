"""Tests for reconfox.core.orchestrator."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconfox.core.ffuf_scanner import FfufError
from reconfox.core.nmap_scanner import NmapError
from reconfox.core.orchestrator import (
    Orchestrator,
    ProgressEvent,
)
from reconfox.core.resolver import ResolverError
from reconfox.models import (
    ASNInfo,
    Geolocation,
    PortInfo,
    ScanMode,
    ScanStatus,
    Target,
    WebFinding,
)

# --- Fake collaborators --------------------------------------------------


class FakeResolver:
    def __init__(self, raise_on_resolve: bool = False) -> None:
        self.raise_on_resolve = raise_on_resolve
        self.calls: list[Target] = []

    async def resolve(self, target: Target) -> Target:
        self.calls.append(target)
        if self.raise_on_resolve:
            raise ResolverError("dns failed")
        target.ip = "93.184.216.34"
        target.asn = ASNInfo(asn=15133, asn_name="EDGECAST", isp="Edgecast")
        target.geo = Geolocation(country="USA", city="Los Angeles")
        return target


class FakeNmap:
    def __init__(self, error: bool = False) -> None:
        self.error = error
        self.calls: list[tuple[str, ScanMode]] = []

    async def scan(self, target: str, mode: ScanMode, ports: str | None = None) -> list[PortInfo]:
        self.calls.append((target, mode))
        if self.error:
            raise NmapError("nmap failed")
        return [PortInfo(port=80, protocol="tcp", state="open", service="http")]


class FakeFfuf:
    def __init__(self, error: bool = False) -> None:
        self.error = error
        self.calls: list[tuple[str, Path]] = []

    async def fuzz(
        self,
        target_url: str,
        wordlist: Path,
        match_codes: tuple[int, ...] | list[int] = (),  # noqa: ARG002
        threads: int = 40,  # noqa: ARG002
    ) -> list[WebFinding]:
        self.calls.append((target_url, wordlist))
        if self.error:
            raise FfufError("ffuf failed")
        return [WebFinding(url=f"{target_url}/admin", status=200, length=10)]


# --- Tests ---------------------------------------------------------------


class TestOrchestrator:
    def _make(
        self,
        *,
        resolver_fail: bool = False,
        nmap_fail: bool = False,
        ffuf_fail: bool = False,
        events: list[ProgressEvent] | None = None,
    ) -> tuple[Orchestrator, FakeResolver, FakeNmap, FakeFfuf]:
        resolver = FakeResolver(raise_on_resolve=resolver_fail)
        nmap = FakeNmap(error=nmap_fail)
        ffuf = FakeFfuf(error=ffuf_fail)
        on_progress = events.append if events is not None else None
        orch = Orchestrator(
            resolver=resolver,  # type: ignore[arg-type]
            nmap_scanner=nmap,  # type: ignore[arg-type]
            ffuf_scanner=ffuf,  # type: ignore[arg-type]
            wordlist=Path("/tmp/wl.txt"),  # noqa: S108 — wordlist is never read in tests
            on_progress=on_progress,
        )
        return orch, resolver, nmap, ffuf

    async def test_happy_path_completed(self) -> None:
        orch, resolver, nmap, ffuf = self._make()
        result = await orch.run("https://example.com", ScanMode.QUICK)
        assert result.status == ScanStatus.COMPLETED
        assert result.target.ip == "93.184.216.34"
        assert len(result.ports) == 1
        assert len(result.web_findings) == 1
        assert result.errors == []
        assert result.duration_seconds is not None
        assert resolver.calls and nmap.calls and ffuf.calls

    async def test_resolve_failure_short_circuits(self) -> None:
        orch, resolver, nmap, ffuf = self._make(resolver_fail=True)
        result = await orch.run("https://example.com", ScanMode.QUICK)
        assert result.status == ScanStatus.FAILED
        assert any("dns failed" in e for e in result.errors)
        assert nmap.calls == []
        assert ffuf.calls == []
        assert resolver.calls != []

    async def test_nmap_failure_yields_partial(self) -> None:
        orch, _, _, _ = self._make(nmap_fail=True)
        result = await orch.run("https://example.com", ScanMode.QUICK)
        assert result.status == ScanStatus.PARTIAL
        assert result.ports == []
        assert len(result.web_findings) == 1
        assert any("nmap failed" in e for e in result.errors)

    async def test_ffuf_failure_yields_partial(self) -> None:
        orch, _, _, _ = self._make(ffuf_fail=True)
        result = await orch.run("https://example.com", ScanMode.QUICK)
        assert result.status == ScanStatus.PARTIAL
        assert len(result.ports) == 1
        assert result.web_findings == []
        assert any("ffuf failed" in e for e in result.errors)

    async def test_both_scans_failure_yields_failed(self) -> None:
        orch, _, _, _ = self._make(nmap_fail=True, ffuf_fail=True)
        result = await orch.run("https://example.com", ScanMode.QUICK)
        assert result.status == ScanStatus.FAILED

    async def test_passes_mode_to_nmap(self) -> None:
        orch, _, nmap, _ = self._make()
        await orch.run("https://example.com", ScanMode.FULL)
        assert nmap.calls[0][1] == ScanMode.FULL

    async def test_progress_events_emitted_in_order(self) -> None:
        events: list[ProgressEvent] = []
        orch, _, _, _ = self._make(events=events)
        await orch.run("https://example.com", ScanMode.QUICK)
        # at least: resolve start/end, nmap start/end, ffuf start/end
        phases = [e.phase for e in events]
        assert phases.count("resolve") >= 2
        assert phases.count("nmap") >= 2
        assert phases.count("ffuf") >= 2
        # resolve must finish before nmap/ffuf start
        resolve_done_idx = next(
            i for i, e in enumerate(events) if e.phase == "resolve" and e.status == "completed"
        )
        nmap_start_idx = next(
            i for i, e in enumerate(events) if e.phase == "nmap" and e.status == "started"
        )
        assert resolve_done_idx < nmap_start_idx

    async def test_invalid_url_yields_failed(self) -> None:
        orch, _, _, _ = self._make()
        result = await orch.run("not a url", ScanMode.QUICK)
        assert result.status == ScanStatus.FAILED
        assert any("Invalid URL" in e for e in result.errors)


@pytest.mark.parametrize("mode", [ScanMode.QUICK, ScanMode.FULL, ScanMode.STEALTH])
async def test_all_modes_supported(mode: ScanMode) -> None:
    resolver = FakeResolver()
    nmap = FakeNmap()
    ffuf = FakeFfuf()
    orch = Orchestrator(
        resolver=resolver,  # type: ignore[arg-type]
        nmap_scanner=nmap,  # type: ignore[arg-type]
        ffuf_scanner=ffuf,  # type: ignore[arg-type]
        wordlist=Path("/tmp/wl.txt"),  # noqa: S108 — wordlist is never read in tests
    )
    result = await orch.run("http://example.com", mode)
    assert result.mode == mode
    assert result.status == ScanStatus.COMPLETED
