"""Tests for reconfox.core.stages — Scanner-Protocol adapters around the tools."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconfox.core.ffuf_scanner import FfufError
from reconfox.core.nmap_scanner import NmapError
from reconfox.core.resolver import ResolverError
from reconfox.core.scanner import ScanContext
from reconfox.core.stages import (
    ExploitStage,
    FfufStage,
    NmapStage,
    ResolveStage,
    default_pipeline,
)
from reconfox.models import (
    ASNInfo,
    PortInfo,
    ScanMode,
    ScanResult,
    ScanStatus,
    Severity,
    Target,
    Vulnerability,
    WebFinding,
)

# --- fakes ---------------------------------------------------------------


class FakeResolver:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    async def resolve(self, target: Target) -> Target:
        if self.fail:
            raise ResolverError("dns failed")
        target.ip = "93.184.216.34"
        target.asn = ASNInfo(asn=15133, asn_name="EDGECAST")
        return target


class FakeNmap:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, ScanMode]] = []

    async def scan(self, target: str, mode: ScanMode, ports: str | None = None) -> list[PortInfo]:
        self.calls.append((target, mode))
        if self.fail:
            raise NmapError("nmap failed")
        return [PortInfo(port=80, protocol="tcp", state="open", service="http", product="nginx")]


class FakeFfuf:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, Path]] = []

    async def fuzz(
        self,
        target_url: str,
        wordlist: Path,
        match_codes: tuple[int, ...] | list[int] = (),  # noqa: ARG002
        threads: int = 40,  # noqa: ARG002
    ) -> list[WebFinding]:
        self.calls.append((target_url, wordlist))
        if self.fail:
            raise FfufError("ffuf failed")
        return [WebFinding(url=f"{target_url}/admin", status=200, length=10)]


class FakeFinder:
    async def find_for_ports(self, ports: list[PortInfo]) -> list[Vulnerability]:  # noqa: ARG002
        return [Vulnerability(title="CVE thing", severity=Severity.HIGH, source="searchsploit")]


def _ctx(target: Target | None = None, *, ports: list[PortInfo] | None = None) -> ScanContext:
    t = target or Target.from_url("https://example.com")
    result = ScanResult(
        target=t,
        mode=ScanMode.QUICK,
        started_at=datetime(2026, 6, 10, tzinfo=UTC),
        status=ScanStatus.RUNNING,
    )
    if ports is not None:
        result.ports = ports
    return ScanContext(
        target=t, mode=ScanMode.QUICK, wordlist=Path("/tmp/wl.txt"),  # noqa: S108
        result=result, emit=lambda *a, **k: None,
    )


# --- ResolveStage --------------------------------------------------------


class TestResolveStage:
    def test_metadata(self) -> None:
        stage = ResolveStage(FakeResolver())
        assert stage.name == "resolve"
        assert stage.depends_on == ()
        assert stage.critical is True

    async def test_run_enriches_target(self) -> None:
        ctx = _ctx()
        await ResolveStage(FakeResolver()).run(ctx)
        assert ctx.target.ip == "93.184.216.34"

    async def test_run_propagates_resolver_error(self) -> None:
        ctx = _ctx()
        with pytest.raises(ResolverError):
            await ResolveStage(FakeResolver(fail=True)).run(ctx)


# --- NmapStage -----------------------------------------------------------


class TestNmapStage:
    def test_depends_on_resolve(self) -> None:
        assert NmapStage(FakeNmap()).depends_on == ("resolve",)

    def test_not_applicable_without_ip(self) -> None:
        ctx = _ctx()  # ip not resolved
        assert NmapStage(FakeNmap()).applicable(ctx) is False

    def test_applicable_with_ip(self) -> None:
        ctx = _ctx()
        ctx.target.ip = "1.1.1.1"
        assert NmapStage(FakeNmap()).applicable(ctx) is True

    async def test_run_sets_ports_and_passes_mode(self) -> None:
        ctx = _ctx()
        ctx.target.ip = "1.1.1.1"
        nmap = FakeNmap()
        await NmapStage(nmap).run(ctx)
        assert len(ctx.result.ports) == 1
        assert nmap.calls[0] == ("1.1.1.1", ScanMode.QUICK)

    async def test_run_propagates_nmap_error(self) -> None:
        ctx = _ctx()
        ctx.target.ip = "1.1.1.1"
        with pytest.raises(NmapError):
            await NmapStage(FakeNmap(fail=True)).run(ctx)


# --- FfufStage -----------------------------------------------------------


class TestFfufStage:
    async def test_run_sets_web_findings(self) -> None:
        ctx = _ctx()
        await FfufStage(FakeFfuf()).run(ctx)
        assert len(ctx.result.web_findings) == 1

    async def test_run_propagates_ffuf_error(self) -> None:
        ctx = _ctx()
        with pytest.raises(FfufError):
            await FfufStage(FakeFfuf(fail=True)).run(ctx)


# --- ExploitStage --------------------------------------------------------


class TestExploitStage:
    def test_not_applicable_without_finder(self) -> None:
        ctx = _ctx(ports=[PortInfo(port=80, protocol="tcp", state="open", product="nginx")])
        assert ExploitStage(None).applicable(ctx) is False

    def test_not_applicable_without_ports(self) -> None:
        ctx = _ctx()  # no ports
        assert ExploitStage(FakeFinder()).applicable(ctx) is False

    def test_applicable_with_finder_and_ports(self) -> None:
        ctx = _ctx(ports=[PortInfo(port=80, protocol="tcp", state="open", product="nginx")])
        assert ExploitStage(FakeFinder()).applicable(ctx) is True

    async def test_run_sets_vulnerabilities(self) -> None:
        ctx = _ctx(ports=[PortInfo(port=80, protocol="tcp", state="open", product="nginx")])
        await ExploitStage(FakeFinder()).run(ctx)
        assert len(ctx.result.vulnerabilities) == 1


# --- default_pipeline ----------------------------------------------------


class TestDefaultPipeline:
    def test_builds_four_stages_with_deps(self) -> None:
        stages = default_pipeline(FakeResolver(), FakeNmap(), FakeFfuf(), FakeFinder())
        names = [s.name for s in stages]
        assert names == ["resolve", "nmap", "ffuf", "exploits"]
        by_name = {s.name: s for s in stages}
        assert by_name["nmap"].depends_on == ("resolve",)
        assert by_name["ffuf"].depends_on == ("resolve",)
        assert by_name["exploits"].depends_on == ("nmap",)

    def test_exploit_optional(self) -> None:
        stages = default_pipeline(FakeResolver(), FakeNmap(), FakeFfuf())
        assert stages[-1].applicable(
            _ctx(ports=[PortInfo(port=80, protocol="tcp", state="open", product="x")])
        ) is False  # no finder → skipped
