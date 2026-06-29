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
    HttpProbeStage,
    NmapStage,
    NucleiStage,
    ResolveStage,
    SubdomainStage,
    TlsStage,
    default_pipeline,
)
from reconfox.models import (
    ASNInfo,
    HttpProbe,
    PortInfo,
    ScanMode,
    ScanResult,
    ScanStatus,
    Severity,
    Subdomain,
    Target,
    TlsInfo,
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


class FakeProber:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def probe(self, url: str) -> HttpProbe:
        self.calls.append(url)
        return HttpProbe(url=url, status=200, title="Home", server="nginx", technologies=["nginx"])


class FakeNuclei:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    async def scan(self, urls: list[str]) -> list[Vulnerability]:
        self.calls.append(urls)
        return [Vulnerability(title="nuclei hit", severity=Severity.HIGH, source="nuclei")]


class FakeSubdomainFinder:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def find(self, domain: str) -> list[Subdomain]:
        self.calls.append(domain)
        return [Subdomain(name=f"www.{domain}", ip="1.1.1.1", source="crt.sh")]


class FakeTls:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    async def probe(self, host: str, port: int = 443) -> TlsInfo:
        self.calls.append((host, port))
        return TlsInfo(host=host, port=port, version="TLSv1.3", subject=host)


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


# --- SubdomainStage ------------------------------------------------------


class TestSubdomainStage:
    def test_runs_first_no_deps(self) -> None:
        assert SubdomainStage(FakeSubdomainFinder()).depends_on == ()

    def test_not_applicable_without_finder(self) -> None:
        assert SubdomainStage(None).applicable(_ctx()) is False

    def test_not_applicable_for_ip_target(self) -> None:
        ctx = _ctx(Target.from_url("http://1.2.3.4"))
        assert SubdomainStage(FakeSubdomainFinder()).applicable(ctx) is False

    def test_applicable_for_domain(self) -> None:
        assert SubdomainStage(FakeSubdomainFinder()).applicable(_ctx()) is True

    async def test_run_populates_subdomains(self) -> None:
        ctx = _ctx()
        finder = FakeSubdomainFinder()
        await SubdomainStage(finder).run(ctx)
        assert finder.calls == ["example.com"]
        assert [s.name for s in ctx.result.subdomains] == ["www.example.com"]


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


# --- TlsStage ------------------------------------------------------------


class TestTlsStage:
    def test_not_applicable_without_prober(self) -> None:
        ctx = _ctx(Target.from_url("https://example.com"))
        assert TlsStage(None).applicable(ctx) is False

    def test_applicable_for_https(self) -> None:
        ctx = _ctx(Target.from_url("https://example.com"))
        assert TlsStage(FakeTls()).applicable(ctx) is True

    def test_not_applicable_for_plain_http(self) -> None:
        ctx = _ctx(Target.from_url("http://example.com"))  # port 80, not https
        assert TlsStage(FakeTls()).applicable(ctx) is False

    async def test_run_sets_tls_info(self) -> None:
        ctx = _ctx(Target.from_url("https://example.com"))
        tls = FakeTls()
        await TlsStage(tls).run(ctx)
        assert ctx.result.tls is not None
        assert ctx.result.tls.version == "TLSv1.3"
        assert tls.calls == [("example.com", 443)]


# --- HttpProbeStage ------------------------------------------------------


class TestHttpProbeStage:
    def test_depends_on_nmap(self) -> None:
        assert HttpProbeStage(FakeProber()).depends_on == ("nmap",)

    def test_not_applicable_without_prober(self) -> None:
        assert HttpProbeStage(None).applicable(_ctx()) is False

    def test_applicable_with_prober(self) -> None:
        assert HttpProbeStage(FakeProber()).applicable(_ctx()) is True

    async def test_run_probes_target_url(self) -> None:
        ctx = _ctx()
        prober = FakeProber()
        await HttpProbeStage(prober).run(ctx)
        assert len(ctx.result.http_probes) == 1
        assert prober.calls == ["https://example.com"]

    async def test_run_also_probes_discovered_http_ports(self) -> None:
        ctx = _ctx(
            ports=[
                PortInfo(port=8080, protocol="tcp", state="open", service="http-proxy"),
                PortInfo(port=22, protocol="tcp", state="open", service="ssh"),
            ]
        )
        prober = FakeProber()
        await HttpProbeStage(prober).run(ctx)
        # target url + the open http port (8080), but NOT ssh
        assert "https://example.com" in prober.calls
        assert any(":8080" in u for u in prober.calls)
        assert not any(":22" in u for u in prober.calls)


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

    async def test_run_appends_vulnerabilities(self) -> None:
        ctx = _ctx(ports=[PortInfo(port=80, protocol="tcp", state="open", product="nginx")])
        # a pre-existing finding (e.g. from nuclei) must not be clobbered
        ctx.result.vulnerabilities.append(
            Vulnerability(title="pre", severity=Severity.LOW, source="nuclei")
        )
        await ExploitStage(FakeFinder()).run(ctx)
        titles = [v.title for v in ctx.result.vulnerabilities]
        assert "pre" in titles
        assert "CVE thing" in titles


# --- NucleiStage ---------------------------------------------------------


class TestNucleiStage:
    def test_depends_on_http(self) -> None:
        assert NucleiStage(FakeNuclei()).depends_on == ("http",)

    def test_not_applicable_without_scanner(self) -> None:
        assert NucleiStage(None).applicable(_ctx()) is False

    def test_applicable_with_scanner(self) -> None:
        assert NucleiStage(FakeNuclei()).applicable(_ctx()) is True

    async def test_run_scans_live_probe_urls(self) -> None:
        ctx = _ctx()
        ctx.result.http_probes = [
            HttpProbe(url="https://example.com", status=200, final_url="https://example.com/"),
            HttpProbe(url="https://dead.example", status=None, error="refused"),
        ]
        nuclei = FakeNuclei()
        await NucleiStage(nuclei).run(ctx)
        # only the live probe's final_url, not the dead one
        assert nuclei.calls == [["https://example.com/"]]

    async def test_run_falls_back_to_target_url(self) -> None:
        ctx = _ctx()  # no probes
        nuclei = FakeNuclei()
        await NucleiStage(nuclei).run(ctx)
        assert nuclei.calls == [["https://example.com"]]

    async def test_run_appends_findings(self) -> None:
        ctx = _ctx()
        ctx.result.vulnerabilities.append(
            Vulnerability(title="exploit-db hit", severity=Severity.MEDIUM, source="searchsploit")
        )
        await NucleiStage(FakeNuclei()).run(ctx)
        titles = [v.title for v in ctx.result.vulnerabilities]
        assert "exploit-db hit" in titles
        assert "nuclei hit" in titles


# --- default_pipeline ----------------------------------------------------


class TestDefaultPipeline:
    def test_builds_stages_with_deps(self) -> None:
        stages = default_pipeline(
            FakeResolver(), FakeNmap(), FakeFfuf(), FakeFinder(), FakeProber(), FakeNuclei(),
            FakeSubdomainFinder(), FakeTls(),
        )
        names = [s.name for s in stages]
        assert names == [
            "subdomains", "resolve", "tls", "nmap", "ffuf", "http", "nuclei", "exploits"
        ]
        by_name = {s.name: s for s in stages}
        assert by_name["subdomains"].depends_on == ()
        assert by_name["tls"].depends_on == ("resolve",)
        assert by_name["nmap"].depends_on == ("resolve",)
        assert by_name["ffuf"].depends_on == ("resolve",)
        assert by_name["http"].depends_on == ("nmap",)
        assert by_name["nuclei"].depends_on == ("http",)
        assert by_name["exploits"].depends_on == ("nmap",)

    def test_optional_stages_skipped_when_absent(self) -> None:
        stages = default_pipeline(FakeResolver(), FakeNmap(), FakeFfuf())
        by_name = {s.name: s for s in stages}
        # no finder, prober, or nuclei → those stages skipped
        assert by_name["exploits"].applicable(
            _ctx(ports=[PortInfo(port=80, protocol="tcp", state="open", product="x")])
        ) is False
        assert by_name["http"].applicable(_ctx()) is False
        assert by_name["nuclei"].applicable(_ctx()) is False
