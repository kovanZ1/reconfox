"""Concrete Scanner stages — thin adapters wrapping each recon tool.

Each stage owns its own progress emits (started / info / completed) and raises
the tool's domain error on failure; the orchestrator catches it, records the
error and decides whether to abort (for ``critical`` stages) or continue.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from reconfox.core.scanner import Phase, ScanContext, Scanner
from reconfox.core.scope import ScopePolicy
from reconfox.models import (
    HttpProbe,
    PortInfo,
    ScanMode,
    Subdomain,
    Target,
    TlsInfo,
    Vulnerability,
    WebFinding,
)


# Structural tool interfaces — real tools and test fakes both satisfy these.
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


class HttpProberProtocol(Protocol):
    async def probe(self, url: str) -> HttpProbe: ...


class NucleiProtocol(Protocol):
    async def scan(self, urls: list[str]) -> list[Vulnerability]: ...


class SubdomainFinderProtocol(Protocol):
    async def find(self, domain: str) -> list[Subdomain]: ...


class TlsProberProtocol(Protocol):
    async def probe(self, host: str, port: int = 443) -> TlsInfo: ...


def _now() -> datetime:
    return datetime.now(UTC)


class SubdomainStage:
    """Enumerate subdomains of the target (passive crt.sh + active DNS brute).

    Runs in the first wave (no deps); skipped for bare-IP targets. Opt-in via a
    finder being supplied.
    """

    name = "subdomains"
    phase: Phase = "subdomains"
    depends_on: tuple[str, ...] = ()
    critical = False

    def __init__(self, finder: SubdomainFinderProtocol | None) -> None:
        self.finder = finder

    def applicable(self, ctx: ScanContext) -> bool:
        if self.finder is None:
            return False
        try:
            ipaddress.ip_address(ctx.target.hostname)
        except ValueError:
            return True  # a hostname → enumerable
        return False  # a bare IP → nothing to enumerate

    async def run(self, ctx: ScanContext) -> None:
        assert self.finder is not None  # noqa: S101 — guaranteed by applicable()
        domain = ctx.target.hostname
        ctx.emit("subdomains", "started", f"enumerating {domain}")
        start = _now()
        subs = await self.finder.find(domain)
        ctx.result.subdomains = subs
        for s in subs[:20]:
            ctx.emit("subdomains", "info", f"{s.name} ({s.ip or '?'}) [{s.source}]")
        if len(subs) > 20:
            ctx.emit("subdomains", "info", f"... and {len(subs) - 20} more")
        ctx.emit(
            "subdomains", "completed", f"{len(subs)} subdomain(s)", (_now() - start).total_seconds()
        )


class ResolveStage:
    """Resolve IP and (optionally) enrich the target. Fatal if it fails.

    When a ``ScopePolicy`` is supplied, the resolved IP is checked against it
    right here — an out-of-scope target raises before any active stage runs
    (this stage is ``critical``, so the whole pipeline aborts for that target).
    """

    name = "resolve"
    phase: Phase = "resolve"
    depends_on: tuple[str, ...] = ()
    critical = True

    def __init__(self, resolver: ResolverProtocol, scope: ScopePolicy | None = None) -> None:
        self.resolver = resolver
        self.scope = scope

    def applicable(self, ctx: ScanContext) -> bool:  # noqa: ARG002
        return True

    async def run(self, ctx: ScanContext) -> None:
        ctx.emit("resolve", "started", f"resolving {ctx.target.hostname}")
        start = _now()
        await self.resolver.resolve(ctx.target)
        if self.scope is not None and ctx.target.ip is not None:
            # Raises ScopeError → critical abort → nmap/ffuf/nuclei never touch it.
            self.scope.enforce(ctx.target.ip)
        t = ctx.target
        ctx.emit("resolve", "info", f"ip: {t.ip}")
        if t.asn is not None and t.asn.asn:
            asn_str = f"AS{t.asn.asn} {t.asn.asn_name or ''}".strip()
            ctx.emit("resolve", "info", f"asn: {asn_str}")
        if t.geo is not None and (t.geo.city or t.geo.country):
            loc = ", ".join(filter(None, [t.geo.city, t.geo.country]))
            ctx.emit("resolve", "info", f"location: {loc}")
        ctx.emit("resolve", "completed", None, (_now() - start).total_seconds())


class TlsStage:
    """Inspect the target's TLS endpoint (version/cipher/cert). HTTPS only."""

    name = "tls"
    phase: Phase = "tls"
    depends_on: tuple[str, ...] = ("resolve",)
    critical = False

    def __init__(self, prober: TlsProberProtocol | None) -> None:
        self.prober = prober

    def applicable(self, ctx: ScanContext) -> bool:
        return self.prober is not None and (ctx.target.is_https or ctx.target.port == 443)

    async def run(self, ctx: ScanContext) -> None:
        assert self.prober is not None  # noqa: S101 — guaranteed by applicable()
        port = ctx.target.port if ctx.target.is_https else 443
        ctx.emit("tls", "started", f"tls {ctx.target.hostname}:{port}")
        start = _now()
        info = await self.prober.probe(ctx.target.hostname, port)
        ctx.result.tls = info
        if info.error:
            ctx.emit("tls", "info", info.error)
        else:
            ctx.emit("tls", "info", f"{info.version or '?'} · {info.subject or '?'}")
        ctx.emit("tls", "completed", None, (_now() - start).total_seconds())


class NmapStage:
    """Port + service scan. Applicable only once an IP is known."""

    name = "nmap"
    phase: Phase = "nmap"
    depends_on: tuple[str, ...] = ("resolve",)
    critical = False

    def __init__(self, scanner: NmapProtocol) -> None:
        self.scanner = scanner

    def applicable(self, ctx: ScanContext) -> bool:
        return ctx.target.ip is not None

    async def run(self, ctx: ScanContext) -> None:
        ip = ctx.target.ip
        ctx.emit("nmap", "started", f"scanning {ip} (mode={ctx.mode.value})")
        start = _now()
        ports = await self.scanner.scan(ip, ctx.mode)  # type: ignore[arg-type]
        # Store only open ports: every downstream consumer (summary counts,
        # report headings, exploit lookup) treats result.ports as "open".
        open_ports = [p for p in ports if p.state == "open"]
        ctx.result.ports = open_ports
        for p in sorted(open_ports, key=lambda x: x.port):
            svc = p.service or "?"
            ver = f"{p.product or ''} {p.version or ''}".strip()
            tail = f" {ver}" if ver else ""
            ctx.emit("nmap", "info", f"{p.port}/{p.protocol} open {svc}{tail}")
        ctx.emit(
            "nmap", "completed", f"{len(open_ports)} open port(s)", (_now() - start).total_seconds()
        )


class FfufStage:
    """Web content discovery via ffuf."""

    name = "ffuf"
    phase: Phase = "ffuf"
    depends_on: tuple[str, ...] = ("resolve",)
    critical = False

    def __init__(self, scanner: FfufProtocol) -> None:
        self.scanner = scanner

    def applicable(self, ctx: ScanContext) -> bool:  # noqa: ARG002
        return True

    async def run(self, ctx: ScanContext) -> None:
        ctx.emit("ffuf", "started", f"fuzzing {ctx.target.url} with {ctx.wordlist.name}")
        start = _now()
        findings = await self.scanner.fuzz(ctx.target.url, ctx.wordlist)
        ctx.result.web_findings = findings
        for f in findings[:20]:
            ctx.emit("ffuf", "info", f"{f.status} {f.url}")
        if len(findings) > 20:
            ctx.emit("ffuf", "info", f"... and {len(findings) - 20} more")
        ctx.emit(
            "ffuf", "completed", f"{len(findings)} finding(s)", (_now() - start).total_seconds()
        )


class HttpProbeStage:
    """HTTP fingerprint of the target's web endpoints. Runs after nmap so it can
    probe discovered web ports as well as the target URL."""

    name = "http"
    phase: Phase = "http"
    depends_on: tuple[str, ...] = ("nmap",)
    critical = False

    def __init__(self, prober: HttpProberProtocol | None) -> None:
        self.prober = prober

    def applicable(self, ctx: ScanContext) -> bool:  # noqa: ARG002
        return self.prober is not None

    async def run(self, ctx: ScanContext) -> None:
        assert self.prober is not None  # noqa: S101 — guaranteed by applicable()
        urls = self._target_urls(ctx)
        ctx.emit("http", "started", f"probing {len(urls)} endpoint(s)")
        start = _now()
        probes = []
        for url in urls:
            probe = await self.prober.probe(url)
            probes.append(probe)
            status = "ERR" if probe.status is None else str(probe.status)
            tech = f" [{', '.join(probe.technologies)}]" if probe.technologies else ""
            ctx.emit("http", "info", f"{status} {url}{tech}")
        ctx.result.http_probes = probes
        live = sum(1 for p in probes if p.status is not None)
        ctx.emit(
            "http", "completed", f"{live}/{len(probes)} live", (_now() - start).total_seconds()
        )

    @staticmethod
    def _target_urls(ctx: ScanContext) -> list[str]:
        t = ctx.target
        urls = [t.url]
        seen = {t.url}
        for p in ctx.result.ports:
            svc = (p.service or "").lower()
            if p.state == "open" and svc.startswith("http"):
                scheme = "https" if ("https" in svc or "ssl" in svc or p.port == 443) else "http"
                url = f"{scheme}://{t.hostname}:{p.port}"
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
        return urls


class NucleiStage:
    """Active template-based vulnerability scan against live web URLs."""

    name = "nuclei"
    phase: Phase = "nuclei"
    depends_on: tuple[str, ...] = ("http",)
    critical = False

    def __init__(self, scanner: NucleiProtocol | None) -> None:
        self.scanner = scanner

    def applicable(self, ctx: ScanContext) -> bool:
        return self.scanner is not None and bool(self._targets(ctx))

    async def run(self, ctx: ScanContext) -> None:
        assert self.scanner is not None  # noqa: S101 — guaranteed by applicable()
        urls = self._targets(ctx)
        ctx.emit("nuclei", "started", f"scanning {len(urls)} url(s)")
        start = _now()
        vulns = await self.scanner.scan(urls)
        ctx.result.vulnerabilities.extend(vulns)
        for v in vulns[:10]:
            ctx.emit("nuclei", "info", f"[{v.severity.value}] {v.title}")
        if len(vulns) > 10:
            ctx.emit("nuclei", "info", f"... and {len(vulns) - 10} more")
        ctx.emit(
            "nuclei", "completed", f"{len(vulns)} finding(s)", (_now() - start).total_seconds()
        )

    @staticmethod
    def _targets(ctx: ScanContext) -> list[str]:
        live = [p.final_url or p.url for p in ctx.result.http_probes if p.status is not None]
        urls = live or [ctx.target.url]
        seen: set[str] = set()
        out: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out


class ExploitStage:
    """Exploit lookup for discovered services. Needs ports and a finder."""

    name = "exploits"
    phase: Phase = "exploits"
    depends_on: tuple[str, ...] = ("nmap",)
    critical = False

    def __init__(self, finder: ExploitFinderProtocol | None) -> None:
        self.finder = finder

    def applicable(self, ctx: ScanContext) -> bool:
        return self.finder is not None and bool(ctx.result.ports)

    async def run(self, ctx: ScanContext) -> None:
        assert self.finder is not None  # noqa: S101 — guaranteed by applicable()
        relevant = [p for p in ctx.result.ports if p.product]
        ctx.emit("exploits", "started", f"querying for {len(relevant)} service(s)")
        start = _now()
        vulns = await self.finder.find_for_ports(ctx.result.ports)
        # extend (not assign): nuclei may run concurrently and also add findings
        ctx.result.vulnerabilities.extend(vulns)
        for v in vulns[:10]:
            label = f"[{v.severity.value}] {v.title}"
            if v.cve:
                label += f" ({v.cve})"
            ctx.emit("exploits", "info", label)
        if len(vulns) > 10:
            ctx.emit("exploits", "info", f"... and {len(vulns) - 10} more")
        ctx.emit(
            "exploits",
            "completed",
            f"{len(vulns)} potential vuln(s)",
            (_now() - start).total_seconds(),
        )


def default_pipeline(
    resolver: ResolverProtocol,
    nmap_scanner: NmapProtocol,
    ffuf_scanner: FfufProtocol,
    exploit_finder: ExploitFinderProtocol | None = None,
    http_prober: HttpProberProtocol | None = None,
    nuclei_scanner: NucleiProtocol | None = None,
    subdomain_finder: SubdomainFinderProtocol | None = None,
    tls_prober: TlsProberProtocol | None = None,
    scope: ScopePolicy | None = None,
) -> list[Scanner]:
    """Standard pipeline: subdomains, resolve→tls, nmap‖ffuf, http, then nuclei‖exploits."""
    return [
        SubdomainStage(subdomain_finder),
        ResolveStage(resolver, scope=scope),
        TlsStage(tls_prober),
        NmapStage(nmap_scanner),
        FfufStage(ffuf_scanner),
        HttpProbeStage(http_prober),
        NucleiStage(nuclei_scanner),
        ExploitStage(exploit_finder),
    ]
