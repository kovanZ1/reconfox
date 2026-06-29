"""reconfox command-line interface."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import sys
import tomllib
from pathlib import Path

import click
from rich.console import Console

from reconfox import __version__
from reconfox.core.diffing import compute_diff
from reconfox.core.exploit_finder import ExploitFinder
from reconfox.core.ffuf_scanner import FfufScanner
from reconfox.core.http_prober import HttpProber
from reconfox.core.metasploit_finder import MetasploitFinder
from reconfox.core.nmap_scanner import NmapScanner
from reconfox.core.nuclei_scanner import NucleiScanner
from reconfox.core.orchestrator import Orchestrator, ProgressEvent, default_pipeline
from reconfox.core.resolver import Resolver
from reconfox.core.subdomain_finder import SubdomainFinder
from reconfox.core.tls_prober import TlsProber
from reconfox.models import ScanMode, ScanResult, ScanStatus, Severity
from reconfox.reporting import (
    ReportFormat,
    render,
    render_diff_markdown,
    render_ndjson,
    write_report,
    write_report_to_file,
)

DEFAULT_WORDLIST = Path("/usr/share/wordlists/dirb/common.txt")
DEFAULT_OUTPUT = Path("./reports")
console = Console()
# When report data goes to stdout, all human/progress output must go to stderr
# so stdout stays pipe-clean.
err_console = Console(stderr=True)


def build_orchestrator(
    wordlist: Path,
    nmap_binary: str,
    ffuf_binary: str,
    use_metasploit: bool = False,
    on_progress: object | None = None,
    enrich: bool = False,
    proxy: str | None = None,
    timeout: float | None = None,
    use_nuclei: bool = False,
    nuclei_binary: str = "nuclei",
    threads: int = 40,
    rate: int | None = None,
    nmap_min_rate: int | None = None,
    nmap_max_rate: int | None = None,
    scan_delay: str | None = None,
    use_subdomains: bool = False,
) -> Orchestrator:
    """Wire real scanners together. Tests monkeypatch this with a fake factory."""
    finder: ExploitFinder | MetasploitFinder = (
        MetasploitFinder() if use_metasploit else ExploitFinder(timeout=timeout)
    )
    nuclei = NucleiScanner(binary=nuclei_binary, timeout=timeout) if use_nuclei else None
    subdomains = SubdomainFinder(proxy=proxy) if use_subdomains else None
    stages = default_pipeline(
        resolver=Resolver(enrich=enrich, proxy=proxy),
        nmap_scanner=NmapScanner(
            binary=nmap_binary,
            timeout=timeout,
            min_rate=nmap_min_rate,
            max_rate=nmap_max_rate,
            scan_delay=scan_delay,
        ),
        ffuf_scanner=FfufScanner(binary=ffuf_binary, timeout=timeout, threads=threads, rate=rate),
        exploit_finder=finder,
        http_prober=HttpProber(proxy=proxy),
        nuclei_scanner=nuclei,
        subdomain_finder=subdomains,
        tls_prober=TlsProber(),
    )
    return Orchestrator(
        stages,
        wordlist=wordlist,
        on_progress=on_progress,  # type: ignore[arg-type]
    )


def _load_config(config_path: Path | None) -> dict:
    """Load config.toml as a click default_map ({command: {param: value}}).

    Explicit --config wins; otherwise the XDG default path is tried (optional).
    """
    if config_path is None:
        xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        config_path = Path(xdg) / "reconfox" / "config.toml"
        if not config_path.exists():
            return {}
    try:
        return tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


@click.group(
    invoke_without_command=True,
    context_settings={"auto_envvar_prefix": "RECONFOX"},
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Путь к config.toml (по умолчанию ~/.config/reconfox/config.toml).",
)
@click.version_option(version=__version__, prog_name="reconfox")
@click.pass_context
def main(ctx: click.Context, config_path: Path | None) -> None:
    """reconfox — recon toolkit for authorized security testing.

    Настройки читаются из config.toml ([scan]/[diff] таблицы) и переменных
    RECONFOX_* ; приоритет: флаг CLI > env > config > дефолт.
    """
    config = _load_config(config_path)
    if config:
        ctx.default_map = config
    if ctx.invoked_subcommand is None:
        from reconfox.tui import run_tui

        def factory(
            wordlist: Path,
            use_metasploit: bool,
            on_progress: object | None = None,
        ) -> Orchestrator:
            return build_orchestrator(
                wordlist=wordlist,
                nmap_binary="nmap",
                ffuf_binary="ffuf",
                use_metasploit=use_metasploit,
                on_progress=on_progress,
            )

        run_tui(orchestrator_factory=factory)


@main.command(name="diff")
@click.argument("old_file", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.argument("new_file", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "-f", "--format", "fmt",
    type=click.Choice(["md", "json"], case_sensitive=False),
    default="md", show_default=True, help="Формат diff-отчёта.",
)
@click.option(
    "-O", "--output-file", type=click.Path(path_type=Path), default=None,
    help="Записать diff в файл (иначе — в stdout).",
)
@click.option(
    "--fail-on-change", is_flag=True,
    help="Выйти с кодом 3, если есть изменения (для мониторинга в CI/cron).",
)
def diff(
    old_file: Path, new_file: Path, fmt: str, output_file: Path | None, fail_on_change: bool
) -> None:
    """Сравнить два JSON-отчёта reconfox (что появилось/исчезло между сканами)."""
    try:
        old = ScanResult.model_validate_json(old_file.read_text(encoding="utf-8"))
        new = ScanResult.model_validate_json(new_file.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        console.print(f"[red][-][/red] не удалось прочитать отчёты: {exc}")
        sys.exit(2)

    result = compute_diff(old, new)
    if fmt.lower() == "json":
        text = result.model_dump_json(indent=2)
    else:
        text = render_diff_markdown(result)
    if output_file is not None:
        output_file.write_text(text, encoding="utf-8")
        console.print(f"[green][+][/green] diff → {output_file}")
    else:
        click.echo(text)

    if fail_on_change and result.has_changes:
        sys.exit(3)


@main.command()
@click.argument("urls", nargs=-1)
@click.option(
    "-iL",
    "--target-file",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    default=None,
    help="Файл со списком целей (по одной в строке). Можно вместе с аргументами.",
)
@click.option(
    "-m",
    "--mode",
    type=click.Choice([m.value for m in ScanMode], case_sensitive=False),
    default=ScanMode.QUICK.value,
    show_default=True,
    help="Профиль сканирования.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=DEFAULT_OUTPUT,
    show_default=True,
    help="Папка для отчёта (если не указан --output-file).",
)
@click.option(
    "-O",
    "--output-file",
    type=click.Path(path_type=Path),
    default=None,
    help="Полный путь к файлу отчёта. Формат определяется по расширению "
    "(.md / .html / .json). Имеет приоритет над --output и --format.",
)
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(["md", "html", "json", "sarif", "all"], case_sensitive=False),
    default="md",
    show_default=True,
    help="Формат(ы) отчёта.",
)
@click.option(
    "--wordlist",
    type=click.Path(path_type=Path),
    default=DEFAULT_WORDLIST,
    show_default=True,
    help="Wordlist для ffuf.",
)
@click.option("--nmap-binary", default="nmap", show_default=True, help="Путь к nmap.")
@click.option("--ffuf-binary", default="ffuf", show_default=True, help="Путь к ffuf.")
@click.option("--threads", type=int, default=40, show_default=True, help="Потоки ffuf (-t).")
@click.option(
    "--rate", type=int, default=None,
    help="Лимит запросов/сек для ffuf (-rate). 0/не задано — без лимита.",
)
@click.option("--nmap-min-rate", type=int, default=None, help="nmap --min-rate (пакетов/сек).")
@click.option("--nmap-max-rate", type=int, default=None, help="nmap --max-rate (пакетов/сек).")
@click.option(
    "--scan-delay", default=None,
    help="nmap --scan-delay между пробами (напр. 500ms, 1s) — для скрытности.",
)
@click.option(
    "--metasploit",
    is_flag=True,
    help="Использовать Metasploit RPC (msfrpcd) вместо searchsploit.",
)
@click.option(
    "--subdomains",
    is_flag=True,
    help="Искать поддомены (crt.sh + DNS-brute). Обращается к третьей стороне "
    "(crt.sh) и шумит DNS — поэтому opt-in.",
)
@click.option(
    "--scan-subdomains",
    is_flag=True,
    help="Найти поддомены И прогнать по каждому весь конвейер (включает --subdomains). "
    "Итог — отчёт по основной цели + по каждому поддомену.",
)
@click.option(
    "--nuclei",
    is_flag=True,
    help="Активное сканирование уязвимостей через nuclei (по живым URL). "
    "Интрузивно — только с разрешения владельца цели.",
)
@click.option("--nuclei-binary", default="nuclei", show_default=True, help="Путь к nuclei.")
@click.option(
    "--enrich",
    is_flag=True,
    help="Обогащать гео/ASN через ip-api.com. По умолчанию ВЫКЛ (OPSEC: "
    "иначе IP цели уходит третьей стороне открытым текстом).",
)
@click.option(
    "--proxy",
    default=None,
    help="Проксировать исходящий HTTP (обогащение ip-api) через URL прокси.",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=None,
    help="Таймаут на один сканер, секунды. По умолчанию зависит от режима.",
)
@click.option(
    "--ndjson",
    is_flag=True,
    help="Стримить находки в stdout как NDJSON (одна JSON-строка на запись); "
    "человекочитаемый вывод уходит в stderr. Файлы не пишутся.",
)
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default=None,
    help="Выйти с кодом 3, если есть уязвимость этой важности или выше (для CI).",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Подробный вывод (каждый шаг).",
)
@click.option("--no-tui", is_flag=True, help="Headless режим (без TUI).")
def scan(
    urls: tuple[str, ...],
    target_file: Path | None,
    mode: str,
    output: Path,
    output_file: Path | None,
    fmt: str,
    wordlist: Path,
    nmap_binary: str,
    ffuf_binary: str,
    threads: int,
    rate: int | None,
    nmap_min_rate: int | None,
    nmap_max_rate: int | None,
    scan_delay: str | None,
    metasploit: bool,
    subdomains: bool,
    scan_subdomains: bool,
    nuclei: bool,
    nuclei_binary: str,
    enrich: bool,
    proxy: str | None,
    timeout: float | None,
    ndjson: bool,
    fail_on: str | None,
    verbose: bool,
    no_tui: bool,  # noqa: ARG001 — CLI flag for symmetry with TUI mode
) -> None:
    """Разведка одной или нескольких целей.

    Цели — аргументы, файл (-iL), stdin ('-') и/или CIDR (10.0.0.0/24).
    """
    # stdout is reserved for report data when piping; route human output to stderr.
    to_stdout = ndjson or (output_file is not None and str(output_file) == "-")
    out = err_console if to_stdout else console

    try:
        targets = _collect_targets(urls, target_file)
    except ValueError as exc:
        out.print(f"[red][-][/red] {exc}")
        sys.exit(2)
    if not targets:
        out.print("[red][-][/red] не задано ни одной цели")
        sys.exit(2)

    scan_mode = ScanMode(mode.lower())
    progress_cb = _make_progress(verbose, out)
    orch = build_orchestrator(
        wordlist=wordlist,
        nmap_binary=nmap_binary,
        ffuf_binary=ffuf_binary,
        use_metasploit=metasploit,
        on_progress=progress_cb,
        enrich=enrich,
        proxy=proxy,
        timeout=timeout,
        use_nuclei=nuclei,
        nuclei_binary=nuclei_binary,
        threads=threads,
        rate=rate,
        nmap_min_rate=nmap_min_rate,
        nmap_max_rate=nmap_max_rate,
        scan_delay=scan_delay,
        use_subdomains=subdomains or scan_subdomains,
    )

    fail_threshold = Severity(fail_on.lower()) if fail_on else None

    if scan_subdomains:
        _check_multi_output(output_file, to_stdout, ndjson, out)
        out.print(
            f"[bold green]reconfox[/bold green] [grey50]targets=[/grey50]{len(targets)}+subdomains "
            f"[grey50]mode=[/grey50][bold yellow]{scan_mode.value}[/bold yellow]"
        )
        results = asyncio.run(_expand_all(orch, targets, scan_mode))
        _output_multi_results(results, output, fmt, to_stdout, out, fail_threshold)
    elif len(targets) == 1:
        _scan_single(
            orch, targets[0], scan_mode, output, output_file, fmt, ndjson, to_stdout, out,
            fail_threshold,
        )
    else:
        _scan_multi(
            orch, targets, scan_mode, output, output_file, fmt, ndjson, to_stdout, out,
            fail_threshold,
        )


async def _expand_all(
    orch: Orchestrator, targets: list[str], mode: ScanMode
) -> list[ScanResult]:
    results: list[ScanResult] = []
    for target in targets:
        results.extend(await orch.run_with_subdomain_expansion(target, mode))
    return results


def _scan_single(  # noqa: PLR0913 — CLI plumbing
    orch: Orchestrator,
    url: str,
    scan_mode: ScanMode,
    output: Path,
    output_file: Path | None,
    fmt: str,
    ndjson: bool,
    to_stdout: bool,
    out: Console,
    fail_threshold: Severity | None,
) -> None:
    _banner(url, scan_mode, out)
    result: ScanResult = asyncio.run(orch.run(url, scan_mode))

    if to_stdout:
        _emit_stdout(result, fmt, ndjson)
    elif output_file is not None:
        try:
            path, used_fmt = write_report_to_file(result, output_file)
            out.print(f"[green][+][/green] Saved [cyan]{used_fmt.value}[/cyan]: {path}")
        except (ValueError, OSError) as exc:
            out.print(f"[red][-][/red] Failed to write {output_file}: {exc}")
            sys.exit(2)
    else:
        output.mkdir(parents=True, exist_ok=True)
        for f in _resolve_formats(fmt):
            path = write_report(result, output, f)
            out.print(f"[green][+][/green] Saved [cyan]{f.value}[/cyan]: {path}")

    _print_summary(result, out)
    _exit_code([result], fail_threshold, out)


def _scan_multi(  # noqa: PLR0913 — CLI plumbing
    orch: Orchestrator,
    targets: list[str],
    scan_mode: ScanMode,
    output: Path,
    output_file: Path | None,
    fmt: str,
    ndjson: bool,
    to_stdout: bool,
    out: Console,
    fail_threshold: Severity | None,
) -> None:
    _check_multi_output(output_file, to_stdout, ndjson, out)
    out.print(f"[bold green]reconfox[/bold green] [grey50]targets=[/grey50]{len(targets)} "
              f"[grey50]mode=[/grey50][bold yellow]{scan_mode.value}[/bold yellow]")
    results: list[ScanResult] = asyncio.run(orch.run_many(targets, scan_mode))
    _output_multi_results(results, output, fmt, to_stdout, out, fail_threshold)


def _check_multi_output(
    output_file: Path | None, to_stdout: bool, ndjson: bool, out: Console
) -> None:
    if output_file is not None and not to_stdout:
        out.print("[red][-][/red] -O поддерживает только одну цель; используй -o (папка)")
        sys.exit(2)
    if to_stdout and not ndjson:
        out.print("[red][-][/red] -O - только для одной цели; для нескольких используй --ndjson")
        sys.exit(2)


def _output_multi_results(
    results: list[ScanResult],
    output: Path,
    fmt: str,
    to_stdout: bool,
    out: Console,
    fail_threshold: Severity | None,
) -> None:
    if to_stdout:  # ndjson stream of every result
        for result in results:
            click.echo(render_ndjson(result), nl=False)
    else:
        output.mkdir(parents=True, exist_ok=True)
        formats = _resolve_formats(fmt)
        for result in results:
            for f in formats:
                path = write_report(result, output, f)
                out.print(
                    f"[green][+][/green] [cyan]{result.target.hostname}[/cyan] {f.value}: {path}"
                )

    _print_multi_summary(results, out)
    _exit_code(results, fail_threshold, out)


def _exit_code(results: list[ScanResult], fail_threshold: Severity | None, out: Console) -> None:
    """CI-aware exit: 3 when findings meet --fail-on, 1 when every scan failed."""
    if fail_threshold is not None:
        worst = [r.highest_severity for r in results if r.highest_severity is not None]
        if any(s.score >= fail_threshold.score for s in worst):
            out.print(f"[red][-][/red] fail-on: найдена уязвимость ≥ {fail_threshold.value}")
            sys.exit(3)
    if results and all(r.status == ScanStatus.FAILED for r in results):
        sys.exit(1)


def _emit_stdout(result: ScanResult, fmt: str, ndjson: bool) -> None:
    if ndjson:
        click.echo(render_ndjson(result), nl=False)
    else:
        single = ReportFormat.JSON if fmt.lower() == "all" else ReportFormat(fmt.lower())
        click.echo(render(result, single))


def _collect_targets(urls: tuple[str, ...], target_file: Path | None) -> list[str]:
    """Gather targets from args, '-' (stdin), a file, expanding CIDRs; dedup."""
    raw: list[str] = []
    for item in urls:
        if item == "-":
            raw.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            raw.append(item)
    if target_file is not None:
        raw.extend(
            line.strip()
            for line in target_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    seen: set[str] = set()
    out: list[str] = []
    for entry in raw:
        for target in _expand_target(entry):
            if target not in seen:
                seen.add(target)
                out.append(target)
    return out


_MAX_CIDR_HOSTS = 4096


def _expand_target(entry: str) -> list[str]:
    """Expand a CIDR into host IPs; pass anything else through unchanged."""
    if "/" not in entry or entry.startswith(("http://", "https://")):
        return [entry]
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return [entry]  # not a CIDR (e.g. host/path) — treat as a single target
    if network.num_addresses > _MAX_CIDR_HOSTS:
        raise ValueError(f"CIDR {entry} слишком большой (>{_MAX_CIDR_HOSTS} адресов)")
    hosts = [str(h) for h in network.hosts()]
    return hosts or [str(network.network_address)]


def _resolve_formats(raw: str) -> list[ReportFormat]:
    raw = raw.lower()
    if raw == "all":
        return [ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON]
    return [ReportFormat(raw)]


def _make_progress(verbose: bool, out: Console):  # type: ignore[no-untyped-def]
    def callback(event: ProgressEvent) -> None:
        # Default mode skips info-level sub-events; verbose mode shows them all.
        if not verbose and event.status == "info":
            return
        _render(event, out)

    return callback


def _banner(url: str, mode: ScanMode, out: Console) -> None:
    out.print()
    out.print(
        f"[bold green]reconfox[/bold green] "
        f"[grey50]mode=[/grey50][bold yellow]{mode.value}[/bold yellow] "
        f"[grey50]target=[/grey50][bold cyan]{url}[/bold cyan]"
    )
    out.print("[grey50]" + "─" * 70 + "[/grey50]")


def _render(event: ProgressEvent, out: Console) -> None:
    marker, color = _marker_for(event.status)
    msg = event.message or ""
    timing = (
        f" [grey50]({event.duration_seconds:.1f}s)[/grey50]"
        if event.duration_seconds is not None
        else ""
    )
    if event.status == "info":
        out.print(f"      [{color}]{marker}[/{color}] [grey70]{msg}[/grey70]")
        return
    extra = f" — {msg}" if msg else ""
    out.print(
        f"  [{color}]{marker}[/{color}] [bold]{event.phase}[/bold]: {event.status}{extra}{timing}"
    )


def _marker_for(status: str) -> tuple[str, str]:
    return {
        "started": ("[*]", "yellow"),
        "info": ("→", "cyan"),
        "completed": ("[+]", "green"),
        "failed": ("[-]", "red"),
    }.get(status, ("[?]", "white"))


def _print_multi_summary(results: list[ScanResult], out: Console) -> None:
    by_status: dict[str, int] = {}
    ports = web = vulns = subs = 0
    for r in results:
        by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        ports += len(r.ports)
        web += len(r.web_findings)
        vulns += len(r.vulnerabilities)
        subs += len(r.subdomains)
    out.print("[grey50]" + "─" * 70 + "[/grey50]")
    status_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items()))
    out.print(
        f"  targets: [cyan]{len(results)}[/cyan] ({status_str})\n"
        f"  subdomains: [cyan]{subs}[/cyan]   ports: [cyan]{ports}[/cyan]   "
        f"web: [cyan]{web}[/cyan]   vulns: [cyan]{vulns}[/cyan]"
    )


def _print_summary(result: ScanResult, out: Console) -> None:
    status_color = {
        ScanStatus.COMPLETED: "green",
        ScanStatus.PARTIAL: "yellow",
        ScanStatus.FAILED: "red",
    }.get(result.status, "white")
    out.print("[grey50]" + "─" * 70 + "[/grey50]")
    out.print(
        f"  status:  [bold {status_color}]{result.status.value}[/bold {status_color}]\n"
        f"  ports:   [cyan]{len(result.ports)}[/cyan] open\n"
        f"  web:     [cyan]{len(result.web_findings)}[/cyan] findings\n"
        f"  vulns:   [cyan]{len(result.vulnerabilities)}[/cyan] potential\n"
        f"  time:    "
        + (f"{result.duration_seconds:.1f}s" if result.duration_seconds else "—")
    )
    if result.errors:
        out.print("[red]  errors:[/red]")
        for err in result.errors:
            out.print(f"    [red]•[/red] {err}")


if __name__ == "__main__":
    main()
