"""reconfox command-line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console

from reconfox import __version__
from reconfox.core.exploit_finder import ExploitFinder
from reconfox.core.ffuf_scanner import FfufScanner
from reconfox.core.metasploit_finder import MetasploitFinder
from reconfox.core.nmap_scanner import NmapScanner
from reconfox.core.orchestrator import Orchestrator, ProgressEvent
from reconfox.core.resolver import Resolver
from reconfox.models import ScanMode, ScanResult, ScanStatus
from reconfox.reporting import ReportFormat, write_report, write_report_to_file

DEFAULT_WORDLIST = Path("/usr/share/wordlists/dirb/common.txt")
DEFAULT_OUTPUT = Path("./reports")
console = Console()


def build_orchestrator(
    wordlist: Path,
    nmap_binary: str,
    ffuf_binary: str,
    use_metasploit: bool = False,
    on_progress: object | None = None,
) -> Orchestrator:
    """Wire real scanners together. Tests monkeypatch this with a fake factory."""
    finder: ExploitFinder | MetasploitFinder = (
        MetasploitFinder() if use_metasploit else ExploitFinder()
    )
    return Orchestrator(
        resolver=Resolver(),
        nmap_scanner=NmapScanner(binary=nmap_binary),
        ffuf_scanner=FfufScanner(binary=ffuf_binary),
        exploit_finder=finder,
        wordlist=wordlist,
        on_progress=on_progress,  # type: ignore[arg-type]
    )


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="reconfox")
@click.pass_context
def main(ctx: click.Context) -> None:
    """reconfox — recon toolkit for authorized security testing."""
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


@main.command()
@click.argument("url")
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
    type=click.Choice(["md", "html", "json", "all"], case_sensitive=False),
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
@click.option(
    "--metasploit",
    is_flag=True,
    help="Использовать Metasploit RPC (msfrpcd) вместо searchsploit.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Подробный вывод (каждый шаг).",
)
@click.option("--no-tui", is_flag=True, help="Headless режим (без TUI).")
def scan(
    url: str,
    mode: str,
    output: Path,
    output_file: Path | None,
    fmt: str,
    wordlist: Path,
    nmap_binary: str,
    ffuf_binary: str,
    metasploit: bool,
    verbose: bool,
    no_tui: bool,  # noqa: ARG001 — CLI flag for symmetry with TUI mode
) -> None:
    """Запустить разведку против указанного URL."""
    scan_mode = ScanMode(mode.lower())
    progress_cb = _make_progress(verbose)

    orch = build_orchestrator(
        wordlist=wordlist,
        nmap_binary=nmap_binary,
        ffuf_binary=ffuf_binary,
        use_metasploit=metasploit,
        on_progress=progress_cb,
    )

    _banner(url, scan_mode)
    result: ScanResult = asyncio.run(orch.run(url, scan_mode))

    written: list[Path] = []
    if output_file is not None:
        try:
            path, used_fmt = write_report_to_file(result, output_file)
            written.append(path)
            console.print(f"[green][+][/green] Saved [cyan]{used_fmt.value}[/cyan]: {path}")
        except (ValueError, OSError) as exc:
            console.print(f"[red][-][/red] Failed to write {output_file}: {exc}")
            sys.exit(2)
    else:
        formats = _resolve_formats(fmt)
        output.mkdir(parents=True, exist_ok=True)
        for f in formats:
            path = write_report(result, output, f)
            written.append(path)
            console.print(f"[green][+][/green] Saved [cyan]{f.value}[/cyan]: {path}")

    _print_summary(result)
    if result.status == ScanStatus.FAILED:
        sys.exit(1)


def _resolve_formats(raw: str) -> list[ReportFormat]:
    raw = raw.lower()
    if raw == "all":
        return [ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON]
    return [ReportFormat(raw)]


def _make_progress(verbose: bool):  # type: ignore[no-untyped-def]
    if verbose:
        return _print_progress_verbose
    return _print_progress


def _banner(url: str, mode: ScanMode) -> None:
    console.print()
    console.print(
        f"[bold green]reconfox[/bold green] "
        f"[grey50]mode=[/grey50][bold yellow]{mode.value}[/bold yellow] "
        f"[grey50]target=[/grey50][bold cyan]{url}[/bold cyan]"
    )
    console.print("[grey50]" + "─" * 70 + "[/grey50]")


def _print_progress(event: ProgressEvent) -> None:
    # Default mode skips info-level sub-events; verbose mode shows them all.
    if event.status == "info":
        return
    _render(event)


def _print_progress_verbose(event: ProgressEvent) -> None:
    _render(event)


def _render(event: ProgressEvent) -> None:
    marker, color = _marker_for(event.status)
    msg = event.message or ""
    timing = (
        f" [grey50]({event.duration_seconds:.1f}s)[/grey50]"
        if event.duration_seconds is not None
        else ""
    )
    if event.status == "info":
        console.print(f"      [{color}]{marker}[/{color}] [grey70]{msg}[/grey70]")
        return
    extra = f" — {msg}" if msg else ""
    console.print(
        f"  [{color}]{marker}[/{color}] [bold]{event.phase}[/bold]: {event.status}{extra}{timing}"
    )


def _marker_for(status: str) -> tuple[str, str]:
    return {
        "started": ("[*]", "yellow"),
        "info": ("→", "cyan"),
        "completed": ("[+]", "green"),
        "failed": ("[-]", "red"),
    }.get(status, ("[?]", "white"))


def _print_summary(result: ScanResult) -> None:
    status_color = {
        ScanStatus.COMPLETED: "green",
        ScanStatus.PARTIAL: "yellow",
        ScanStatus.FAILED: "red",
    }.get(result.status, "white")
    console.print("[grey50]" + "─" * 70 + "[/grey50]")
    console.print(
        f"  status:  [bold {status_color}]{result.status.value}[/bold {status_color}]\n"
        f"  ports:   [cyan]{len(result.ports)}[/cyan] open\n"
        f"  web:     [cyan]{len(result.web_findings)}[/cyan] findings\n"
        f"  vulns:   [cyan]{len(result.vulnerabilities)}[/cyan] potential\n"
        f"  time:    "
        + (f"{result.duration_seconds:.1f}s" if result.duration_seconds else "—")
    )
    if result.errors:
        console.print("[red]  errors:[/red]")
        for err in result.errors:
            console.print(f"    [red]•[/red] {err}")


if __name__ == "__main__":
    main()
