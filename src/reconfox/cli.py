"""reconfox command-line interface.

Two entry points:

  reconfox                     → launches TUI (Этап 9)
  reconfox scan <url> [opts]   → headless CLI mode, writes a report
"""

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
from reconfox.reporting import ReportFormat, write_report

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
    help="Scan profile.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=DEFAULT_OUTPUT,
    show_default=True,
    help="Directory to write reports into.",
)
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(["md", "html", "both"], case_sensitive=False),
    default="md",
    show_default=True,
    help="Report format(s) to emit.",
)
@click.option(
    "--wordlist",
    type=click.Path(path_type=Path),
    default=DEFAULT_WORDLIST,
    show_default=True,
    help="Wordlist for directory fuzzing.",
)
@click.option("--nmap-binary", default="nmap", show_default=True, help="Path to nmap.")
@click.option("--ffuf-binary", default="ffuf", show_default=True, help="Path to ffuf.")
@click.option(
    "--metasploit",
    is_flag=True,
    help="Use Metasploit RPC (msfrpcd) for exploit search instead of searchsploit.",
)
@click.option("--no-tui", is_flag=True, help="Headless mode (no TUI). Used by tests/CI.")
def scan(
    url: str,
    mode: str,
    output: Path,
    fmt: str,
    wordlist: Path,
    nmap_binary: str,
    ffuf_binary: str,
    metasploit: bool,
    no_tui: bool,  # noqa: ARG001 — reserved for Этап 9
) -> None:
    """Run reconnaissance against a target URL."""
    scan_mode = ScanMode(mode.lower())
    formats = _resolve_formats(fmt)

    orch = build_orchestrator(
        wordlist=wordlist,
        nmap_binary=nmap_binary,
        ffuf_binary=ffuf_binary,
        use_metasploit=metasploit,
        on_progress=_print_progress,
    )

    console.print(f"[bold]reconfox[/bold] {scan_mode.value} → [cyan]{url}[/cyan]")
    result: ScanResult = asyncio.run(orch.run(url, scan_mode))

    output.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for f in formats:
        path = write_report(result, output, f)
        written.append(path)

    _print_summary(result, written)
    if result.status == ScanStatus.FAILED:
        sys.exit(1)


def _resolve_formats(raw: str) -> list[ReportFormat]:
    raw = raw.lower()
    if raw == "both":
        return [ReportFormat.HTML, ReportFormat.MARKDOWN]
    if raw == "html":
        return [ReportFormat.HTML]
    return [ReportFormat.MARKDOWN]


def _print_progress(event: ProgressEvent) -> None:
    color: dict[str, str] = {"started": "yellow", "completed": "green", "failed": "red"}[
        event.status
    ]  # type: ignore[assignment]
    msg = event.message or ""
    extra = f" — {msg}" if msg else ""
    console.print(f"  [{color}]{event.phase}: {event.status}[/{color}]{extra}")


def _print_summary(result: ScanResult, files: list[Path]) -> None:
    status_color = {
        ScanStatus.COMPLETED: "green",
        ScanStatus.PARTIAL: "yellow",
        ScanStatus.FAILED: "red",
    }.get(result.status, "white")
    console.print()
    console.print(
        f"Status: [bold {status_color}]{result.status.value}[/bold {status_color}]  "
        f"Ports: {len(result.ports)}  "
        f"Web: {len(result.web_findings)}  "
        f"Vulns: {len(result.vulnerabilities)}"
    )
    for path in files:
        console.print(f"Report: [cyan]{path}[/cyan]")
    if result.errors:
        console.print("[red]Errors:[/red]")
        for err in result.errors:
            console.print(f"  • {err}")


if __name__ == "__main__":
    main()
