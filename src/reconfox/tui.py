"""Textual TUI front-end for reconfox.

One-screen app: enter URL → pick mode/options → start → watch live progress.
Result is written to disk and surfaced on screen.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    RadioButton,
    RadioSet,
    Static,
)

from reconfox.core.orchestrator import Orchestrator, ProgressEvent
from reconfox.models import ScanMode, ScanResult, ScanStatus
from reconfox.reporting import ReportFormat, write_report

if TYPE_CHECKING:
    from textual.worker import Worker


DEFAULT_WORDLIST = Path("/usr/share/wordlists/dirb/common.txt")


class ReconFoxApp(App[None]):
    """Single-screen reconfox TUI."""

    CSS = """
    Screen { background: $surface; }
    #target-row { height: 3; margin: 1 2 0 2; }
    #target-row Label { width: 12; padding: 1 1 0 0; }
    #target-row Input { width: 1fr; }
    #options { padding: 1 2; height: auto; }
    #options Label.section { color: $accent; text-style: bold; padding: 1 0 0 0; }
    #buttons { padding: 0 2; height: 3; }
    Button { margin: 0 1; }
    #log { border: solid $accent; height: 1fr; margin: 0 2; }
    #results { border: solid $accent; height: 12; margin: 1 2 0 2; }
    #status-bar { padding: 0 2; height: 1; color: $text-muted; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "start_scan", "Run"),
    ]

    target_url: reactive[str] = reactive("")
    mode: reactive[ScanMode] = reactive(ScanMode.QUICK)
    use_metasploit: reactive[bool] = reactive(False)
    output_dir: reactive[str] = reactive("./reports")

    def __init__(
        self,
        orchestrator_factory,  # type: ignore[no-untyped-def]
        wordlist: Path = DEFAULT_WORDLIST,
        formats: list[ReportFormat] | None = None,
    ) -> None:
        super().__init__()
        self._orchestrator_factory = orchestrator_factory
        self._wordlist = wordlist
        self._formats = formats or [ReportFormat.MARKDOWN, ReportFormat.HTML]
        self._scan_worker: Worker[None] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="target-row"):
            yield Label("URL цели:")
            yield Input(placeholder="https://example.com", id="url-input")
        with Vertical(id="options"):
            yield Label("Режим сканирования", classes="section")
            with RadioSet(id="mode-set"):
                yield RadioButton("Quick — топ-100 портов", value=True, id="mode-quick")
                yield RadioButton("Full — все 65535 портов", id="mode-full")
                yield RadioButton("Stealth — медленный SYN", id="mode-stealth")
            yield Label("Дополнительно", classes="section")
            yield Checkbox("Metasploit RPC (msfrpcd)", id="msf-checkbox")
            yield Label("Папка отчёта", classes="section")
            yield Input(value="./reports", id="output-input")
        with Horizontal(id="buttons"):
            yield Button("▶ Запустить (R)", id="start-btn", variant="primary")
            yield Button("⏹ Стоп", id="stop-btn", variant="warning", disabled=True)
            yield Button("Выход (Q)", id="quit-btn", variant="error")
        yield Log(id="log", highlight=True)
        yield DataTable(id="results")
        yield Static("Готов к запуску.", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "reconfox"
        self.sub_title = "Authorized reconnaissance toolkit"
        table = self.query_one("#results", DataTable)
        table.add_columns("Port", "Service", "Product", "Version")

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        idx = event.radio_set.pressed_index
        self.mode = [ScanMode.QUICK, ScanMode.FULL, ScanMode.STEALTH][idx]

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "msf-checkbox":
            self.use_metasploit = event.value

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "url-input":
            self.target_url = event.value
        elif event.input.id == "output-input":
            self.output_dir = event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start-btn":
            self.action_start_scan()
        elif event.button.id == "stop-btn":
            self._cancel_scan()
        elif event.button.id == "quit-btn":
            self.exit()

    def action_start_scan(self) -> None:
        if not self.target_url.strip():
            self._set_status("[red]Введите URL цели сначала.[/red]")
            return
        if self._scan_worker is not None and not self._scan_worker.is_finished:
            return

        log = self.query_one("#log", Log)
        log.clear()
        self.query_one("#start-btn", Button).disabled = True
        self.query_one("#stop-btn", Button).disabled = False
        self._set_status(f"[yellow]Сканирование {self.target_url}…[/yellow]")
        self._scan_worker = self.run_worker(self._run_scan(), exclusive=True)

    def _cancel_scan(self) -> None:
        if self._scan_worker and not self._scan_worker.is_finished:
            self._scan_worker.cancel()
            self._set_status("[yellow]Сканирование отменено.[/yellow]")
            self.query_one("#start-btn", Button).disabled = False
            self.query_one("#stop-btn", Button).disabled = True

    async def _run_scan(self) -> None:
        orch: Orchestrator = self._orchestrator_factory(
            wordlist=self._wordlist,
            use_metasploit=self.use_metasploit,
            on_progress=self._on_progress,
        )
        try:
            result = await orch.run(self.target_url, self.mode)
        except Exception as exc:  # noqa: BLE001 — surface every error to the UI
            self._log_line(f"[red]Ошибка: {exc}[/red]")
            self._set_status(f"[red]Сбой: {exc}[/red]")
            self.query_one("#start-btn", Button).disabled = False
            self.query_one("#stop-btn", Button).disabled = True
            return

        self._populate_results(result)
        self._save_reports(result)
        color = {
            ScanStatus.COMPLETED: "green",
            ScanStatus.PARTIAL: "yellow",
            ScanStatus.FAILED: "red",
        }.get(result.status, "white")
        self._set_status(
            f"[{color}]Статус: {result.status.value}[/{color}]  "
            f"Ports: {len(result.ports)}  "
            f"Web: {len(result.web_findings)}  "
            f"Vulns: {len(result.vulnerabilities)}"
        )
        self.query_one("#start-btn", Button).disabled = False
        self.query_one("#stop-btn", Button).disabled = True

    def _on_progress(self, event: ProgressEvent) -> None:
        color = {"started": "yellow", "completed": "green", "failed": "red"}[event.status]
        extra = f" — {event.message}" if event.message else ""
        # Log is thread-safe — Textual handles dispatch.
        line = f"[{color}]{event.phase}: {event.status}[/{color}]{extra}"
        self.call_from_thread(self._log_line, line)

    def _log_line(self, line: str) -> None:
        log = self.query_one("#log", Log)
        log.write_line(line)

    def _set_status(self, message: str) -> None:
        self.query_one("#status-bar", Static).update(message)

    def _populate_results(self, result: ScanResult) -> None:
        table = self.query_one("#results", DataTable)
        table.clear()
        for p in sorted(result.ports, key=lambda x: x.port):
            table.add_row(
                str(p.port),
                p.service or "—",
                p.product or "—",
                p.version or "—",
            )

    def _save_reports(self, result: ScanResult) -> None:
        out = Path(self.output_dir)
        for fmt in self._formats:
            try:
                path = write_report(result, out, fmt)
                self._log_line(f"[cyan]→ {path}[/cyan]")
            except OSError as exc:
                self._log_line(f"[red]write {fmt.value}: {exc}[/red]")


def run_tui(orchestrator_factory, wordlist: Path = DEFAULT_WORDLIST) -> None:  # type: ignore[no-untyped-def]
    """Entry-point called from cli.py — runs the Textual app."""
    app = ReconFoxApp(orchestrator_factory=orchestrator_factory, wordlist=wordlist)
    app.run()
