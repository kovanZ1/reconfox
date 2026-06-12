"""reconfox Textual TUI — hacker-style single screen.

Layout (top → bottom):
  ╭─ banner (ASCII logo)
  ├─ target row: URL + mode + msf + output file + format
  ├─ phase panel: progress bars for resolve / nmap / ffuf / exploits
  ├─ live log: every step with [+]/[*]/[-] prefix
  ├─ findings table: ports + services
  ╰─ status bar
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Input,
    Label,
    Log,
    ProgressBar,
    RadioButton,
    RadioSet,
    Static,
)

from reconfox.core.orchestrator import Orchestrator, ProgressEvent
from reconfox.models import ScanMode, ScanResult, ScanStatus
from reconfox.reporting import (
    ReportFormat,
    default_filename,
    write_report,
    write_report_to_file,
)

if TYPE_CHECKING:
    from textual.worker import Worker


DEFAULT_WORDLIST = Path("/usr/share/wordlists/dirb/common.txt")

BANNER = r"""[bold #00ff5f]
   ┳┓┏┓┏┓┏┓┳┓┏┓┏┓┓┏
   ┣┫┣ ┃ ┃┃┃┃┣ ┃┃┏┛
   ┛┗┗┛┗┛┗┛┛┗┻ ┗┛┛┗[/bold #00ff5f]  [#ffb000]v0.2 // recon toolkit[/#ffb000]
[#5a5a5a]   authorized testing only — see README[/#5a5a5a]"""


class ReconFoxApp(App[None]):
    """Hacker-style one-screen reconfox TUI."""

    CSS = """
    Screen {
        background: #0b0d0e;
    }
    #banner {
        height: 5;
        padding: 1 2 0 2;
    }
    #target-row {
        height: 3;
        margin: 0 2;
    }
    #target-row Label {
        width: 8;
        color: #00ff5f;
        padding: 1 0 0 0;
    }
    #target-row Input {
        width: 1fr;
        background: #14181a;
        color: #d7ffd7;
    }
    #target-row Input:focus {
        border: tall #00ff5f;
    }
    #options-row {
        height: auto;
        padding: 1 2;
    }
    #options-row .col {
        width: 1fr;
        padding: 0 1 0 0;
    }
    #options-row .col Label {
        color: #ffb000;
        text-style: bold;
        padding: 0 0 1 0;
    }
    Checkbox, RadioButton {
        color: #d7ffd7;
        background: transparent;
    }
    Checkbox > .toggle--button, RadioButton > .toggle--button {
        color: #00ff5f;
    }
    #output-row {
        height: 3;
        padding: 0 2;
    }
    #output-row Label {
        width: 12;
        color: #00ff5f;
        padding: 1 0 0 0;
    }
    #output-row Input {
        width: 1fr;
        background: #14181a;
        color: #d7ffd7;
    }
    #buttons {
        height: 3;
        padding: 0 2;
    }
    Button {
        margin: 0 1;
        background: #14181a;
        color: #00ff5f;
        border: tall #1a1f22;
    }
    Button.-primary {
        background: #00ff5f 20%;
        color: #00ff5f;
        border: tall #00ff5f;
    }
    Button.-warning {
        color: #ffb000;
        border: tall #ffb000;
    }
    Button.-error {
        color: #ff4040;
        border: tall #ff4040;
    }
    #phases {
        height: auto;
        padding: 0 2;
    }
    .phase-row {
        height: 1;
    }
    .phase-label {
        width: 14;
        color: #d7ffd7;
    }
    .phase-label.-running { color: #ffb000; }
    .phase-label.-done    { color: #00ff5f; }
    .phase-label.-fail    { color: #ff4040; }
    .phase-bar {
        width: 1fr;
    }
    #log {
        border: round #1f3a23;
        background: #07090a;
        color: #c5e8c5;
        height: 1fr;
        margin: 1 2 0 2;
    }
    #findings {
        border: round #1f3a23;
        background: #07090a;
        height: 10;
        margin: 0 2;
    }
    #findings > .datatable--header {
        background: #14181a;
        color: #00ff5f;
    }
    #status-bar {
        padding: 0 2;
        height: 1;
        color: #5a5a5a;
    }
    """

    BINDINGS = [
        Binding("ctrl+r", "start_scan", "Run scan"),
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+l", "clear_log", "Clear log"),
    ]

    # Reactive state
    target_url: reactive[str] = reactive("")
    mode: reactive[ScanMode] = reactive(ScanMode.QUICK)
    use_metasploit: reactive[bool] = reactive(False)
    output_path: reactive[str] = reactive("")
    fmt: reactive[ReportFormat] = reactive(ReportFormat.MARKDOWN)

    def __init__(
        self,
        orchestrator_factory: Any,
        wordlist: Path = DEFAULT_WORDLIST,
    ) -> None:
        super().__init__()
        self._factory = orchestrator_factory
        self._wordlist = wordlist
        self._scan_worker: Worker[None] | None = None
        self._phase_state: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="banner")

        with Horizontal(id="target-row"):
            yield Label("> target")
            yield Input(placeholder="https://example.com", id="url-input")

        with Horizontal(id="options-row"):
            with Vertical(classes="col"):
                yield Label("[ mode ]")
                with RadioSet(id="mode-set"):
                    yield RadioButton("quick", value=True, id="m-q")
                    yield RadioButton("full", id="m-f")
                    yield RadioButton("stealth", id="m-s")
            with Vertical(classes="col"):
                yield Label("[ format ]")
                with RadioSet(id="fmt-set"):
                    yield RadioButton("markdown", value=True, id="f-md")
                    yield RadioButton("html", id="f-html")
                    yield RadioButton("json", id="f-json")
            with Vertical(classes="col"):
                yield Label("[ extras ]")
                yield Checkbox("metasploit rpc", id="msf-checkbox")

        with Horizontal(id="output-row"):
            yield Label("> output")
            yield Input(
                placeholder="./reports/report.md (leave blank → auto-name)",
                id="output-input",
            )

        with Horizontal(id="buttons"):
            yield Button("▶ run (^R)", id="start-btn", variant="primary")
            yield Button("⏹ abort", id="stop-btn", variant="warning", disabled=True)
            yield Button("clear log (^L)", id="clear-btn")
            yield Button("quit (^C)", id="quit-btn", variant="error")

        with Vertical(id="phases"):
            for phase in ("resolve", "nmap", "ffuf", "exploits"):
                with Horizontal(classes="phase-row"):
                    yield Label(f"  {phase:8s} ", classes="phase-label", id=f"lbl-{phase}")
                    yield ProgressBar(
                        total=100, show_eta=False, show_percentage=False,
                        classes="phase-bar", id=f"bar-{phase}",
                    )

        yield Log(id="log", highlight=True)
        yield DataTable(id="findings")
        yield Static("ready.", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "reconfox"
        self.sub_title = "authorized recon // press Ctrl-R to launch"
        table = self.query_one("#findings", DataTable)
        table.add_columns("port", "proto", "service", "product", "version")

    # --- input handlers --------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "url-input":
            self.target_url = event.value
        elif event.input.id == "output-input":
            self.output_path = event.value

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "mode-set":
            self.mode = [ScanMode.QUICK, ScanMode.FULL, ScanMode.STEALTH][
                event.radio_set.pressed_index
            ]
        elif event.radio_set.id == "fmt-set":
            self.fmt = [
                ReportFormat.MARKDOWN, ReportFormat.HTML, ReportFormat.JSON
            ][event.radio_set.pressed_index]

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "msf-checkbox":
            self.use_metasploit = event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "start-btn":
            self.action_start_scan()
        elif bid == "stop-btn":
            self._cancel_scan()
        elif bid == "clear-btn":
            self.action_clear_log()
        elif bid == "quit-btn":
            self.exit()

    # --- actions ---------------------------------------------------------

    def action_clear_log(self) -> None:
        self.query_one("#log", Log).clear()

    def action_start_scan(self) -> None:
        url = self.target_url.strip()
        if not url:
            self._set_status("[#ff4040]error: target URL is empty[/]")
            return
        if self._scan_worker is not None and not self._scan_worker.is_finished:
            return

        log = self.query_one("#log", Log)
        log.clear()
        for phase in ("resolve", "nmap", "ffuf", "exploits"):
            self._reset_phase(phase)
        self.query_one("#findings", DataTable).clear()
        self.query_one("#start-btn", Button).disabled = True
        self.query_one("#stop-btn", Button).disabled = False

        self._log("[#00ff5f][*][/] starting scan")
        self._log(f"[#5a5a5a]    target: {url}[/]")
        self._log(f"[#5a5a5a]    mode:   {self.mode.value}[/]")
        self._log(f"[#5a5a5a]    fmt:    {self.fmt.value}[/]")
        self._log(f"[#5a5a5a]    msf:    {'on' if self.use_metasploit else 'off'}[/]")

        self._set_status(
            f"[#ffb000]running...[/] target=[#00ff5f]{url}[/] mode=[#00ff5f]{self.mode.value}[/]"
        )
        self._scan_worker = self.run_worker(self._run_scan(url), exclusive=True)

    def _cancel_scan(self) -> None:
        if self._scan_worker and not self._scan_worker.is_finished:
            self._scan_worker.cancel()
            self._log("[#ff4040][-][/] scan aborted by user")
            self._set_status("[#ff4040]aborted[/]")
            self.query_one("#start-btn", Button).disabled = False
            self.query_one("#stop-btn", Button).disabled = True

    # --- the scan --------------------------------------------------------

    async def _run_scan(self, url: str) -> None:
        orch: Orchestrator = self._factory(
            wordlist=self._wordlist,
            use_metasploit=self.use_metasploit,
            on_progress=self._on_progress,
        )
        try:
            result = await orch.run(url, self.mode)
        except Exception as exc:  # noqa: BLE001
            self._log(f"[#ff4040][-][/] {exc}")
            self._set_status(f"[#ff4040]crash: {exc}[/]")
            self._reenable_run()
            return

        self._populate_findings(result)
        written = self._save_report(result)
        for path, fmt in written:
            self._log(f"[#00ff5f][+][/] report ([#ffb000]{fmt.value}[/]) → {path}")

        status_color = {
            ScanStatus.COMPLETED: "#00ff5f",
            ScanStatus.PARTIAL: "#ffb000",
            ScanStatus.FAILED: "#ff4040",
        }.get(result.status, "#5a5a5a")
        self._set_status(
            f"[{status_color}]{result.status.value}[/]  "
            f"ports=[#00ff5f]{len(result.ports)}[/]  "
            f"web=[#00ff5f]{len(result.web_findings)}[/]  "
            f"vulns=[#00ff5f]{len(result.vulnerabilities)}[/]  "
            f"time={result.duration_seconds:.1f}s"
            if result.duration_seconds is not None
            else f"[{status_color}]{result.status.value}[/]"
        )
        self._reenable_run()

    # --- progress / log helpers ------------------------------------------

    def _on_progress(self, event: ProgressEvent) -> None:
        self.call_from_thread(self._apply_progress, event)

    def _apply_progress(self, event: ProgressEvent) -> None:
        if event.status == "started":
            self._set_phase(event.phase, "running")
            self._log(f"[#ffb000][*][/] [bold]{event.phase}[/]: {event.message or ''}")
        elif event.status == "info":
            self._log(f"[#5a5a5a]    →[/] {event.message}")
        elif event.status == "completed":
            self._set_phase(event.phase, "done")
            tail = ""
            if event.duration_seconds is not None:
                tail = f" [#5a5a5a]({event.duration_seconds:.1f}s)[/]"
            self._log(
                f"[#00ff5f][+][/] [bold]{event.phase}[/]: "
                f"{event.message or 'completed'}{tail}"
            )
        elif event.status == "failed":
            self._set_phase(event.phase, "fail")
            self._log(f"[#ff4040][-][/] [bold]{event.phase}[/]: {event.message or 'failed'}")

    def _reset_phase(self, phase: str) -> None:
        self._phase_state[phase] = "idle"
        bar = self.query_one(f"#bar-{phase}", ProgressBar)
        bar.update(progress=0)
        label = self.query_one(f"#lbl-{phase}", Label)
        label.set_classes("phase-label")

    def _set_phase(self, phase: str, state: str) -> None:
        self._phase_state[phase] = state
        bar = self.query_one(f"#bar-{phase}", ProgressBar)
        label = self.query_one(f"#lbl-{phase}", Label)
        if state == "running":
            bar.update(total=None, progress=0)  # indeterminate
            label.set_classes("phase-label -running")
        elif state == "done":
            bar.update(total=100, progress=100)
            label.set_classes("phase-label -done")
        elif state == "fail":
            bar.update(total=100, progress=100)
            label.set_classes("phase-label -fail")

    def _log(self, line: str) -> None:
        self.query_one("#log", Log).write_line(line)

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Static).update(msg)

    def _populate_findings(self, result: ScanResult) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear()
        for p in sorted(result.ports, key=lambda x: x.port):
            table.add_row(
                str(p.port),
                p.protocol,
                p.service or "—",
                p.product or "—",
                p.version or "—",
            )

    def _save_report(self, result: ScanResult) -> list[tuple[Path, ReportFormat]]:
        written: list[tuple[Path, ReportFormat]] = []
        out = self.output_path.strip()
        try:
            if out:
                file_path = Path(out)
                if file_path.suffix.lower() in {".md", ".html", ".htm", ".json", ".markdown"}:
                    p, used = write_report_to_file(result, file_path)
                    written.append((p, used))
                else:
                    # treated as directory
                    file_path.mkdir(parents=True, exist_ok=True)
                    p = write_report(result, file_path, self.fmt)
                    written.append((p, self.fmt))
            else:
                out_dir = Path("./reports")
                out_dir.mkdir(parents=True, exist_ok=True)
                target = out_dir / default_filename(result, self.fmt)
                p, used = write_report_to_file(result, target)
                written.append((p, used))
        except (OSError, ValueError) as exc:
            self._log(f"[#ff4040][-][/] write failed: {exc}")
        return written

    def _reenable_run(self) -> None:
        self.query_one("#start-btn", Button).disabled = False
        self.query_one("#stop-btn", Button).disabled = True


def run_tui(orchestrator_factory: Any, wordlist: Path = DEFAULT_WORDLIST) -> None:
    """Entry point — invoked from cli.py."""
    app = ReconFoxApp(orchestrator_factory=orchestrator_factory, wordlist=wordlist)
    app.run()


# Silence unused import warning in some lints.
_ = datetime
