"""reconfox Textual TUI — hacker-style single screen.

Layout (top → bottom):
  ╭─ banner (ANSI-shadow logo + amber tagline)
  ├─ target row: URL input
  ├─ output row: path input
  ├─ opts row: mode / format cycle-buttons + msf toggle
  ├─ action row: run / abort / clear / quit
  ├─ PHASES: 4 colored progress bars (resolve / nmap / ffuf / exploits)
  ├─ LIVE LOG: coloured stream of every step
  ├─ FINDINGS: table of open ports / services
  ╰─ status bar
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    RichLog,
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

_BANNER_FILE = Path(__file__).parent / "assets" / "banner.txt"
_PHASES = ("resolve", "nmap", "ffuf", "exploits")
_BAR_WIDTH = 34
_MODE_CYCLE = (ScanMode.QUICK, ScanMode.FULL, ScanMode.STEALTH)
_FMT_CYCLE = (ReportFormat.MARKDOWN, ReportFormat.HTML, ReportFormat.JSON)


def _load_banner() -> str:
    try:
        art = _BANNER_FILE.read_text(encoding="utf-8").rstrip("\n")
    except OSError:
        art = "  reconfox"
    tagline = (
        "[#ffb000]        v0.2 // recon toolkit[/]"
        "  [#5a5a5a]· authorized testing only[/]"
    )
    return f"[bold #00ff5f]{art}[/]\n{tagline}"


class ReconFoxApp(App[None]):
    """Hacker-style one-screen reconfox TUI."""

    CSS = """
    Screen {
        background: #0b0d0e;
    }
    #banner {
        height: 8;
        padding: 1 2 0 2;
    }
    .row {
        height: 3;
        margin: 0 2;
    }
    .row > Label {
        width: 10;
        color: #00ff5f;
        content-align: left middle;
        height: 3;
        padding: 1 0 0 0;
    }
    .row Input {
        width: 1fr;
        background: #11161a;
        color: #d7ffd7;
        border: tall #1a2a1f;
    }
    .row Input:focus {
        border: tall #00ff5f;
    }
    /* opt cycle-buttons */
    .opt-btn {
        height: 3;
        min-width: 20;
        margin: 0 1 0 0;
        background: #11161a;
        color: #00ff5f;
        border: tall #1a2a1f;
        text-style: bold;
    }
    .opt-btn:hover { border: tall #00ff5f; }
    .opt-btn.-on {
        color: #0b0d0e;
        background: #00ff5f;
        border: tall #00ff5f;
    }
    #opts-gap { width: 1fr; height: 3; }
    /* action buttons */
    #actions {
        height: 3;
        margin: 1 2 0 2;
    }
    #actions Button {
        margin: 0 1 0 0;
        min-width: 16;
        background: #11161a;
        color: #00ff5f;
        border: tall #1a2a1f;
        text-style: bold;
    }
    #start-btn { color: #00ff5f; border: tall #00ff5f; }
    #stop-btn  { color: #ffb000; border: tall #ffb000; }
    #quit-btn  { color: #ff4040; border: tall #ff4040; }
    #actions Button:disabled { color: #3a3f3a; border: tall #1a2a1f; text-style: none; }
    .section-title {
        height: 1;
        padding: 0 2;
        color: #ffb000;
        text-style: bold;
        margin: 1 0 0 0;
    }
    #phases-body {
        height: 4;
        padding: 0 2;
        background: #07090a;
    }
    #log {
        border: round #1f3a23;
        background: #07090a;
        color: #c5e8c5;
        height: 1fr;
        min-height: 8;
        margin: 0 2;
    }
    #findings {
        border: round #1f3a23;
        background: #07090a;
        height: 8;
        margin: 0 2;
    }
    #findings > .datatable--header {
        background: #11161a;
        color: #00ff5f;
        text-style: bold;
    }
    #status-bar {
        dock: bottom;
        padding: 0 2;
        height: 1;
        background: #07090a;
        color: #5a5a5a;
    }
    """

    BINDINGS = [
        Binding("ctrl+r", "start_scan", "Run scan"),
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+l", "clear_log", "Clear log"),
    ]

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
        # phase -> {"state": str, "frac": float, "dur": float|None}
        self._phases: dict[str, dict[str, Any]] = {
            p: {"state": "idle", "frac": 0.0, "dur": None} for p in _PHASES
        }
        self._phase_timer: Any | None = None

    # --- compose ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(_load_banner(), id="banner")

        with Horizontal(id="target-row", classes="row"):
            yield Label("> target")
            yield Input(placeholder="https://example.com", id="url-input")

        with Horizontal(id="output-row", classes="row"):
            yield Label("> output")
            yield Input(
                placeholder="./reports/report.md   (blank → auto-name)",
                id="output-input",
            )

        with Horizontal(id="opts-row", classes="row"):
            yield Label("> opts")
            yield Button(self._mode_label(), id="mode-btn", classes="opt-btn")
            yield Button(self._fmt_label(), id="fmt-btn", classes="opt-btn")
            yield Button(self._msf_label(), id="msf-btn", classes="opt-btn")
            yield Static("", id="opts-gap")

        with Horizontal(id="actions"):
            yield Button("▶  RUN  ^R", id="start-btn")
            yield Button("■  ABORT", id="stop-btn", disabled=True)
            yield Button("CLEAR  ^L", id="clear-btn")
            yield Button("✕  QUIT  ^C", id="quit-btn")

        yield Static("══ PHASES ══════════════════", classes="section-title")
        yield Static(id="phases-body")

        yield Static("══ LIVE LOG ════════════════", classes="section-title")
        yield RichLog(id="log", markup=True, wrap=False, max_lines=2000)

        yield Static("══ FINDINGS ════════════════", classes="section-title")
        yield DataTable(id="findings")

        yield Static(self._idle_status(), id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "reconfox"
        self.sub_title = "authorized recon"
        table = self.query_one("#findings", DataTable)
        table.add_columns("port", "proto", "service", "product", "version")
        self._render_phases()

    # --- option labels ---------------------------------------------------

    def _mode_label(self) -> str:
        return f"mode: {self.mode.value} ▾"

    def _fmt_label(self) -> str:
        return f"fmt: {self.fmt.value} ▾"

    def _msf_label(self) -> str:
        return f"msf: {'ON' if self.use_metasploit else 'off'}"

    @staticmethod
    def _idle_status() -> str:
        return "[#5a5a5a]ready  ·  ^R run   ^L clear   ^C quit[/]"

    # --- input handlers --------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "url-input":
            self.target_url = event.value
        elif event.input.id == "output-input":
            self.output_path = event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "mode-btn":
            self._cycle_mode()
        elif bid == "fmt-btn":
            self._cycle_fmt()
        elif bid == "msf-btn":
            self._toggle_msf()
        elif bid == "start-btn":
            self.action_start_scan()
        elif bid == "stop-btn":
            self._cancel_scan()
        elif bid == "clear-btn":
            self.action_clear_log()
        elif bid == "quit-btn":
            self.exit()

    def _cycle_mode(self) -> None:
        idx = (_MODE_CYCLE.index(self.mode) + 1) % len(_MODE_CYCLE)
        self.mode = _MODE_CYCLE[idx]
        self.query_one("#mode-btn", Button).label = self._mode_label()

    def _cycle_fmt(self) -> None:
        idx = (_FMT_CYCLE.index(self.fmt) + 1) % len(_FMT_CYCLE)
        self.fmt = _FMT_CYCLE[idx]
        self.query_one("#fmt-btn", Button).label = self._fmt_label()

    def _toggle_msf(self) -> None:
        self.use_metasploit = not self.use_metasploit
        btn = self.query_one("#msf-btn", Button)
        btn.label = self._msf_label()
        btn.set_class(self.use_metasploit, "-on")

    # --- actions ---------------------------------------------------------

    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_start_scan(self) -> None:
        url = self.target_url.strip()
        if not url:
            self._set_status("[#ff4040]error: target URL is empty[/]")
            return
        if self._scan_worker is not None and not self._scan_worker.is_finished:
            return

        self.query_one("#log", RichLog).clear()
        for p in _PHASES:
            self._phases[p] = {"state": "idle", "frac": 0.0, "dur": None}
        self._render_phases()
        self.query_one("#findings", DataTable).clear()
        self.query_one("#start-btn", Button).disabled = True
        self.query_one("#stop-btn", Button).disabled = False

        self._log("[#00ff5f][*][/] starting scan")
        self._log(f"[#5a5a5a]    target : {url}[/]")
        self._log(f"[#5a5a5a]    mode   : {self.mode.value}[/]")
        self._log(f"[#5a5a5a]    format : {self.fmt.value}[/]")
        self._log(f"[#5a5a5a]    msf    : {'on' if self.use_metasploit else 'off'}[/]")

        self._set_status(
            f"[#ffb000]running...[/] [#00ff5f]{url}[/] · mode=[#00ff5f]{self.mode.value}[/]"
        )
        self._phase_timer = self.set_interval(0.08, self._tick_phases)
        self._scan_worker = self.run_worker(self._run_scan(url), exclusive=True)

    def _cancel_scan(self) -> None:
        if self._scan_worker and not self._scan_worker.is_finished:
            self._scan_worker.cancel()
            self._log("[#ff4040][-][/] scan aborted by user")
            self._set_status("[#ff4040]aborted[/]")
            self._stop_timer()
            self._reenable_run()

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
            self._stop_timer()
            self._reenable_run()
            return

        self._populate_findings(result)
        for path, fmt in self._save_report(result):
            self._log(f"[#00ff5f][+][/] report ([#ffb000]{fmt.value}[/]) → {path}")

        color = {
            ScanStatus.COMPLETED: "#00ff5f",
            ScanStatus.PARTIAL: "#ffb000",
            ScanStatus.FAILED: "#ff4040",
        }.get(result.status, "#5a5a5a")
        if result.duration_seconds is not None:
            self._set_status(
                f"[{color}]{result.status.value}[/]  ·  "
                f"ports=[#00ff5f]{len(result.ports)}[/]  "
                f"web=[#00ff5f]{len(result.web_findings)}[/]  "
                f"vulns=[#00ff5f]{len(result.vulnerabilities)}[/]  "
                f"[#5a5a5a]{result.duration_seconds:.1f}s[/]"
            )
        else:
            self._set_status(f"[{color}]{result.status.value}[/]")
        self._stop_timer()
        self._reenable_run()

    # --- progress / phases ----------------------------------------------

    def _on_progress(self, event: ProgressEvent) -> None:
        self.call_from_thread(self._apply_progress, event)

    def _apply_progress(self, event: ProgressEvent) -> None:
        phase = event.phase
        if event.status == "started":
            self._phases[phase] = {"state": "running", "frac": 0.0, "dur": None}
            self._log(f"[#ffb000][*][/] [bold]{phase}[/]: {event.message or 'started'}")
        elif event.status == "info":
            self._log(f"[#5a5a5a]    →[/] {event.message}")
        elif event.status == "completed":
            self._phases[phase] = {
                "state": "done", "frac": 1.0, "dur": event.duration_seconds,
            }
            tail = f" [#5a5a5a]({event.duration_seconds:.1f}s)[/]" if event.duration_seconds else ""
            self._log(f"[#00ff5f][+][/] [bold]{phase}[/]: {event.message or 'done'}{tail}")
        elif event.status == "failed":
            self._phases[phase] = {"state": "fail", "frac": 1.0, "dur": None}
            self._log(f"[#ff4040][-][/] [bold]{phase}[/]: {event.message or 'failed'}")
        self._render_phases()

    def _tick_phases(self) -> None:
        changed = False
        for st in self._phases.values():
            if st["state"] == "running":
                st["frac"] = (st["frac"] + 0.05) % 1.0
                changed = True
        if changed:
            self._render_phases()

    def _stop_timer(self) -> None:
        if self._phase_timer is not None:
            self._phase_timer.stop()
            self._phase_timer = None

    def _render_phases(self) -> None:
        lines = [self._phase_line(p) for p in _PHASES]
        self.query_one("#phases-body", Static).update("\n".join(lines))

    def _phase_line(self, name: str) -> str:
        st = self._phases[name]
        state, frac, dur = st["state"], st["frac"], st["dur"]
        if state == "done":
            bar = f"[#00ff5f]{'█' * _BAR_WIDTH}[/]"
            status = f"[#00ff5f]done {dur:.1f}s[/]" if dur is not None else "[#00ff5f]done[/]"
            lbl = "#00ff5f"
        elif state == "fail":
            bar = f"[#ff4040]{'█' * _BAR_WIDTH}[/]"
            status = "[#ff4040]failed[/]"
            lbl = "#ff4040"
        elif state == "running":
            n = max(1, int(frac * _BAR_WIDTH))
            bar = f"[#ffb000]{'█' * n}[/][#1a2a1f]{'─' * (_BAR_WIDTH - n)}[/]"
            status = "[#ffb000]scanning[/]"
            lbl = "#ffb000"
        else:
            bar = f"[#1a2a1f]{'─' * _BAR_WIDTH}[/]"
            status = "[#3a3f3a]idle[/]"
            lbl = "#5a5a5a"
        return f"[{lbl}]{name:<9}[/] {bar}  {status}"

    # --- log / findings --------------------------------------------------

    def _log(self, line: str) -> None:
        self.query_one("#log", RichLog).write(line)

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Static).update(msg)

    def _populate_findings(self, result: ScanResult) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear()
        for p in sorted(result.ports, key=lambda x: x.port):
            table.add_row(
                str(p.port), p.protocol, p.service or "—",
                p.product or "—", p.version or "—",
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
                    file_path.mkdir(parents=True, exist_ok=True)
                    written.append((write_report(result, file_path, self.fmt), self.fmt))
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
