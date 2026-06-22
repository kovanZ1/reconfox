"""reconfox Textual TUI — hacker-style single screen.

Matches the project's design reference:
  ╭─ banner: larry3d "reconfox" logo (green) + amber tagline
  ├─ target / output inputs
  ├─ opts: mode / format cycle-buttons + [ ] msf toggle
  ├─ actions: ▶ RUN / ■ ABORT / CLEAR / × QUIT
  ├─ PHASES PANEL: label + percent + thick colored bar
  ├─ LIVE LOG: rounded green box (border-title) with coloured stream
  ├─ FINDINGS TABLE: rounded green box, pipe-separated columns
  ╰─ status bar
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Footer,
    Input,
    Label,
    RichLog,
    Static,
)

from reconfox.core.orchestrator import Orchestrator, ProgressEvent
from reconfox.models import PortInfo, ScanMode, ScanResult, ScanStatus
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
_PHASES = ("resolve", "nmap", "ffuf", "http", "nuclei", "exploits")
_MODE_CYCLE = (ScanMode.QUICK, ScanMode.FULL, ScanMode.STEALTH)
_FMT_CYCLE = (ReportFormat.MARKDOWN, ReportFormat.HTML, ReportFormat.JSON)
_FMT_NAMES = {
    ReportFormat.MARKDOWN: "markdown",
    ReportFormat.HTML: "html",
    ReportFormat.JSON: "json",
}

# Findings table column widths (chars).
_COLS = (("PORT", 5), ("PROTO", 6), ("SERVICE", 9), ("PRODUCT", 14), ("VERSION", 10))


def _load_banner() -> str:
    try:
        art = _BANNER_FILE.read_text(encoding="utf-8").rstrip("\n")
    except OSError:
        art = "  reconfox"
    return f"[bold #2ee66a]{art}[/]"


def format_findings_table(ports: list[PortInfo]) -> str:
    """Render an aligned, pipe-separated findings table with rich markup."""
    header = " [#5fb98f]" + "[/] | [#5fb98f]".join(
        name.ljust(w) for name, w in _COLS
    ) + "[/]"
    if not ports:
        return header + "\n [#3a4a40]— no open ports yet —[/]"
    lines = [header]
    for p in sorted(ports, key=lambda x: x.port):
        cells = [
            str(p.port).ljust(_COLS[0][1]),
            p.protocol.ljust(_COLS[1][1]),
            (p.service or "—").ljust(_COLS[2][1]),
            (p.product or "—").ljust(_COLS[3][1]),
            (p.version or "—").ljust(_COLS[4][1]),
        ]
        lines.append(" [#d7ffd7]" + "[/] [#3a4a40]|[/] [#d7ffd7]".join(cells) + "[/]")
    return "\n".join(lines)


class ReconFoxApp(App[None]):
    """Hacker-style one-screen reconfox TUI."""

    CSS = """
    Screen { background: #0a0d0b; }

    #banner-row { height: 9; align: center top; padding: 1 0 0 0; }
    #banner { width: auto; color: #2ee66a; }
    #tagline { width: auto; color: #ffb000; text-align: center; }

    .row { height: 3; margin: 0 2; }
    .row > Label {
        width: 10; height: 3; padding: 1 0 0 0;
        color: #2ee66a; content-align: left middle;
    }
    .row Input {
        width: 1fr; background: #0d1410; color: #d7ffd7;
        border: round #163a22;
    }
    .row Input:focus { border: round #2ee66a; }

    .opt-btn {
        height: 3; min-width: 22; margin: 0 1 0 0;
        background: #0d1410; color: #2ee66a;
        border: round #1f5a33; text-style: bold;
    }
    .opt-btn:hover { border: round #2ee66a; }
    .opt-btn.-on { color: #2ee66a; background: #0d1410; border: round #2ee66a; }
    #opts-gap { width: 1fr; height: 3; }

    #actions { height: 3; margin: 1 2 0 2; }
    #actions Button {
        margin: 0 2 0 0; min-width: 16;
        background: #0d1410; border: round #1f5a33; text-style: bold;
    }
    #start-btn { color: #2ee66a; border: round #2ee66a; }
    #stop-btn  { color: #0a0d0b; background: #d99e00; border: round #d99e00; }
    #clear-btn { color: #6a7a70; border: round #2a3a30; }
    #quit-btn  { color: #ff5555; border: round #ff5555; }
    #actions Button:disabled {
        color: #3a4a40; background: #0d1410; border: round #18241c; text-style: none;
    }

    .section-title { height: 1; padding: 0 2; color: #4a8a64; text-style: bold; margin: 1 0 0 0; }
    #phases-body { height: 11; padding: 0 3; background: #0a0d0b; }

    #log {
        border: round #2ee66a; border-title-color: #2ee66a; border-title-align: left;
        background: #060906; color: #c5e8c5; height: 1fr; min-height: 8; margin: 0 2;
        padding: 0 1;
    }
    #findings {
        border: round #2ee66a; border-title-color: #2ee66a; border-title-align: left;
        background: #060906; height: 9; margin: 0 2; padding: 0 1;
    }
    #status-bar {
        dock: bottom; padding: 0 2; height: 1; background: #060906; color: #5a6a5a;
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
        self._phases: dict[str, dict[str, Any]] = {
            p: {"state": "idle", "frac": 0.0, "dur": None} for p in _PHASES
        }
        self._phase_timer: Any | None = None

    # --- compose ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="banner-row"):
            yield Static(_load_banner(), id="banner")
            yield Static("v0.2 // recon toolkit  ·  authorized testing only", id="tagline")

        with Horizontal(id="target-row", classes="row"):
            yield Label("> target")
            yield Input(placeholder="https://example.com", id="url-input")

        with Horizontal(id="output-row", classes="row"):
            yield Label("> output")
            yield Input(placeholder="reports/scan.md   (blank → auto)", id="output-input")

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
            yield Button("×  QUIT  ^C", id="quit-btn")

        yield Static(self._title_rule("PHASES PANEL"), classes="section-title")
        yield Static(id="phases-body")

        log = RichLog(id="log", markup=True, wrap=False, max_lines=2000)
        log.border_title = "LIVE LOG"
        yield log

        findings = Static(format_findings_table([]), id="findings")
        findings.border_title = "FINDINGS TABLE"
        yield findings

        yield Static(self._idle_status(), id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "reconfox"
        self.sub_title = "authorized recon"
        self._render_phases()

    # --- small renderers -------------------------------------------------

    @staticmethod
    def _title_rule(title: str) -> str:
        return f"── {title} " + "─" * max(0, 40 - len(title))

    def _mode_label(self) -> str:
        return f"mode: {self.mode.value} ▼"

    def _fmt_label(self) -> str:
        return f"format: {_FMT_NAMES[self.fmt]} ▼"

    def _msf_label(self) -> str:
        return "[x] msf" if self.use_metasploit else "[ ] msf"

    @staticmethod
    def _idle_status() -> str:
        return "[#5a6a5a]ready  ·  ^R run   ^L clear   ^C quit[/]"

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
        self.mode = _MODE_CYCLE[(_MODE_CYCLE.index(self.mode) + 1) % len(_MODE_CYCLE)]
        self.query_one("#mode-btn", Button).label = self._mode_label()

    def _cycle_fmt(self) -> None:
        self.fmt = _FMT_CYCLE[(_FMT_CYCLE.index(self.fmt) + 1) % len(_FMT_CYCLE)]
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
            self._set_status("[#ff5555]error: target URL is empty[/]")
            return
        if self._scan_worker is not None and not self._scan_worker.is_finished:
            return

        self.query_one("#log", RichLog).clear()
        for p in _PHASES:
            self._phases[p] = {"state": "idle", "frac": 0.0, "dur": None}
        self._render_phases()
        self.query_one("#findings", Static).update(format_findings_table([]))
        self.query_one("#start-btn", Button).disabled = True
        self.query_one("#stop-btn", Button).disabled = False

        self._log("[#2ee66a][+][/] starting scan")
        self._log(f"[#5a6a5a]    target : {url}[/]")
        self._log(f"[#5a6a5a]    mode   : {self.mode.value}[/]")
        self._log(f"[#5a6a5a]    format : {self.fmt.value}[/]")
        self._log(f"[#5a6a5a]    msf    : {'on' if self.use_metasploit else 'off'}[/]")

        self._set_status(
            f"[#ffb000]running...[/] [#2ee66a]{url}[/] · mode=[#2ee66a]{self.mode.value}[/]"
        )
        self._phase_timer = self.set_interval(0.08, self._tick_phases)
        self._scan_worker = self.run_worker(self._run_scan(url), exclusive=True)

    def _cancel_scan(self) -> None:
        if self._scan_worker and not self._scan_worker.is_finished:
            self._scan_worker.cancel()
            self._log("[#ff5555][-][/] scan aborted by user")
            self._set_status("[#ff5555]aborted[/]")
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
            self._log(f"[#ff5555][-][/] {exc}")
            self._set_status(f"[#ff5555]crash: {exc}[/]")
            self._stop_timer()
            self._reenable_run()
            return

        self.query_one("#findings", Static).update(format_findings_table(result.ports))
        for path, fmt in self._save_report(result):
            self._log(f"[#2ee66a][+][/] report ([#ffb000]{fmt.value}[/]) → {path}")

        color = {
            ScanStatus.COMPLETED: "#2ee66a",
            ScanStatus.PARTIAL: "#ffb000",
            ScanStatus.FAILED: "#ff5555",
        }.get(result.status, "#5a6a5a")
        if result.duration_seconds is not None:
            self._set_status(
                f"[{color}]{result.status.value}[/]  ·  "
                f"ports=[#2ee66a]{len(result.ports)}[/]  "
                f"web=[#2ee66a]{len(result.web_findings)}[/]  "
                f"vulns=[#2ee66a]{len(result.vulnerabilities)}[/]  "
                f"[#5a6a5a]{result.duration_seconds:.1f}s[/]"
            )
        else:
            self._set_status(f"[{color}]{result.status.value}[/]")
        self._stop_timer()
        self._reenable_run()

    # --- progress / phases ----------------------------------------------

    def _on_progress(self, event: ProgressEvent) -> None:
        # The scan worker is an asyncio task on the app's event loop, so the
        # orchestrator invokes this on the UI thread — update widgets directly.
        # call_from_thread() RAISES when used on the app thread (and the
        # orchestrator swallows that), which silently dropped every update.
        app_thread = getattr(self, "_thread_id", None)
        if app_thread is None or threading.get_ident() == app_thread:
            self._apply_progress(event)
        else:
            self.call_from_thread(self._apply_progress, event)

    def _apply_progress(self, event: ProgressEvent) -> None:
        phase = event.phase
        if event.status == "started":
            self._phases[phase] = {"state": "running", "frac": 0.0, "dur": None}
            self._log(f"[#ffb000][*][/] [bold]{phase}[/]: {event.message or 'started'}")
        elif event.status == "info":
            self._log(f"[#5a6a5a]    →[/] {event.message}")
        elif event.status == "completed":
            self._phases[phase] = {"state": "done", "frac": 1.0, "dur": event.duration_seconds}
            tail = f" [#5a6a5a]({event.duration_seconds:.1f}s)[/]" if event.duration_seconds else ""
            self._log(f"[#2ee66a][+][/] [bold]{phase}[/]: {event.message or 'done'}{tail}")
        elif event.status == "failed":
            self._phases[phase] = {"state": "fail", "frac": 1.0, "dur": None}
            self._log(f"[#ff5555][-][/] [bold]{phase}[/]: {event.message or 'failed'}")
        self._render_phases()

    def _tick_phases(self) -> None:
        changed = False
        for st in self._phases.values():
            if st["state"] == "running":
                st["frac"] = min(0.95, st["frac"] + 0.03)
                changed = True
        if changed:
            self._render_phases()

    def _stop_timer(self) -> None:
        if self._phase_timer is not None:
            self._phase_timer.stop()
            self._phase_timer = None

    # prefix = name(9) + space(1) + pct(4) + spaces(2) = 16 chars before the bar
    _PHASE_PREFIX = 16
    _TRACK = "#243026"  # unfilled bar track — subtle but visible

    def _bar_width(self) -> int:
        """Bar spans the full panel width minus the label/percent prefix."""
        try:
            avail = self.query_one("#phases-body", Static).content_size.width
        except Exception:  # noqa: BLE001 — not mounted yet
            avail = 0
        if avail <= 0:
            avail = max(46, self.size.width - 8)
        return max(20, avail - self._PHASE_PREFIX - 1)

    def on_resize(self, event: Any) -> None:  # noqa: ARG002
        self._render_phases()

    def _render_phases(self) -> None:
        bar_w = self._bar_width()
        rows: list[str] = []
        for i, name in enumerate(_PHASES):
            rows.append(self._phase_line(name, bar_w))
            if i < len(_PHASES) - 1:
                rows.append("")  # blank line → visual gap between bars
        text = Text.from_markup("\n".join(rows))
        text.no_wrap = True
        text.overflow = "crop"
        self.query_one("#phases-body", Static).update(text)

    def _phase_line(self, name: str, bar_w: int) -> str:
        st = self._phases[name]
        state, frac = st["state"], st["frac"]
        if state == "done":
            pct, col, fill = 100, "#2ee66a", bar_w
        elif state == "fail":
            pct, col, fill = 100, "#ff5555", bar_w
        elif state == "running":
            pct, col, fill = int(frac * 100), "#d99e00", max(1, int(frac * bar_w))
        else:
            pct, col, fill = 0, "#4a5a4a", 0
        bar = f"[{col}]{'█' * fill}[/][{self._TRACK}]{'█' * (bar_w - fill)}[/]"
        return f"[{col}]{name:<9}[/] [{col}]{pct:>3}%[/]  {bar}"

    # --- log / findings --------------------------------------------------

    def _log(self, line: str) -> None:
        self.query_one("#log", RichLog).write(line)

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Static).update(msg)

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
            self._log(f"[#ff5555][-][/] write failed: {exc}")
        return written

    def _reenable_run(self) -> None:
        self.query_one("#start-btn", Button).disabled = False
        self.query_one("#stop-btn", Button).disabled = True


def run_tui(orchestrator_factory: Any, wordlist: Path = DEFAULT_WORDLIST) -> None:
    """Entry point — invoked from cli.py."""
    app = ReconFoxApp(orchestrator_factory=orchestrator_factory, wordlist=wordlist)
    app.run()
