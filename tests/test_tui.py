"""Smoke + interaction tests for the Textual TUI app."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconfox.models import ScanMode, ScanResult, ScanStatus, Target
from reconfox.reporting import ReportFormat
from reconfox.tui import ReconFoxApp


def _completed_result() -> ScanResult:
    target = Target.from_url("https://example.com")
    target.ip = "93.184.216.34"
    return ScanResult(
        target=target,
        mode=ScanMode.QUICK,
        started_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 6, 10, 12, 0, 5, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
    )


class FakeOrchestrator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ScanMode]] = []

    async def run(self, url: str, mode: ScanMode) -> ScanResult:
        self.calls.append((url, mode))
        return _completed_result()


@pytest.fixture
def app(tmp_path: Path) -> ReconFoxApp:
    fake = FakeOrchestrator()

    def factory(**kwargs: object) -> FakeOrchestrator:  # noqa: ARG001
        return fake

    return ReconFoxApp(orchestrator_factory=factory, wordlist=tmp_path / "wl.txt")


async def test_app_mounts(app: ReconFoxApp) -> None:
    async with app.run_test():
        assert app.title == "reconfox"


async def test_default_state(app: ReconFoxApp) -> None:
    async with app.run_test():
        assert app.mode == ScanMode.QUICK
        assert app.fmt == ReportFormat.MARKDOWN
        assert app.use_metasploit is False


async def test_mode_button_cycles(app: ReconFoxApp) -> None:
    from textual.widgets import Button

    async with app.run_test() as pilot:
        btn = app.query_one("#mode-btn", Button)
        assert app.mode == ScanMode.QUICK
        btn.press()
        await pilot.pause()
        assert app.mode == ScanMode.FULL
        btn.press()
        await pilot.pause()
        assert app.mode == ScanMode.STEALTH
        btn.press()
        await pilot.pause()
        assert app.mode == ScanMode.QUICK  # wraps around
        # label reflects current mode
        assert "quick" in str(btn.label).lower()


async def test_format_button_cycles(app: ReconFoxApp) -> None:
    from textual.widgets import Button

    async with app.run_test() as pilot:
        btn = app.query_one("#fmt-btn", Button)
        assert app.fmt == ReportFormat.MARKDOWN
        btn.press()
        await pilot.pause()
        assert app.fmt == ReportFormat.HTML
        btn.press()
        await pilot.pause()
        assert app.fmt == ReportFormat.JSON
        btn.press()
        await pilot.pause()
        assert app.fmt == ReportFormat.MARKDOWN  # wraps


async def test_msf_button_toggles(app: ReconFoxApp) -> None:
    from textual.widgets import Button

    async with app.run_test() as pilot:
        btn = app.query_one("#msf-btn", Button)
        assert app.use_metasploit is False
        btn.press()
        await pilot.pause()
        assert app.use_metasploit is True
        btn.press()
        await pilot.pause()
        assert app.use_metasploit is False


async def test_start_without_url_shows_error(app: ReconFoxApp) -> None:
    async with app.run_test() as pilot:
        await pilot.press("ctrl+r")
        await pilot.pause()
        from textual.widgets import Static

        status_widget = app.query_one("#status-bar", Static)
        text = str(status_widget.render()).lower()
        assert "url" in text or "error" in text


class ProgressOrchestrator:
    """Fake orchestrator that emits real ProgressEvents to exercise phase bars."""

    def __init__(self, on_progress) -> None:  # noqa: ANN001
        self.on_progress = on_progress

    async def run(self, url: str, mode: ScanMode) -> ScanResult:  # noqa: ARG002
        from reconfox.core.orchestrator import ProgressEvent

        self.on_progress(ProgressEvent(phase="resolve", status="started"))
        self.on_progress(ProgressEvent(phase="resolve", status="completed", duration_seconds=0.4))
        self.on_progress(ProgressEvent(phase="nmap", status="started"))
        self.on_progress(ProgressEvent(phase="ffuf", status="failed", message="boom"))
        return _completed_result()


async def test_progress_events_update_phase_bars(tmp_path: Path) -> None:
    """Regression: progress callback must update phase state (was lost via
    call_from_thread raising on the app's own loop thread)."""

    def factory(on_progress=None, **kwargs):  # noqa: ANN001, ARG001
        return ProgressOrchestrator(on_progress)

    app = ReconFoxApp(orchestrator_factory=factory, wordlist=tmp_path / "wl.txt")
    async with app.run_test() as pilot:
        app.query_one("#url-input").value = "https://example.com"
        app.output_path = str(tmp_path / "out.md")
        await pilot.pause()
        await pilot.press("ctrl+r")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app._phases["resolve"]["state"] == "done"
        assert app._phases["ffuf"]["state"] == "fail"


async def test_full_scan_run_completes(app: ReconFoxApp, tmp_path: Path) -> None:
    async with app.run_test() as pilot:
        app.query_one("#url-input").value = "https://example.com"
        app.output_path = str(tmp_path / "out.md")
        await pilot.pause()
        await pilot.press("ctrl+r")
        await app.workers.wait_for_complete()
        await pilot.pause()
        # findings panel exists and run completed without error
        assert app.query_one("#findings") is not None
        status = str(app.query_one("#status-bar").render()).lower()
        assert "completed" in status or "ports" in status


def test_findings_table_formats_columns() -> None:
    from reconfox.models import PortInfo
    from reconfox.tui import format_findings_table

    rows = [
        PortInfo(
            port=22, protocol="tcp", state="open",
            service="ssh", product="OpenSSH", version="8.4",
        ),
        PortInfo(
            port=80, protocol="tcp", state="open",
            service="http", product="nginx", version="1.18",
        ),
    ]
    text = format_findings_table(rows)
    assert "PORT" in text and "SERVICE" in text and "VERSION" in text
    assert "|" in text  # pipe separators like the reference
    assert "22" in text and "OpenSSH" in text and "nginx" in text


def test_findings_table_empty() -> None:
    from reconfox.tui import format_findings_table

    text = format_findings_table([])
    assert "PORT" in text  # header still present
