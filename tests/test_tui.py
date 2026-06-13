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


async def test_full_scan_run_populates_findings(app: ReconFoxApp, tmp_path: Path) -> None:
    from textual.widgets import DataTable

    async with app.run_test() as pilot:
        app.query_one("#url-input").value = "https://example.com"
        app.output_path = str(tmp_path / "out.md")
        await pilot.pause()
        await pilot.press("ctrl+r")
        # let the worker finish
        await app.workers.wait_for_complete()
        await pilot.pause()
        table = app.query_one("#findings", DataTable)
        # fake result has no ports, but the run must complete without error
        assert table is not None
        status = str(app.query_one("#status-bar").render()).lower()
        assert "completed" in status or "ports" in status
