"""Smoke tests for the Textual TUI app."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconfox.models import ScanMode, ScanResult, ScanStatus, Target
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
    async with app.run_test() as pilot:  # noqa: F841
        # Compose ran without raising — that's the smoke test.
        assert app.title == "reconfox"


async def test_default_mode_is_quick(app: ReconFoxApp) -> None:
    async with app.run_test():
        assert app.mode == ScanMode.QUICK


async def test_start_without_url_shows_error(app: ReconFoxApp) -> None:
    async with app.run_test() as pilot:
        await pilot.press("r")
        await pilot.pause()
        from textual.widgets import Static

        status_widget = app.query_one("#status-bar", Static)
        assert "URL" in str(status_widget.render())
