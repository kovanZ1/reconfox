"""Tests for reconfox.cli — Click CLI entry point."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from reconfox import cli
from reconfox.models import ScanMode, ScanResult, ScanStatus, Target


def _completed_result(url: str = "https://example.com") -> ScanResult:
    target = Target.from_url(url)
    target.ip = "93.184.216.34"
    return ScanResult(
        target=target,
        mode=ScanMode.QUICK,
        started_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 6, 10, 12, 0, 10, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
    )


class FakeOrchestrator:
    """Stand-in that doesn't touch nmap/ffuf/network."""

    def __init__(self, result: ScanResult | None = None) -> None:
        self.result = result or _completed_result()
        self.run_calls: list[tuple[str, ScanMode]] = []

    async def run(self, url: str, mode: ScanMode) -> ScanResult:
        self.run_calls.append((url, mode))
        return self.result


def _result_with_ports(url: str = "https://example.com") -> ScanResult:
    from reconfox.models import PortInfo

    r = _completed_result(url)
    r.ports = [PortInfo(port=80, protocol="tcp", state="open", service="http", product="nginx")]
    return r


@pytest.fixture(autouse=True)
def _patch_orchestrator(monkeypatch: pytest.MonkeyPatch) -> FakeOrchestrator:
    fake = FakeOrchestrator()

    def factory(**kwargs: Any) -> FakeOrchestrator:  # noqa: ARG001
        return fake

    monkeypatch.setattr(cli, "build_orchestrator", factory)
    return fake


class TestCliRoot:
    def test_help_works(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli.main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output.lower()

    def test_version_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli.main, ["--version"])
        assert result.exit_code == 0
        assert "0.2.1" in result.output


class TestScanCommand:
    def test_basic_scan_writes_report(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui"],
        )
        assert result.exit_code == 0, result.output
        # default format = md
        files = list(tmp_path.glob("*.md"))
        assert len(files) >= 1
        assert _patch_orchestrator.run_calls == [
            ("https://example.com", ScanMode.QUICK)
        ]

    def test_mode_full(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        runner = CliRunner()
        runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "-m", "full", "--no-tui"],
        )
        assert _patch_orchestrator.run_calls[0][1] == ScanMode.FULL

    def test_mode_stealth(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        runner = CliRunner()
        runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "-m", "stealth", "--no-tui"],
        )
        assert _patch_orchestrator.run_calls[0][1] == ScanMode.STEALTH

    def test_format_html(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "-f", "html", "--no-tui"],
        )
        assert result.exit_code == 0
        assert list(tmp_path.glob("*.html"))
        assert not list(tmp_path.glob("*.md"))

    def test_format_all(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "-f", "all", "--no-tui"],
        )
        assert result.exit_code == 0
        assert list(tmp_path.glob("*.html"))
        assert list(tmp_path.glob("*.md"))
        assert list(tmp_path.glob("*.json"))

    def test_format_json(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "-f", "json", "--no-tui"],
        )
        assert result.exit_code == 0
        assert list(tmp_path.glob("*.json"))
        assert not list(tmp_path.glob("*.md"))

    def test_output_file_explicit_path(self, tmp_path: Path) -> None:
        target = tmp_path / "custom_report.html"
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-O", str(target), "--no-tui"],
        )
        assert result.exit_code == 0, result.output
        assert target.exists()
        assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
        # No auto-generated reports
        assert list(tmp_path.glob("reconfox_*.md")) == []

    def test_output_file_with_unknown_extension_fails(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-O", str(tmp_path / "x.xyz"), "--no-tui"],
        )
        assert result.exit_code == 2
        assert "extension" in result.output.lower() or "unknown" in result.output.lower()

    def test_verbose_flag_accepted(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "-v", "--no-tui"],
        )
        assert result.exit_code == 0

    def test_invalid_mode_rejected(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "https://example.com", "-o", str(tmp_path), "-m", "weird"]
        )
        assert result.exit_code != 0
        assert "invalid" in result.output.lower() or "не верно" in result.output.lower()

    def test_failed_scan_exit_code_nonzero(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        failed = _completed_result()
        failed.status = ScanStatus.FAILED
        failed.errors = ["nmap: timeout"]
        _patch_orchestrator.result = failed
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui"]
        )
        assert result.exit_code != 0

    def test_partial_scan_exit_code_zero(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        partial = _completed_result()
        partial.status = ScanStatus.PARTIAL
        partial.errors = ["nmap: timeout"]
        _patch_orchestrator.result = partial
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui"]
        )
        assert result.exit_code == 0  # partial is treated as success-with-warnings


class TestUnixIO:
    def test_target_read_from_stdin(self, _patch_orchestrator: FakeOrchestrator) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "-", "--no-tui", "--ndjson"], input="https://example.com\n"
        )
        assert result.exit_code == 0, result.output
        assert _patch_orchestrator.run_calls[0][0] == "https://example.com"

    def test_ndjson_stdout_is_clean_jsonl(
        self, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        _patch_orchestrator.result = _result_with_ports()
        runner = CliRunner()
        result = runner.invoke(cli.main, ["scan", "https://example.com", "--no-tui", "--ndjson"])
        assert result.exit_code == 0, result.output
        lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
        records = [json.loads(ln) for ln in lines]  # every line must be valid JSON
        assert records[0]["type"] == "target"
        assert records[-1]["type"] == "summary"
        assert any(r["type"] == "port" for r in records)

    def test_ndjson_writes_no_files(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(
            cli.main, ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui", "--ndjson"]
        )
        assert list(tmp_path.iterdir()) == []

    def test_json_report_to_stdout_dash(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "https://example.com", "--no-tui", "-f", "json", "-O", "-"]
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)  # pure stdout must be parseable JSON
        assert data["target"]["hostname"] == "example.com"

    def test_human_output_kept_off_stdout(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli.main, ["scan", "https://example.com", "--no-tui", "--ndjson"])
        # progress/summary chatter must go to stderr, leaving stdout pipe-clean
        assert "status:" not in result.stdout
        assert "status" in result.stderr.lower() or "reconfox" in result.stderr.lower()
