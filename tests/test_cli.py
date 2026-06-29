"""Tests for reconfox.cli — Click CLI entry point."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from reconfox import cli
from reconfox.models import ScanMode, ScanResult, ScanStatus, Severity, Target, Vulnerability


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
        self.run_many_calls: list[tuple[list[str], ScanMode]] = []
        self.expansion_calls: list[tuple[str, ScanMode]] = []

    async def run(self, url: str, mode: ScanMode) -> ScanResult:
        self.run_calls.append((url, mode))
        return self.result

    async def run_many(
        self, urls: list[str], mode: ScanMode, max_concurrency: int = 10  # noqa: ARG002
    ) -> list[ScanResult]:
        self.run_many_calls.append((list(urls), mode))
        # distinct hostnames per target so per-target report files don't collide
        return [_completed_result(u if "://" in u else f"http://{u}") for u in urls]

    async def run_with_subdomain_expansion(
        self, url: str, mode: ScanMode, max_concurrency: int = 10  # noqa: ARG002
    ) -> list[ScanResult]:
        from urllib.parse import urlparse

        self.expansion_calls.append((url, mode))
        base = url if "://" in url else f"http://{url}"
        host = urlparse(base).hostname or "example.com"
        return [
            _completed_result(base),
            _completed_result(f"http://www.{host}"),
            _completed_result(f"http://dev.{host}"),
        ]


def _result_with_ports(url: str = "https://example.com") -> ScanResult:
    from reconfox.models import PortInfo

    r = _completed_result(url)
    r.ports = [PortInfo(port=80, protocol="tcp", state="open", service="http", product="nginx")]
    return r


def _result_with_high_vuln(url: str = "https://example.com") -> ScanResult:
    r = _completed_result(url)
    r.vulnerabilities = [Vulnerability(title="bad", severity=Severity.HIGH, source="nuclei")]
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

    def test_tuning_flags_accepted(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            [
                "scan", "https://example.com", "-o", str(tmp_path), "--no-tui",
                "--threads", "10", "--rate", "50",
                "--nmap-min-rate", "100", "--nmap-max-rate", "500", "--scan-delay", "1s",
            ],
        )
        assert result.exit_code == 0, result.output

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


class TestMultiTarget:
    def test_multiple_args_write_per_target_reports(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://a.example", "https://b.example", "-o", str(tmp_path), "--no-tui"],
        )
        assert result.exit_code == 0, result.output
        assert _patch_orchestrator.run_many_calls[0][0] == [
            "https://a.example",
            "https://b.example",
        ]
        assert len(list(tmp_path.glob("*.md"))) == 2  # one report per target

    def test_target_file(self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator) -> None:
        tf = tmp_path / "targets.txt"
        tf.write_text("https://a.example\nhttps://b.example\n\n")  # blank line ignored
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "--target-file", str(tf), "-o", str(tmp_path), "--no-tui"]
        )
        assert result.exit_code == 0, result.output
        assert _patch_orchestrator.run_many_calls[0][0] == [
            "https://a.example",
            "https://b.example",
        ]

    def test_cidr_expands_to_hosts(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "10.0.0.0/30", "-o", str(tmp_path), "--no-tui"]
        )
        assert result.exit_code == 0, result.output
        called = _patch_orchestrator.run_many_calls[0][0]
        assert "10.0.0.1" in called
        assert "10.0.0.2" in called

    def test_stdin_multi(self, _patch_orchestrator: FakeOrchestrator) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "-", "--no-tui", "--ndjson"],
            input="https://a.example\nhttps://b.example\n",
        )
        assert result.exit_code == 0, result.output
        assert _patch_orchestrator.run_many_calls[0][0] == [
            "https://a.example",
            "https://b.example",
        ]

    def test_ndjson_streams_all_targets(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "https://a.example", "https://b.example", "--no-tui", "--ndjson"]
        )
        assert result.exit_code == 0, result.output
        targets = [
            json.loads(ln)
            for ln in result.stdout.splitlines()
            if ln.strip() and json.loads(ln)["type"] == "target"
        ]
        hosts = {t["hostname"] for t in targets}
        assert hosts == {"a.example", "b.example"}

    def test_output_file_rejects_multiple_targets(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            [
                "scan", "https://a.example", "https://b.example",
                "-O", str(tmp_path / "x.json"), "--no-tui",
            ],
        )
        assert result.exit_code == 2

    def test_scan_subdomains_expands_and_reports(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui", "--scan-subdomains"],
        )
        assert result.exit_code == 0, result.output
        assert _patch_orchestrator.expansion_calls[0][0] == "https://example.com"
        # primary + 2 discovered subdomains → 3 reports
        assert len(list(tmp_path.glob("*.md"))) == 3


class TestConfig:
    def test_config_file_sets_default_mode(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        cfg = tmp_path / "c.toml"
        cfg.write_text('[scan]\nmode = "full"\n', encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["--config", str(cfg), "scan", "https://example.com", "-o", str(tmp_path), "--no-tui"],
        )
        assert result.exit_code == 0, result.output
        assert _patch_orchestrator.run_calls[0][1] == ScanMode.FULL

    def test_cli_arg_overrides_config(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        cfg = tmp_path / "c.toml"
        cfg.write_text('[scan]\nmode = "full"\n', encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            [
                "--config", str(cfg), "scan", "https://example.com",
                "-m", "quick", "-o", str(tmp_path), "--no-tui",
            ],
        )
        assert result.exit_code == 0, result.output
        assert _patch_orchestrator.run_calls[0][1] == ScanMode.QUICK

    def test_no_config_is_harmless(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui"]
        )
        assert result.exit_code == 0, result.output


class TestDiffCommand:
    def _write(self, path: Path, result: ScanResult) -> None:
        path.write_text(result.model_dump_json(), encoding="utf-8")

    def test_diff_reports_changes(self, tmp_path: Path) -> None:
        old = _completed_result()
        new = _result_with_ports()  # adds an open port 80
        self._write(tmp_path / "old.json", old)
        self._write(tmp_path / "new.json", new)
        runner = CliRunner()
        result = runner.invoke(
            cli.main, ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json")]
        )
        assert result.exit_code == 0, result.output
        assert "80" in result.output

    def test_diff_json_output(self, tmp_path: Path) -> None:
        self._write(tmp_path / "old.json", _completed_result())
        self._write(tmp_path / "new.json", _result_with_ports())
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"), "-f", "json"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert any(p["port"] == 80 for p in data["added_ports"])


class TestSarifAndFailOn:
    def test_format_sarif_writes_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "-f", "sarif", "--no-tui"],
        )
        assert result.exit_code == 0, result.output
        assert list(tmp_path.glob("*.sarif"))

    def test_fail_on_triggers_exit_3(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        _patch_orchestrator.result = _result_with_high_vuln()
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui", "--fail-on", "high"],
        )
        assert result.exit_code == 3

    def test_fail_on_not_triggered_below_threshold(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        # default result has no vulnerabilities → nothing meets the threshold
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            ["scan", "https://example.com", "-o", str(tmp_path), "--no-tui", "--fail-on", "high"],
        )
        assert result.exit_code == 0

    def test_fail_on_multi_target(
        self, tmp_path: Path, _patch_orchestrator: FakeOrchestrator
    ) -> None:
        # run_many returns COMPLETED results without vulns by default → no trigger;
        # but a high finding in any target must trip the gate. Patch run_many output.
        async def run_many(urls, mode, max_concurrency=10):  # noqa: ANN001, ARG001
            return [_result_with_high_vuln(u) for u in urls]

        _patch_orchestrator.run_many = run_many  # type: ignore[assignment]
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            [
                "scan", "https://a.example", "https://b.example",
                "-o", str(tmp_path), "--no-tui", "--fail-on", "high",
            ],
        )
        assert result.exit_code == 3
