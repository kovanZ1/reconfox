"""Tests for write_report_to_file and JSON format."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconfox.models import (
    PortInfo,
    ScanMode,
    ScanResult,
    ScanStatus,
    Target,
)
from reconfox.reporting import (
    ReportFormat,
    render_json,
    write_report_to_file,
)


def _result(url: str = "https://example.com") -> ScanResult:
    target = Target.from_url(url)
    target.ip = "93.184.216.34"
    return ScanResult(
        target=target,
        mode=ScanMode.QUICK,
        started_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 6, 10, 12, 0, 5, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
        ports=[PortInfo(port=80, protocol="tcp", state="open", service="http")],
    )


class TestRenderJson:
    def test_valid_json(self) -> None:
        out = render_json(_result())
        data = json.loads(out)
        assert data["target"]["ip"] == "93.184.216.34"
        assert data["status"] == "completed"
        assert data["ports"][0]["port"] == 80

    def test_indented_by_default(self) -> None:
        out = render_json(_result())
        assert "\n" in out


class TestWriteToFile:
    def test_explicit_md_path(self, tmp_path: Path) -> None:
        p = tmp_path / "report.md"
        path, fmt = write_report_to_file(_result(), p)
        assert path == p.resolve()
        assert fmt == ReportFormat.MARKDOWN
        assert path.read_text(encoding="utf-8").startswith("# reconfox report")

    def test_explicit_html_path(self, tmp_path: Path) -> None:
        p = tmp_path / "deep" / "report.html"
        path, fmt = write_report_to_file(_result(), p)
        assert fmt == ReportFormat.HTML
        assert path.exists()
        assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    def test_explicit_json_path(self, tmp_path: Path) -> None:
        p = tmp_path / "report.json"
        path, fmt = write_report_to_file(_result(), p)
        assert fmt == ReportFormat.JSON
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["target"]["hostname"] == "example.com"

    def test_unknown_suffix_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown report extension"):
            write_report_to_file(_result(), tmp_path / "report.xyz")

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        p = tmp_path / "a" / "b" / "c" / "out.md"
        path, _ = write_report_to_file(_result(), p)
        assert path.exists()

    def test_htm_extension_treated_as_html(self, tmp_path: Path) -> None:
        path, fmt = write_report_to_file(_result(), tmp_path / "x.htm")
        assert fmt == ReportFormat.HTML
        assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
