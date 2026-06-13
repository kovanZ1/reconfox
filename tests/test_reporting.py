"""Tests for reconfox.reporting — Markdown and HTML report generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconfox.models import (
    ASNInfo,
    Geolocation,
    PortInfo,
    ScanMode,
    ScanResult,
    ScanStatus,
    Severity,
    Target,
    Vulnerability,
    WebFinding,
)
from reconfox.reporting import ReportFormat, render_html, render_markdown, write_report


@pytest.fixture
def sample_result() -> ScanResult:
    target = Target.from_url("https://example.com")
    target.ip = "93.184.216.34"
    target.asn = ASNInfo(asn=15133, asn_name="EDGECAST", isp="Edgecast", org="Verizon")
    target.geo = Geolocation(country="USA", city="Los Angeles", lat=34.0522, lon=-118.2437)
    return ScanResult(
        target=target,
        mode=ScanMode.FULL,
        started_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 6, 10, 12, 5, 30, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
        ports=[
            PortInfo(
                port=80, protocol="tcp", state="open", service="http", product="nginx",
                version="1.18.0",
            ),
            PortInfo(port=22, protocol="tcp", state="open", service="ssh", product="OpenSSH"),
        ],
        web_findings=[
            WebFinding(url="https://example.com/admin", status=200, length=1234),
            WebFinding(
                url="https://example.com/login",
                status=302,
                length=0,
                redirect="https://example.com/auth",
            ),
        ],
        vulnerabilities=[
            Vulnerability(
                title="OpenSSH 7.2 Username Enumeration",
                severity=Severity.MEDIUM,
                source="searchsploit",
                cve="CVE-2018-15473",
                affected_port=22,
                affected_service="ssh",
            ),
            Vulnerability(
                title="nginx 1.18 Information Disclosure",
                severity=Severity.HIGH,
                source="searchsploit",
                affected_port=80,
            ),
        ],
    )


# --- Markdown ------------------------------------------------------------


class TestMarkdown:
    def test_contains_header(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "# reconfox report" in out

    def test_contains_target_info(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "https://example.com" in out
        assert "93.184.216.34" in out
        assert "EDGECAST" in out
        assert "Los Angeles" in out

    def test_contains_ports_table(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "## Открытые порты" in out
        assert "| 80 |" in out or "| 80 " in out
        assert "nginx" in out
        assert "OpenSSH" in out

    def test_contains_web_findings(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "## Веб-находки" in out
        assert "/admin" in out
        assert "302" in out

    def test_contains_vulnerabilities(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "## Уязвимости" in out
        assert "CVE-2018-15473" in out
        assert "OpenSSH 7.2 Username Enumeration" in out

    def test_no_vulns_section_when_empty(self, sample_result: ScanResult) -> None:
        sample_result.vulnerabilities = []
        out = render_markdown(sample_result)
        assert "## Уязвимости" not in out

    def test_includes_status_and_duration(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "completed" in out.lower()
        assert "330" in out  # 5min 30s = 330 seconds

    def test_lists_errors_when_present(self, sample_result: ScanResult) -> None:
        sample_result.errors = ["nmap: timeout", "ffuf: connection refused"]
        out = render_markdown(sample_result)
        assert "## Ошибки" in out
        assert "nmap: timeout" in out

    def test_neutralizes_markup_injection_in_scan_data(self) -> None:
        """Scan data is attacker-influenced; it must not inject HTML/Markdown."""
        target = Target.from_url("https://evil.test")
        target.ip = "10.0.0.1"
        result = ScanResult(
            target=target,
            mode=ScanMode.QUICK,
            started_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
            finished_at=datetime(2026, 6, 10, 12, 0, 5, tzinfo=UTC),
            status=ScanStatus.COMPLETED,
            ports=[
                PortInfo(
                    port=80, protocol="tcp", state="open", service="http",
                    product="<script>alert(1)</script>", version="1|2",
                ),
            ],
            web_findings=[
                WebFinding(url="https://evil.test/a`b|c", status=200, length=1),
            ],
            vulnerabilities=[
                Vulnerability(
                    title="Evil\n## Injected Heading",
                    severity=Severity.HIGH,
                    source="searchsploit",
                    affected_port=80,
                ),
            ],
            errors=["<img src=x onerror=alert(1)>"],
        )
        out = render_markdown(result)
        # raw HTML must be neutralized (the markdown is later rendered as HTML)
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out
        assert "<img src=x" not in out
        # a newline in scan data must not spawn a real heading/section
        assert "\n## Injected Heading" not in out
        # a pipe must be escaped so it can't break out of a table cell
        assert "1\\|2" in out


# --- HTML ----------------------------------------------------------------


class TestHtml:
    def test_renders_valid_html(self, sample_result: ScanResult) -> None:
        out = render_html(sample_result)
        assert out.startswith("<!DOCTYPE html>")
        assert "<html" in out and "</html>" in out
        assert "<title>" in out

    def test_contains_target_info(self, sample_result: ScanResult) -> None:
        out = render_html(sample_result)
        assert "https://example.com" in out
        assert "93.184.216.34" in out

    def test_contains_ports(self, sample_result: ScanResult) -> None:
        out = render_html(sample_result)
        assert "nginx" in out
        assert "OpenSSH" in out

    def test_contains_status_badge(self, sample_result: ScanResult) -> None:
        out = render_html(sample_result)
        assert "completed" in out.lower()

    def test_dark_theme_css(self, sample_result: ScanResult) -> None:
        out = render_html(sample_result)
        # inline style block must exist for self-contained report
        assert "<style>" in out

    def test_escapes_html_in_user_data(self, sample_result: ScanResult) -> None:
        sample_result.errors = ["<script>alert(1)</script>"]
        out = render_html(sample_result)
        # script tag must be escaped
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out


# --- write_report --------------------------------------------------------


class TestWriteReport:
    def test_writes_markdown(self, sample_result: ScanResult, tmp_path: Path) -> None:
        path = write_report(sample_result, tmp_path, ReportFormat.MARKDOWN)
        assert path.exists()
        assert path.suffix == ".md"
        content = path.read_text(encoding="utf-8")
        assert "# reconfox report" in content

    def test_writes_html(self, sample_result: ScanResult, tmp_path: Path) -> None:
        path = write_report(sample_result, tmp_path, ReportFormat.HTML)
        assert path.exists()
        assert path.suffix == ".html"
        content = path.read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html>")

    def test_creates_output_dir_if_missing(
        self, sample_result: ScanResult, tmp_path: Path
    ) -> None:
        sub = tmp_path / "deep" / "nested"
        path = write_report(sample_result, sub, ReportFormat.HTML)
        assert path.exists()

    def test_filename_includes_hostname_and_timestamp(
        self, sample_result: ScanResult, tmp_path: Path
    ) -> None:
        path = write_report(sample_result, tmp_path, ReportFormat.MARKDOWN)
        assert "example.com" in path.name
        # timestamp from started_at
        assert "2026-06-10" in path.name
