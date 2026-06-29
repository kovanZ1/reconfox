"""Tests for reconfox.reporting — Markdown and HTML report generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconfox.models import (
    ASNInfo,
    Geolocation,
    HttpProbe,
    PortInfo,
    ScanMode,
    ScanResult,
    ScanStatus,
    Severity,
    Subdomain,
    Target,
    TlsInfo,
    Vulnerability,
    WebFinding,
)
from reconfox.reporting import (
    ReportFormat,
    render_html,
    render_markdown,
    render_ndjson,
    render_sarif,
    write_report,
)


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
        http_probes=[
            HttpProbe(
                url="https://example.com",
                status=200,
                final_url="https://example.com/",
                title="Example Domain",
                server="nginx",
                technologies=["nginx"],
            ),
        ],
        subdomains=[
            Subdomain(name="dev.example.com", ip="93.184.216.35", source="crt.sh"),
        ],
        tls=TlsInfo(
            host="example.com", port=443, version="TLSv1.3",
            subject="example.com", issuer="R3", san=["example.com", "www.example.com"],
        ),
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

    def test_contains_http_section(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "## HTTP" in out
        assert "Example Domain" in out
        assert "nginx" in out

    def test_contains_subdomains_section(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "## Поддомены" in out
        assert "dev.example.com" in out

    def test_contains_tls_section(self, sample_result: ScanResult) -> None:
        out = render_markdown(sample_result)
        assert "## TLS" in out
        assert "TLSv1.3" in out

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


# --- NDJSON --------------------------------------------------------------


class TestNdjson:
    def _lines(self, sample_result: ScanResult) -> list[dict]:
        import json

        out = render_ndjson(sample_result)
        assert out.endswith("\n")
        return [json.loads(line) for line in out.splitlines()]

    def test_every_line_is_valid_json(self, sample_result: ScanResult) -> None:
        records = self._lines(sample_result)
        assert len(records) >= 2

    def test_first_is_target_last_is_summary(self, sample_result: ScanResult) -> None:
        records = self._lines(sample_result)
        assert records[0]["type"] == "target"
        assert records[0]["schema_version"]
        assert records[-1]["type"] == "summary"

    def test_one_record_per_finding(self, sample_result: ScanResult) -> None:
        records = self._lines(sample_result)
        types = [r["type"] for r in records]
        assert types.count("port") == len(sample_result.ports)
        assert types.count("web") == len(sample_result.web_findings)
        assert types.count("vuln") == len(sample_result.vulnerabilities)
        assert types.count("http") == len(sample_result.http_probes)
        assert types.count("subdomain") == len(sample_result.subdomains)
        assert types.count("tls") == (1 if sample_result.tls else 0)

    def test_summary_counts(self, sample_result: ScanResult) -> None:
        summary = self._lines(sample_result)[-1]
        assert summary["ports"] == len(sample_result.ports)
        assert summary["web"] == len(sample_result.web_findings)
        assert summary["vulns"] == len(sample_result.vulnerabilities)
        assert summary["status"] == sample_result.status.value


# --- Diff ----------------------------------------------------------------


class TestDiffReport:
    def test_markdown_lists_added_and_removed(self) -> None:
        from reconfox.core.diffing import compute_diff
        from reconfox.reporting import render_diff_markdown

        old = ScanResult(
            target=Target.from_url("https://example.com"),
            mode=ScanMode.QUICK,
            started_at=datetime(2026, 6, 10, tzinfo=UTC),
            status=ScanStatus.COMPLETED,
            ports=[PortInfo(port=22, protocol="tcp", state="open")],
        )
        new = ScanResult(
            target=Target.from_url("https://example.com"),
            mode=ScanMode.QUICK,
            started_at=datetime(2026, 6, 11, tzinfo=UTC),
            status=ScanStatus.COMPLETED,
            ports=[PortInfo(port=443, protocol="tcp", state="open")],
        )
        out = render_diff_markdown(compute_diff(old, new))
        assert "443" in out  # added
        assert "22" in out   # removed

    def test_markdown_no_changes(self) -> None:
        from reconfox.core.diffing import compute_diff
        from reconfox.reporting import render_diff_markdown

        r = ScanResult(
            target=Target.from_url("https://example.com"),
            mode=ScanMode.QUICK,
            started_at=datetime(2026, 6, 10, tzinfo=UTC),
            status=ScanStatus.COMPLETED,
        )
        out = render_diff_markdown(compute_diff(r, r))
        assert "без изменений" in out.lower() or "no changes" in out.lower()


# --- SARIF ---------------------------------------------------------------


class TestSarif:
    def _doc(self, sample_result: ScanResult) -> dict:
        import json

        return json.loads(render_sarif(sample_result))

    def test_valid_skeleton(self, sample_result: ScanResult) -> None:
        doc = self._doc(sample_result)
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "reconfox"

    def test_one_result_per_vulnerability(self, sample_result: ScanResult) -> None:
        results = self._doc(sample_result)["runs"][0]["results"]
        assert len(results) == len(sample_result.vulnerabilities)

    def test_severity_maps_to_level(self, sample_result: ScanResult) -> None:
        results = self._doc(sample_result)["runs"][0]["results"]
        levels = {r["level"] for r in results}
        # fixture has a HIGH (nginx) and a MEDIUM (OpenSSH) finding
        assert "error" in levels  # high → error
        assert "warning" in levels  # medium → warning

    def test_cve_becomes_rule_id(self, sample_result: ScanResult) -> None:
        rule_ids = {r["ruleId"] for r in self._doc(sample_result)["runs"][0]["results"]}
        assert "CVE-2018-15473" in rule_ids


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

    def test_writes_sarif(self, sample_result: ScanResult, tmp_path: Path) -> None:
        import json

        path = write_report(sample_result, tmp_path, ReportFormat.SARIF)
        assert path.exists()
        assert path.suffix == ".sarif"
        assert json.loads(path.read_text(encoding="utf-8"))["version"] == "2.1.0"

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
