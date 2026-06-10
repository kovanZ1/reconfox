"""Tests for reconfox.models — data structures used across scanners and reports."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

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

# --- Geolocation ---------------------------------------------------------

class TestGeolocation:
    def test_full_creation(self) -> None:
        geo = Geolocation(
            country="Russia",
            country_code="RU",
            region="Moscow",
            city="Moscow",
            lat=55.7558,
            lon=37.6173,
            timezone="Europe/Moscow",
        )
        assert geo.country == "Russia"
        assert geo.country_code == "RU"
        assert geo.lat == pytest.approx(55.7558)

    def test_all_fields_optional(self) -> None:
        geo = Geolocation()
        assert geo.country is None
        assert geo.lat is None

    def test_serialization_roundtrip(self) -> None:
        geo = Geolocation(country="Russia", city="Moscow")
        dumped = geo.model_dump()
        assert dumped["country"] == "Russia"
        restored = Geolocation.model_validate(dumped)
        assert restored == geo


# --- ASNInfo -------------------------------------------------------------

class TestASNInfo:
    def test_creation(self) -> None:
        asn = ASNInfo(asn=15169, asn_name="GOOGLE", isp="Google LLC", org="Google")
        assert asn.asn == 15169
        assert asn.isp == "Google LLC"

    def test_all_optional(self) -> None:
        ASNInfo()  # must not raise


# --- Target --------------------------------------------------------------

class TestTarget:
    def test_from_url_https(self) -> None:
        target = Target.from_url("https://example.com")
        assert target.url == "https://example.com"
        assert target.hostname == "example.com"
        assert target.is_https is True
        assert target.port == 443

    def test_from_url_http(self) -> None:
        target = Target.from_url("http://example.com")
        assert target.is_https is False
        assert target.port == 80

    def test_from_url_with_explicit_port(self) -> None:
        target = Target.from_url("https://example.com:8443")
        assert target.port == 8443
        assert target.is_https is True

    def test_from_url_with_path(self) -> None:
        target = Target.from_url("https://example.com/admin/panel")
        assert target.hostname == "example.com"
        assert target.path == "/admin/panel"

    def test_from_url_no_scheme_assumed_http(self) -> None:
        target = Target.from_url("example.com")
        assert target.is_https is False
        assert target.hostname == "example.com"

    def test_from_url_invalid(self) -> None:
        with pytest.raises(ValueError, match="Invalid URL"):
            Target.from_url("not a url at all")

    def test_from_url_empty(self) -> None:
        with pytest.raises(ValueError):
            Target.from_url("")

    def test_ip_initially_none(self) -> None:
        target = Target.from_url("https://example.com")
        assert target.ip is None

    def test_enrich_with_ip(self) -> None:
        target = Target.from_url("https://example.com")
        target.ip = "93.184.216.34"
        assert target.ip == "93.184.216.34"

    def test_invalid_ip_rejected(self) -> None:
        target = Target.from_url("https://example.com")
        with pytest.raises(ValidationError):
            target.ip = "not-an-ip"


# --- PortInfo ------------------------------------------------------------

class TestPortInfo:
    def test_basic(self) -> None:
        port = PortInfo(port=80, protocol="tcp", state="open")
        assert port.port == 80
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.cpe == []
        assert port.scripts == {}

    def test_full(self) -> None:
        port = PortInfo(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            product="OpenSSH",
            version="8.4p1",
            cpe=["cpe:/a:openbsd:openssh:8.4p1"],
            scripts={"ssh-hostkey": "RSA 2048"},
        )
        assert port.product == "OpenSSH"
        assert "cpe:/a:openbsd:openssh:8.4p1" in port.cpe

    def test_invalid_port_too_high(self) -> None:
        with pytest.raises(ValidationError):
            PortInfo(port=70000, protocol="tcp", state="open")

    def test_invalid_port_negative(self) -> None:
        with pytest.raises(ValidationError):
            PortInfo(port=-1, protocol="tcp", state="open")

    def test_invalid_protocol(self) -> None:
        with pytest.raises(ValidationError):
            PortInfo(port=80, protocol="icmp", state="open")  # type: ignore[arg-type]

    def test_invalid_state(self) -> None:
        with pytest.raises(ValidationError):
            PortInfo(port=80, protocol="tcp", state="weird")  # type: ignore[arg-type]


# --- WebFinding ----------------------------------------------------------

class TestWebFinding:
    def test_basic(self) -> None:
        f = WebFinding(url="http://target/admin", status=200, length=1234)
        assert f.status == 200
        assert f.length == 1234

    def test_with_redirect(self) -> None:
        f = WebFinding(
            url="http://target/old",
            status=302,
            length=0,
            redirect="http://target/new",
        )
        assert f.redirect == "http://target/new"

    def test_invalid_status_code(self) -> None:
        with pytest.raises(ValidationError):
            WebFinding(url="http://target/x", status=999, length=0)


# --- Severity ------------------------------------------------------------

class TestSeverity:
    def test_str_values(self) -> None:
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_score_ordering(self) -> None:
        assert Severity.CRITICAL.score > Severity.HIGH.score
        assert Severity.HIGH.score > Severity.MEDIUM.score
        assert Severity.MEDIUM.score > Severity.LOW.score
        assert Severity.LOW.score > Severity.INFO.score


# --- Vulnerability -------------------------------------------------------

class TestVulnerability:
    def test_minimum(self) -> None:
        v = Vulnerability(
            title="OpenSSH Username Enumeration",
            severity=Severity.MEDIUM,
            source="searchsploit",
        )
        assert v.severity == Severity.MEDIUM
        assert v.source == "searchsploit"
        assert v.cve is None

    def test_with_cve_and_references(self) -> None:
        v = Vulnerability(
            title="EternalBlue",
            severity=Severity.CRITICAL,
            source="metasploit",
            cve="CVE-2017-0144",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
            affected_port=445,
            affected_service="smb",
            metasploit_module="exploit/windows/smb/ms17_010_eternalblue",
        )
        assert v.cve == "CVE-2017-0144"
        assert len(v.references) == 1
        assert v.affected_port == 445

    def test_invalid_source(self) -> None:
        with pytest.raises(ValidationError):
            Vulnerability(
                title="x", severity=Severity.LOW, source="bogus"  # type: ignore[arg-type]
            )


# --- ScanMode / ScanStatus -----------------------------------------------

class TestScanModeStatus:
    def test_mode_values(self) -> None:
        assert ScanMode.QUICK.value == "quick"
        assert ScanMode.FULL.value == "full"
        assert ScanMode.STEALTH.value == "stealth"

    def test_status_values(self) -> None:
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.PARTIAL.value == "partial"


# --- ScanResult ----------------------------------------------------------

class TestScanResult:
    def _make_target(self) -> Target:
        target = Target.from_url("http://example.com")
        target.ip = "93.184.216.34"
        return target

    def test_minimum(self) -> None:
        start = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)
        result = ScanResult(
            target=self._make_target(),
            mode=ScanMode.QUICK,
            started_at=start,
        )
        assert result.status == ScanStatus.PENDING
        assert result.finished_at is None
        assert result.ports == []
        assert result.duration_seconds is None

    def test_duration_when_completed(self) -> None:
        start = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)
        end = start + timedelta(seconds=330)
        result = ScanResult(
            target=self._make_target(),
            mode=ScanMode.FULL,
            started_at=start,
            finished_at=end,
            status=ScanStatus.COMPLETED,
        )
        assert result.duration_seconds == pytest.approx(330.0)

    def test_aggregate_severity_when_empty(self) -> None:
        result = ScanResult(
            target=self._make_target(),
            mode=ScanMode.QUICK,
            started_at=datetime.now(UTC),
        )
        assert result.highest_severity is None

    def test_aggregate_severity_returns_max(self) -> None:
        result = ScanResult(
            target=self._make_target(),
            mode=ScanMode.QUICK,
            started_at=datetime.now(UTC),
            vulnerabilities=[
                Vulnerability(title="low", severity=Severity.LOW, source="searchsploit"),
                Vulnerability(title="crit", severity=Severity.CRITICAL, source="searchsploit"),
                Vulnerability(title="med", severity=Severity.MEDIUM, source="searchsploit"),
            ],
        )
        assert result.highest_severity == Severity.CRITICAL

    def test_serialization_roundtrip(self) -> None:
        original = ScanResult(
            target=self._make_target(),
            mode=ScanMode.FULL,
            started_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
            status=ScanStatus.COMPLETED,
            ports=[PortInfo(port=22, protocol="tcp", state="open", service="ssh")],
            web_findings=[WebFinding(url="http://x/a", status=200, length=10)],
        )
        dumped = original.model_dump(mode="json")
        restored = ScanResult.model_validate(dumped)
        assert restored.target.ip == original.target.ip
        assert restored.ports[0].port == 22
        assert restored.web_findings[0].url == "http://x/a"
