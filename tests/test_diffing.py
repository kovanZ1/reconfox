"""Tests for reconfox.core.diffing — compare two ScanResults."""

from __future__ import annotations

from datetime import UTC, datetime

from reconfox.core.diffing import compute_diff
from reconfox.models import (
    PortInfo,
    ScanMode,
    ScanResult,
    ScanStatus,
    Severity,
    Subdomain,
    Target,
    Vulnerability,
    WebFinding,
)


def _result(
    *,
    ports: list[PortInfo] | None = None,
    web: list[WebFinding] | None = None,
    vulns: list[Vulnerability] | None = None,
    subs: list[Subdomain] | None = None,
) -> ScanResult:
    return ScanResult(
        target=Target.from_url("https://example.com"),
        mode=ScanMode.QUICK,
        started_at=datetime(2026, 6, 10, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
        ports=ports or [],
        web_findings=web or [],
        vulnerabilities=vulns or [],
        subdomains=subs or [],
    )


def _port(n: int) -> PortInfo:
    return PortInfo(port=n, protocol="tcp", state="open")


class TestComputeDiff:
    def test_added_and_removed_ports(self) -> None:
        old = _result(ports=[_port(80), _port(22)])
        new = _result(ports=[_port(80), _port(443)])
        diff = compute_diff(old, new)
        assert [p.port for p in diff.added_ports] == [443]
        assert [p.port for p in diff.removed_ports] == [22]

    def test_same_number_different_protocol_not_collided(self) -> None:
        """53/tcp closing while 53/udp opens must show as removed + added, not
        cancel out (the diff keys ports on (port, protocol))."""
        old = _result(ports=[PortInfo(port=53, protocol="tcp", state="open")])
        new = _result(ports=[PortInfo(port=53, protocol="udp", state="open")])
        diff = compute_diff(old, new)
        assert [(p.port, p.protocol) for p in diff.added_ports] == [(53, "udp")]
        assert [(p.port, p.protocol) for p in diff.removed_ports] == [(53, "tcp")]

    def test_service_version_drift_is_surfaced(self) -> None:
        """A version bump on the same port is real attack-surface drift and must
        appear in the diff (removed old + added new)."""
        old = _result(
            ports=[
                PortInfo(port=22, protocol="tcp", state="open", product="OpenSSH", version="8.2")
            ]
        )
        new = _result(
            ports=[
                PortInfo(port=22, protocol="tcp", state="open", product="OpenSSH", version="9.6")
            ]
        )
        diff = compute_diff(old, new)
        assert [p.version for p in diff.added_ports] == ["9.6"]
        assert [p.version for p in diff.removed_ports] == ["8.2"]
        assert diff.has_changes is True

    def test_subdomains_diff(self) -> None:
        old = _result(subs=[Subdomain(name="a.example.com", source="crt.sh")])
        new = _result(
            subs=[
                Subdomain(name="a.example.com", source="crt.sh"),
                Subdomain(name="b.example.com", source="dns-brute"),
            ]
        )
        diff = compute_diff(old, new)
        assert [s.name for s in diff.added_subdomains] == ["b.example.com"]
        assert diff.removed_subdomains == []

    def test_web_diff_by_url(self) -> None:
        old = _result(web=[WebFinding(url="https://example.com/a", status=200, length=1)])
        new = _result(web=[WebFinding(url="https://example.com/b", status=200, length=1)])
        diff = compute_diff(old, new)
        assert [f.url for f in diff.added_web] == ["https://example.com/b"]
        assert [f.url for f in diff.removed_web] == ["https://example.com/a"]

    def test_vulns_diff_by_cve_and_port(self) -> None:
        v_old = Vulnerability(title="X", severity=Severity.HIGH, source="nuclei", cve="CVE-1")
        v_new = Vulnerability(title="Y", severity=Severity.HIGH, source="nuclei", cve="CVE-2")
        old = _result(vulns=[v_old])
        new = _result(vulns=[v_old, v_new])
        diff = compute_diff(old, new)
        assert [v.cve for v in diff.added_vulns] == ["CVE-2"]
        assert diff.removed_vulns == []

    def test_no_changes(self) -> None:
        old = _result(ports=[_port(80)])
        new = _result(ports=[_port(80)])
        diff = compute_diff(old, new)
        assert diff.has_changes is False

    def test_has_changes_true_when_something_differs(self) -> None:
        diff = compute_diff(_result(), _result(ports=[_port(80)]))
        assert diff.has_changes is True
