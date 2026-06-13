"""Tests for reconfox.core.nmap_scanner."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from reconfox.core.nmap_scanner import NmapError, NmapScanner
from reconfox.models import ScanMode

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 93.184.216.34" start="1717000000">
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="ECS" version="1.0" extrainfo="">
          <cpe>cpe:/a:edgecast:edgecast</cpe>
        </service>
        <script id="http-title" output="Example Domain"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="ECS" version="1.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestParseXml:
    def test_parses_open_port_with_service(self) -> None:
        ports = NmapScanner.parse_xml(SAMPLE_XML)
        port80 = next(p for p in ports if p.port == 80)
        assert port80.state == "open"
        assert port80.protocol == "tcp"
        assert port80.service == "http"
        assert port80.product == "ECS"
        assert port80.version == "1.0"

    def test_parses_cpe_list(self) -> None:
        ports = NmapScanner.parse_xml(SAMPLE_XML)
        port80 = next(p for p in ports if p.port == 80)
        assert "cpe:/a:edgecast:edgecast" in port80.cpe

    def test_parses_scripts(self) -> None:
        ports = NmapScanner.parse_xml(SAMPLE_XML)
        port80 = next(p for p in ports if p.port == 80)
        assert port80.scripts.get("http-title") == "Example Domain"

    def test_parses_filtered_port(self) -> None:
        ports = NmapScanner.parse_xml(SAMPLE_XML)
        port22 = next(p for p in ports if p.port == 22)
        assert port22.state == "filtered"
        assert port22.service is None

    def test_returns_empty_on_no_hosts(self) -> None:
        empty_xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
        assert NmapScanner.parse_xml(empty_xml) == []

    def test_raises_on_malformed_xml(self) -> None:
        with pytest.raises(NmapError, match="parse"):
            NmapScanner.parse_xml("<<not xml>>")


class TestBuildArgs:
    def test_quick_mode_args(self) -> None:
        args = NmapScanner.build_args("1.1.1.1", ScanMode.QUICK)
        assert "1.1.1.1" in args
        assert "-F" in args  # top 100 ports
        assert "-sV" in args
        assert "-T4" in args
        assert "-oX" in args
        assert "-" in args  # XML to stdout

    def test_full_mode_args(self) -> None:
        args = NmapScanner.build_args("1.1.1.1", ScanMode.FULL)
        assert "-p-" in args  # all ports
        assert "-sV" in args
        assert "-sC" in args  # default scripts

    def test_stealth_mode_args(self) -> None:
        args = NmapScanner.build_args("1.1.1.1", ScanMode.STEALTH)
        assert "-sS" in args  # SYN stealth
        assert "-T2" in args
        assert "-f" in args  # fragmentation

    def test_custom_ports_override(self) -> None:
        args = NmapScanner.build_args("1.1.1.1", ScanMode.QUICK, ports="80,443,8080")
        assert "-p" in args
        idx = args.index("-p")
        assert args[idx + 1] == "80,443,8080"
        assert "-F" not in args  # explicit -p overrides default


class TestScanIntegration:
    """`scan` method with mocked subprocess."""

    async def test_scan_returns_ports(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:  # noqa: ARG001
            return _FakeProcess(stdout=SAMPLE_XML.encode(), stderr=b"", returncode=0)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        scanner = NmapScanner()
        ports = await scanner.scan("93.184.216.34", ScanMode.QUICK)
        assert len(ports) == 3
        assert any(p.port == 80 and p.state == "open" for p in ports)

    async def test_scan_raises_on_nonzero_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:  # noqa: ARG001
            return _FakeProcess(stdout=b"", stderr=b"permission denied", returncode=1)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        scanner = NmapScanner()
        with pytest.raises(NmapError, match="permission denied"):
            await scanner.scan("1.1.1.1", ScanMode.QUICK)

    async def test_scan_uses_custom_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[Any] = []

        async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:
            captured.append(args)
            return _FakeProcess(stdout=SAMPLE_XML.encode(), stderr=b"", returncode=0)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        scanner = NmapScanner(binary="/usr/local/bin/nmap")
        await scanner.scan("1.1.1.1", ScanMode.QUICK)
        assert captured[0][0] == "/usr/local/bin/nmap"

    async def test_scan_kills_process_on_cancel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Aborting a scan must kill the running nmap child, not orphan it."""
        proc = _CancellingProcess()

        async def fake_exec(*args: Any, **kwargs: Any) -> _CancellingProcess:  # noqa: ARG001
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        scanner = NmapScanner()
        with pytest.raises(asyncio.CancelledError):
            await scanner.scan("1.1.1.1", ScanMode.FULL)
        assert proc.killed is True


class _FakeProcess:
    """Minimal asyncio.subprocess.Process stand-in."""

    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


class _CancellingProcess:
    """Process whose communicate() is cancelled mid-flight."""

    def __init__(self) -> None:
        self.killed = False
        self.returncode: int | None = None

    async def communicate(self) -> tuple[bytes, bytes]:
        raise asyncio.CancelledError

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return 0
