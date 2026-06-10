"""Tests for reconfox.core.metasploit_finder — read-only msfrpcd search."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from reconfox.core.metasploit_finder import MetasploitFinder
from reconfox.models import PortInfo, Severity


class FakeModules:
    """Stand-in for pymetasploit3.msfrpc.MsfRpcClient.modules."""

    def __init__(self, results: list[dict[str, Any]] | None = None) -> None:
        self._results = results or []
        self.queries: list[str] = []

    def search(self, term: str) -> list[dict[str, Any]]:
        self.queries.append(term)
        return self._results


class FakeMsfRpc:
    def __init__(self, results: list[dict[str, Any]] | None = None) -> None:
        self.modules = FakeModules(results)


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: Any | None) -> None:
    """Replace the lazy MsfRpcClient factory used by MetasploitFinder."""
    from reconfox.core import metasploit_finder

    # In CI/dev env without pymetasploit3 installed, _msf_available is False.
    # Pretend the package is importable for these tests — only the connect call matters.
    monkeypatch.setattr(metasploit_finder, "_msf_available", True)

    if fake is None:
        def factory(*args: Any, **kwargs: Any) -> Any:  # noqa: ARG001
            raise ConnectionError("msfrpcd is down")
    else:
        def factory(*args: Any, **kwargs: Any) -> Any:  # noqa: ARG001
            return fake

    monkeypatch.setattr(metasploit_finder, "_connect", factory)


class TestFindForPort:
    async def test_skips_port_without_product(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeMsfRpc()
        _patch_client(monkeypatch, fake)
        finder = MetasploitFinder()
        vulns = await finder.find_for_port(PortInfo(port=80, protocol="tcp", state="open"))
        assert vulns == []
        assert fake.modules.queries == []

    async def test_maps_search_result_to_vulnerability(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeMsfRpc(
            results=[
                {
                    "type": "exploit",
                    "fullname": "exploit/windows/smb/ms17_010_eternalblue",
                    "name": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
                    "rank": "average",
                    "references": [["CVE", "2017-0144"], ["URL", "https://nvd.nist.gov/CVE-2017-0144"]],
                }
            ]
        )
        _patch_client(monkeypatch, fake)
        finder = MetasploitFinder()
        vulns = await finder.find_for_port(
            PortInfo(
                port=445, protocol="tcp", state="open",
                service="smb", product="Microsoft Windows SMB",
            )
        )
        assert len(vulns) == 1
        v = vulns[0]
        assert v.source == "metasploit"
        assert v.metasploit_module == "exploit/windows/smb/ms17_010_eternalblue"
        assert v.cve == "CVE-2017-0144"
        assert v.affected_port == 445
        assert v.affected_service == "smb"
        assert v.severity == Severity.MEDIUM  # rank=average → MEDIUM

    async def test_uses_product_in_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeMsfRpc()
        _patch_client(monkeypatch, fake)
        finder = MetasploitFinder()
        await finder.find_for_port(
            PortInfo(port=22, protocol="tcp", state="open", product="OpenSSH", version="7.2")
        )
        assert fake.modules.queries
        query = fake.modules.queries[0]
        assert "OpenSSH" in query

    async def test_skips_auxiliary_post_etc(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only exploits are surfaced as Vulnerability."""
        fake = FakeMsfRpc(
            results=[
                {
                    "type": "auxiliary", "fullname": "auxiliary/scanner/smb/x",
                    "name": "x", "rank": "normal",
                },
                {"type": "post", "fullname": "post/multi/x", "name": "y", "rank": "normal"},
                {"type": "exploit", "fullname": "exploit/x", "name": "z", "rank": "good"},
            ]
        )
        _patch_client(monkeypatch, fake)
        finder = MetasploitFinder()
        vulns = await finder.find_for_port(
            PortInfo(port=445, protocol="tcp", state="open", product="SMB")
        )
        assert len(vulns) == 1
        assert vulns[0].metasploit_module == "exploit/x"

    async def test_connection_failure_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, None)  # connection error
        finder = MetasploitFinder()
        vulns = await finder.find_for_port(
            PortInfo(port=445, protocol="tcp", state="open", product="SMB")
        )
        assert vulns == []

    async def test_rank_excellent_is_critical(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeMsfRpc(
            results=[
                {"type": "exploit", "fullname": "exploit/x", "name": "x",
                 "rank": "excellent", "references": [["CVE", "2024-1"]]},
            ]
        )
        _patch_client(monkeypatch, fake)
        finder = MetasploitFinder()
        vulns = await finder.find_for_port(
            PortInfo(port=80, protocol="tcp", state="open", product="nginx")
        )
        assert vulns[0].severity == Severity.CRITICAL


class TestFindForPorts:
    async def test_runs_for_each_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeMsfRpc()
        _patch_client(monkeypatch, fake)
        finder = MetasploitFinder()
        ports = [
            PortInfo(port=22, protocol="tcp", state="open", product="OpenSSH"),
            PortInfo(port=80, protocol="tcp", state="open", product="nginx"),
            PortInfo(port=443, protocol="tcp", state="open"),  # no product → skipped
        ]
        await finder.find_for_ports(ports)
        assert len(fake.modules.queries) == 2

    async def test_caches_client_across_ports(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One msfrpcd connection is reused for all ports in a run."""
        from reconfox.core import metasploit_finder

        fake = FakeMsfRpc()
        connect_calls = 0

        def factory(*args: Any, **kwargs: Any) -> Any:  # noqa: ARG001
            nonlocal connect_calls
            connect_calls += 1
            return fake

        monkeypatch.setattr(metasploit_finder, "_msf_available", True)
        monkeypatch.setattr(metasploit_finder, "_connect", factory)
        finder = MetasploitFinder()
        await finder.find_for_ports(
            [
                PortInfo(port=22, protocol="tcp", state="open", product="OpenSSH"),
                PortInfo(port=80, protocol="tcp", state="open", product="nginx"),
            ]
        )
        assert connect_calls == 1


def test_msfrpc_module_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing without pymetasploit3 installed must not crash."""
    # this simulates the import path being missing — covered by graceful _connect path
    from reconfox.core import metasploit_finder

    monkeypatch.setattr(metasploit_finder, "_msf_available", False)
    finder = MetasploitFinder()
    # use sync helper to verify it short-circuits when module is missing
    assert finder._client_available() is False


# silence unused-import warning for MagicMock — it's exported for future tests
_ = MagicMock
