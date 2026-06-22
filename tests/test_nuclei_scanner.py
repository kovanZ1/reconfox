"""Tests for reconfox.core.nuclei_scanner — nuclei wrapper."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from reconfox.core.nuclei_scanner import NucleiScanner
from reconfox.models import Severity

SAMPLE_JSONL = "\n".join(
    [
        '{"template-id":"tech-detect","info":{"name":"Tech Detection","severity":"info"},'
        '"matched-at":"https://t/","host":"t"}',
        '{"template-id":"CVE-2021-1234","info":{"name":"Some RCE","severity":"critical",'
        '"description":"very bad","reference":["https://x.example"],'
        '"classification":{"cve-id":["CVE-2021-1234"]}},"matched-at":"https://t/x"}',
        "",  # blank line must be tolerated
        "not json at all",  # garbage line must be skipped
    ]
)


class TestParseJsonl:
    def test_parses_findings(self) -> None:
        vulns = NucleiScanner.parse_jsonl(SAMPLE_JSONL)
        assert len(vulns) == 2

    def test_maps_severity_and_source(self) -> None:
        vulns = NucleiScanner.parse_jsonl(SAMPLE_JSONL)
        assert vulns[0].severity == Severity.INFO
        assert vulns[0].title == "Tech Detection"
        assert vulns[0].source == "nuclei"

    def test_extracts_cve_description_references(self) -> None:
        rce = NucleiScanner.parse_jsonl(SAMPLE_JSONL)[1]
        assert rce.severity == Severity.CRITICAL
        assert rce.cve == "CVE-2021-1234"
        assert rce.description == "very bad"
        assert rce.references == ["https://x.example"]

    def test_empty_output(self) -> None:
        assert NucleiScanner.parse_jsonl("") == []


class TestScan:
    async def test_scan_returns_vulns_and_builds_args(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[Any] = []

        async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:  # noqa: ARG001
            captured.append(args)
            return _FakeProcess(SAMPLE_JSONL.encode(), b"", 0)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        vulns = await NucleiScanner().scan(["https://t/"])
        assert len(vulns) == 2
        flat = list(captured[0])
        assert "-u" in flat
        assert "https://t/" in flat
        assert "-jsonl" in flat

    async def test_empty_urls_skips_subprocess(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called = False

        async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:  # noqa: ARG001
            nonlocal called
            called = True
            return _FakeProcess(b"", b"", 0)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        assert await NucleiScanner().scan([]) == []
        assert called is False

    async def test_timeout_degrades_to_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proc = _HangingProcess()

        async def fake_exec(*args: Any, **kwargs: Any) -> _HangingProcess:  # noqa: ARG001
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        assert await NucleiScanner(timeout=0.05).scan(["https://t/"]) == []
        assert proc.killed is True


class _FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


class _HangingProcess:
    def __init__(self) -> None:
        self.killed = False
        self.returncode: int | None = None

    async def communicate(self) -> tuple[bytes, bytes]:
        await asyncio.sleep(30)
        return b"", b""

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return -9
