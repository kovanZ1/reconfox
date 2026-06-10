"""Tests for reconfox.core.ffuf_scanner."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from reconfox.core.ffuf_scanner import FfufError, FfufScanner

SAMPLE_OUTPUT = json.dumps(
    {
        "commandline": "ffuf -u http://target/FUZZ -w common.txt",
        "time": "2026-06-10T12:00:00Z",
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "position": 1,
                "status": 200,
                "length": 1234,
                "words": 80,
                "lines": 42,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "http://target/admin",
                "duration": 12345678,
            },
            {
                "input": {"FUZZ": "login"},
                "position": 2,
                "status": 302,
                "length": 0,
                "words": 0,
                "lines": 0,
                "content-type": "text/html",
                "redirectlocation": "http://target/login.php",
                "url": "http://target/login",
                "duration": 1234567,
            },
            {
                "input": {"FUZZ": "private"},
                "position": 3,
                "status": 403,
                "length": 162,
                "words": 5,
                "lines": 7,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "http://target/private",
                "duration": 1234567,
            },
        ],
    }
)


class TestParseJson:
    def test_parses_findings(self) -> None:
        findings = FfufScanner.parse_json(SAMPLE_OUTPUT)
        assert len(findings) == 3
        admin = next(f for f in findings if "admin" in f.url)
        assert admin.status == 200
        assert admin.length == 1234
        assert admin.words == 80
        assert admin.lines == 42

    def test_parses_redirect(self) -> None:
        findings = FfufScanner.parse_json(SAMPLE_OUTPUT)
        login = next(f for f in findings if "login" in f.url)
        assert login.status == 302
        assert login.redirect == "http://target/login.php"

    def test_empty_results(self) -> None:
        empty = json.dumps({"commandline": "ffuf", "time": "now", "results": []})
        assert FfufScanner.parse_json(empty) == []

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(FfufError, match="parse"):
            FfufScanner.parse_json("not json")


class TestBuildArgs:
    def test_appends_fuzz_when_missing(self, tmp_path: Path) -> None:
        wl = tmp_path / "common.txt"
        wl.write_text("admin\nlogin\n")
        args = FfufScanner.build_args("http://target", wl, match_codes=[200, 403])
        assert "-u" in args
        idx = args.index("-u")
        assert args[idx + 1] == "http://target/FUZZ"
        assert "-w" in args
        assert str(wl) in args
        assert "-mc" in args
        idx = args.index("-mc")
        assert args[idx + 1] == "200,403"

    def test_keeps_existing_fuzz_marker(self, tmp_path: Path) -> None:
        wl = tmp_path / "x.txt"
        wl.write_text("a\n")
        args = FfufScanner.build_args(
            "http://target/api/FUZZ/users", wl, match_codes=[200]
        )
        idx = args.index("-u")
        assert args[idx + 1] == "http://target/api/FUZZ/users"

    def test_uses_json_output_to_stdout(self, tmp_path: Path) -> None:
        wl = tmp_path / "x.txt"
        wl.write_text("a\n")
        args = FfufScanner.build_args("http://target", wl, match_codes=[200])
        assert "-of" in args
        assert "json" in args
        assert "-o" in args
        idx = args.index("-o")
        assert args[idx + 1] == "/dev/stdout"

    def test_silences_progress(self, tmp_path: Path) -> None:
        wl = tmp_path / "x.txt"
        wl.write_text("a\n")
        args = FfufScanner.build_args("http://target", wl, match_codes=[200])
        assert "-s" in args  # silent

    def test_threads_flag(self, tmp_path: Path) -> None:
        wl = tmp_path / "x.txt"
        wl.write_text("a\n")
        args = FfufScanner.build_args(
            "http://target", wl, match_codes=[200], threads=80
        )
        idx = args.index("-t")
        assert args[idx + 1] == "80"

    def test_wordlist_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FfufError, match="wordlist"):
            FfufScanner.build_args(
                "http://target", tmp_path / "missing.txt", match_codes=[200]
            )


class TestFuzz:
    async def test_fuzz_returns_findings(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        wl = tmp_path / "wl.txt"
        wl.write_text("admin\n")

        async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:  # noqa: ARG001
            return _FakeProcess(stdout=SAMPLE_OUTPUT.encode(), stderr=b"", returncode=0)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        scanner = FfufScanner()
        findings = await scanner.fuzz("http://target", wl)
        assert len(findings) == 3

    async def test_fuzz_raises_on_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        wl = tmp_path / "wl.txt"
        wl.write_text("admin\n")

        async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProcess:  # noqa: ARG001
            return _FakeProcess(stdout=b"", stderr=b"some error", returncode=2)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        scanner = FfufScanner()
        with pytest.raises(FfufError, match="some error"):
            await scanner.fuzz("http://target", wl)


class _FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr
