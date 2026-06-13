"""Tests for reconfox.core._proc — the shared subprocess helper."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from reconfox.core._proc import run_capture


class _OkProcess:
    """Process whose communicate() returns immediately."""

    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


class _HangingProcess:
    """Process whose communicate() never returns — used to trigger a timeout."""

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


def _patch(monkeypatch: pytest.MonkeyPatch, proc: Any) -> None:
    async def fake_exec(*args: Any, **kwargs: Any) -> Any:  # noqa: ARG001
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)


class TestRunCapture:
    async def test_returns_rc_stdout_stderr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, _OkProcess(b"out", b"err", 0))
        rc, stdout, stderr = await run_capture("echo", "hi")
        assert rc == 0
        assert stdout == b"out"
        assert stderr == b"err"

    async def test_propagates_nonzero_returncode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, _OkProcess(b"", b"boom", 2))
        rc, _, stderr = await run_capture("false")
        assert rc == 2
        assert stderr == b"boom"

    async def test_works_with_explicit_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, _OkProcess(b"ok", b"", 0))
        rc, stdout, _ = await run_capture("echo", "hi", timeout=5.0)
        assert rc == 0
        assert stdout == b"ok"

    async def test_timeout_kills_child_and_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _HangingProcess()
        _patch(monkeypatch, proc)
        with pytest.raises(TimeoutError):
            await run_capture("sleep", "30", timeout=0.05)
        assert proc.killed is True

    async def test_cancellation_kills_child_and_reraises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _CancellingProcess()
        _patch(monkeypatch, proc)
        with pytest.raises(asyncio.CancelledError):
            await run_capture("sleep", "30")
        assert proc.killed is True
