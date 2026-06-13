"""Shared subprocess helper: run a command and kill the child on cancellation.

Without this, aborting a scan (worker.cancel()) leaves long-running children
like ``nmap -p-`` orphaned in the background.
"""

from __future__ import annotations

import asyncio
import contextlib


async def run_capture(binary: str, *args: str) -> tuple[int, bytes, bytes]:
    """Run ``binary args``; return (returncode, stdout, stderr).

    If the awaiting task is cancelled, the child process is killed before the
    CancelledError propagates.
    """
    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await proc.communicate()
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
            await proc.wait()
        raise
    return proc.returncode or 0, stdout, stderr
