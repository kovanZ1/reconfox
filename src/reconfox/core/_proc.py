"""Shared subprocess helper: run a command, with cancellation- and timeout-safe
child cleanup.

Without this, aborting a scan (``worker.cancel()``) or hitting a deadline would
leave long-running children like ``nmap -p-`` orphaned in the background.
"""

from __future__ import annotations

import asyncio
import contextlib


async def run_capture(
    binary: str,
    *args: str,
    # ASYNC109: a timeout param is deliberate here — this helper centralizes
    # killing the child on timeout, which a caller-side asyncio.timeout() can't do.
    timeout: float | None = None,  # noqa: ASYNC109
) -> tuple[int, bytes, bytes]:
    """Run ``binary args``; return (returncode, stdout, stderr).

    If ``timeout`` (seconds) is given and elapses, the child is killed and
    ``TimeoutError`` is raised. If the awaiting task is cancelled, the child is
    likewise killed before ``CancelledError`` propagates.
    """
    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        if timeout is None:
            stdout, stderr = await proc.communicate()
        else:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except (TimeoutError, asyncio.CancelledError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
            await proc.wait()
        raise
    return proc.returncode or 0, stdout, stderr
