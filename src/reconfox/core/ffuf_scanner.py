"""Async wrapper around ffuf for directory and content discovery.

ffuf writes its JSON report to a real file (``-o``); we read it back afterwards.
Writing to a temp file instead of ``/dev/stdout`` avoids ffuf's silent-mode and
buffering quirks that produced empty / unparseable stdout on some targets.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
from pathlib import Path

from reconfox.core._proc import run_capture
from reconfox.models import WebFinding


class FfufError(RuntimeError):
    """Raised when ffuf fails or its output cannot be parsed."""


DEFAULT_MATCH_CODES = (200, 301, 302, 307, 401, 403, 405)
DEFAULT_THREADS = 40
DEFAULT_TIMEOUT = 900.0  # seconds — anti-hang ceiling, override via FfufScanner(timeout=...)


class FfufScanner:
    def __init__(
        self,
        binary: str = "ffuf",
        timeout: float | None = None,
        threads: int = DEFAULT_THREADS,
        rate: int | None = None,
    ) -> None:
        self.binary = binary
        self.timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
        self.threads = threads
        self.rate = rate

    @staticmethod
    def build_args(
        target_url: str,
        wordlist: Path,
        output_file: Path,
        match_codes: list[int] | tuple[int, ...] = DEFAULT_MATCH_CODES,
        threads: int = DEFAULT_THREADS,
        rate: int | None = None,
    ) -> list[str]:
        if not wordlist.exists():
            raise FfufError(f"wordlist not found: {wordlist}")
        url = target_url if "FUZZ" in target_url else target_url.rstrip("/") + "/FUZZ"
        args = [
            "-u", url,
            "-w", str(wordlist),
            "-mc", ",".join(str(c) for c in match_codes),
            "-t", str(threads),
        ]
        if rate is not None and rate > 0:
            args.extend(["-rate", str(rate)])
        args.extend(["-of", "json", "-o", str(output_file), "-s"])
        return args

    async def fuzz(
        self,
        target_url: str,
        wordlist: Path,
        match_codes: list[int] | tuple[int, ...] = DEFAULT_MATCH_CODES,
        threads: int | None = None,
        rate: int | None = None,
    ) -> list[WebFinding]:
        threads = threads if threads is not None else self.threads
        rate = rate if rate is not None else self.rate
        fd, tmp_name = tempfile.mkstemp(prefix="reconfox_ffuf_", suffix=".json")
        os.close(fd)
        out_path = Path(tmp_name)
        try:
            args = self.build_args(target_url, wordlist, out_path, match_codes, threads, rate)
            try:
                rc, _, stderr = await run_capture(self.binary, *args, timeout=self.timeout)
            except TimeoutError as exc:
                raise FfufError(f"ffuf timed out after {self.timeout:.0f}s") from exc
            except FileNotFoundError as exc:
                raise FfufError(
                    f"{self.binary} not found — install ffuf (e.g. sudo apt install ffuf)"
                ) from exc
            if rc != 0:
                err = stderr.decode(errors="replace").strip() or "unknown ffuf error"
                raise FfufError(f"ffuf exited with code {rc}: {err}")
            raw = await asyncio.to_thread(
                out_path.read_text, encoding="utf-8", errors="replace"
            )
            return self.parse_json(raw)
        finally:
            with contextlib.suppress(OSError):
                await asyncio.to_thread(out_path.unlink)

    @staticmethod
    def parse_json(output: str) -> list[WebFinding]:
        # ffuf can legitimately produce an empty file (no matches / blocked target).
        if not output.strip():
            return []
        try:
            data = json.loads(output)
        except json.JSONDecodeError as exc:
            raise FfufError(f"could not parse ffuf JSON: {exc}") from exc

        findings: list[WebFinding] = []
        for item in data.get("results", []):
            redirect = item.get("redirectlocation") or None
            findings.append(
                WebFinding(
                    url=item["url"],
                    status=item["status"],
                    length=item["length"],
                    words=item.get("words"),
                    lines=item.get("lines"),
                    redirect=redirect,
                )
            )
        return findings
