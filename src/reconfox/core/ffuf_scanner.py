"""Async wrapper around ffuf for directory and content discovery."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from reconfox.models import WebFinding


class FfufError(RuntimeError):
    """Raised when ffuf fails or its output cannot be parsed."""


DEFAULT_MATCH_CODES = (200, 301, 302, 307, 401, 403, 405)
DEFAULT_THREADS = 40


class FfufScanner:
    def __init__(self, binary: str = "ffuf") -> None:
        self.binary = binary

    @staticmethod
    def build_args(
        target_url: str,
        wordlist: Path,
        match_codes: list[int] | tuple[int, ...] = DEFAULT_MATCH_CODES,
        threads: int = DEFAULT_THREADS,
    ) -> list[str]:
        if not wordlist.exists():
            raise FfufError(f"wordlist not found: {wordlist}")
        url = target_url if "FUZZ" in target_url else target_url.rstrip("/") + "/FUZZ"
        return [
            "-u",
            url,
            "-w",
            str(wordlist),
            "-mc",
            ",".join(str(c) for c in match_codes),
            "-t",
            str(threads),
            "-of",
            "json",
            "-o",
            "/dev/stdout",
            "-s",
        ]

    async def fuzz(
        self,
        target_url: str,
        wordlist: Path,
        match_codes: list[int] | tuple[int, ...] = DEFAULT_MATCH_CODES,
        threads: int = DEFAULT_THREADS,
    ) -> list[WebFinding]:
        args = self.build_args(target_url, wordlist, match_codes, threads)
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip() or "unknown ffuf error"
            raise FfufError(f"ffuf exited with code {proc.returncode}: {err}")
        return self.parse_json(stdout.decode(errors="replace"))

    @staticmethod
    def parse_json(output: str) -> list[WebFinding]:
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
