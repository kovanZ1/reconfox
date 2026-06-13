"""Orchestrator — a generic driver that schedules Scanner stages by dependency.

The driver knows nothing about nmap/ffuf specifically: it runs every registered
stage whose dependencies are satisfied, in concurrent waves, isolating failures
so one broken scanner can't kill the run. A ``critical`` stage failing (resolve)
aborts the rest. New capabilities plug in via ``default_pipeline`` / a custom
stage list — no orchestrator edits required.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from reconfox.core.scanner import (
    Phase,
    ProgressCallback,
    ProgressEvent,
    ScanContext,
    Scanner,
    Status,
)
from reconfox.core.stages import default_pipeline
from reconfox.models import ScanMode, ScanResult, ScanStatus, Target

__all__ = [
    "Orchestrator",
    "Phase",
    "ProgressCallback",
    "ProgressEvent",
    "ScanContext",
    "Scanner",
    "Status",
    "default_pipeline",
]


class Orchestrator:
    def __init__(
        self,
        stages: Sequence[Scanner],
        wordlist: Path,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.stages = list(stages)
        self.wordlist = wordlist
        self._on_progress = on_progress

    def _emit(
        self,
        phase: Phase,
        status: Status,
        message: str | None = None,
        duration: float | None = None,
    ) -> None:
        if self._on_progress is None:
            return
        # Callback must not break the run — swallow any error it raises.
        with contextlib.suppress(Exception):
            self._on_progress(
                ProgressEvent(
                    phase=phase, status=status, message=message, duration_seconds=duration
                )
            )

    async def run(self, target_url: str, mode: ScanMode) -> ScanResult:
        started_at = datetime.now(UTC)

        try:
            target = Target.from_url(target_url)
        except ValueError as exc:
            return ScanResult(
                target=_placeholder_target(target_url),
                mode=mode,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status=ScanStatus.FAILED,
                errors=[f"target: {exc}"],
            )

        result = ScanResult(
            target=target,
            mode=mode,
            started_at=started_at,
            status=ScanStatus.RUNNING,
        )
        ctx = ScanContext(
            target=target,
            mode=mode,
            wordlist=self.wordlist,
            result=result,
            emit=self._emit,
        )
        await self._drive(ctx)
        result.finished_at = datetime.now(UTC)
        result.status = self._derive_status(result)
        return result

    async def _drive(self, ctx: ScanContext) -> None:
        """Run stages in dependency-ordered concurrent waves."""
        done: set[str] = set()
        remaining = list(self.stages)
        aborted = False
        while remaining and not aborted:
            ready = [s for s in remaining if all(dep in done for dep in s.depends_on)]
            if not ready:
                break  # unsatisfiable dependency — stop rather than spin
            outcomes = await asyncio.gather(*(self._run_stage(s, ctx) for s in ready))
            for stage, ok in zip(ready, outcomes, strict=True):
                done.add(stage.name)
                remaining.remove(stage)
                if not ok and stage.critical:
                    aborted = True

    async def _run_stage(self, stage: Scanner, ctx: ScanContext) -> bool:
        """Run one stage; return True on success/skip, False on failure."""
        if not stage.applicable(ctx):
            return True
        start = datetime.now(UTC)
        try:
            await stage.run(ctx)
        except Exception as exc:  # noqa: BLE001 — stage isolation; one failure must not kill the run
            self._emit(
                stage.phase, "failed", str(exc), (datetime.now(UTC) - start).total_seconds()
            )
            ctx.result.errors.append(f"{stage.phase}: {exc}")
            return False
        return True

    @staticmethod
    def _derive_status(result: ScanResult) -> ScanStatus:
        if not result.errors:
            return ScanStatus.COMPLETED
        if result.ports or result.web_findings:
            return ScanStatus.PARTIAL
        return ScanStatus.FAILED


def _placeholder_target(raw: str) -> Target:
    """Stand-in target when URL parsing fails — keeps ScanResult constructable."""
    return Target(url=raw, hostname="unknown", path="/", port=80, is_https=False)
