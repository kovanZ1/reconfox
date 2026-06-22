"""Scanner abstraction: the contract every recon stage implements.

A ``Scanner`` is a self-describing pipeline stage — it declares its name, the
phase it reports under, what it depends on, whether its failure is fatal, and
when it is applicable. The orchestrator is a generic driver that schedules
scanners by their dependencies; adding a new capability (subdomains, HTTP
probe, nuclei, ...) is "write a Scanner and register it", not "edit the
orchestrator".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from reconfox.models import ScanMode, ScanResult, Target

Phase = Literal[
    "subdomains", "resolve", "nmap", "ffuf", "http", "nuclei", "exploits", "report"
]
Status = Literal["started", "info", "completed", "failed"]


@dataclass(frozen=True)
class ProgressEvent:
    phase: Phase
    status: Status
    message: str | None = None
    duration_seconds: float | None = None


ProgressCallback = Callable[[ProgressEvent], None]

# emit(phase, status, message=None, duration=None) — supplied by the orchestrator.
EmitFn = Callable[..., None]


@dataclass
class ScanContext:
    """Everything a scanner reads/writes during a run.

    Scanners mutate ``result`` (append ports / web findings / vulnerabilities)
    and report via ``emit``; the shared target is enriched in place.
    """

    target: Target
    mode: ScanMode
    wordlist: Path
    result: ScanResult
    emit: EmitFn


@runtime_checkable
class Scanner(Protocol):
    """A single recon stage. Implementations wrap one tool/source."""

    name: str
    phase: Phase
    depends_on: tuple[str, ...]
    critical: bool

    def applicable(self, ctx: ScanContext) -> bool:
        """Whether this stage has work to do for the current context."""
        ...

    async def run(self, ctx: ScanContext) -> None:
        """Do the work, writing into ``ctx.result`` and emitting progress.

        Raise the tool's domain error on failure — the driver records it.
        """
        ...
