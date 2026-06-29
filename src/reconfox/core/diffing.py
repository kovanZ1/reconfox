"""Diff two ScanResults — what appeared / disappeared between scans.

Useful for monitoring (cron a scan, diff against last run, alert only on new
findings) and for tracking how a target's attack surface drifts over time.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Sequence
from typing import TypeVar

from reconfox.models import ScanDiff, ScanResult

T = TypeVar("T")


def _diff(
    old: Sequence[T], new: Sequence[T], key: Callable[[T], Hashable]
) -> tuple[list[T], list[T]]:
    old_keys = {key(x) for x in old}
    new_keys = {key(x) for x in new}
    added = [x for x in new if key(x) not in old_keys]
    removed = [x for x in old if key(x) not in new_keys]
    return added, removed


def _label(result: ScanResult) -> str:
    return f"{result.target.hostname} @ {result.started_at.isoformat()}"


def compute_diff(old: ScanResult, new: ScanResult) -> ScanDiff:
    added_sub, removed_sub = _diff(old.subdomains, new.subdomains, lambda s: s.name)
    added_port, removed_port = _diff(old.ports, new.ports, lambda p: p.port)
    added_web, removed_web = _diff(old.web_findings, new.web_findings, lambda f: f.url)
    added_vuln, removed_vuln = _diff(
        old.vulnerabilities,
        new.vulnerabilities,
        lambda v: (v.cve or v.title, v.affected_port),
    )
    return ScanDiff(
        old_label=_label(old),
        new_label=_label(new),
        added_subdomains=added_sub,
        removed_subdomains=removed_sub,
        added_ports=added_port,
        removed_ports=removed_port,
        added_web=added_web,
        removed_web=removed_web,
        added_vulns=added_vuln,
        removed_vulns=removed_vuln,
    )
