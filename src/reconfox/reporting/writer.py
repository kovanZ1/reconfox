"""Persist rendered reports to disk."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

from reconfox.models import ScanResult
from reconfox.reporting.html import render_html
from reconfox.reporting.json_report import render_json
from reconfox.reporting.markdown import render_markdown
from reconfox.reporting.sarif import render_sarif


class ReportFormat(StrEnum):
    MARKDOWN = "md"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"


_SAFE_HOSTNAME = re.compile(r"[^a-zA-Z0-9._-]+")
_FORMAT_BY_SUFFIX: dict[str, ReportFormat] = {
    ".md": ReportFormat.MARKDOWN,
    ".markdown": ReportFormat.MARKDOWN,
    ".html": ReportFormat.HTML,
    ".htm": ReportFormat.HTML,
    ".json": ReportFormat.JSON,
    ".sarif": ReportFormat.SARIF,
}


def render(result: ScanResult, fmt: ReportFormat) -> str:
    if fmt == ReportFormat.HTML:
        return render_html(result)
    if fmt == ReportFormat.JSON:
        return render_json(result)
    if fmt == ReportFormat.SARIF:
        return render_sarif(result)
    return render_markdown(result)


def default_filename(result: ScanResult, fmt: ReportFormat) -> str:
    hostname = _SAFE_HOSTNAME.sub("_", result.target.hostname)
    timestamp = result.started_at.strftime("%Y-%m-%d_%H-%M-%S")
    return f"reconfox_{hostname}_{timestamp}.{fmt.value}"


def write_report(
    result: ScanResult,
    output_dir: Path,
    fmt: ReportFormat,
) -> Path:
    """Write report into output_dir with an auto-generated filename."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / default_filename(result, fmt)
    path.write_text(render(result, fmt), encoding="utf-8")
    return path


def write_report_to_file(result: ScanResult, file_path: Path) -> tuple[Path, ReportFormat]:
    """Write a report to an explicit file path. Format is inferred from extension.

    Returns the absolute path written and the format used.
    """
    file_path = file_path.expanduser().resolve()
    suffix = file_path.suffix.lower()
    if suffix not in _FORMAT_BY_SUFFIX:
        raise ValueError(
            f"unknown report extension {suffix!r}; "
            f"expected one of: {', '.join(sorted(_FORMAT_BY_SUFFIX))}"
        )
    fmt = _FORMAT_BY_SUFFIX[suffix]
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(render(result, fmt), encoding="utf-8")
    return file_path, fmt
