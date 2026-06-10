"""Persist rendered reports to disk."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

from reconfox.models import ScanResult
from reconfox.reporting.html import render_html
from reconfox.reporting.markdown import render_markdown


class ReportFormat(StrEnum):
    MARKDOWN = "md"
    HTML = "html"


_SAFE_HOSTNAME = re.compile(r"[^a-zA-Z0-9._-]+")


def write_report(
    result: ScanResult,
    output_dir: Path,
    fmt: ReportFormat,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    hostname = _SAFE_HOSTNAME.sub("_", result.target.hostname)
    timestamp = result.started_at.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reconfox_{hostname}_{timestamp}.{fmt.value}"
    path = output_dir / filename
    content = render_html(result) if fmt == ReportFormat.HTML else render_markdown(result)
    path.write_text(content, encoding="utf-8")
    return path
