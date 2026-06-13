"""Report generation — Markdown / HTML / JSON."""

from reconfox.reporting.html import render_html
from reconfox.reporting.json_report import render_json
from reconfox.reporting.markdown import render_markdown
from reconfox.reporting.ndjson import render_ndjson
from reconfox.reporting.writer import (
    ReportFormat,
    default_filename,
    render,
    write_report,
    write_report_to_file,
)

__all__ = [
    "ReportFormat",
    "default_filename",
    "render",
    "render_html",
    "render_json",
    "render_markdown",
    "render_ndjson",
    "write_report",
    "write_report_to_file",
]
