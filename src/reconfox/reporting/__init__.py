"""Report generation — Markdown and HTML."""

from reconfox.reporting.html import render_html
from reconfox.reporting.markdown import render_markdown
from reconfox.reporting.writer import ReportFormat, write_report

__all__ = ["ReportFormat", "render_html", "render_markdown", "write_report"]
