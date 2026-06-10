"""Render ScanResult as a self-contained HTML report with inline dark-theme CSS."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from reconfox.models import ScanResult

_env = Environment(
    loader=PackageLoader("reconfox.reporting", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(result: ScanResult) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(result=result)
