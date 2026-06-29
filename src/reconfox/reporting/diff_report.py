"""Render a ScanDiff as Markdown."""

from __future__ import annotations

from io import StringIO

from reconfox.models import ScanDiff, Vulnerability
from reconfox.reporting.markdown import _md


def render_diff_markdown(diff: ScanDiff) -> str:
    buf = StringIO()
    buf.write("# reconfox diff\n\n")
    buf.write(f"**Было:** {_md(diff.old_label)}  \n")
    buf.write(f"**Стало:** {_md(diff.new_label)}  \n\n---\n\n")

    if not diff.has_changes:
        buf.write("_Без изменений._\n")
        return buf.getvalue()

    _section(
        buf, "Поддомены",
        [f"{s.name} ({s.ip or '?'})" for s in diff.added_subdomains],
        [f"{s.name} ({s.ip or '?'})" for s in diff.removed_subdomains],
    )
    _section(
        buf, "Порты",
        [f"{p.port}/{p.protocol} {p.service or ''}".strip() for p in diff.added_ports],
        [f"{p.port}/{p.protocol} {p.service or ''}".strip() for p in diff.removed_ports],
    )
    _section(
        buf, "Веб-находки",
        [f"{f.status} {f.url}" for f in diff.added_web],
        [f"{f.status} {f.url}" for f in diff.removed_web],
    )
    _section(
        buf, "Уязвимости",
        [_vuln_label(v) for v in diff.added_vulns],
        [_vuln_label(v) for v in diff.removed_vulns],
    )
    return buf.getvalue()


def _vuln_label(v: Vulnerability) -> str:
    cve = f" — {v.cve}" if v.cve else ""
    return f"[{v.severity.value}] {v.title}{cve}"


def _section(buf: StringIO, title: str, added: list[str], removed: list[str]) -> None:
    if not added and not removed:
        return
    buf.write(f"## {title}\n\n")
    for item in added:
        buf.write(f"- ➕ {_md(item)}\n")
    for item in removed:
        buf.write(f"- ➖ {_md(item)}\n")
    buf.write("\n")
