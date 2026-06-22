"""Render ScanResult as GitHub-flavored Markdown."""

from __future__ import annotations

import html
from io import StringIO

from reconfox.models import ScanResult


def _md(value: object, default: str = "—") -> str:
    """Neutralize untrusted text so scan data can't inject Markdown or HTML.

    Scan output (service banners, page titles, URLs, redirect targets, error
    strings) is attacker-influenced, and the rendered Markdown is frequently
    converted to HTML downstream — so we HTML-escape and defang the table/inline
    metacharacters (``|`` and backticks) and flatten newlines.
    """
    if value is None:
        return default
    text = str(value)
    if not text:
        return default
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = html.escape(text, quote=False)
    return text.replace("|", "\\|").replace("`", "\\`")


def render_markdown(result: ScanResult) -> str:
    buf = StringIO()
    _header(buf, result)
    _target_block(buf, result)
    _subdomains_block(buf, result)
    _ports_block(buf, result)
    _http_block(buf, result)
    _web_block(buf, result)
    _vuln_block(buf, result)
    _errors_block(buf, result)
    _footer(buf, result)
    return buf.getvalue()


def _header(buf: StringIO, result: ScanResult) -> None:
    buf.write("# reconfox report\n\n")
    buf.write(f"**Target:** {_md(result.target.url)}  \n")
    buf.write(f"**Mode:** `{result.mode.value}`  \n")
    buf.write(f"**Status:** `{result.status.value}`  \n")
    buf.write(f"**Started:** {result.started_at.isoformat()}  \n")
    if result.duration_seconds is not None:
        buf.write(f"**Duration:** {result.duration_seconds:.0f} s  \n")
    buf.write("\n---\n\n")


def _target_block(buf: StringIO, result: ScanResult) -> None:
    t = result.target
    buf.write("## Цель\n\n")
    buf.write("| Поле | Значение |\n|---|---|\n")
    buf.write(f"| Hostname | {_md(t.hostname)} |\n")
    buf.write(f"| IP | {_md(t.ip)} |\n")
    buf.write(f"| Port | {t.port} |\n")
    buf.write(f"| HTTPS | {'да' if t.is_https else 'нет'} |\n")
    if t.asn:
        asn_str = f"AS{t.asn.asn} {t.asn.asn_name or ''}".strip()
        buf.write(f"| ASN | {_md(asn_str)} |\n")
        if t.asn.isp:
            buf.write(f"| ISP | {_md(t.asn.isp)} |\n")
    if t.geo:
        loc = ", ".join(filter(None, [t.geo.city, t.geo.region, t.geo.country]))
        if loc:
            buf.write(f"| Локация | {_md(loc)} |\n")
    buf.write("\n")


def _subdomains_block(buf: StringIO, result: ScanResult) -> None:
    if not result.subdomains:
        return
    buf.write("## Поддомены\n\n")
    buf.write("| Поддомен | IP | Источник |\n|---|---|---|\n")
    for s in sorted(result.subdomains, key=lambda x: x.name):
        buf.write(f"| {_md(s.name)} | {_md(s.ip)} | {_md(s.source)} |\n")
    buf.write("\n")


def _ports_block(buf: StringIO, result: ScanResult) -> None:
    if not result.ports:
        return
    buf.write("## Открытые порты\n\n")
    buf.write("| Порт | Proto | State | Service | Product | Version |\n")
    buf.write("|---|---|---|---|---|---|\n")
    for p in sorted(result.ports, key=lambda x: x.port):
        buf.write(
            f"| {p.port} | {p.protocol} | {p.state} | "
            f"{_md(p.service)} | {_md(p.product)} | {_md(p.version)} |\n"
        )
    buf.write("\n")


def _http_block(buf: StringIO, result: ScanResult) -> None:
    if not result.http_probes:
        return
    buf.write("## HTTP\n\n")
    buf.write("| URL | Status | Title | Server | Tech |\n|---|---|---|---|---|\n")
    for p in result.http_probes:
        status = "—" if p.status is None else str(p.status)
        tech = ", ".join(p.technologies) if p.technologies else "—"
        buf.write(
            f"| {_md(p.url)} | {status} | {_md(p.title)} | {_md(p.server)} | {_md(tech)} |\n"
        )
    buf.write("\n")


def _web_block(buf: StringIO, result: ScanResult) -> None:
    if not result.web_findings:
        return
    buf.write("## Веб-находки\n\n")
    buf.write("| URL | Status | Length | Redirect |\n|---|---|---|---|\n")
    for f in result.web_findings:
        buf.write(f"| {_md(f.url)} | {f.status} | {f.length} | {_md(f.redirect)} |\n")
    buf.write("\n")


def _vuln_block(buf: StringIO, result: ScanResult) -> None:
    if not result.vulnerabilities:
        return
    buf.write("## Уязвимости\n\n")
    by_sev = sorted(result.vulnerabilities, key=lambda v: -v.severity.score)
    for v in by_sev:
        port_info = f" (порт {v.affected_port})" if v.affected_port else ""
        cve_info = f" — {_md(v.cve)}" if v.cve else ""
        buf.write(f"### [{v.severity.value.upper()}] {_md(v.title)}{cve_info}{port_info}\n\n")
        buf.write(f"- **Источник:** {v.source}\n")
        if v.description:
            buf.write(f"- **Описание:** {_md(v.description)}\n")
        if v.metasploit_module:
            buf.write(f"- **Metasploit:** {_md(v.metasploit_module)}\n")
        if v.exploit_path:
            buf.write(f"- **Exploit:** {_md(v.exploit_path)}\n")
        for ref in v.references:
            buf.write(f"- {_md(ref)}\n")
        buf.write("\n")


def _errors_block(buf: StringIO, result: ScanResult) -> None:
    if not result.errors:
        return
    buf.write("## Ошибки\n\n")
    for err in result.errors:
        buf.write(f"- {_md(err)}\n")
    buf.write("\n")


def _footer(buf: StringIO, result: ScanResult) -> None:
    buf.write("---\n\n")
    buf.write("_Generated by [reconfox](https://github.com/kovanZ1/reconfox)._\n")
    if result.finished_at:
        buf.write(f"_Finished at: {result.finished_at.isoformat()}_\n")
