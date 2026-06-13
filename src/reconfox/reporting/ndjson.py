"""Render ScanResult as newline-delimited JSON (NDJSON / JSONL).

One JSON object per line so the output streams cleanly into other tools
(``reconfox ... | jq``, ``| nuclei``, etc.). Each record carries a ``type`` and
the host it belongs to; the first line is the target, the last is a summary.
The schema is versioned so consumers can depend on it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from reconfox.models import ScanResult

SCHEMA_VERSION = "1.0"


def _records(result: ScanResult) -> Iterator[dict]:
    t = result.target
    host = t.hostname
    yield {
        "type": "target",
        "schema_version": SCHEMA_VERSION,
        "url": t.url,
        "hostname": host,
        "ip": t.ip,
        "mode": result.mode.value,
    }
    for p in result.ports:
        yield {
            "type": "port",
            "host": host,
            "port": p.port,
            "protocol": p.protocol,
            "state": p.state,
            "service": p.service,
            "product": p.product,
            "version": p.version,
        }
    for f in result.web_findings:
        yield {
            "type": "web",
            "host": host,
            "url": f.url,
            "status": f.status,
            "length": f.length,
            "redirect": f.redirect,
        }
    for v in result.vulnerabilities:
        yield {
            "type": "vuln",
            "host": host,
            "title": v.title,
            "severity": v.severity.value,
            "cve": v.cve,
            "source": v.source,
            "affected_port": v.affected_port,
        }
    yield {
        "type": "summary",
        "schema_version": SCHEMA_VERSION,
        "host": host,
        "status": result.status.value,
        "ports": len(result.ports),
        "web": len(result.web_findings),
        "vulns": len(result.vulnerabilities),
        "errors": result.errors,
    }


def render_ndjson(result: ScanResult) -> str:
    """Serialize a ScanResult as NDJSON — one compact JSON object per line."""
    return "".join(
        json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
        for rec in _records(result)
    )
