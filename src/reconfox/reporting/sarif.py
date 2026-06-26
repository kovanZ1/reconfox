"""Render ScanResult vulnerabilities as SARIF 2.1.0.

SARIF is the standard static-analysis result format consumed by GitHub / GitLab
code scanning, so emitting it lets reconfox findings show up in CI security
dashboards. Each Vulnerability becomes a SARIF result; severity maps to level.
"""

from __future__ import annotations

import json
import re

from reconfox import __version__
from reconfox.models import ScanResult, Severity, Vulnerability

_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-") or "finding"


def _rule_id(vuln: Vulnerability) -> str:
    return vuln.cve or _slug(vuln.title)


def render_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for v in result.vulnerabilities:
        rid = _rule_id(v)
        rules.setdefault(
            rid,
            {"id": rid, "name": v.title[:120], "shortDescription": {"text": v.title}},
        )
        message = v.title if not v.description else f"{v.title} — {v.description}"
        props: dict[str, object] = {"severity": v.severity.value, "source": v.source}
        if v.cve:
            props["cve"] = v.cve
        if v.affected_port is not None:
            props["port"] = v.affected_port
        results.append(
            {
                "ruleId": rid,
                "level": _LEVEL[v.severity],
                "message": {"text": message},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": result.target.url}}}
                ],
                "properties": props,
            }
        )

    doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reconfox",
                        "version": __version__,
                        "informationUri": "https://github.com/kovanZ1/reconfox",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
