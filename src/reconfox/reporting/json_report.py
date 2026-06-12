"""Render ScanResult as machine-readable JSON."""

from __future__ import annotations

import json

from reconfox.models import ScanResult


def render_json(result: ScanResult, indent: int | None = 2) -> str:
    """Serialize a ScanResult to JSON using pydantic's own JSON encoder."""
    return result.model_dump_json(indent=indent)


def render_json_compact(result: ScanResult) -> str:
    """One-line JSON, useful for piping into jq."""
    return json.dumps(json.loads(result.model_dump_json()), separators=(",", ":"))
