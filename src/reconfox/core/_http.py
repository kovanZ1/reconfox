"""Shared httpx helper: read a response body with a hard size ceiling.

The target and third-party sources (crt.sh, ip-api) are untrusted: an unbounded
read of a multi-gigabyte body (or a slow endless stream) would exhaust memory
and OOM-kill the scan. Every HTTP body read in reconfox goes through
``fetch_capped`` so no single response can do that.
"""

from __future__ import annotations

import httpx

# 5 MiB — generous for any HTML/JSON recon response, small enough to never OOM.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024


async def fetch_capped(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> tuple[httpx.Response, bytes]:
    """Perform ``method url`` reading at most ``max_bytes`` of the body.

    Returns ``(response, body)`` where ``body`` is the (possibly truncated)
    bytes read. Redirects are NOT followed here — the caller decides. Use the
    returned ``body``, not ``response.content`` (which is never fully read).
    """
    async with client.stream(method, url) as response:
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
    return response, b"".join(chunks)[:max_bytes]


def decode_body(response: httpx.Response, body: bytes) -> str:
    """Decode capped body bytes to text using the response's charset."""
    enc = response.charset_encoding or "utf-8"
    try:
        return body.decode(enc, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")
