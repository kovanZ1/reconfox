"""Tests for reconfox.core._http — size-capped HTTP body reads."""

from __future__ import annotations

import httpx
import respx

from reconfox.core._http import decode_body, fetch_capped


class TestFetchCapped:
    async def test_reads_small_body_whole(self) -> None:
        with respx.mock:
            respx.get("http://t.test/").mock(return_value=httpx.Response(200, text="hello"))
            async with httpx.AsyncClient() as client:
                response, body = await fetch_capped(client, "GET", "http://t.test/")
        assert response.status_code == 200
        assert body == b"hello"

    async def test_truncates_oversized_body(self) -> None:
        with respx.mock:
            respx.get("http://t.test/").mock(return_value=httpx.Response(200, text="x" * 10_000))
            async with httpx.AsyncClient() as client:
                _, body = await fetch_capped(client, "GET", "http://t.test/", max_bytes=100)
        assert len(body) <= 100

    async def test_decode_body_uses_charset(self) -> None:
        with respx.mock:
            respx.get("http://t.test/").mock(
                return_value=httpx.Response(
                    200,
                    content="héllo".encode(),
                    headers={"content-type": "text/html; charset=utf-8"},
                )
            )
            async with httpx.AsyncClient() as client:
                response, body = await fetch_capped(client, "GET", "http://t.test/")
        assert decode_body(response, body) == "héllo"
