"""Tests for reconfox.core.http_prober — httpx-based HTTP fingerprinting."""

from __future__ import annotations

import httpx
import respx

from reconfox.core.http_prober import HttpProber


class TestExtractTitle:
    def test_extracts_and_collapses_whitespace(self) -> None:
        assert HttpProber._extract_title("<title>  Hi\n   there </title>") == "Hi there"

    def test_case_insensitive(self) -> None:
        assert HttpProber._extract_title("<TITLE>Admin</TITLE>") == "Admin"

    def test_none_when_absent(self) -> None:
        assert HttpProber._extract_title("<html>no title here</html>") is None


class TestDetectTech:
    def test_from_server_and_powered_by(self) -> None:
        headers = httpx.Headers({"Server": "nginx/1.25", "X-Powered-By": "PHP/8.1"})
        techs = HttpProber._detect_tech(headers)
        assert "nginx" in techs
        assert "PHP" in techs

    def test_from_cookies(self) -> None:
        headers = httpx.Headers(
            [("set-cookie", "wordpress_logged_in=1"), ("set-cookie", "other=2")]
        )
        assert "WordPress" in HttpProber._detect_tech(headers)

    def test_empty_when_nothing_matches(self) -> None:
        assert HttpProber._detect_tech(httpx.Headers({"Server": "secret"})) == []


class TestProbe:
    async def test_probe_collects_fingerprint(self) -> None:
        with respx.mock:
            respx.get("http://t.test/").mock(
                return_value=httpx.Response(
                    200,
                    html="<html><head><title>Hello</title></head></html>",
                    headers={"Server": "nginx/1.25", "X-Powered-By": "PHP/8.1"},
                )
            )
            probe = await HttpProber().probe("http://t.test/")
        assert probe.status == 200
        assert probe.title == "Hello"
        assert probe.server == "nginx/1.25"
        assert "nginx" in probe.technologies
        assert "PHP" in probe.technologies
        assert probe.error is None

    async def test_probe_follows_redirects(self) -> None:
        with respx.mock:
            respx.get("http://t.test/").mock(
                return_value=httpx.Response(302, headers={"Location": "http://t.test/home"})
            )
            respx.get("http://t.test/home").mock(
                return_value=httpx.Response(200, html="<title>Home</title>")
            )
            probe = await HttpProber().probe("http://t.test/")
        assert probe.status == 200
        assert probe.final_url == "http://t.test/home"
        assert probe.title == "Home"

    async def test_probe_error_is_captured_not_raised(self) -> None:
        with respx.mock:
            respx.get("http://down.test/").mock(side_effect=httpx.ConnectError("refused"))
            probe = await HttpProber().probe("http://down.test/")
        assert probe.status is None
        assert probe.error
