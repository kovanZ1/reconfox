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

    async def test_probe_blocks_redirect_to_internal_metadata_host(self) -> None:
        """A target that 302s to the cloud-metadata / internal host must NOT be
        followed there (SSRF guard), and the internal endpoint is never fetched."""
        with respx.mock:
            respx.get("http://t.test/").mock(
                return_value=httpx.Response(
                    302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
                )
            )
            meta = respx.get("http://169.254.169.254/latest/meta-data/").mock(
                return_value=httpx.Response(200, text="AWS_SECRET_KEY")
            )
            probe = await HttpProber().probe("http://t.test/")
        assert meta.call_count == 0  # internal endpoint never fetched
        assert probe.error is not None
        assert "169.254.169.254" in probe.error

    async def test_probe_allows_redirect_to_internal_when_opted_in(self) -> None:
        """allow_private=True (lab scanning) must let internal redirects through."""
        with respx.mock:
            respx.get("http://t.test/").mock(
                return_value=httpx.Response(302, headers={"Location": "http://127.0.0.1/app"})
            )
            respx.get("http://127.0.0.1/app").mock(
                return_value=httpx.Response(200, html="<title>Lab</title>")
            )
            probe = await HttpProber(allow_private=True).probe("http://t.test/")
        assert probe.status == 200
        assert probe.title == "Lab"

    async def test_probe_caps_oversized_body(self) -> None:
        """A hostile target streaming a huge body must be truncated, not loaded whole."""
        body = "x" * 100 + "<title>LATE</title>"  # title lives past the cap
        with respx.mock:
            respx.get("http://t.test/").mock(return_value=httpx.Response(200, html=body))
            probe = await HttpProber(max_bytes=16).probe("http://t.test/")
        assert probe.status == 200
        assert probe.title is None  # body truncated before the title tag
