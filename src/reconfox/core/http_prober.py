"""HTTP fingerprinting — talk HTTP(S) to the target and describe what answers.

Unlike nmap's banner, this captures what a pentester actually triages on: final
URL after redirects, page title, Server header and a best-effort technology
guess from headers/cookies. Probing the target itself is the authorized action,
so it is on by default (the third-party ip-api enrichment is the one that is not).
"""

from __future__ import annotations

import re
from collections.abc import Mapping

import httpx

from reconfox.core._http import MAX_RESPONSE_BYTES, decode_body, fetch_capped
from reconfox.core.netguard import host_is_private
from reconfox.models import HttpProbe

DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 10

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class _RedirectBlocked(Exception):
    """A redirect was refused by the SSRF guard (internal/private destination)."""

# (header, lowercase-needle, technology) — best-effort, header/cookie based.
_TECH_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "microsoft-iis", "IIS"),
    ("server", "litespeed", "LiteSpeed"),
    ("server", "gunicorn", "Gunicorn"),
    ("server", "caddy", "Caddy"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express"),
    ("x-powered-by", "next.js", "Next.js"),
    ("x-generator", "drupal", "Drupal"),
    ("x-generator", "wordpress", "WordPress"),
    ("set-cookie", "wordpress_", "WordPress"),
    ("set-cookie", "wp-settings", "WordPress"),
    ("set-cookie", "laravel_session", "Laravel"),
    ("set-cookie", "csrftoken", "Django"),
    ("set-cookie", "phpsessid", "PHP"),
    ("set-cookie", "jsessionid", "Java"),
]


class HttpProber:
    """Fetch a URL and summarise the response into an HttpProbe."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        verify: bool = False,
        proxy: str | None = None,
        allow_private: bool = False,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        # verify=False by default: recon targets routinely have self-signed certs,
        # and we still want to fingerprint them. See roadmap: make this explicit.
        self.timeout = timeout
        self.verify = verify
        self.proxy = proxy
        # allow_private=True lets redirects reach internal hosts (lab scanning);
        # by default a target cannot steer the prober at 169.254.169.254 etc.
        self.allow_private = allow_private
        self.max_bytes = max_bytes

    async def probe(self, url: str) -> HttpProbe:
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=self.timeout,
                verify=self.verify,
                proxy=self.proxy,
            ) as client:
                response, body = await self._fetch(client, url)
        except _RedirectBlocked as exc:
            return HttpProbe(url=url, error=str(exc))
        except httpx.HTTPError as exc:
            return HttpProbe(url=url, error=str(exc) or exc.__class__.__name__)

        return HttpProbe(
            url=url,
            status=response.status_code,
            final_url=str(response.url),
            title=self._extract_title(decode_body(response, body)),
            server=response.headers.get("server"),
            technologies=self._detect_tech(response.headers),
            content_length=_content_length(response, body),
        )

    async def _fetch(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[httpx.Response, bytes]:
        """Follow redirects manually, guarding each hop against internal hosts.

        The initial URL is the operator's explicit choice and is always fetched;
        redirects that leave for a *different* private/internal host are refused
        (SSRF). With a proxy set, DNS happens at the proxy, so the guard — which
        resolves locally — is skipped.
        """
        initial_host = httpx.URL(url).host
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            response, body = await fetch_capped(client, "GET", current, self.max_bytes)
            location = response.headers.get("location")
            if not response.is_redirect or not location:
                return response, body
            next_url = httpx.URL(response.url).join(location)
            if not self.allow_private and self.proxy is None:
                host = next_url.host
                if host != initial_host and await host_is_private(host):
                    raise _RedirectBlocked(
                        f"blocked redirect to internal host {host} (SSRF guard)"
                    )
            current = str(next_url)
        raise _RedirectBlocked(f"too many redirects (>{MAX_REDIRECTS})")

    @staticmethod
    def _extract_title(body: str) -> str | None:
        match = _TITLE_RE.search(body)
        if not match:
            return None
        title = " ".join(match.group(1).split())
        return title[:200] or None

    @staticmethod
    def _detect_tech(headers: Mapping[str, str]) -> list[str]:
        techs: list[str] = []
        for header_name, needle, tech in _TECH_SIGNATURES:
            values = _header_values(headers, header_name).lower()
            if needle in values and tech not in techs:
                techs.append(tech)
        return techs


def _header_values(headers: Mapping[str, str], name: str) -> str:
    # httpx.Headers stores repeated headers (e.g. Set-Cookie) separately.
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        return " ".join(get_list(name))
    return headers.get(name, "")


def _content_length(response: httpx.Response, body: bytes) -> int | None:
    raw = response.headers.get("content-length")
    if raw is not None:
        try:
            return int(raw)
        except ValueError:
            pass
    return len(body)
