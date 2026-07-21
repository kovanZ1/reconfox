"""Subdomain enumeration — passive (crt.sh CT logs) + active (DNS bruteforce).

Subdomain discovery is the foundation of recon: it surfaces the forgotten
dev/staging/admin hosts that the typed-in target hides. This finder combines a
free passive source (crt.sh certificate transparency) with a small active DNS
bruteforce, deduplicates, and resolves each name to an IP.

OPSEC note: crt.sh is a third party and DNS bruteforce is noisy, so the stage
that drives this is opt-in (``--subdomains``).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from reconfox.core._http import decode_body, fetch_capped
from reconfox.core.resolver import DnsResolver, default_dns_resolver
from reconfox.models import Subdomain

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
DEFAULT_HTTP_TIMEOUT = 20.0

# Small built-in list — keeps a default run fast and seclists-free.
DEFAULT_SUBDOMAIN_WORDS: tuple[str, ...] = (
    "www", "mail", "ftp", "dev", "staging", "stage", "test", "api", "admin",
    "portal", "vpn", "remote", "ns1", "ns2", "smtp", "webmail", "secure", "shop",
    "blog", "m", "mobile", "app", "cdn", "static", "assets", "img", "beta", "demo",
    "git", "gitlab", "jenkins", "ci", "db", "backup", "dashboard", "internal",
    "intranet", "proxy", "gateway", "auth", "sso", "status", "monitor", "grafana",
    "kibana", "jira", "confluence",
)


class SubdomainFinder:
    def __init__(
        self,
        dns_resolver: DnsResolver = default_dns_resolver,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        proxy: str | None = None,
        wordlist: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self._dns = dns_resolver
        self.timeout = timeout
        self.proxy = proxy
        self.wordlist = tuple(wordlist) if wordlist is not None else DEFAULT_SUBDOMAIN_WORDS

    async def find(self, domain: str) -> list[Subdomain]:
        found: dict[str, dict[str, Any]] = {}
        for name in await self._crtsh(domain):
            found.setdefault(name, {"ip": None, "source": "crt.sh"})
        for name, ip in (await self._brute(domain)).items():
            if name in found:
                if found[name]["ip"] is None:
                    found[name]["ip"] = ip
            else:
                found[name] = {"ip": ip, "source": "dns-brute"}

        out: list[Subdomain] = []
        for name in sorted(found):
            info = found[name]
            ip = info["ip"]
            if ip is None:
                _, ip = await self._safe_resolve(name)
            out.append(Subdomain(name=name, ip=ip, source=info["source"]))
        return out

    async def _crtsh(self, domain: str) -> set[str]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, proxy=self.proxy) as client:
                response, body = await fetch_capped(
                    client, "GET", CRTSH_URL.format(domain=domain)
                )
        except httpx.HTTPError:
            return set()  # passive source is best-effort
        if response.status_code != 200:
            return set()
        return self._parse_crtsh(decode_body(response, body), domain)

    @staticmethod
    def _parse_crtsh(text: str, domain: str) -> set[str]:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return set()
        suffix = f".{domain}"
        names: set[str] = set()
        for entry in data if isinstance(data, list) else []:
            raw = str(entry.get("name_value", "")) if isinstance(entry, dict) else ""
            for line in raw.splitlines():
                name = line.strip().lstrip("*.").lower()
                if name and name != domain and name.endswith(suffix):
                    names.add(name)
        return names

    async def _brute(self, domain: str) -> dict[str, str]:
        candidates = [f"{word}.{domain}" for word in self.wordlist]
        results = await asyncio.gather(*(self._safe_resolve(c) for c in candidates))
        return {name: ip for name, ip in results if ip is not None}

    async def _safe_resolve(self, name: str) -> tuple[str, str | None]:
        try:
            return name, await self._dns(name)
        except Exception:  # noqa: BLE001 — any resolver failure means "no record"
            return name, None
