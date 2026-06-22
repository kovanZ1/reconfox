"""Tests for reconfox.core.subdomain_finder."""

from __future__ import annotations

import httpx
import respx

from reconfox.core.resolver import ResolverError
from reconfox.core.subdomain_finder import SubdomainFinder

CRTSH_SAMPLE = [
    {"name_value": "www.example.com"},
    {"name_value": "admin.example.com\nwww.example.com"},  # multi-line, duplicate
    {"name_value": "*.example.com"},  # wildcard → stripped → apex, excluded
    {"name_value": "example.com"},  # apex itself, excluded
    {"name_value": "other.notexample.com"},  # different domain, excluded
]

_KNOWN = {"www.example.com": "1.1.1.1", "api.example.com": "2.2.2.2"}


async def _fake_dns(name: str) -> str:
    if name in _KNOWN:
        return _KNOWN[name]
    raise ResolverError(f"NXDOMAIN: {name}")


class TestParseCrtsh:
    def test_collects_subdomains_excludes_apex_and_others(self) -> None:
        import json

        names = SubdomainFinder._parse_crtsh(json.dumps(CRTSH_SAMPLE), "example.com")
        assert "www.example.com" in names
        assert "admin.example.com" in names
        assert "example.com" not in names  # apex excluded
        assert "other.notexample.com" not in names  # other domain excluded
        assert not any(n.startswith("*") for n in names)  # wildcards stripped

    def test_bad_json_returns_empty(self) -> None:
        assert SubdomainFinder._parse_crtsh("not json", "example.com") == set()


class TestFind:
    async def test_merges_passive_and_active(self) -> None:
        with respx.mock:
            respx.get(url__regex=r"https://crt\.sh/.*").mock(
                return_value=httpx.Response(200, json=CRTSH_SAMPLE)
            )
            finder = SubdomainFinder(dns_resolver=_fake_dns, wordlist=["www", "api", "nope"])
            subs = await finder.find("example.com")

        by_name = {s.name: s for s in subs}
        # www: from crt.sh, resolvable
        assert by_name["www.example.com"].ip == "1.1.1.1"
        assert by_name["www.example.com"].source == "crt.sh"
        # admin: from crt.sh, not resolvable → ip None, still reported
        assert by_name["admin.example.com"].ip is None
        # api: found only by brute force
        assert by_name["api.example.com"].source == "dns-brute"
        assert by_name["api.example.com"].ip == "2.2.2.2"
        # nope: not resolvable and not in crt.sh → absent
        assert "nope.example.com" not in by_name

    async def test_crtsh_failure_still_returns_brute(self) -> None:
        with respx.mock:
            respx.get(url__regex=r"https://crt\.sh/.*").mock(
                side_effect=httpx.ConnectError("down")
            )
            finder = SubdomainFinder(dns_resolver=_fake_dns, wordlist=["api"])
            subs = await finder.find("example.com")
        names = {s.name for s in subs}
        assert names == {"api.example.com"}
