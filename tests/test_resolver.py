"""Tests for reconfox.core.resolver."""

from __future__ import annotations

import httpx
import pytest
import respx

from reconfox.core.resolver import Resolver, ResolverError
from reconfox.models import Target

# Sample response from ip-api.com
IP_API_SUCCESS = {
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "region": "CA",
    "regionName": "California",
    "city": "San Francisco",
    "zip": "94107",
    "lat": 37.7621,
    "lon": -122.3971,
    "timezone": "America/Los_Angeles",
    "isp": "Cloudflare, Inc.",
    "org": "Cloudflare, Inc.",
    "as": "AS13335 Cloudflare, Inc.",
    "query": "1.1.1.1",
}

IP_API_FAILURE = {"status": "fail", "message": "invalid query", "query": "0.0.0.0"}  # noqa: S104


async def _fake_dns_ok(hostname: str) -> str:  # noqa: ARG001
    return "93.184.216.34"


async def _fake_dns_fail(hostname: str) -> str:
    raise ResolverError(f"DNS failure: {hostname}")


class TestResolver:
    async def test_resolves_hostname_to_ip(self) -> None:
        target = Target.from_url("https://example.com")
        async with httpx.AsyncClient() as client, respx.mock:
            respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(200, json=IP_API_SUCCESS)
            )
            resolver = Resolver(http_client=client, dns_resolver=_fake_dns_ok, enrich=True)
            enriched = await resolver.resolve(target)
        assert enriched.ip == "93.184.216.34"

    async def test_skip_dns_when_hostname_is_ip(self) -> None:
        target = Target.from_url("http://1.1.1.1")
        async with httpx.AsyncClient() as client, respx.mock:
            respx.get("http://ip-api.com/json/1.1.1.1").mock(
                return_value=httpx.Response(200, json=IP_API_SUCCESS)
            )
            resolver = Resolver(http_client=client, dns_resolver=_fake_dns_fail, enrich=True)
            enriched = await resolver.resolve(target)
        assert enriched.ip == "1.1.1.1"

    async def test_fills_geo_from_api(self) -> None:
        target = Target.from_url("https://example.com")
        async with httpx.AsyncClient() as client, respx.mock:
            respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(200, json=IP_API_SUCCESS)
            )
            resolver = Resolver(http_client=client, dns_resolver=_fake_dns_ok, enrich=True)
            enriched = await resolver.resolve(target)
        assert enriched.geo is not None
        assert enriched.geo.country == "United States"
        assert enriched.geo.city == "San Francisco"
        assert enriched.geo.lat == pytest.approx(37.7621)
        assert enriched.geo.timezone == "America/Los_Angeles"

    async def test_parses_asn_correctly(self) -> None:
        target = Target.from_url("https://example.com")
        async with httpx.AsyncClient() as client, respx.mock:
            respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(200, json=IP_API_SUCCESS)
            )
            resolver = Resolver(http_client=client, dns_resolver=_fake_dns_ok, enrich=True)
            enriched = await resolver.resolve(target)
        assert enriched.asn is not None
        assert enriched.asn.asn == 13335
        assert enriched.asn.asn_name == "Cloudflare, Inc."
        assert enriched.asn.isp == "Cloudflare, Inc."
        assert enriched.asn.org == "Cloudflare, Inc."

    async def test_dns_failure_raises(self) -> None:
        target = Target.from_url("https://nonexistent.invalid")
        async with httpx.AsyncClient() as client:
            resolver = Resolver(http_client=client, dns_resolver=_fake_dns_fail, enrich=True)
            with pytest.raises(ResolverError, match="DNS"):
                await resolver.resolve(target)

    async def test_geo_failure_is_not_fatal(self) -> None:
        """If ip-api returns an error, we keep the resolved IP but skip geo."""
        target = Target.from_url("https://example.com")
        async with httpx.AsyncClient() as client, respx.mock:
            respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(200, json=IP_API_FAILURE)
            )
            resolver = Resolver(http_client=client, dns_resolver=_fake_dns_ok, enrich=True)
            enriched = await resolver.resolve(target)
        assert enriched.ip == "93.184.216.34"
        assert enriched.geo is None
        assert enriched.asn is None

    async def test_http_5xx_is_not_fatal(self) -> None:
        target = Target.from_url("https://example.com")
        async with httpx.AsyncClient() as client, respx.mock:
            respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(500)
            )
            resolver = Resolver(http_client=client, dns_resolver=_fake_dns_ok, enrich=True)
            enriched = await resolver.resolve(target)
        assert enriched.ip == "93.184.216.34"
        assert enriched.geo is None

    async def test_works_as_async_context_manager(self) -> None:
        target = Target.from_url("https://example.com")
        with respx.mock:
            respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(200, json=IP_API_SUCCESS)
            )
            async with Resolver(dns_resolver=_fake_dns_ok, enrich=True) as resolver:
                enriched = await resolver.resolve(target)
        assert enriched.ip == "93.184.216.34"

    async def test_no_enrichment_by_default_is_opsec_safe(self) -> None:
        """Default: no third-party ip-api call, no geo/asn — but IP still resolved."""
        target = Target.from_url("https://example.com")
        with respx.mock:
            route = respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(200, json=IP_API_SUCCESS)
            )
            async with Resolver(dns_resolver=_fake_dns_ok) as resolver:
                enriched = await resolver.resolve(target)
        assert enriched.ip == "93.184.216.34"
        assert enriched.geo is None
        assert enriched.asn is None
        assert route.called is False

    async def test_no_http_client_created_when_not_enriching(self) -> None:
        """Without enrichment no HTTP client is created at all (no accidental traffic)."""
        resolver = Resolver(enrich=False)
        assert resolver._http is None

    async def test_proxy_is_stored_for_enrichment(self) -> None:
        # No eager owned client: the enrichment client is created per-request and
        # closed, so nothing leaks when the Resolver is used outside `async with`.
        resolver = Resolver(enrich=True, proxy="http://127.0.0.1:8080")
        assert resolver._proxy == "http://127.0.0.1:8080"
        assert resolver._http is None

    async def test_enrichment_without_injected_client_does_not_leak(self) -> None:
        """Enrichment works with no injected client (the per-request client is
        created and closed internally — the previous owned-client leak is gone)."""
        target = Target.from_url("https://example.com")
        with respx.mock:
            respx.get("http://ip-api.com/json/93.184.216.34").mock(
                return_value=httpx.Response(200, json=IP_API_SUCCESS)
            )
            resolver = Resolver(dns_resolver=_fake_dns_ok, enrich=True)
            assert resolver._http is None  # nothing owned/eager
            enriched = await resolver.resolve(target)
        assert enriched.geo is not None  # per-request client did the fetch
        assert enriched.asn is not None
