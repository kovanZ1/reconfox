"""URL → IP / ASN / Geolocation resolver.

DNS lookup is asynchronous and pluggable so tests can inject a fake resolver.
IP geolocation and ASN data are fetched from ip-api.com (free tier, 45 req/min).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from types import TracebackType
from typing import Any, Self

import httpx

from reconfox.models import ASNInfo, Geolocation, Target

DnsResolver = Callable[[str], Awaitable[str]]

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_TIMEOUT = 10.0
DNS_TIMEOUT = 5.0
_AS_FIELD_RE = re.compile(r"^AS(\d+)\s+(.+)$")


class ResolverError(RuntimeError):
    """Raised when DNS lookup fails or target cannot be enriched."""


async def default_dns_resolver(hostname: str) -> str:
    """Resolve hostname to an IPv4 address using the system resolver."""
    loop = asyncio.get_running_loop()
    try:
        results = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET),
            timeout=DNS_TIMEOUT,
        )
    except (TimeoutError, socket.gaierror, OSError) as exc:
        raise ResolverError(f"DNS resolution failed for {hostname}: {exc}") from exc
    if not results:
        raise ResolverError(f"DNS returned no records for {hostname}")
    return results[0][4][0]


class Resolver:
    """Enrich a Target with IP, ASN and Geolocation."""

    def __init__(
        self,
        http_client: httpx.AsyncClient | None = None,
        dns_resolver: DnsResolver = default_dns_resolver,
    ) -> None:
        self._http = http_client or httpx.AsyncClient(timeout=IP_API_TIMEOUT)
        self._owns_http = http_client is None
        self._dns_resolver = dns_resolver

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def resolve(self, target: Target) -> Target:
        target.ip = await self._resolve_ip(target.hostname)
        geo, asn = await self._fetch_ip_meta(target.ip)
        target.geo = geo
        target.asn = asn
        return target

    async def _resolve_ip(self, hostname: str) -> str:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return await self._dns_resolver(hostname)
        return hostname

    async def _fetch_ip_meta(self, ip: str) -> tuple[Geolocation | None, ASNInfo | None]:
        try:
            response = await self._http.get(IP_API_URL.format(ip=ip))
        except httpx.HTTPError:
            return None, None
        if response.status_code != 200:
            return None, None
        try:
            data: dict[str, Any] = response.json()
        except ValueError:
            return None, None
        if data.get("status") != "success":
            return None, None
        return self._parse_geo(data), self._parse_asn(data)

    @staticmethod
    def _parse_geo(data: dict[str, Any]) -> Geolocation:
        return Geolocation(
            country=data.get("country"),
            country_code=data.get("countryCode"),
            region=data.get("regionName"),
            city=data.get("city"),
            lat=data.get("lat"),
            lon=data.get("lon"),
            timezone=data.get("timezone"),
        )

    @staticmethod
    def _parse_asn(data: dict[str, Any]) -> ASNInfo:
        as_field = data.get("as", "")
        asn_number: int | None = None
        asn_name: str | None = None
        match = _AS_FIELD_RE.match(as_field)
        if match:
            asn_number = int(match.group(1))
            asn_name = match.group(2)
        return ASNInfo(
            asn=asn_number,
            asn_name=asn_name,
            isp=data.get("isp"),
            org=data.get("org"),
        )
