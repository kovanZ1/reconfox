"""Network-scope safety helpers shared by the HTTP prober (SSRF guard) and the
target scope filter.

An address is treated as *private* — unsafe to reach unless the operator
explicitly opts in — when it is loopback, link-local (which includes the cloud
metadata address ``169.254.169.254``), private (RFC1918 / IPv6 ULA), reserved,
multicast or unspecified. Keeping this in one place means the redirect SSRF
guard and the ``--scope`` filter agree on what "internal" means.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket


def ip_is_private(ip: str) -> bool:
    """True if ``ip`` is an address a recon tool should not reach by accident."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


async def resolve_ips(host: str) -> list[str]:
    """Resolve ``host`` to all of its IPs (v4 + v6), de-duplicated in order.

    An IP literal is returned as-is (no lookup). Returns an empty list if the
    name cannot be resolved.
    """
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


async def host_is_private(host: str) -> bool:
    """True if ``host`` is (or resolves to) any private/internal address.

    Fail-closed: a host that cannot be resolved is reported as private, so an
    unresolvable redirect target is never followed.
    """
    ips = await resolve_ips(host)
    if not ips:
        return True
    return any(ip_is_private(ip) for ip in ips)
