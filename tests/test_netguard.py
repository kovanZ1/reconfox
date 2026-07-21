"""Tests for reconfox.core.netguard — private/internal address detection."""

from __future__ import annotations

import pytest

from reconfox.core import netguard


class TestIpIsPrivate:
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",  # loopback
            "10.0.0.5",  # RFC1918
            "192.168.1.1",  # RFC1918
            "172.16.0.1",  # RFC1918
            "169.254.169.254",  # link-local / cloud metadata
            "0.0.0.0",  # unspecified  # noqa: S104
            "::1",  # IPv6 loopback
            "fd00::1",  # IPv6 ULA
            "fe80::1",  # IPv6 link-local
        ],
    )
    def test_private_addresses(self, ip: str) -> None:
        assert netguard.ip_is_private(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
    def test_public_addresses(self, ip: str) -> None:
        assert netguard.ip_is_private(ip) is False

    def test_non_ip_is_not_private(self) -> None:
        assert netguard.ip_is_private("not-an-ip") is False


class TestResolveIps:
    async def test_ip_literal_returned_as_is(self) -> None:
        assert await netguard.resolve_ips("8.8.8.8") == ["8.8.8.8"]
        assert await netguard.resolve_ips("::1") == ["::1"]

    async def test_unresolvable_returns_empty(self) -> None:
        assert await netguard.resolve_ips("no.such.host.invalid") == []


class TestHostIsPrivate:
    async def test_private_ip_literal(self) -> None:
        assert await netguard.host_is_private("169.254.169.254") is True

    async def test_public_ip_literal(self) -> None:
        assert await netguard.host_is_private("8.8.8.8") is False

    async def test_unresolvable_is_private_fail_closed(self) -> None:
        assert await netguard.host_is_private("no.such.host.invalid") is True
