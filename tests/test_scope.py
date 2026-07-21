"""Tests for reconfox.core.scope — engagement scope enforcement."""

from __future__ import annotations

import pytest

from reconfox.core.scope import ScopeError, ScopePolicy


class TestPrivateGuard:
    def test_private_ip_refused_by_default(self) -> None:
        policy = ScopePolicy.from_cli()
        with pytest.raises(ScopeError, match="private"):
            policy.enforce("127.0.0.1")
        with pytest.raises(ScopeError, match="private"):
            policy.enforce("10.1.2.3")

    def test_public_ip_allowed_by_default(self) -> None:
        ScopePolicy.from_cli().enforce("93.184.216.34")  # no raise

    def test_allow_private_lets_internal_through(self) -> None:
        ScopePolicy.from_cli(allow_private=True).enforce("192.168.1.5")  # no raise


class TestAllowList:
    def test_ip_in_scope_allowed(self) -> None:
        ScopePolicy.from_cli(scope=["93.184.216.0/24"]).enforce("93.184.216.34")

    def test_ip_out_of_allow_list_refused(self) -> None:
        policy = ScopePolicy.from_cli(scope=["93.184.216.0/24"])
        with pytest.raises(ScopeError, match="not in scope"):
            policy.enforce("8.8.8.8")

    def test_allow_list_exempts_from_private_guard(self) -> None:
        # operator deliberately scoped an internal range → private guard must not fire
        ScopePolicy.from_cli(scope=["10.0.0.0/8"]).enforce("10.1.2.3")


class TestDenyList:
    def test_denied_ip_refused(self) -> None:
        policy = ScopePolicy.from_cli(out_of_scope=["8.8.8.0/24"])
        with pytest.raises(ScopeError, match="out of scope"):
            policy.enforce("8.8.8.8")

    def test_deny_takes_precedence_over_allow(self) -> None:
        policy = ScopePolicy.from_cli(scope=["8.8.0.0/16"], out_of_scope=["8.8.8.0/24"])
        with pytest.raises(ScopeError, match="out of scope"):
            policy.enforce("8.8.8.8")


class TestIsActive:
    def test_default_is_active_due_to_private_guard(self) -> None:
        assert ScopePolicy.from_cli().is_active is True

    def test_fully_permissive_is_inactive(self) -> None:
        assert ScopePolicy.from_cli(allow_private=True).is_active is False

    def test_bad_cidr_raises(self) -> None:
        with pytest.raises(ValueError):
            ScopePolicy.from_cli(scope=["not-a-cidr"])
