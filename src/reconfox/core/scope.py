"""Engagement scope enforcement — keep active scans inside authorization.

For an authorized-pentest tool, hitting an out-of-scope host is a contract/legal
breach, so reconfox can hard-refuse targets before any active stage runs:

  --scope CIDR          allow-list; the resolved IP must fall inside one
  --out-of-scope CIDR   deny-list; the resolved IP must fall inside none
  (default)             a target resolving to a private/internal address is
                        refused unless --allow-private (blunts DNS-rebind and
                        mistyped-target from steering scans onto internal infra)

The check runs on the *resolved* IP inside the critical resolve stage, so an
out-of-scope target aborts before nmap/ffuf/nuclei ever touch it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

from reconfox.core.netguard import ip_is_private

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(RuntimeError):
    """Raised when a target is out of the authorized engagement scope."""


def _parse_networks(entries: Iterable[str]) -> list[IPNetwork]:
    nets: list[IPNetwork] = []
    for entry in entries:
        entry = entry.strip()
        if entry:
            nets.append(ipaddress.ip_network(entry, strict=False))
    return nets


@dataclass
class ScopePolicy:
    allow: list[IPNetwork] = field(default_factory=list)
    deny: list[IPNetwork] = field(default_factory=list)
    allow_private: bool = False

    @classmethod
    def from_cli(
        cls,
        scope: Iterable[str] = (),
        out_of_scope: Iterable[str] = (),
        allow_private: bool = False,
    ) -> ScopePolicy:
        """Build a policy from CLI flags. Raises ValueError on a bad CIDR."""
        return cls(
            allow=_parse_networks(scope),
            deny=_parse_networks(out_of_scope),
            allow_private=allow_private,
        )

    @property
    def is_active(self) -> bool:
        """True if the policy does anything (else it can be skipped entirely)."""
        return bool(self.allow) or bool(self.deny) or not self.allow_private

    def enforce(self, ip: str) -> None:
        """Raise ScopeError if ``ip`` is outside the authorized scope."""
        addr = ipaddress.ip_address(ip)
        if self.deny and any(addr in net for net in self.deny):
            raise ScopeError(f"{ip} is out of scope (matches --out-of-scope)")
        in_allow = bool(self.allow) and any(addr in net for net in self.allow)
        if self.allow and not in_allow:
            raise ScopeError(f"{ip} is not in scope (not in any --scope range)")
        # An explicit allow-list membership means the operator deliberately scoped
        # this range (which may be internal), so the private guard doesn't apply.
        if not self.allow_private and not in_allow and ip_is_private(ip):
            raise ScopeError(
                f"{ip} is a private/internal address — pass --allow-private to scan it"
            )
