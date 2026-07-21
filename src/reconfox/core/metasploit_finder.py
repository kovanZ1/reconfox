"""Metasploit Framework RPC client — READ-ONLY module discovery.

This wrapper deliberately never EXECUTES modules — it only queries `msfrpcd`
for matching exploit modules by service product/version and surfaces them as
Vulnerability records. Running exploits is out of scope for reconfox.

Requires `msfrpcd -P <password> -S` running on localhost (or wherever you point it).
`pymetasploit3` is an optional dependency: install via `pip install reconfox[msf]`.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from reconfox.models import PortInfo, Severity, Vulnerability

MIN_PRODUCT_LEN = 2

# Passwords a security tool must refuse to connect with: unset, or the value
# historically shipped in .env.example. Refusing to authenticate with a public
# well-known default avoids nudging the operator toward an exposed msfrpcd.
_INSECURE_MSF_PASSWORDS = frozenset({"", "changeme"})  # noqa: S105


class MetasploitError(RuntimeError):
    """Raised for a misconfigured Metasploit RPC connection (e.g. default password)."""


try:
    from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore[import-not-found]

    _msf_available = True
except ImportError:  # pragma: no cover
    MsfRpcClient = None  # type: ignore[assignment,misc]
    _msf_available = False


# Maps Metasploit module "rank" → reconfox Severity.
# https://docs.metasploit.com/docs/development/developing-modules/guides/exploit-ranking.html
_RANK_TO_SEVERITY: dict[str, Severity] = {
    "excellent": Severity.CRITICAL,
    "great": Severity.HIGH,
    "good": Severity.HIGH,
    "normal": Severity.MEDIUM,
    "average": Severity.MEDIUM,
    "low": Severity.LOW,
    "manual": Severity.INFO,
}


def _connect(
    password: str, server: str, port: int, ssl: bool, username: str
) -> Any:
    """Thin wrapper so tests can monkeypatch the client factory."""
    if not _msf_available:  # pragma: no cover
        raise RuntimeError("pymetasploit3 not installed")
    return MsfRpcClient(password, server=server, port=port, ssl=ssl, username=username)


class MetasploitFinder:
    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ssl: bool | None = None,
    ) -> None:
        self.host = host or os.environ.get("MSF_RPC_HOST", "127.0.0.1")
        self.port = port or int(os.environ.get("MSF_RPC_PORT", "55553"))
        self.username = username or os.environ.get("MSF_RPC_USER", "msf")
        self.password = password or os.environ.get("MSF_RPC_PASS", "")
        env_ssl = os.environ.get("MSF_RPC_SSL", "true").lower() in {"1", "true", "yes"}
        self.ssl = ssl if ssl is not None else env_ssl
        self._client: Any | None = None

    def _client_available(self) -> bool:
        if not _msf_available:
            return False
        if self.password in _INSECURE_MSF_PASSWORDS:
            raise MetasploitError(
                "MSF_RPC_PASS is unset or the shipped default 'changeme' — set a real "
                "msfrpcd password (MSF_RPC_PASS=...) before using --metasploit"
            )
        if self._client is not None:
            return True
        try:
            self._client = _connect(
                self.password, self.host, self.port, self.ssl, self.username
            )
        except Exception:  # noqa: BLE001 — any failure means "no metasploit"
            self._client = None
            return False
        return True

    async def find_for_port(self, port: PortInfo) -> list[Vulnerability]:
        if not port.product or len(port.product.strip()) < MIN_PRODUCT_LEN:
            return []
        if not self._client_available():
            return []
        query = port.product
        if port.version:
            query = f"{port.product} {port.version}"
        return await asyncio.to_thread(self._search_sync, query, port)

    async def find_for_ports(self, ports: list[PortInfo]) -> list[Vulnerability]:
        relevant = [p for p in ports if p.product and len(p.product.strip()) >= MIN_PRODUCT_LEN]
        if not relevant:
            return []
        if not self._client_available():
            return []
        # Serial inside one connection — pymetasploit3 client is not thread-safe.
        out: list[Vulnerability] = []
        for p in relevant:
            out.extend(await asyncio.to_thread(self._search_sync, _build_query(p), p))
        return out

    def _search_sync(self, query: str, port: PortInfo) -> list[Vulnerability]:
        assert self._client is not None  # noqa: S101 — narrowing for the type checker
        try:
            results = self._client.modules.search(query)
        except Exception:  # noqa: BLE001
            return []
        return [
            _to_vuln(item, port)
            for item in results
            if isinstance(item, dict) and item.get("type") == "exploit"
        ]


def _build_query(port: PortInfo) -> str:
    if port.version:
        return f"{port.product} {port.version}"
    return port.product or ""


def _to_vuln(item: dict[str, Any], port: PortInfo) -> Vulnerability:
    fullname = item.get("fullname", "unknown")
    name = item.get("name", fullname)
    rank = item.get("rank", "normal")
    severity = _RANK_TO_SEVERITY.get(str(rank).lower(), Severity.MEDIUM)
    cve = _extract_cve(item.get("references", []))
    return Vulnerability(
        title=name,
        severity=severity,
        source="metasploit",
        cve=cve,
        affected_port=port.port,
        affected_service=port.service,
        metasploit_module=fullname,
    )


def _extract_cve(refs: list[Any]) -> str | None:
    for ref in refs:
        if isinstance(ref, list | tuple) and len(ref) >= 2 and str(ref[0]).upper() == "CVE":
            return f"CVE-{ref[1]}"
    return None
