"""TLS handshake + certificate inspection.

For an HTTPS-focused recon tool, knowing the negotiated TLS version, cipher and
the served certificate (subject / issuer / SANs / validity) is core signal —
SANs in particular often leak extra hostnames. A verified handshake yields the
full certificate dict; for self-signed/expired certs we fall back to an
unverified handshake to still report version/cipher plus the verify error.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Sequence
from typing import Any

from reconfox.models import TlsInfo

DEFAULT_TIMEOUT = 10.0


class TlsProber:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    async def probe(self, host: str, port: int = 443) -> TlsInfo:
        return await asyncio.to_thread(self._probe_sync, host, port)

    def _probe_sync(self, host: str, port: int) -> TlsInfo:
        ctx = ssl.create_default_context()
        try:
            version, cipher, cert = self._handshake(ctx, host, port)
            return self._parse(cert, host, port, version, cipher, None)
        except ssl.SSLCertVerificationError as exc:
            info = self._unverified(host, port)
            info.error = f"cert verify failed: {exc.verify_message or exc}"
            return info
        except (OSError, ssl.SSLError) as exc:
            return TlsInfo(host=host, port=port, error=str(exc) or exc.__class__.__name__)

    def _unverified(self, host: str, port: int) -> TlsInfo:
        # Deliberately skip verification to fingerprint self-signed/expired certs.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            version, cipher, cert = self._handshake(ctx, host, port)
        except (OSError, ssl.SSLError) as exc:
            return TlsInfo(host=host, port=port, error=str(exc) or exc.__class__.__name__)
        return self._parse(cert, host, port, version, cipher, None)

    def _handshake(
        self, ctx: ssl.SSLContext, host: str, port: int
    ) -> tuple[str | None, str | None, dict[str, Any]]:
        with (
            socket.create_connection((host, port), timeout=self.timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls_sock,
        ):
            cipher = tls_sock.cipher()
            cert = tls_sock.getpeercert() or {}
            return tls_sock.version(), (cipher[0] if cipher else None), cert

    @staticmethod
    def _parse(
        cert: dict[str, Any],
        host: str,
        port: int,
        version: str | None,
        cipher: str | None,
        error: str | None,
    ) -> TlsInfo:
        san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
        return TlsInfo(
            host=host,
            port=port,
            version=version,
            cipher=cipher,
            subject=TlsProber._name(cert.get("subject")),
            issuer=TlsProber._name(cert.get("issuer")),
            san=san,
            not_before=cert.get("notBefore"),
            not_after=cert.get("notAfter"),
            error=error,
        )

    @staticmethod
    def _name(rdn_seq: Sequence[Sequence[tuple[str, str]]] | None) -> str | None:
        if not rdn_seq:
            return None
        for rdn in rdn_seq:
            for key, value in rdn:
                if key == "commonName":
                    return value
        for rdn in rdn_seq:  # fallback: first attribute of any kind
            for _, value in rdn:
                return value
        return None
