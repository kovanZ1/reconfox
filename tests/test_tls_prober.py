"""Tests for reconfox.core.tls_prober — certificate/TLS parsing."""

from __future__ import annotations

from reconfox.core.tls_prober import TlsProber

SAMPLE_CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
    "subjectAltName": (
        ("DNS", "example.com"),
        ("DNS", "www.example.com"),
        ("IP Address", "1.2.3.4"),
    ),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Apr  1 00:00:00 2026 GMT",
}


class TestParse:
    def test_extracts_cert_fields(self) -> None:
        info = TlsProber._parse(SAMPLE_CERT, "example.com", 443, "TLSv1.3", "TLS_AES_256", None)
        assert info.host == "example.com"
        assert info.port == 443
        assert info.version == "TLSv1.3"
        assert info.cipher == "TLS_AES_256"
        assert info.subject == "example.com"
        assert info.issuer == "R3"  # commonName preferred
        assert info.not_after == "Apr  1 00:00:00 2026 GMT"

    def test_san_only_dns_names(self) -> None:
        info = TlsProber._parse(SAMPLE_CERT, "example.com", 443, None, None, None)
        assert info.san == ["example.com", "www.example.com"]  # IP entry excluded

    def test_empty_cert_keeps_version(self) -> None:
        # self-signed path: no cert dict but we still negotiated a version/cipher
        info = TlsProber._parse({}, "self.test", 443, "TLSv1.2", "ECDHE", "verify failed")
        assert info.version == "TLSv1.2"
        assert info.subject is None
        assert info.error == "verify failed"


class TestName:
    def test_prefers_common_name(self) -> None:
        rdn = ((("organizationName", "Org"),), (("commonName", "the-cn"),))
        assert TlsProber._name(rdn) == "the-cn"

    def test_none_for_empty(self) -> None:
        assert TlsProber._name(()) is None
