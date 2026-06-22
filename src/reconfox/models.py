"""Data models for reconfox.

All structures shared between scanners, orchestrator and report generators.
Built on pydantic v2 for validation and JSON serialization.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Geolocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None


class ASNInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asn: int | None = None
    asn_name: str | None = None
    isp: str | None = None
    org: str | None = None


class Target(BaseModel):
    """A reconnaissance target. Created from a URL, enriched by Resolver."""

    model_config = ConfigDict(validate_assignment=True)

    url: str
    hostname: str
    path: str = "/"
    port: int = Field(ge=1, le=65535)
    is_https: bool = False
    ip: str | None = None
    asn: ASNInfo | None = None
    geo: Geolocation | None = None
    whois: dict[str, str | int | float | bool | None] | None = None

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        ipaddress.ip_address(v)
        return v

    @classmethod
    def from_url(cls, url: str) -> Target:
        """Parse a URL into a Target. Accepts urls with or without scheme."""
        if not url or not url.strip():
            raise ValueError("Invalid URL: empty")
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        if not parsed.hostname or any(c.isspace() for c in parsed.hostname):
            raise ValueError(f"Invalid URL: {url!r}")
        is_https = parsed.scheme == "https"
        port = parsed.port or (443 if is_https else 80)
        return cls(
            url=url,
            hostname=parsed.hostname,
            path=parsed.path or "/",
            port=port,
            is_https=is_https,
        )


class PortInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    state: Literal["open", "filtered", "closed", "open|filtered"]
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: list[str] = Field(default_factory=list)
    scripts: dict[str, str] = Field(default_factory=dict)


class WebFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    status: int = Field(ge=100, le=599)
    length: int = Field(ge=0)
    words: int | None = None
    lines: int | None = None
    redirect: str | None = None


class Subdomain(BaseModel):
    """A discovered subdomain of the target, optionally resolved to an IP."""

    model_config = ConfigDict(extra="forbid")

    name: str
    ip: str | None = None
    source: str  # e.g. "crt.sh", "dns-brute"


class HttpProbe(BaseModel):
    """Result of an HTTP fingerprint probe against one endpoint."""

    model_config = ConfigDict(extra="forbid")

    url: str
    status: int | None = None
    final_url: str | None = None
    title: str | None = None
    server: str | None = None
    technologies: list[str] = Field(default_factory=list)
    content_length: int | None = None
    error: str | None = None


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


VulnSource = Literal["searchsploit", "metasploit", "nmap-nse", "nuclei", "manual"]


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    severity: Severity
    source: VulnSource
    cve: str | None = None
    description: str | None = None
    references: list[str] = Field(default_factory=list)
    affected_port: int | None = None
    affected_service: str | None = None
    exploit_path: str | None = None
    metasploit_module: str | None = None


class ScanMode(StrEnum):
    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ScanResult(BaseModel):
    """Aggregate result of all phases of a recon run."""

    model_config = ConfigDict(extra="forbid")

    target: Target
    mode: ScanMode
    started_at: datetime
    finished_at: datetime | None = None
    status: ScanStatus = ScanStatus.PENDING
    subdomains: list[Subdomain] = Field(default_factory=list)
    ports: list[PortInfo] = Field(default_factory=list)
    web_findings: list[WebFinding] = Field(default_factory=list)
    http_probes: list[HttpProbe] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def highest_severity(self) -> Severity | None:
        if not self.vulnerabilities:
            return None
        return max(self.vulnerabilities, key=lambda v: v.severity.score).severity
