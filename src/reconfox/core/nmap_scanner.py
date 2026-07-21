"""Async wrapper around nmap.

Generates command-line arguments per ScanMode, runs nmap via
asyncio.create_subprocess_exec, and parses the XML output into PortInfo objects.
"""

from __future__ import annotations

from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DET  # type: ignore[import-untyped]

from reconfox.core._proc import run_capture
from reconfox.models import PortInfo, ScanMode


class NmapError(RuntimeError):
    """Raised when nmap fails or its output cannot be parsed."""


_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.QUICK: ["-T4", "-F", "-sV"],
    ScanMode.FULL: ["-T4", "-p-", "-sV", "-sC"],
    ScanMode.STEALTH: ["-T2", "-sS", "-f", "-sV"],
}

# Per-mode default timeout ceilings (seconds). These are anti-hang safety nets,
# not tuned scan budgets — a full -p- or stealth -T2 scan can legitimately run
# for a while. Override via NmapScanner(timeout=...).
_MODE_TIMEOUTS: dict[ScanMode, float] = {
    ScanMode.QUICK: 600.0,
    ScanMode.FULL: 3600.0,
    ScanMode.STEALTH: 3600.0,
}


class NmapScanner:
    """Run nmap and parse its output."""

    def __init__(
        self,
        binary: str = "nmap",
        timeout: float | None = None,
        min_rate: int | None = None,
        max_rate: int | None = None,
        scan_delay: str | None = None,
    ) -> None:
        self.binary = binary
        # None → fall back to the per-mode ceiling in `scan`.
        self.timeout = timeout
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.scan_delay = scan_delay

    @staticmethod
    def build_args(
        target: str,
        mode: ScanMode,
        ports: str | None = None,
        min_rate: int | None = None,
        max_rate: int | None = None,
        scan_delay: str | None = None,
    ) -> list[str]:
        flags = list(_MODE_FLAGS[mode])
        if ports is not None:
            flags = [f for f in flags if f not in {"-F", "-p-"}]
            flags.extend(["-p", ports])
        # Rate / timing controls (opt-in) — let stealth actually be slow.
        if min_rate is not None:
            flags.extend(["--min-rate", str(min_rate)])
        if max_rate is not None:
            flags.extend(["--max-rate", str(max_rate)])
        if scan_delay is not None:
            flags.extend(["--scan-delay", scan_delay])
        # XML output to stdout
        flags.extend(["-oX", "-"])
        flags.append(target)
        return flags

    async def scan(
        self,
        target: str,
        mode: ScanMode,
        ports: str | None = None,
    ) -> list[PortInfo]:
        args = self.build_args(
            target, mode, ports, self.min_rate, self.max_rate, self.scan_delay
        )
        timeout = self.timeout if self.timeout is not None else _MODE_TIMEOUTS[mode]
        try:
            rc, stdout, stderr = await run_capture(self.binary, *args, timeout=timeout)
        except TimeoutError as exc:
            raise NmapError(f"nmap timed out after {timeout:.0f}s") from exc
        except FileNotFoundError as exc:
            raise NmapError(
                f"{self.binary} not found — install nmap (e.g. sudo apt install nmap)"
            ) from exc
        if rc != 0:
            err = stderr.decode(errors="replace").strip() or "unknown nmap error"
            raise NmapError(f"nmap exited with code {rc}: {err}")
        return self.parse_xml(stdout.decode(errors="replace"))

    @staticmethod
    def parse_xml(xml_text: str) -> list[PortInfo]:
        try:
            root = DET.fromstring(xml_text)
        except (ParseError, ValueError) as exc:
            raise NmapError(f"could not parse nmap XML: {exc}") from exc

        results: list[PortInfo] = []
        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                # A single anomalous element (sctp/ip proto, state=unfiltered,
                # portid=0, ...) must not discard every port on the host —
                # pydantic ValidationError subclasses ValueError, so we skip it.
                try:
                    results.append(_port_from_element(port_el))
                except ValueError:
                    continue
        return results


def _port_from_element(port_el) -> PortInfo:  # type: ignore[no-untyped-def]
    port_num = int(port_el.get("portid", "0"))
    protocol = port_el.get("protocol", "tcp")
    state_el = port_el.find("state")
    state = state_el.get("state", "closed") if state_el is not None else "closed"

    service_el = port_el.find("service")
    service = product = version = None
    cpes: list[str] = []
    if service_el is not None:
        service = service_el.get("name")
        product = service_el.get("product")
        version = service_el.get("version")
        for cpe_el in service_el.findall("cpe"):
            if cpe_el.text:
                cpes.append(cpe_el.text)

    scripts: dict[str, str] = {}
    for script_el in port_el.findall("script"):
        script_id = script_el.get("id")
        script_out = script_el.get("output")
        if script_id and script_out:
            scripts[script_id] = script_out

    return PortInfo(
        port=port_num,
        protocol=protocol,  # type: ignore[arg-type]
        state=state,  # type: ignore[arg-type]
        service=service,
        product=product,
        version=version,
        cpe=cpes,
        scripts=scripts,
    )
