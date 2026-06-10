"""Async wrapper around nmap.

Generates command-line arguments per ScanMode, runs nmap via
asyncio.create_subprocess_exec, and parses the XML output into PortInfo objects.
"""

from __future__ import annotations

import asyncio
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DET  # type: ignore[import-untyped]

from reconfox.models import PortInfo, ScanMode


class NmapError(RuntimeError):
    """Raised when nmap fails or its output cannot be parsed."""


_MODE_FLAGS: dict[ScanMode, list[str]] = {
    ScanMode.QUICK: ["-T4", "-F", "-sV"],
    ScanMode.FULL: ["-T4", "-p-", "-sV", "-sC"],
    ScanMode.STEALTH: ["-T2", "-sS", "-f", "-sV"],
}


class NmapScanner:
    """Run nmap and parse its output."""

    def __init__(self, binary: str = "nmap") -> None:
        self.binary = binary

    @staticmethod
    def build_args(target: str, mode: ScanMode, ports: str | None = None) -> list[str]:
        flags = list(_MODE_FLAGS[mode])
        if ports is not None:
            flags = [f for f in flags if f not in {"-F", "-p-"}]
            flags.extend(["-p", ports])
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
        args = self.build_args(target, mode, ports)
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip() or "unknown nmap error"
            raise NmapError(f"nmap exited with code {proc.returncode}: {err}")
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
                results.append(_port_from_element(port_el))
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
