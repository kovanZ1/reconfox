"""Tests for reconfox.core.doctor — environment readiness checks."""

from __future__ import annotations

from pathlib import Path

from reconfox.core import doctor


def _which_all(binary: str) -> str:
    return f"/usr/bin/{binary}"


def _no_version(binary: str) -> None:  # noqa: ARG001
    return None


class TestCheckTools:
    def test_all_present(self) -> None:
        tools = doctor.check_tools(which=_which_all, version=lambda b: f"{b} 1.0")
        by_name = {t.name: t for t in tools}
        assert {"nmap", "ffuf", "searchsploit", "nuclei"} <= set(by_name)
        assert all(t.ok for t in tools)
        assert by_name["nmap"].version == "nmap 1.0"

    def test_missing_tool_reported(self) -> None:
        def which(binary: str) -> str | None:
            return None if binary == "nuclei" else f"/usr/bin/{binary}"

        tools = doctor.check_tools(which=which, version=_no_version)
        nuclei = next(t for t in tools if t.name == "nuclei")
        assert nuclei.ok is False
        assert nuclei.required is False  # nuclei is optional
        assert "nuclei" in nuclei.hint

    def test_nmap_and_ffuf_are_required(self) -> None:
        tools = doctor.check_tools(which=lambda b: None, version=_no_version)
        by_name = {t.name: t for t in tools}
        assert by_name["nmap"].required is True
        assert by_name["ffuf"].required is True
        assert by_name["searchsploit"].required is False


class TestRequiredOk:
    def test_true_when_required_present(self) -> None:
        def which(binary: str) -> str | None:
            # required present, an optional one missing
            return None if binary == "searchsploit" else f"/usr/bin/{binary}"

        assert doctor.required_ok(doctor.check_tools(which=which, version=_no_version)) is True

    def test_false_when_required_missing(self) -> None:
        def which(binary: str) -> str | None:
            return None if binary == "nmap" else f"/usr/bin/{binary}"

        assert doctor.required_ok(doctor.check_tools(which=which, version=_no_version)) is False


class TestCheckWordlist:
    def test_exists(self, tmp_path: Path) -> None:
        wl = tmp_path / "common.txt"
        wl.write_text("admin\n")
        status = doctor.check_wordlist(wl)
        assert status.exists is True
        assert status.path == wl

    def test_missing(self, tmp_path: Path) -> None:
        status = doctor.check_wordlist(tmp_path / "nope.txt")
        assert status.exists is False
        assert "seclists" in status.hint
