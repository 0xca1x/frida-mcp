from __future__ import annotations

import re
import subprocess

import frida
import pytest

from fuzzmind_frida_mcp.tools.runtimes.objc import objc_classes


pytestmark = pytest.mark.ios_simulator


def _first_available_iphone_udid() -> str:
    result = subprocess.run(
        ["xcrun", "simctl", "list", "devices", "available"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    for line in result.stdout.splitlines():
        if "iPhone" not in line:
            continue
        match = re.search(r"\(([0-9A-F-]{36})\)", line)
        if match:
            return match.group(1)
    raise AssertionError("no available iPhone simulator found")


def test_ios_simulator_springboard_attach_permission_boundary():
    udid = _first_available_iphone_udid()
    subprocess.run(["xcrun", "simctl", "boot", udid], capture_output=True, text=True, timeout=60)
    booted = subprocess.run(
        ["xcrun", "simctl", "bootstatus", udid, "-b"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert booted.returncode == 0, booted.stderr or booted.stdout
    try:
        springboard = next(p for p in frida.get_local_device().enumerate_processes() if p.name == "SpringBoard")
        result = objc_classes(str(springboard.pid), "UIView*")
        assert "error" in result
        assert "permission denied" in result["error"] or "unable to access process" in result["error"]
    finally:
        subprocess.run(["xcrun", "simctl", "shutdown", udid], capture_output=True, text=True, timeout=60)
