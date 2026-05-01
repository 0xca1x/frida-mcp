from __future__ import annotations

import lzma
import os
import subprocess
import time
import urllib.request
from pathlib import Path

import frida
import pytest

from fuzzmind_frida_mcp.tools.lifecycle.device import list_apps, list_devices
from fuzzmind_frida_mcp.tools.recipes.workflow import android_frida_server_status, bridge_install, bridge_status
from fuzzmind_frida_mcp.tools.runtimes.java import java_call, java_list_classes, java_list_methods


pytestmark = pytest.mark.android_emulator


SDK_ROOT = Path.home() / "Library" / "Android" / "sdk"
ADB = SDK_ROOT / "platform-tools" / "adb"
EMULATOR = SDK_ROOT / "emulator" / "emulator"


def _android_env() -> dict[str, str]:
    env = os.environ.copy()
    env["ANDROID_SDK_ROOT"] = str(SDK_ROOT)
    env["PATH"] = f"{SDK_ROOT / 'platform-tools'}:{env.get('PATH', '')}"
    env["FUZZMIND_FRIDA_BRIDGE_ROOT"] = str(Path.home() / ".fuzzmind" / "frida-mcp" / "frida-bridges")
    return env


def _run(args: list[str], *, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=_android_env())
    if check:
        assert result.returncode == 0, result.stderr or result.stdout
    return result


def _adb(*args: str, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run([str(ADB), *args], timeout=timeout, check=check)


def _boot_completed() -> bool:
    result = _adb("shell", "getprop", "sys.boot_completed", check=False)
    return result.stdout.strip().replace("\r", "") == "1"


def _device_serial() -> str | None:
    result = _adb("devices", check=False)
    for line in result.stdout.splitlines()[1:]:
        columns = line.split()
        if len(columns) >= 2 and columns[0].startswith("emulator-") and columns[1] == "device":
            return columns[0]
    return None


@pytest.fixture(scope="session")
def android_emulator():
    assert ADB.is_file(), f"adb not found: {ADB}"
    assert EMULATOR.is_file(), f"emulator not found: {EMULATOR}"

    started = None
    serial = _device_serial()
    if serial is None or not _boot_completed():
        avds = _run([str(EMULATOR), "-list-avds"]).stdout.splitlines()
        avd = os.environ.get("FUZZMIND_ANDROID_AVD") or ("test_api35" if "test_api35" in avds else (avds[0] if avds else ""))
        assert avd, "no Android AVD available"
        started = subprocess.Popen(
            [
                str(EMULATOR),
                "-avd",
                avd,
                "-no-window",
                "-no-audio",
                "-no-boot-anim",
                "-gpu",
                "swiftshader_indirect",
                "-no-snapshot-save",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_android_env(),
        )
        _adb("wait-for-device", timeout=120)
        deadline = time.time() + 180
        while time.time() < deadline and not _boot_completed():
            time.sleep(2)
        assert _boot_completed(), "Android emulator did not finish booting"
        serial = _device_serial()

    assert serial is not None
    yield serial

    if started is not None:
        _adb("-s", serial, "emu", "kill", check=False)
        try:
            started.wait(timeout=20)
        except subprocess.TimeoutExpired:
            started.terminate()
            started.wait(timeout=10)


@pytest.fixture
def android_frida_server(android_emulator):
    _adb("root", check=False)
    _adb("wait-for-device", timeout=60)
    root_id = _adb("shell", "id").stdout
    assert "uid=0(root)" in root_id

    version = frida.__version__
    cache = Path("/tmp") / f"fuzzmind-frida-android-{version}"
    binary = cache / f"frida-server-{version}-android-arm64"
    if not binary.is_file():
        cache.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-arm64.xz"
        compressed = cache / "frida-server.xz"
        urllib.request.urlretrieve(url, compressed)
        binary.write_bytes(lzma.decompress(compressed.read_bytes()))
    binary.chmod(0o755)

    _adb("push", str(binary), "/data/local/tmp/frida-server", timeout=120)
    _adb("shell", "chmod", "755", "/data/local/tmp/frida-server")
    _adb("shell", "pkill", "frida-server", check=False)
    _adb("shell", "/data/local/tmp/frida-server -D -C -d /data/local/tmp")
    time.sleep(1)
    assert _adb("shell", "pidof", "frida-server").stdout.strip()
    assert _adb("shell", "/data/local/tmp/frida-server", "--version").stdout.strip() == version
    return android_emulator


def test_android_emulator_adb_root_and_frida_server_status(android_frida_server):
    status = android_frida_server_status()
    assert status["adb_available"] is True
    assert status["device"]["abi"]["stdout"] == "arm64-v8a"
    assert status["device"]["sdk"]["stdout"] == "35"
    assert status["frida_server"]["version"]["stdout"] == frida.__version__
    assert status["frida_server"]["pid"]["stdout"]


def test_android_frida_lists_usb_device_and_apps(android_frida_server):
    devices = list_devices()
    assert any(item["id"] == android_frida_server and item["type"] == "usb" for item in devices["items"])

    apps = list_apps(device_id=android_frida_server)
    assert apps["count"] > 0
    assert any(item["identifier"] == "com.android.settings" for item in apps["items"])


def test_android_java_bridge_tools_attach_to_emulator_app(android_frida_server):
    status = bridge_status()
    if not status.get("bridges", {}).get("java", {}).get("available"):
        installed = bridge_install(["java"])
        assert installed["installed"] is True
    assert bridge_status()["bridges"]["java"]["available"] is True

    _adb("shell", "am", "start", "-a", "android.settings.SETTINGS")
    time.sleep(2)
    apps = list_apps(device_id=android_frida_server)["items"]
    settings = next(item for item in apps if item["identifier"] == "com.android.settings" and item["pid"])
    target = str(settings["pid"])

    classes = java_list_classes(target, filter="android.app", limit=10, device_id=android_frida_server)
    assert "error" not in classes
    assert classes["events"][0]["type"] == "java_classes"
    assert classes["events"][0]["count"] > 0

    methods = java_list_methods(target, "java.lang.String", device_id=android_frida_server)
    assert "error" not in methods
    assert methods["events"][0]["type"] == "java_methods"
    assert methods["events"][0]["count"] > 0

    called = java_call(
        target,
        "send({ type: 'java_call_probe', version: Java.use('java.lang.System').getProperty('java.version').toString() });",
        device_id=android_frida_server,
    )
    assert "error" not in called
    assert called["events"][0]["type"] == "java_call_probe"
