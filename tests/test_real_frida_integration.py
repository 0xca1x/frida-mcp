from __future__ import annotations

import platform
import shutil
import subprocess
import time
from pathlib import Path

import frida
import pytest

from fuzzmind_frida_mcp.tools import _core
from fuzzmind_frida_mcp.tools.instrumentation.kernel import kernel_enumerate_modules
from fuzzmind_frida_mcp.tools.lifecycle import process as process_tools
from fuzzmind_frida_mcp.tools.lifecycle import script as script_tools
from fuzzmind_frida_mcp.tools.lifecycle import session as session_tools
from fuzzmind_frida_mcp.tools.runtimes.objc import dump_class, objc_classes


pytestmark = pytest.mark.real_frida


TARGET_SOURCE = r"""
#include <stdio.h>
#include <unistd.h>

volatile int fm_counter = 0;

int fm_add(int a, int b) {
    return a + b;
}

int main(void) {
    setbuf(stdout, NULL);
    puts("ready");
    for (;;) {
        fm_counter++;
        usleep(100000);
    }
    return 0;
}
"""


@pytest.fixture(scope="session")
def compiled_target(tmp_path_factory) -> Path:
    compiler = shutil.which("cc")
    assert compiler is not None, "cc is required for real Frida integration tests"

    build_dir = tmp_path_factory.mktemp("real-frida-target")
    source = build_dir / "fm_frida_target.c"
    binary = build_dir / "fm_frida_target"
    source.write_text(TARGET_SOURCE)

    result = subprocess.run(
        [compiler, "-O0", "-g", str(source), "-o", str(binary)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert binary.is_file()
    return binary


@pytest.fixture
def running_target(compiled_target):
    proc = subprocess.Popen(
        [str(compiled_target)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 5
        line = ""
        while time.time() < deadline and line != "ready":
            line = proc.stdout.readline().strip()
        assert line == "ready"
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_core_run_script_real_spawn_executes_gumjs_and_returns_binary_payload(compiled_target):
    js = """
    'use strict';
    send({
      type: 'real_spawn_probe',
      pid: Process.id,
      arch: Process.arch,
      platform: Process.platform
    }, new Uint8Array([1, 2, 3]).buffer);
    """

    result = _core._run_script(
        frida,
        str(compiled_target),
        js,
        duration_seconds=0,
        mode="spawn",
        kill_on_exit=True,
    )

    assert "error" not in result
    assert result["mode"] == "spawn"
    assert result["kill_on_exit"] is True
    assert result["event_count"] == 1
    event = result["events"][0]
    assert event["type"] == "real_spawn_probe"
    assert event["platform"] in ("darwin", "linux", "windows")
    assert event["data_size"] == 3
    assert event["data_base64"] == "AQID"


def test_frida_eval_real_spawn_uses_public_tool_path(compiled_target):
    result = script_tools.eval_code(
        target=str(compiled_target),
        js_code="send({ type: 'frida_eval_probe', pid: Process.id, pointerSize: Process.pointerSize });",
        duration_seconds=0,
        mode="spawn",
        kill_on_exit=True,
    )

    assert "error" not in result
    assert result["event_count"] == 1
    event = result["events"][0]
    assert event["type"] == "frida_eval_probe"
    assert event["pointerSize"] in {4, 8}


def test_lifecycle_tools_real_attach_to_owned_process(running_target):
    target = str(running_target.pid)

    info = process_tools.process_info(target)
    assert "error" not in info
    info_event = info["events"][0]
    assert info_event["type"] == "process_info"
    assert info_event["id"] == running_target.pid
    assert info_event["arch"] in ("arm64", "x64", "ia32")

    modules = process_tools.enumerate_modules(target)
    assert "error" not in modules
    modules_event = modules["events"][0]
    assert modules_event["type"] == "modules"
    assert modules_event["count"] > 0
    assert any(item["name"] == "fm_frida_target" for item in modules_event["items"])

    threads = process_tools.enumerate_threads(target)
    assert "error" not in threads
    threads_event = threads["events"][0]
    assert threads_event["type"] == "threads"
    assert threads_event["count"] > 0


def test_persistent_session_real_spawn_script_rpc_events_and_disconnect(compiled_target, fresh_registry):
    connected = session_tools.connect(
        target=str(compiled_target),
        spawn=True,
        kill_on_disconnect=True,
    )
    assert connected["status"] == "connected"
    session_id = connected["session_id"]

    try:
        loaded = script_tools.script_load(
            """
            'use strict';
            rpc.exports = {
              add(left, right) {
                return left + right;
              }
            };
            send({ type: 'persistent_probe', pid: Process.id });
            """,
            session_id=session_id,
            name="persistent-probe",
        )
        assert loaded["status"] == "loaded"

        rpc = script_tools.script_call_rpc(
            loaded["script_id"],
            "add",
            [20, 22],
            session_id=session_id,
        )
        assert rpc["status"] == "ok"
        assert rpc["result"] == 42

        events = script_tools.script_get_events(
            script_id=loaded["script_id"],
            session_id=session_id,
        )
        assert events["count"] == 1
        assert events["events"][0]["payload"]["type"] == "persistent_probe"
    finally:
        disconnected = session_tools.disconnect(session_id)
        assert disconnected["status"] == "disconnected"


@pytest.mark.skipif(platform.system() != "Darwin", reason="ObjC/Foundation requires macOS")
def test_objc_bridge_real_attach_to_owned_foundation_process(tmp_path, monkeypatch):
    monkeypatch.setenv("FUZZMIND_FRIDA_BRIDGE_ROOT", str(Path.home() / ".fuzzmind" / "frida-mcp" / "frida-bridges"))
    source = tmp_path / "objc_target.m"
    binary = tmp_path / "objc_target"
    source.write_text(
        """
#import <Foundation/Foundation.h>
@interface FMProbe : NSObject
@end
@implementation FMProbe
@end
int main(void) {
  @autoreleasepool {
    NSLog(@"ready %@", [FMProbe class]);
    while (1) { [NSThread sleepForTimeInterval:1.0]; }
  }
  return 0;
}
"""
    )
    result = subprocess.run(
        ["cc", "-framework", "Foundation", "-fobjc-arc", "-O0", "-g", str(source), "-o", str(binary)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

    proc = subprocess.Popen([str(binary)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1)
        classes = objc_classes(str(proc.pid), "FMProbe")
        assert "error" not in classes
        assert classes["events"][0]["type"] == "classes"
        assert "FMProbe" in classes["events"][0]["items"]

        dumped = dump_class(str(proc.pid), "FMProbe")
        assert "error" not in dumped
        assert dumped["events"][0]["type"] == "class_dump"
        assert dumped["events"][0]["class_name"] == "FMProbe"
        assert dumped["events"][0]["super_class"] == "NSObject"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_kernel_api_real_host_reports_unavailable_without_kernel_access():
    result = kernel_enumerate_modules()
    assert result["events"][0]["type"] == "error"
    assert "Kernel API not available" in result["events"][0]["message"]
