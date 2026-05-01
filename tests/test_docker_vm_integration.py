from __future__ import annotations

import json
import subprocess
import textwrap

import pytest


pytestmark = pytest.mark.docker_vm


IMAGE = "python:3.13-slim"
FRIDA_VERSION = "17.9.3"


PID1_PROBE = """
import frida
import json
import time
try:
    session = frida.attach(1)
    events = []
    script = session.create_script("send({type: 'docker_probe', pid: Process.id, platform: Process.platform, arch: Process.arch});")
    script.on('message', lambda message, data: events.append(message))
    script.load()
    time.sleep(0.2)
    script.unload()
    session.detach()
    print(json.dumps({'ok': True, 'events': events}))
except Exception as exc:
    print(json.dumps({'ok': False, 'error_type': type(exc).__name__, 'error': str(exc)}))
"""


CHILD_PROBE = """
import frida
import json
import subprocess
import time
proc = subprocess.Popen(['sleep', '30'])
try:
    session = frida.attach(proc.pid)
    events = []
    script = session.create_script("send({type: 'docker_child_probe', pid: Process.id, platform: Process.platform, arch: Process.arch});")
    script.on('message', lambda message, data: events.append(message))
    script.load()
    time.sleep(0.2)
    script.unload()
    session.detach()
    print(json.dumps({'ok': True, 'events': events}))
except Exception as exc:
    print(json.dumps({'ok': False, 'error_type': type(exc).__name__, 'error': str(exc)}))
finally:
    proc.terminate()
    proc.wait(timeout=5)
"""


def _run(args: list[str], *, input_text: str | None = None, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=input_text, capture_output=True, text=True, timeout=timeout)
    if check:
        assert result.returncode == 0, result.stderr or result.stdout
    return result


def _docker_probe(container: str, script: str, user: str | None = None) -> dict:
    args = ["docker", "exec", "-i"]
    if user is not None:
        args.extend(["--user", user])
    args.extend([container, "python", "-"])
    result = _run(args, input_text=textwrap.dedent(script), check=False)
    assert result.stdout.strip(), result.stderr
    return json.loads(result.stdout)


def test_docker_linux_vm_frida_attach_permission_matrix():
    _run(["docker", "version"], timeout=30)
    name = "fm-frida-permission-matrix"
    _run(["docker", "rm", "-f", name], check=False, timeout=30)
    try:
        _run(["docker", "run", "-d", "--name", name, "--platform", "linux/arm64", IMAGE, "sleep", "300"], timeout=180)
        _run(
            [
                "docker",
                "exec",
                name,
                "sh",
                "-lc",
                f"python -m pip install -q frida=={FRIDA_VERSION} >/tmp/pip.log 2>&1 && chmod -R a+rx /usr/local/lib/python3.13/site-packages/frida* /usr/local/bin || true",
            ],
            timeout=180,
        )

        root_pid1 = _docker_probe(name, PID1_PROBE)
        assert root_pid1["ok"] is True
        assert root_pid1["events"][0]["payload"]["platform"] == "linux"

        non_root_pid1 = _docker_probe(name, PID1_PROBE, user="1000:1000")
        assert non_root_pid1["ok"] is False
        assert non_root_pid1["error_type"] == "PermissionDeniedError"

        non_root_child = _docker_probe(name, CHILD_PROBE, user="1000:1000")
        assert non_root_child["ok"] is True
        assert non_root_child["events"][0]["payload"]["type"] == "docker_child_probe"
    finally:
        _run(["docker", "rm", "-f", name], check=False, timeout=30)
