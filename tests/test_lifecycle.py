from __future__ import annotations

from types import SimpleNamespace

from fuzzmind_frida_mcp.tools import _core
from fuzzmind_frida_mcp.tools.lifecycle import process as process_tools
from fuzzmind_frida_mcp.tools.lifecycle import script as script_tools
from fuzzmind_frida_mcp.tools.lifecycle import session as session_tools


class FakeLoadedScript:
    def __init__(self, source, message=None):
        self.source = source
        self.callbacks = {}
        self.loaded = False
        self.unloaded = False
        self.message = message or ({"type": "send", "payload": {"ready": True}}, b"\x01\x02")
        self.exports_sync = SimpleNamespace(echo=lambda value: value)

    def on(self, event, callback):
        self.callbacks[event] = callback

    def load(self):
        self.loaded = True
        if "message" in self.callbacks:
            self.callbacks["message"](*self.message)

    def unload(self):
        self.unloaded = True

    def post(self, _message):
        pass


class FakeSession:
    def __init__(self):
        self._impl = SimpleNamespace(pid=1234)
        self.created_sources = []

    def on(self, _event, _callback):
        pass

    def create_script(self, source, **_kwargs):
        self.created_sources.append(source)
        return FakeLoadedScript(source)

    def detach(self):
        pass


class FakeDevice:
    id = "local"
    name = "Local Device"
    type = "local"

    def __init__(self):
        self.spawn_calls = []
        self.attach_calls = []
        self.resumed = []
        self.session = FakeSession()

    def spawn(self, program, **kwargs):
        self.spawn_calls.append((program, kwargs))
        return 1234

    def attach(self, target, **kwargs):
        self.attach_calls.append((target, kwargs))
        return self.session

    def resume(self, pid):
        self.resumed.append(pid)

    def enumerate_processes(self):
        return [
            SimpleNamespace(pid=3, name="zeta"),
            SimpleNamespace(pid=1, name="Alpha"),
            SimpleNamespace(pid=2, name="beta-helper"),
        ]

    def enumerate_applications(self):
        return [SimpleNamespace(identifier="com.example.app", name="Example", pid=0)]


class FakeFrida:
    __version__ = "17.9.3"

    def __init__(self, device):
        self.device = device

    def get_local_device(self):
        return self.device


def test_connect_spawn_creates_persistent_session_without_shelling_out(monkeypatch, fresh_registry):
    device = FakeDevice()
    monkeypatch.setattr(session_tools, "_load_frida", lambda: FakeFrida(device))

    result = session_tools.connect(
        target="/bin/echo 'hello world'",
        spawn=True,
        env={"A": "B"},
        cwd="/tmp",
        stdio="pipe",
    )

    assert result["status"] == "connected"
    assert result["pid"] == 1234
    assert result["session_id"] == fresh_registry.get_active().id
    assert device.spawn_calls == [(["/bin/echo", "hello world"], {"env": {"A": "B"}, "cwd": "/tmp", "stdio": "pipe"})]
    assert device.attach_calls == [(1234, {})]
    assert device.resumed == [1234]


def test_connect_attach_identifier_reports_not_running(monkeypatch):
    device = FakeDevice()
    monkeypatch.setattr(session_tools, "_load_frida", lambda: FakeFrida(device))

    result = session_tools.connect(attach_identifier="com.example.app")

    assert result["error"] == "application is not running: com.example.app"
    assert "frida_launch_app" in result["hint"]
    assert device.attach_calls == []


def test_process_list_filters_and_sorts_from_frida_api(monkeypatch):
    device = FakeDevice()
    monkeypatch.setattr(process_tools, "_load_frida", lambda: FakeFrida(device))

    result = process_tools.list_processes("a")

    assert result == {
        "items": [
            {"pid": 1, "name": "Alpha"},
            {"pid": 2, "name": "beta-helper"},
            {"pid": 3, "name": "zeta"},
        ],
        "count": 3,
    }


def test_check_uses_frida_module_and_tool_presence_without_running_tools(monkeypatch):
    monkeypatch.setattr(process_tools, "_load_frida", lambda: SimpleNamespace(__version__="17.9.3"))
    seen = []

    def fake_have_tool(name):
        seen.append(name)
        return name == "frida-ps"

    monkeypatch.setattr(process_tools, "_have_tool", fake_have_tool)

    assert process_tools.check() == {
        "available": True,
        "core_version": "17.9.3",
        "frida_ps": True,
        "frida_trace": False,
    }
    assert seen == ["frida-ps", "frida-trace"]


def test_script_load_prepares_source_loads_script_and_queues_events(fresh_registry):
    device = FakeDevice()
    fs = fresh_registry.create(device=device, session=device.session, target="target", pid=1234)

    result = script_tools.script_load(
        "send(parameters.value);",
        session_id=fs.id,
        name="probe",
        parameters={"value": 42},
        auto_perform=True,
    )

    assert result["status"] == "loaded"
    managed = fs.get_script(result["script_id"])
    assert managed is not None
    assert managed.loaded is True
    assert "globalThis.parameters = {\"value\": 42};" in managed.source
    assert "Java.perform(function ()" in managed.source
    events = script_tools.script_get_events(script_id=managed.id, session_id=fs.id)["events"]
    assert events[0]["payload"] == {"ready": True}
    assert events[0]["data_base64"] == "AQI="


def test_eval_code_passes_prepared_source_to_run_script(monkeypatch):
    calls = []
    monkeypatch.setattr(script_tools, "_load_frida", lambda: object())

    def fake_run_script(frida, target, js, duration_seconds, mode, **kwargs):
        calls.append((frida, target, js, duration_seconds, mode, kwargs))
        return {"event_count": 0, "events": []}

    monkeypatch.setattr(script_tools, "_run_script", fake_run_script)

    result = script_tools.eval_code(
        target="123",
        js_code="send(parameters.answer);",
        duration_seconds=2,
        mode="spawn",
        parameters={"answer": 7},
        runtime="qjs",
        kill_on_exit=True,
    )

    assert result == {"event_count": 0, "events": []}
    _frida, target, js, duration_seconds, mode, kwargs = calls[0]
    assert target == "123"
    assert duration_seconds == 2
    assert mode == "spawn"
    assert "globalThis.parameters = {\"answer\": 7};" in js
    assert kwargs["runtime"] == "qjs"
    assert kwargs["kill_on_exit"] is True
