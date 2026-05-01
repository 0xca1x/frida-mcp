from __future__ import annotations

from types import SimpleNamespace

import pytest

from fuzzmind_frida_mcp.tools import _core


class FakeFridaScript:
    def __init__(self):
        self.posts = []
        self.unloaded = False
        self.exports_sync = SimpleNamespace(add=lambda left, right: left + right)

    def post(self, message):
        self.posts.append(message)

    def unload(self):
        self.unloaded = True


class FakeSession:
    def __init__(self):
        self.callbacks = {}
        self.detached = False
        self._impl = SimpleNamespace(pid=4321)

    def on(self, event, callback):
        self.callbacks[event] = callback

    def detach(self):
        self.detached = True


class FakeDevice:
    name = "local"

    def __init__(self):
        self.killed = []

    def kill(self, pid):
        self.killed.append(pid)


def test_split_spawn_target_honors_shell_quoting():
    assert _core._split_spawn_target('/bin/echo "hello world"') == ["/bin/echo", "hello world"]
    with pytest.raises(ValueError, match="spawn target is empty"):
        _core._split_spawn_target("   ")


def test_bridge_import_block_only_imports_used_bridges():
    block = _core._bridge_import_block("Java.perform(function () {}); ObjC.available;")
    assert "frida-java-bridge" in block
    assert "frida-objc-bridge" in block
    assert "frida-swift-bridge" not in block


def test_create_script_prepends_prelude_and_forwards_options(monkeypatch):
    monkeypatch.setattr(_core, "_compile_with_bridges", lambda js: None)
    calls = []

    class SessionWithCreateScript:
        def create_script(self, source, **kwargs):
            calls.append((source, kwargs))
            return "created"

    result = _core._create_script(
        SessionWithCreateScript(),
        "send({type: 'probe'});",
        name="probe",
        runtime="qjs",
    )

    assert result == "created"
    source, kwargs = calls[0]
    assert source.startswith("\n'use strict';")
    assert "send({type: 'probe'});" in source
    assert kwargs == {"name": "probe", "runtime": "qjs"}


def test_managed_script_records_events_posts_messages_and_calls_rpc():
    script = FakeFridaScript()
    managed = _core._ManagedScript(
        id="scr_1",
        session_id="sess_1",
        name="probe",
        kind="script",
        script=script,
        source="send('ready')",
        event_limit=2,
    )

    managed.add_event({"type": "send", "payload": {"ready": True}}, b"abc")
    managed.add_event({"type": "error", "description": "boom", "stack": "trace"})
    managed.add_event({"type": "log", "payload": "ignored"})

    events = managed.get_events(limit=10)
    assert len(events) == 2
    assert events[0]["message_type"] == "error"
    assert events[0]["error"]["description"] == "boom"
    assert events[1]["message"]["payload"] == "ignored"

    managed.post("ping")
    managed.post({"type": "custom"})
    assert script.posts == [{"type": "message", "payload": "ping"}, {"type": "custom"}]
    assert managed.call_rpc("add", [2, 3]) == 5

    managed.unload()
    assert managed.loaded is False
    assert script.unloaded is True


def test_session_registry_tracks_active_session_and_detaches_on_remove():
    registry = _core._SessionRegistry()
    device = FakeDevice()
    session = FakeSession()

    fs = registry.create(device=device, session=session, target="target", pid=4321, kill_on_disconnect=True)

    assert registry.get_active() is fs
    assert registry.list_all()[0]["alive"] is True
    assert "detached" in session.callbacks

    assert registry.remove(fs.id) is True
    assert session.detached is True
    assert device.killed == [4321]
    assert registry.list_all() == []


def test_require_session_removes_dead_active_session(monkeypatch):
    registry = _core._SessionRegistry()
    dead_session = SimpleNamespace(detach=lambda: None)
    registry.create(device=FakeDevice(), session=dead_session, target="dead", pid=99)
    monkeypatch.setattr(_core, "_registry", registry)

    with pytest.raises(RuntimeError, match="Session disconnected"):
        _core._require_session()

    assert registry.list_all() == []
