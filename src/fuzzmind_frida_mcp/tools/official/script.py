"""Official Frida API wrapper group."""
from __future__ import annotations

import base64
import time
import uuid
from threading import RLock
from typing import Any

from .._core import (
    INSTALL_HINT,
    _create_script,
    _get_device,
    _json_safe,
    _load_frida,
    _registry,
    _require_session,
    _run_script,
)
from .common import (
    _BusRecord,
    _PortalRecord,
    _application_summary,
    _bus_records,
    _child_summary,
    _decode_base64,
    _device_summary,
    _official_lock,
    _portal_records,
    _process_summary,
    _service_request_params,
    _spawn_summary,
    _target_value,
)

_script_log_events: dict[str, list[dict[str, Any]]] = {}
_script_log_lock = RLock()



def script_load_bytes(
    data_base64: str,
    session_id: str | None = None,
    name: str | None = None,
    event_limit: int = 1000,
) -> dict[str, Any]:
    """Load a compiled script blob with Session.create_script_from_bytes()."""
    try:
        fs = _require_session(session_id)
        data = base64.b64decode(data_base64)
        script = fs.session.create_script_from_bytes(data, name=name)
        managed = fs.add_script(script=script, source="<bytes>", name=name, kind="script-bytes", event_limit=event_limit)

        def on_message(msg, data):
            managed.add_event(msg, data)

        script.on("message", on_message)
        script.load()
        managed.loaded = True
        return {"status": "loaded", "session_id": fs.id, "script_id": managed.id, "script": managed.to_dict()}
    except Exception as e:
        return {"error": f"script_load_bytes failed: {e}"}


def session_compile_script(
    js_code: str,
    session_id: str | None = None,
    name: str | None = None,
    runtime: str | None = None,
) -> dict[str, Any]:
    """Call Session.compile_script() and return bytecode as base64."""
    try:
        fs = _require_session(session_id)
        blob = fs.session.compile_script(js_code, name=name, runtime=runtime)
        raw = bytes(blob)
        return {
            "status": "compiled",
            "session_id": fs.id,
            "name": name,
            "runtime": runtime,
            "byte_length": len(raw),
            "data_base64": base64.b64encode(raw).decode("ascii"),
        }
    except Exception as e:
        return {"error": f"session_compile_script failed: {e}"}


def session_snapshot_script(
    embed_script: str,
    warmup_script: str | None = None,
    session_id: str | None = None,
    runtime: str | None = None,
) -> dict[str, Any]:
    """Call Session.snapshot_script() and return snapshot bytes as base64."""
    try:
        fs = _require_session(session_id)
        blob = fs.session.snapshot_script(embed_script, warmup_script=warmup_script, runtime=runtime)
        raw = bytes(blob)
        return {
            "status": "snapshotted",
            "session_id": fs.id,
            "runtime": runtime,
            "byte_length": len(raw),
            "data_base64": base64.b64encode(raw).decode("ascii"),
        }
    except Exception as e:
        return {"error": f"session_snapshot_script failed: {e}"}


def script_list_exports(script_id: str, session_id: str | None = None) -> dict[str, Any]:
    """Call Script.list_exports_sync() / list_exports()."""
    found = None
    try:
        from .._core import _registry

        found = _registry.find_script(script_id, session_id=session_id)
    except Exception:
        found = None
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found
    try:
        if hasattr(managed.script, "list_exports_sync"):
            exports = managed.script.list_exports_sync()
        else:
            exports = managed.script.list_exports()
        return {"session_id": fs.id, "script_id": managed.id, "exports": list(exports), "count": len(exports)}
    except Exception as e:
        return {"error": f"script_list_exports failed: {e}", "script_id": script_id}


def script_enable_debugger(script_id: str, port: int | None = None, session_id: str | None = None) -> dict[str, Any]:
    """Call Script.enable_debugger()."""
    from .._core import _registry

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found
    try:
        managed.script.enable_debugger(port=port)
        return {"status": "enabled", "session_id": fs.id, "script_id": managed.id, "port": port}
    except Exception as e:
        return {"error": f"script_enable_debugger failed: {e}", "script_id": script_id}


def script_disable_debugger(script_id: str, session_id: str | None = None) -> dict[str, Any]:
    """Call Script.disable_debugger()."""
    from .._core import _registry

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found
    try:
        managed.script.disable_debugger()
        return {"status": "disabled", "session_id": fs.id, "script_id": managed.id}
    except Exception as e:
        return {"error": f"script_disable_debugger failed: {e}", "script_id": script_id}


def script_post_binary(
    script_id: str,
    message: Any,
    data_base64: str,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Call Script.post(message, data=bytes)."""
    from .._core import _registry

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found
    try:
        raw = base64.b64decode(data_base64)
        managed.script.post(message, data=raw)
        return {"status": "posted", "session_id": fs.id, "script_id": managed.id, "bytes_sent": len(raw)}
    except Exception as e:
        return {"error": f"script_post_binary failed: {e}", "script_id": script_id}


def script_set_log_handler(script_id: str, session_id: str | None = None) -> dict[str, Any]:
    """Set Script.set_log_handler() to queue log events for this MCP."""
    from .._core import _registry

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found

    def handler(*args):
        with _script_log_lock:
            events = _script_log_events.setdefault(managed.id, [])
            events.append({
                "ts": time.time(),
                "session_id": fs.id,
                "script_id": managed.id,
                "args": [_json_safe(arg) for arg in args],
            })
            _script_log_events[managed.id] = events[-1000:]

    try:
        managed.script.set_log_handler(handler)
        with _script_log_lock:
            _script_log_events.setdefault(managed.id, [])
        return {"status": "set", "session_id": fs.id, "script_id": managed.id}
    except Exception as e:
        return {"error": f"script_set_log_handler failed: {e}", "script_id": script_id}


def script_get_log_events(
    script_id: str,
    session_id: str | None = None,
    clear: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """Read queued Script log-handler events."""
    from .._core import _registry

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found
    with _script_log_lock:
        events = list(_script_log_events.get(managed.id, [])[-max(1, min(limit, 1000)):])
        if clear:
            _script_log_events[managed.id] = []
    return {"session_id": fs.id, "script_id": managed.id, "count": len(events), "events": events, "cleared": clear}


def script_get_log_handler(script_id: str, session_id: str | None = None) -> dict[str, Any]:
    """Call Script.get_log_handler() and return a safe description."""
    from .._core import _registry

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found
    try:
        handler = managed.script.get_log_handler()
        return {
            "session_id": fs.id,
            "script_id": managed.id,
            "handler": repr(handler),
            "queued_event_count": len(_script_log_events.get(managed.id, [])),
        }
    except Exception as e:
        return {"error": f"script_get_log_handler failed: {e}", "script_id": script_id}


def script_reset_log_handler(script_id: str, session_id: str | None = None) -> dict[str, Any]:
    """Reset Script logging to Script.default_log_handler."""
    from .._core import _registry

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found
    try:
        managed.script.set_log_handler(managed.script.default_log_handler)
        with _script_log_lock:
            _script_log_events.pop(managed.id, None)
        return {"status": "reset", "session_id": fs.id, "script_id": managed.id}
    except Exception as e:
        return {"error": f"script_reset_log_handler failed: {e}", "script_id": script_id}
