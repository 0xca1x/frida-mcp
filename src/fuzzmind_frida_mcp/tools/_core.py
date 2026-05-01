"""Shared infrastructure for fuzzmind-frida-mcp tools.

Contains Frida lazy-loader, session registry, script runner, and
inline subprocess helpers (zero external dependencies beyond frida).
"""
from __future__ import annotations

import base64
import os
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from threading import RLock
from typing import Any


# ---------------------------------------------------------------------------
# Inline subprocess helpers
# ---------------------------------------------------------------------------

@dataclass
class _ProcResult:
    stdout: str
    stderr: str
    returncode: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _have_tool(name: str) -> bool:
    return _resolve_tool(name) is not None


def _resolve_tool(name: str) -> str | None:
    scripts_dir = os.path.dirname(sys.executable)
    candidates = [os.path.join(scripts_dir, name)]
    if os.name == "nt":
        candidates.extend(os.path.join(scripts_dir, name + ext) for ext in (".exe", ".cmd", ".bat"))

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return shutil.which(name)


def _run_cmd(
    args: list[str],
    *,
    check: bool = False,
    timeout: float = 30.0,
    env: dict | None = None,
) -> _ProcResult:
    if args and os.path.basename(args[0]) == args[0]:
        resolved = _resolve_tool(args[0])
        if resolved is not None:
            args = [resolved, *args[1:]]

    full_env = {**os.environ, **(env or {})} if env else None
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, env=full_env,
        )
    except FileNotFoundError:
        return _ProcResult("", f"command not found: {args[0]}", 127)
    except subprocess.TimeoutExpired:
        return _ProcResult("", f"timeout after {timeout}s", -1)
    if check and r.returncode != 0:
        raise subprocess.CalledProcessError(r.returncode, args, r.stdout, r.stderr)
    return _ProcResult(r.stdout, r.stderr, r.returncode)


# ---------------------------------------------------------------------------
# Frida lazy-loader
# ---------------------------------------------------------------------------

INSTALL_HINT = {
    "install": "pip install frida-tools  (Python bindings + frida-trace / frida-ps)",
    "url": "https://frida.re",
}

_FRIDA_JS_PRELUDE = r"""
'use strict';
if (typeof globalThis.ObjC === 'undefined') {
    const error = 'ObjC bridge is not loaded. With Frida 17+ API clients must bundle frida-objc-bridge, or use a frida-tools entrypoint that provides it.';
    globalThis.ObjC = { available: false, _fmMissingBridge: true, _fmError: error };
}
if (typeof globalThis.Java === 'undefined') {
    const error = 'Java bridge is not loaded. With Frida 17+ API clients must bundle frida-java-bridge, or use a frida-tools entrypoint that provides it.';
    globalThis.Java = {
        available: false,
        _fmMissingBridge: true,
        _fmError: error,
        perform: function () { throw new Error(error); },
        performNow: function () { throw new Error(error); }
    };
}
if (typeof globalThis.Swift === 'undefined') {
    const error = 'Swift bridge is not loaded. Bundle frida-swift-bridge before using Swift bridge APIs.';
    globalThis.Swift = { available: false, _fmMissingBridge: true, _fmError: error };
}
if (typeof globalThis._fm_find_export !== 'function') {
    globalThis._fm_find_export = function (moduleName, exportName) {
        if (moduleName !== null && moduleName !== undefined) {
            const module = Process.findModuleByName(moduleName);
            if (module !== null) {
                const exportAddress = module.findExportByName(exportName);
                if (exportAddress !== null) {
                    return exportAddress;
                }
            }
        }
        return Module.findGlobalExportByName(exportName);
    };
}
"""


def _js_literal(value: Any) -> str:
    """Return a JavaScript literal for JSON-compatible Python data."""
    return json.dumps(value)


def _split_spawn_target(target: str) -> list[str]:
    args = shlex.split(target)
    if not args:
        raise ValueError("spawn target is empty")
    return args


def _bridge_import_block(js: str) -> str:
    """Return ES-module imports needed by bridge-using scripts."""
    imports: list[str] = []
    if "ObjC" in js:
        imports.append("import ObjC from 'frida-objc-bridge';\nglobalThis.ObjC = ObjC;")
    if "Java" in js:
        imports.append("import Java from 'frida-java-bridge';\nglobalThis.Java = Java;")
    if "Swift" in js:
        imports.append("import Swift from 'frida-swift-bridge';\nglobalThis.Swift = Swift;")
    return "\n".join(imports)


def _compile_with_bridges(js: str) -> str | None:
    """Bundle bridge imports when local frida.Compiler can resolve them.

    Frida 17 removed Java/ObjC/Swift bridges from GumJS for API users. If
    the bridge npm packages are available in the project, this compiles an
    IIFE bundle that restores the previous global ObjC/Java/Swift names.
    """
    imports = _bridge_import_block(js)
    if not imports:
        return None

    frida_mod = _load_frida()
    if frida_mod is None or not hasattr(frida_mod, "Compiler"):
        return None

    for root in _bridge_project_roots():
        bundled = _compile_bridge_bundle(frida_mod, imports, js, root)
        if bundled is not None:
            return bundled
    return None


def _bridge_project_roots() -> list[str]:
    roots: list[str] = []
    explicit = os.environ.get("FUZZMIND_FRIDA_BRIDGE_ROOT")
    if explicit:
        roots.append(os.path.expanduser(explicit))
    roots.append(os.path.join(os.path.expanduser("~"), ".fuzzmind", "frida-mcp", "frida-bridges"))
    roots.append(os.getcwd())
    return list(dict.fromkeys(roots))


def _compile_bridge_bundle(frida_mod, imports: str, js: str, project_root: str) -> str | None:
    if not os.path.isdir(project_root):
        return None

    fd, path = tempfile.mkstemp(
        prefix="fuzzmind-frida-agent-",
        suffix=".js",
        dir=project_root,
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(f"{imports}\n{_FRIDA_JS_PRELUDE}\n{js}")
        compiler = frida_mod.Compiler()
        return compiler.build(
            path,
            project_root=project_root,
            bundle_format="iife",
            platform="gum",
            type_check="none",
            source_maps="omitted",
        )
    except Exception:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _create_script(
    session: Any,
    js: str,
    *,
    name: str | None = None,
    runtime: str | None = None,
):
    """Create a Frida script with project helper functions available."""
    bundled = _compile_with_bridges(js)
    source = bundled if bundled is not None else f"{_FRIDA_JS_PRELUDE}\n{js}"
    kwargs: dict[str, Any] = {}
    if name is not None:
        kwargs["name"] = name
    if runtime is not None:
        kwargs["runtime"] = runtime
    try:
        return session.create_script(source, **kwargs)
    except TypeError:
        return session.create_script(source)


def _load_frida():
    try:
        import frida  # local import -- large native module
        return frida
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Session management -- persistent attach/detach lifecycle
# ---------------------------------------------------------------------------

def _truncate_payload(value: Any, limit: int = 10000) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "...[truncated]"
    return value


@dataclass
class _ManagedScript:
    """A long-running script owned by a persistent Frida session."""

    id: str
    session_id: str
    name: str
    kind: str
    script: Any
    source: str
    created_at: float = field(default_factory=time.time)
    loaded: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)
    event_limit: int = 1000
    _event_seq: int = 0
    _lock: RLock = field(default_factory=RLock)

    def add_event(self, msg: dict[str, Any], data: bytes | None = None) -> None:
        with self._lock:
            self._event_seq += 1
            entry: dict[str, Any] = {
                "seq": self._event_seq,
                "ts": time.time(),
                "script_id": self.id,
                "script_name": self.name,
                "kind": self.kind,
                "message_type": msg.get("type", "message"),
            }
            if msg.get("type") == "send":
                entry["payload"] = _truncate_payload(msg.get("payload"))
                if data is not None:
                    raw = bytes(data)
                    entry["data_size"] = len(raw)
                    entry["data_base64"] = base64.b64encode(raw).decode("ascii")
            elif msg.get("type") == "error":
                entry["error"] = {
                    "description": msg.get("description"),
                    "stack": _truncate_payload(msg.get("stack")),
                    "fileName": msg.get("fileName"),
                    "lineNumber": msg.get("lineNumber"),
                    "columnNumber": msg.get("columnNumber"),
                }
            else:
                entry["message"] = {k: _truncate_payload(v) for k, v in msg.items()}

            self.events.append(entry)
            if len(self.events) > self.event_limit:
                self.events = self.events[-self.event_limit:]

    def get_events(self, *, limit: int = 100, clear: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            limit = max(1, min(limit, self.event_limit))
            events = list(self.events[-limit:])
            if clear:
                self.events = []
            return events

    def clear_events(self) -> int:
        with self._lock:
            n = len(self.events)
            self.events = []
            return n

    def post(self, message: Any) -> None:
        if isinstance(message, str):
            self.script.post({"type": "message", "payload": message})
        else:
            self.script.post(message)

    def call_rpc(self, method: str, args: list[Any] | None = None) -> Any:
        exports = getattr(self.script, "exports_sync", None)
        if exports is None:
            exports = getattr(self.script, "exports", None)
        if exports is None:
            raise RuntimeError("script does not expose rpc.exports")

        try:
            fn = getattr(exports, method)
        except AttributeError as e:
            raise RuntimeError(f"rpc method not found: {method}") from e
        if not callable(fn):
            raise RuntimeError(f"rpc export is not callable: {method}")
        return fn(*(args or []))

    def unload(self) -> None:
        try:
            self.script.unload()
        finally:
            self.loaded = False

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "session_id": self.session_id,
                "name": self.name,
                "kind": self.kind,
                "loaded": self.loaded,
                "created_at": self.created_at,
                "event_count": len(self.events),
            }


@dataclass
class _FridaSession:
    """State for a single persistent Frida session."""

    id: str
    device: Any  # frida.core.Device
    session: Any  # frida.core.Session
    target: str
    pid: int | None
    kill_on_disconnect: bool = False
    scripts: dict[str, _ManagedScript] = field(default_factory=dict)
    lifecycle_events: list[dict[str, Any]] = field(default_factory=list)
    lifecycle_event_limit: int = 500
    _lock: RLock = field(default_factory=RLock)

    def add_script(
        self,
        *,
        script: Any,
        source: str,
        name: str | None = None,
        kind: str = "script",
        event_limit: int = 1000,
    ) -> _ManagedScript:
        with self._lock:
            script_id = "scr_" + str(uuid.uuid4())[:8]
            managed = _ManagedScript(
                id=script_id,
                session_id=self.id,
                name=name or script_id,
                kind=kind,
                script=script,
                source=source,
                event_limit=event_limit,
            )
            self.scripts[script_id] = managed
            return managed

    def get_script(self, script_id: str) -> _ManagedScript | None:
        with self._lock:
            return self.scripts.get(script_id)

    def list_scripts(self, kind: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            scripts = [
                managed.to_dict()
                for managed in self.scripts.values()
                if kind is None or managed.kind == kind
            ]
        scripts.sort(key=lambda item: item["created_at"])
        return scripts

    def unload_script(self, script_id: str) -> bool:
        with self._lock:
            managed = self.scripts.pop(script_id, None)
        if managed is None:
            return False
        try:
            managed.unload()
        except Exception:
            pass
        return True

    def unload_scripts(self, kind: str | None = None) -> int:
        with self._lock:
            script_ids = [
                script_id
                for script_id, managed in self.scripts.items()
                if kind is None or managed.kind == kind
            ]
        count = 0
        for script_id in script_ids:
            if self.unload_script(script_id):
                count += 1
        return count

    def get_events(
        self,
        *,
        script_id: str | None = None,
        kind: str | None = None,
        limit: int = 100,
        clear: bool = False,
    ) -> list[dict[str, Any]]:
        with self._lock:
            scripts = list(self.scripts.values())
        if script_id is not None:
            scripts = [managed for managed in scripts if managed.id == script_id]
        if kind is not None:
            scripts = [managed for managed in scripts if managed.kind == kind]

        events: list[dict[str, Any]] = []
        for managed in scripts:
            events.extend(managed.get_events(limit=limit, clear=clear))
        events.sort(key=lambda item: (item.get("ts", 0), item.get("seq", 0)))
        return events[-max(1, limit):]

    def clear_events(self, *, script_id: str | None = None, kind: str | None = None) -> int:
        with self._lock:
            scripts = list(self.scripts.values())
        if script_id is not None:
            scripts = [managed for managed in scripts if managed.id == script_id]
        if kind is not None:
            scripts = [managed for managed in scripts if managed.kind == kind]
        return sum(managed.clear_events() for managed in scripts)

    def add_lifecycle_event(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        with self._lock:
            entry = {
                "type": event_type,
                "ts": time.time(),
                "session_id": self.id,
                "target": self.target,
                "pid": self.pid,
            }
            if payload:
                entry.update(payload)
            self.lifecycle_events.append(entry)
            if len(self.lifecycle_events) > self.lifecycle_event_limit:
                self.lifecycle_events = self.lifecycle_events[-self.lifecycle_event_limit:]

    def get_lifecycle_events(self, *, clear: bool = False, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            limit = max(1, min(limit, self.lifecycle_event_limit))
            events = list(self.lifecycle_events[-limit:])
            if clear:
                self.lifecycle_events = []
            return events

    def clear_lifecycle_events(self) -> int:
        with self._lock:
            n = len(self.lifecycle_events)
            self.lifecycle_events = []
            return n

    def is_alive(self) -> bool:
        try:
            self.session._impl.pid  # noqa: B018  -- side-effect probe
            return True
        except Exception:
            return False

    def detach(self) -> None:
        self.unload_scripts()
        self.add_lifecycle_event("disconnect")
        try:
            self.session.detach()
        except Exception:
            pass
        if self.kill_on_disconnect and self.pid is not None:
            try:
                self.device.kill(self.pid)
            except Exception:
                pass


class _SessionRegistry:
    """Tracks multiple persistent Frida sessions with one active default."""

    def __init__(self) -> None:
        self._sessions: dict[str, _FridaSession] = {}
        self._active_id: str | None = None
        self._lock = RLock()

    def create(
        self,
        device: Any,
        session: Any,
        target: str,
        pid: int | None,
        *,
        kill_on_disconnect: bool = False,
    ) -> _FridaSession:
        sid = str(uuid.uuid4())[:8]
        fs = _FridaSession(
            id=sid,
            device=device,
            session=session,
            target=target,
            pid=pid,
            kill_on_disconnect=kill_on_disconnect,
        )
        _install_session_lifecycle_callbacks(fs)
        with self._lock:
            self._sessions[sid] = fs
            self._active_id = sid
        return fs

    def get_active(self) -> _FridaSession | None:
        with self._lock:
            if self._active_id and self._active_id in self._sessions:
                return self._sessions[self._active_id]
            return None

    def get(self, sid: str) -> _FridaSession | None:
        with self._lock:
            return self._sessions.get(sid)

    def set_active(self, sid: str) -> bool:
        with self._lock:
            if sid in self._sessions:
                self._active_id = sid
                return True
            return False

    def remove(self, sid: str) -> bool:
        with self._lock:
            if sid in self._sessions:
                self._sessions[sid].detach()
                del self._sessions[sid]
                if self._active_id == sid:
                    self._active_id = next(iter(self._sessions), None)
                return True
            return False

    def list_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "id": fs.id,
                    "target": fs.target,
                    "pid": fs.pid,
                    "device": getattr(fs.device, "name", str(fs.device)),
                    "active": fs.id == self._active_id,
                    "alive": fs.is_alive(),
                    "kill_on_disconnect": fs.kill_on_disconnect,
                }
                for fs in self._sessions.values()
            ]

    def find_script(
        self,
        script_id: str,
        session_id: str | None = None,
    ) -> tuple[_FridaSession, _ManagedScript] | None:
        with self._lock:
            if session_id is not None:
                fs = self._sessions.get(session_id)
                sessions = [fs] if fs is not None else []
            else:
                sessions = list(self._sessions.values())
        for fs in sessions:
            managed = fs.get_script(script_id)
            if managed is not None:
                return fs, managed
        return None


_registry = _SessionRegistry()


def _install_session_lifecycle_callbacks(fs: _FridaSession) -> None:
    """Record Frida session lifecycle events when the binding exposes them."""
    on = getattr(fs.session, "on", None)
    if not callable(on):
        return

    def on_detached(reason=None, crash=None, *args):
        payload: dict[str, Any] = {"reason": reason}
        if crash is not None:
            payload["crash"] = _json_safe(crash)
        if args:
            payload["args"] = [_json_safe(arg) for arg in args]
        fs.add_lifecycle_event("detached", payload)

    try:
        on("detached", on_detached)
    except Exception:
        pass


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except Exception:
        return str(value)


def _require_session(session_id: str | None = None) -> _FridaSession:
    """Return the active session or raise with a helpful message."""
    fs = _registry.get(session_id) if session_id is not None else _registry.get_active()
    if fs is None:
        if session_id is not None:
            raise RuntimeError(f"Frida session not found: {session_id}")
        raise RuntimeError("No active Frida session. Use connect() first.")
    if not fs.is_alive():
        _registry.remove(fs.id)
        raise RuntimeError("Session disconnected. Use connect() to reconnect.")
    return fs


def _load_managed_script(
    fs: _FridaSession,
    js_code: str,
    *,
    name: str | None = None,
    kind: str = "script",
    event_limit: int = 1000,
    runtime: str | None = None,
) -> _ManagedScript:
    """Create, register, and load a long-running Frida script."""
    script = _create_script(fs.session, js_code, name=name, runtime=runtime)
    managed = fs.add_script(
        script=script,
        source=js_code,
        name=name,
        kind=kind,
        event_limit=event_limit,
    )

    def on_message(msg, data):
        managed.add_event(msg, data)

    try:
        script.on("message", on_message)
        script.load()
        managed.loaded = True
    except Exception:
        fs.unload_script(managed.id)
        raise
    return managed


def _get_device(frida_mod, device_id: str | None = None):
    """Resolve a Frida device by id, or return the local device."""
    if device_id:
        return frida_mod.get_device(device_id)
    return frida_mod.get_local_device()


def _run_script(
    frida_mod,
    target: str,
    js: str,
    duration_seconds: int,
    mode: str,
    device_id: str | None = None,
    runtime: str | None = None,
    exit_on_error: bool = False,
    kill_on_exit: bool = False,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if data is not None:
                raw = bytes(data)
                if isinstance(payload, dict):
                    payload = dict(payload)
                else:
                    payload = {"payload": payload}
                payload["data_size"] = len(raw)
                payload["data_base64"] = base64.b64encode(raw).decode("ascii")
            events.append(payload)
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        device = _get_device(frida_mod, device_id)
        if mode == "spawn":
            pid = device.spawn(_split_spawn_target(target))
            try:
                session = device.attach(pid)
            except Exception:
                try:
                    device.kill(pid)
                except Exception:
                    try:
                        device.resume(pid)
                    except Exception:
                        pass
                raise
        else:
            if target.isdigit():
                attach_target = int(target)
            else:
                attach_target = target
            if device_id is not None:
                session = device.attach(attach_target)
            else:
                session = frida_mod.attach(attach_target)
            pid = None

        script = _create_script(session, js, runtime=runtime)
        script.on("message", on_message)
        script.load()
        if exit_on_error and any(isinstance(event, dict) and event.get("type") == "error" for event in events):
            try:
                script.unload()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
            if mode == "spawn" and pid is not None:
                try:
                    device.kill(pid)
                except Exception:
                    try:
                        device.resume(pid)
                    except Exception:
                        pass
            return {
                "error": "script emitted an error during load",
                "target": target,
                "device_id": device_id,
                "duration_seconds": duration_seconds,
                "mode": mode,
                "runtime": runtime,
                "kill_on_exit": kill_on_exit,
                "event_count": len(events),
                "events": events[:200],
                "events_truncated": len(events) > 200,
            }
        if mode == "spawn" and pid is not None:
            device.resume(pid)

        time.sleep(duration_seconds)
        script.unload()
        session.detach()
        if mode == "spawn" and pid is not None and kill_on_exit:
            try:
                device.kill(pid)
            except Exception:
                pass
    except frida_mod.PermissionDeniedError as e:
        return {
            "error": f"permission denied attaching to {target}: {e}",
            "hint": (
                "macOS attach can be blocked by Developer Tools/TCC permission, SIP/task_for_pid policy, "
                "platform-binary protections, sandboxing, or architecture mismatch. SIP changes alone do not "
                "guarantee attach. Avoid Apple system binaries such as /bin/sleep as the first probe; "
                "verify a self-built spawned test process works and run frida_host_diagnostics from the same host."
            ),
        }
    except frida_mod.ProcessNotFoundError as e:
        return {"error": f"process not found: {target} ({e})"}
    except Exception as e:
        result: dict[str, Any] = {"error": f"frida script run failed: {e}", "events_collected": len(events)}
        message = str(e)
        if "frida-helper appears to have crashed" in message:
            result["hint"] = (
                "Frida helper crashed while trying to access the spawned target. Verify that the MCP is "
                "using a clean official frida>=17.9.3 install from the same virtual environment, then run "
                "frida_host_diagnostics and retry against a self-built target before testing protected apps."
            )
            return result
        if "unable to access process" in message.lower() or "permission" in message.lower():
            result["hint"] = (
                "Frida could not obtain debug access. On macOS, check Developer Tools/TCC permission "
                "for the terminal/Python host, SIP/task_for_pid policy, platform-binary protections, "
                "sandboxing, and architecture match. Avoid Apple system binaries such as /bin/sleep "
                "as the first probe. If self-built spawn also fails, check frida_host_diagnostics and the "
                "Python host's com.apple.security.cs.debugger entitlement. Disabling SIP alone is not a complete fix."
            )
        return result

    return {
        "target": target,
        "device_id": device_id,
        "duration_seconds": duration_seconds,
        "mode": mode,
        "runtime": runtime,
        "kill_on_exit": kill_on_exit,
        "event_count": len(events),
        "events": events[:200],
        "events_truncated": len(events) > 200,
    }
