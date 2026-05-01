"""fuzzmind-frida-mcp -- session tools."""
from __future__ import annotations

from typing import Any
import time

from .._core import INSTALL_HINT, _create_script, _js_literal, _load_frida, _registry, _split_spawn_target


def _prepare_eval_js(
    js_code: str,
    *,
    parameters: Any | None = None,
    auto_perform: bool = False,
) -> str:
    """Apply CLI-like evaluation conveniences without importing script.py."""
    source = js_code
    if auto_perform:
        source = "Java.perform(function () {\n" + source + "\n});"
    if parameters is not None:
        params = _js_literal(parameters)
        source = (
            f"globalThis.parameters = {params};\n"
            f"globalThis.__frida_mcp_parameters = {params};\n"
            + source
        )
    return source


def connect(
    target: str = "",
    device_id: str | None = None,
    spawn: bool = False,
    attach_identifier: str | None = None,
    attach_frontmost: bool = False,
    await_pattern: str | None = None,
    await_timeout: float = 30.0,
    argv: list[str] | None = None,
    env: dict[str, str] | None = None,
    envp: dict[str, str] | None = None,
    cwd: str | None = None,
    stdio: str | None = None,
    aux: dict[str, Any] | None = None,
    realm: str | None = None,
    persist_timeout: int | None = None,
    pause: bool = False,
    kill_on_disconnect: bool = False,
) -> dict[str, Any]:
    """Connect/attach to a process and create a persistent session.

    `target`: process name or pid (string). When `spawn=True`, the full
    binary path to spawn.
    `device_id`: optional Frida device id; defaults to local device.
    `spawn`: if True, spawn the process instead of attaching to an
    existing one.

    Returns session_id that can be used with session-based tools.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_local_device()

        if await_pattern:
            return await_spawn(
                await_pattern,
                device_id=device_id,
                timeout_seconds=await_timeout,
                attach=True,
                resume=not pause,
                realm=realm,
                persist_timeout=persist_timeout,
                kill_on_disconnect=kill_on_disconnect,
            )

        attach_kwargs: dict[str, Any] = {}
        if realm is not None:
            attach_kwargs["realm"] = realm
        if persist_timeout is not None:
            attach_kwargs["persist_timeout"] = persist_timeout

        pid: int | None = None
        if spawn:
            spawn_kwargs: dict[str, Any] = {}
            if argv is not None:
                spawn_kwargs["argv"] = argv
                spawn_program: str | list[str] = target
            else:
                spawn_program = _split_spawn_target(target)
            if env is not None:
                spawn_kwargs["env"] = env
            if envp is not None:
                spawn_kwargs["envp"] = envp
            if cwd is not None:
                spawn_kwargs["cwd"] = cwd
            if stdio is not None:
                spawn_kwargs["stdio"] = stdio
            if aux is not None:
                spawn_kwargs["aux"] = aux

            pid = device.spawn(spawn_program, **spawn_kwargs)
            try:
                frida_session = device.attach(pid, **attach_kwargs)
            except Exception:
                try:
                    device.kill(pid)
                except Exception:
                    try:
                        device.resume(pid)
                    except Exception:
                        pass
                raise
            if not pause:
                device.resume(pid)
        else:
            if attach_frontmost:
                app = device.get_frontmost_application()
                if app is None or not getattr(app, "pid", 0):
                    return {"error": "no frontmost application with a running pid"}
                pid = int(app.pid)
                frida_session = device.attach(pid, **attach_kwargs)
                target = getattr(app, "identifier", None) or getattr(app, "name", None) or str(pid)
            elif attach_identifier is not None:
                app = _find_application_by_identifier(device, attach_identifier)
                if app is None:
                    return {"error": f"application identifier not found: {attach_identifier}"}
                if not getattr(app, "pid", 0):
                    return {
                        "error": f"application is not running: {attach_identifier}",
                        "hint": "Use frida_launch_app first, or use frida_connect(spawn=True) for executable targets.",
                    }
                pid = int(app.pid)
                frida_session = device.attach(pid, **attach_kwargs)
                target = attach_identifier
            elif target.isdigit():
                pid = int(target)
                frida_session = device.attach(pid, **attach_kwargs)
            else:
                if not target:
                    return {"error": "target is required unless attach_frontmost, attach_identifier, or await_pattern is set"}
                frida_session = device.attach(target, **attach_kwargs)
                try:
                    pid = frida_session._impl.pid
                except Exception:
                    pass

        fs = _registry.create(
            device=device,
            session=frida_session,
            target=target,
            pid=pid,
            kill_on_disconnect=kill_on_disconnect,
        )

        return {
            "status": "connected",
            "session_id": fs.id,
            "device": device.name,
            "target": target,
            "pid": pid,
            "spawn": spawn,
            "paused": bool(spawn and pause),
            "realm": realm,
            "persist_timeout": persist_timeout,
            "kill_on_disconnect": kill_on_disconnect,
        }
    except Exception as e:
        message = str(e)
        result: dict[str, Any] = {"error": f"connect failed: {message}"}
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
                "sandboxing, and architecture match. If self-built spawn also fails, run "
                "frida_host_diagnostics from the same host and check the Python host's "
                "com.apple.security.cs.debugger entitlement. Disabling SIP alone is not a complete fix."
            )
        return result


def await_spawn(
    pattern: str,
    device_id: str | None = None,
    timeout_seconds: float = 30.0,
    attach: bool = True,
    resume: bool = True,
    resume_unmatched: bool = True,
    realm: str | None = None,
    persist_timeout: int | None = None,
    kill_on_disconnect: bool = False,
) -> dict[str, Any]:
    """Wait for a pending spawn matching a substring and optionally attach."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        device = frida.get_device(device_id) if device_id else frida.get_local_device()
        deadline = time.time() + max(0.1, min(float(timeout_seconds), 300.0))
        needle = pattern.lower()
        matched = None
        seen_unmatched: set[int] = set()

        def matches(spawn) -> bool:
            identifier = str(getattr(spawn, "identifier", "") or "")
            pid = str(getattr(spawn, "pid", "") or "")
            return needle in identifier.lower() or needle == pid

        def maybe_resume_unmatched(spawn) -> None:
            pid = getattr(spawn, "pid", None)
            if not resume_unmatched or pid is None or pid in seen_unmatched:
                return
            seen_unmatched.add(pid)
            try:
                device.resume(pid)
            except Exception:
                pass

        def on_spawn_added(spawn) -> None:
            nonlocal matched
            if matched is None and matches(spawn):
                matched = spawn
            elif matched is None:
                maybe_resume_unmatched(spawn)

        on = getattr(device, "on", None)
        if callable(on):
            try:
                on("spawn-added", on_spawn_added)
            except Exception:
                pass

        device.enable_spawn_gating()
        try:
            while time.time() < deadline and matched is None:
                for spawn in device.enumerate_pending_spawn():
                    if matches(spawn):
                        matched = spawn
                        break
                    maybe_resume_unmatched(spawn)
                if matched is None:
                    time.sleep(0.05)
        finally:
            try:
                device.disable_spawn_gating()
            except Exception:
                pass

        if matched is None:
            return {"error": f"spawn not observed before timeout: {pattern}", "timeout_seconds": timeout_seconds}

        pid = int(getattr(matched, "pid"))
        identifier = getattr(matched, "identifier", None)
        if not attach:
            if resume:
                device.resume(pid)
            return {
                "status": "matched",
                "pid": pid,
                "identifier": identifier,
                "resumed": resume,
                "attached": False,
            }

        attach_kwargs: dict[str, Any] = {}
        if realm is not None:
            attach_kwargs["realm"] = realm
        if persist_timeout is not None:
            attach_kwargs["persist_timeout"] = persist_timeout
        frida_session = device.attach(pid, **attach_kwargs)
        fs = _registry.create(
            device=device,
            session=frida_session,
            target=identifier or pattern,
            pid=pid,
            kill_on_disconnect=kill_on_disconnect,
        )
        if resume:
            device.resume(pid)
        return {
            "status": "connected",
            "session_id": fs.id,
            "device": device.name,
            "target": identifier or pattern,
            "pid": pid,
            "spawn": False,
            "await_pattern": pattern,
            "paused": not resume,
            "kill_on_disconnect": kill_on_disconnect,
        }
    except Exception as e:
        return {"error": f"await_spawn failed: {e}", "pattern": pattern}


def _find_application_by_identifier(device, identifier: str):
    for app in device.enumerate_applications():
        if getattr(app, "identifier", None) == identifier:
            return app
    return None


def disconnect(session_id: str | None = None) -> dict[str, Any]:
    """Disconnect from the current or specified session."""
    if session_id:
        if _registry.remove(session_id):
            return {"status": "disconnected", "session_id": session_id}
        return {"error": f"session not found: {session_id}"}

    active = _registry.get_active()
    if active:
        sid = active.id
        _registry.remove(sid)
        return {"status": "disconnected", "session_id": sid}
    return {"status": "not_connected"}

def list_sessions() -> dict[str, Any]:
    """List all active Frida sessions."""
    sessions = _registry.list_all()
    return {"items": sessions, "count": len(sessions)}

def switch_session(session_id: str) -> dict[str, Any]:
    """Switch the active session."""
    if _registry.set_active(session_id):
        fs = _registry.get(session_id)
        return {
            "status": "switched",
            "session_id": session_id,
            "target": fs.target if fs else None,
            "pid": fs.pid if fs else None,
        }
    return {"error": f"session not found: {session_id}"}

def is_connected() -> dict[str, Any]:
    """Check if the current session is alive."""
    fs = _registry.get_active()
    if fs is None:
        return {"connected": False, "reason": "no_session"}

    try:
        alive = fs.is_alive()
        result: dict[str, Any] = {
            "connected": alive,
            "session_id": fs.id,
            "target": fs.target,
            "pid": fs.pid,
            "device": getattr(fs.device, "name", str(fs.device)),
        }
        if not alive:
            result["reason"] = "session_dead"
        return result
    except Exception as e:
        return {"connected": False, "reason": str(e)}

def session_get_events(
    session_id: str | None = None,
    clear: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """Read lifecycle events for a persistent Frida session."""
    if session_id:
        fs = _registry.get(session_id)
    else:
        fs = _registry.get_active()
    if fs is None:
        return {"error": "session not found" if session_id else "no active session"}

    events = fs.get_lifecycle_events(clear=clear, limit=limit)
    return {
        "session_id": fs.id,
        "count": len(events),
        "events": events,
        "cleared": clear,
    }

def session_clear_events(session_id: str | None = None) -> dict[str, Any]:
    """Clear lifecycle events for a persistent Frida session."""
    if session_id:
        fs = _registry.get(session_id)
    else:
        fs = _registry.get_active()
    if fs is None:
        return {"error": "session not found" if session_id else "no active session"}

    return {"session_id": fs.id, "cleared": fs.clear_lifecycle_events()}

def session_recover(session_id: str | None = None) -> dict[str, Any]:
    """Try to recover a broken or crashed Frida session.

    Re-attaches to the same PID/target that was stored in the session
    registry. If the original process is still alive, a new Frida session
    is created and replaces the dead one.

    `session_id`: optional; defaults to the current active session.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    if session_id:
        fs = _registry.get(session_id)
    else:
        fs = _registry.get_active()

    if fs is None:
        return {"error": "no session to recover (none active or specified)"}

    old_target = fs.target
    old_pid = fs.pid
    old_device = fs.device
    old_sid = fs.id

    # Clean up the dead session
    _registry.remove(old_sid)

    try:
        # Try to re-attach by PID first, then by name
        new_session = None
        new_pid = None

        if old_pid is not None:
            try:
                new_session = old_device.attach(old_pid)
                new_pid = old_pid
            except Exception:
                pass

        if new_session is None and old_target and not old_target.isdigit():
            try:
                new_session = old_device.attach(old_target)
                try:
                    new_pid = new_session._impl.pid
                except Exception:
                    new_pid = None
            except Exception:
                pass

        if new_session is None:
            return {
                "error": "recovery failed — process not reachable",
                "old_session_id": old_sid,
                "target": old_target,
                "pid": old_pid,
            }

        new_fs = _registry.create(
            device=old_device,
            session=new_session,
            target=old_target,
            pid=new_pid,
        )

        return {
            "status": "recovered",
            "old_session_id": old_sid,
            "new_session_id": new_fs.id,
            "target": old_target,
            "pid": new_pid,
            "device": getattr(old_device, "name", str(old_device)),
        }
    except Exception as e:
        return {"error": f"session_recover failed: {e}"}

def interactive_eval(
    session_id: str,
    js_code: str,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    exit_on_error: bool = False,
) -> dict[str, Any]:
    """Execute arbitrary JS in an existing persistent Frida session.

    REPL-style evaluation: looks up the session from the global
    registry, creates a one-shot script, loads it, collects messages,
    and unloads. Unlike inject_script, this reuses a persistent session
    so hooks and state remain.

    *session_id*: session id from frida_connect / frida_list_sessions.
    *js_code*: JavaScript to evaluate. Use send() to return data.
    """
    fs = _registry.get(session_id)
    if fs is None:
        return {"error": f"session '{session_id}' not found. Use frida_connect first."}
    if not fs.is_alive():
        _registry.remove(fs.id)
        return {"error": "session is dead. Reconnect with frida_connect."}

    events: list[dict[str, Any]] = []
    binary_chunks: list[bytes] = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            events.append(msg.get("payload"))
            if data is not None:
                binary_chunks.append(data)
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        source = _prepare_eval_js(js_code, parameters=parameters, auto_perform=auto_perform)
        script = _create_script(fs.session, source, runtime=runtime)
        script.on("message", on_message)
        script.load()
        time.sleep(2)
        try:
            script.unload()
        except Exception:
            pass
    except Exception as e:
        return {"error": f"interactive_eval failed: {e}", "session_id": session_id}

    errors = [event for event in events if isinstance(event, dict) and event.get("type") == "error"]
    if exit_on_error and errors:
        return {
            "error": "interactive_eval emitted an error",
            "session_id": session_id,
            "runtime": runtime,
            "errors": errors,
            "events": events[:200],
            "events_truncated": len(events) > 200,
        }

    result: dict[str, Any] = {
        "session_id": session_id,
        "runtime": runtime,
        "event_count": len(events),
        "events": events[:200],
        "events_truncated": len(events) > 200,
    }
    if binary_chunks:
        result["binary_count"] = len(binary_chunks)
    return result
