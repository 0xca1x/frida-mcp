"""fuzzmind-frida-mcp -- device tools."""
from __future__ import annotations

from typing import Any

from .._core import INSTALL_HINT, _get_device, _load_frida


def list_devices() -> dict[str, Any]:
    """List all available Frida devices (USB, remote, local)."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        devices = [
            {"id": d.id, "name": d.name, "type": d.type}
            for d in frida.enumerate_devices()
        ]
        return {"items": devices, "count": len(devices)}
    except Exception as e:
        return {"error": f"enumerate_devices failed: {e}"}

def get_device_info(device_id: str | None = None) -> dict[str, Any]:
    """Get info about a specific device or the default local device."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_local_device()
        procs = device.enumerate_processes()
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
            "process_count": len(procs),
        }
    except Exception as e:
        return {"error": f"get_device_info failed: {e}"}

def remote_device_connect(
    host: str,
    port: int = 27042,
) -> dict[str, Any]:
    """Connect to a remote Frida server and return device info.

    Adds a remote device via `frida.get_device_manager().add_remote_device()`.
    The remote device becomes available for all subsequent operations that
    accept a `device_id` parameter.

    `host`: hostname or IP of the remote Frida server.
    `port`: Frida server port (default 27042).

    Returns device id, name, type, and process count.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        address = f"{host}:{port}" if port != 27042 else host
        if port != 27042:
            address = f"{host}:{port}"
        else:
            address = f"{host}:{port}"

        mgr = frida.get_device_manager()
        device = mgr.add_remote_device(address)

        # Verify connectivity by listing processes
        try:
            procs = device.enumerate_processes()
            proc_count = len(procs)
        except Exception:
            proc_count = -1  # connected but can't list

        return {
            "status": "connected",
            "device_id": device.id,
            "device_name": device.name,
            "device_type": device.type,
            "address": address,
            "process_count": proc_count,
        }
    except Exception as e:
        return {"error": f"remote_device_connect failed: {e}"}

def list_apps(device_id: str | None = None) -> dict[str, Any]:
    """List all installed applications on a device.

    Unlike `list_processes` which only shows running processes, this
    enumerates all installed apps including those not currently running.

    `device_id`: optional Frida device id; defaults to local device.
    Returns identifier, name, and pid (0 if not running) for each app.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        device = _get_device(frida, device_id)
        apps = device.enumerate_applications()
        items = [
            {
                "identifier": a.identifier,
                "name": a.name,
                "pid": a.pid,
            }
            for a in apps
        ]
        items.sort(key=lambda a: a["name"].lower())
        return {"items": items, "count": len(items), "device": device.name}
    except Exception as e:
        return {"error": f"list_apps failed: {e}"}

def get_frontmost_app(device_id: str | None = None) -> dict[str, Any]:
    """Get the frontmost (foreground) application on a device.

    `device_id`: optional Frida device id; defaults to local device.
    Returns {identifier, name, pid} or an error if no app is in front.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        device = _get_device(frida, device_id)
        app = device.get_frontmost_application()
        if app is None:
            return {"error": "no frontmost application found"}
        return {
            "identifier": app.identifier,
            "name": app.name,
            "pid": app.pid,
            "device": device.name,
        }
    except Exception as e:
        return {"error": f"get_frontmost_app failed: {e}"}

def launch_app(
    identifier: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Spawn and resume an application by bundle/package identifier.

    `identifier`: app bundle id (iOS/macOS) or package name (Android),
    e.g. 'com.apple.Safari' or 'com.example.app'.
    `device_id`: optional Frida device id; defaults to local device.

    Uses `device.spawn()` + `device.resume()` to launch the app fresh.
    Returns {pid, identifier}.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        device = _get_device(frida, device_id)
        pid = device.spawn([identifier])
        device.resume(pid)
        return {
            "pid": pid,
            "identifier": identifier,
            "device": device.name,
            "status": "launched",
        }
    except Exception as e:
        return {"error": f"launch_app failed: {e}"}

def kill_app(
    target: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Kill a process by PID or name on a device.

    `target`: integer PID (as string) or process name. If a name is
    given, the process list is searched for a matching entry.
    `device_id`: optional Frida device id; defaults to local device.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        device = _get_device(frida, device_id)

        if target.isdigit():
            pid = int(target)
        else:
            # Resolve name to PID
            procs = device.enumerate_processes()
            matched = [p for p in procs if p.name.lower() == target.lower()]
            if not matched:
                # Try substring match
                matched = [p for p in procs if target.lower() in p.name.lower()]
            if not matched:
                return {"error": f"process not found: {target}"}
            pid = matched[0].pid

        device.kill(pid)
        return {
            "pid": pid,
            "target": target,
            "device": device.name,
            "status": "killed",
        }
    except Exception as e:
        return {"error": f"kill_app failed: {e}"}

def resume_process(target_pid: int, device_id: str | None = None) -> dict[str, Any]:
    """Resume a suspended process by PID.

    Standalone resume -- useful after a spawn that was not immediately
    resumed. *target_pid*: integer process ID.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        device = _get_device(frida, device_id)
        device.resume(target_pid)
        return {"pid": target_pid, "resumed": True}
    except Exception as e:
        return {"error": f"resume_process failed: {e}", "pid": target_pid}
