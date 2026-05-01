"""fuzzmind-frida-mcp -- hooks tools."""
from __future__ import annotations

from typing import Any
import json
import threading
import time

from .._core import (
    INSTALL_HINT,
    _load_frida,
    _load_managed_script,
    _require_session,
    _run_script,
)


def install_hook(
    js_code: str,
    name: str | None = None,
    duration_seconds: int = 0,
) -> dict[str, Any]:
    """Install a persistent hook that stays active and collects messages.

    `js_code`: Frida JS to run. Use `send(...)` to emit messages.
    `name`: optional label for the hook.
    `duration_seconds`: if >0, auto-unload after this many seconds
      (0 = stays until manually uninstalled).
    """
    try:
        fs = _require_session()
    except RuntimeError as e:
        return {"error": str(e)}

    hook_name = name or f"hook_{len(fs.list_scripts(kind='hook'))}"

    try:
        managed = _load_managed_script(fs, js_code, name=hook_name, kind="hook")

        if duration_seconds > 0:
            def _auto_unload():
                time.sleep(duration_seconds)
                fs.unload_script(managed.id)

            threading.Thread(target=_auto_unload, daemon=True).start()

        return {
            "status": "installed",
            "script_id": managed.id,
            "name": hook_name,
            "session_id": fs.id,
            "total_hooks": len(fs.list_scripts(kind="hook")),
        }
    except Exception as e:
        return {"error": f"install_hook failed: {e}"}

def get_hook_messages(clear: bool = False) -> dict[str, Any]:
    """Get collected messages from persistent hooks."""
    try:
        fs = _require_session()
    except RuntimeError as e:
        return {"error": str(e)}

    events = fs.get_events(kind="hook", clear=clear)
    return {"count": len(events), "session_id": fs.id, "events": events}

def clear_hook_messages() -> dict[str, Any]:
    """Clear the hook message buffer."""
    try:
        fs = _require_session()
    except RuntimeError as e:
        return {"error": str(e)}

    cleared = fs.clear_events(kind="hook")
    return {"cleared": cleared, "session_id": fs.id}

def uninstall_hooks() -> dict[str, Any]:
    """Unload all persistent hook scripts in the current session."""
    try:
        fs = _require_session()
    except RuntimeError as e:
        return {"error": str(e)}

    count = fs.unload_scripts(kind="hook")
    return {"uninstalled": count, "session_id": fs.id}

def list_hooks() -> dict[str, Any]:
    """List all installed persistent hooks in the current session."""
    try:
        fs = _require_session()
    except RuntimeError as e:
        return {"error": str(e)}

    hooks = fs.list_scripts(kind="hook")
    return {"items": hooks, "count": len(hooks), "session_id": fs.id}

def hook_native_by_offset(
    module: str,
    offset: str,
    name: str | None = None,
) -> dict[str, Any]:
    """Hook a native function by module name + hex offset.

    `module`: module name (partial match, case-insensitive).
    `offset`: hex offset within the module (e.g. '0x1234').
    `name`: optional label for the hook.

    Different from `hook_native_function` which uses an absolute address.
    This finds the module base at runtime and adds the offset.
    """
    try:
        fs = _require_session()
    except RuntimeError as e:
        return {"error": str(e)}

    hook_name = name or f"native_{module}_{offset}"

    js_code = (
        "var mod = null;\n"
        "var pattern = " + json.dumps(module.lower()) + ";\n"
        "Process.enumerateModules().forEach(function(m) {\n"
        "    if (m.name.toLowerCase().indexOf(pattern) !== -1) mod = m;\n"
        "});\n"
        "if (mod) {\n"
        "    var addr = mod.base.add(" + offset + ");\n"
        "    Interceptor.attach(addr, {\n"
        "        onEnter: function(args) {\n"
        "            var parts = [];\n"
        "            for (var i = 0; i < 6; i++) {\n"
        "                try { parts.push('arg' + i + '=' + args[i]); } catch(e) { break; }\n"
        "            }\n"
        "            send({type: 'enter', hook: " + json.dumps(hook_name) + ",\n"
        "                  address: addr.toString(), args: parts.join(', '),\n"
        "                  tid: Process.getCurrentThreadId(), ts: Date.now()});\n"
        "        },\n"
        "        onLeave: function(ret) {\n"
        "            send({type: 'leave', hook: " + json.dumps(hook_name) + ",\n"
        "                  retval: ret.toString(), ts: Date.now()});\n"
        "        }\n"
        "    });\n"
        "    send({type: 'info', message: 'hooked ' + mod.name + ' @ ' + addr});\n"
        "} else {\n"
        "    send({type: 'error', message: 'module not found: " + module + "'});\n"
        "}\n"
    )

    try:
        managed = _load_managed_script(fs, js_code, name=hook_name, kind="hook")

        return {
            "status": "installed",
            "script_id": managed.id,
            "name": hook_name,
            "module": module,
            "offset": offset,
            "session_id": fs.id,
        }
    except Exception as e:
        return {"error": f"hook_native_by_offset failed: {e}"}

def hook_native_function(
    target: str,
    address: str,
    on_enter_js: str | None = None,
    on_leave_js: str | None = None,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook a native function by address using Interceptor.attach.

    `target`: process name or pid (string).
    `address`: hex address of the function to hook.
    `on_enter_js`: custom JS body for onEnter(args). Has access to `args`,
      `this.context`, and `send()`. Default logs the call.
    `on_leave_js`: custom JS body for onLeave(retval). Has access to `retval`,
      `this.context`, and `send()`. Default logs return.
    `duration_seconds`: how long to keep the hook active.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    enter_body = on_enter_js if on_enter_js else (
        "send({type: 'enter', address: " + address_js + ", "
        "tid: this.threadId, "
        "arg0: args[0].toString(), arg1: args[1].toString(), "
        "arg2: args[2].toString(), timestamp: Date.now()});"
    )
    leave_body = on_leave_js if on_leave_js else (
        "send({type: 'leave', address: " + address_js + ", "
        "retval: retval.toString(), timestamp: Date.now()});"
    )

    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        Interceptor.attach(ptr(address), {{
            onEnter: function(args) {{
                {enter_body}
            }},
            onLeave: function(retval) {{
                {leave_body}
            }}
        }});
        send({{type: 'info', message: 'hooked native at ' + address}});
    }} catch(e) {{
        send({{type: 'error', message: 'hook_native_function failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds, "attach")
