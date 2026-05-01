"""fuzzmind-frida-mcp -- misc tools."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import time

from .._core import INSTALL_HINT, _create_script, _load_frida, _run_script


def set_exception_handler(target: str, duration_seconds: int = 10) -> dict[str, Any]:
    """Install an in-process exception handler to catch crashes.

    Hooks Process.setExceptionHandler for *duration_seconds*. Captured
    exceptions include type, faulting address, and register context.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = """
    'use strict';
    Process.setExceptionHandler(function(ex) {
        var ctx = {};
        try {
            var c = ex.context;
            ctx.pc = c.pc.toString();
            ctx.sp = c.sp.toString();
            if (Process.arch === 'arm64') {
                ctx.lr = c.lr.toString();
                ctx.fp = c.fp.toString();
                for (var i = 0; i < 29; i++) {
                    ctx['x' + i] = c['x' + i].toString();
                }
            } else if (Process.arch === 'x64') {
                ctx.rax = c.rax.toString();
                ctx.rbx = c.rbx.toString();
                ctx.rcx = c.rcx.toString();
                ctx.rdx = c.rdx.toString();
                ctx.rsi = c.rsi.toString();
                ctx.rdi = c.rdi.toString();
                ctx.rbp = c.rbp.toString();
                ctx.rsp = c.rsp.toString();
                ctx.rip = c.rip.toString();
            }
        } catch(e2) {}
        send({
            type: 'exception',
            exception_type: ex.type,
            address: ex.address ? ex.address.toString() : null,
            context: ctx,
            timestamp: Date.now()
        });
        return false;
    });
    send({type: 'exception_handler_installed', ok: true});
    """
    return _run_script(frida, target, js, duration_seconds=duration_seconds, mode="attach")

def run_on_thread(target: str, thread_id: int, js_code: str) -> dict[str, Any]:
    """Execute JavaScript code on a specific thread in the target process.

    Uses Process.runOnThread() to schedule execution on the given OS
    thread. The *js_code* is evaluated within the thread context.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped = js_code.replace("\\", "\\\\").replace("`", "\\`")

    js = f"""
    'use strict';
    try {{
        Process.runOnThread({thread_id}, function() {{
            try {{
                var result = (function() {{ {escaped} }})();
                send({{type: 'run_on_thread', thread_id: {thread_id}, result: result !== undefined ? String(result) : null, ok: true}});
            }} catch (innerErr) {{
                send({{type: 'error', message: 'Thread execution error: ' + innerErr.message}});
            }}
        }});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def heap_search(target: str, class_name: str) -> dict[str, Any]:
    """Search the heap for live instances of an ObjC class.

    `target`: process name or pid (string).
    `class_name`: exact ObjC class name (e.g. 'NSMutableDictionary').

    Uses ObjC.chooseSync() to find instances on the managed heap.
    Returns addresses and a short description of each instance.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    class_name_js = json.dumps(class_name)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        var cls = ObjC.classes[{class_name_js}];
        if (!cls) {{
            send({{type: 'error', message: 'class not found: ' + {class_name_js}}});
        }} else {{
            var instances = ObjC.chooseSync(cls);
            var items = instances.slice(0, 200).map(function(obj) {{
                var desc = '<no description>';
                try {{ desc = obj.toString().substring(0, 200); }} catch(e) {{}}
                return {{address: obj.handle.toString(), description: desc}};
            }});
            send({{
                type: 'heap_search',
                class_name: {class_name_js},
                items: items,
                count: instances.length,
                truncated: instances.length > 200
            }});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def spawn_and_attach(
    binary_path: str,
    script_path: str | None = None,
    duration_seconds: int = 30,
) -> dict[str, Any]:
    """Spawn a process under Frida, optionally inject a JS script, return output."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    p = Path(binary_path)
    if not p.is_file():
        return {"error": f"binary not found: {binary_path}"}

    js: str | None = None
    if script_path:
        sp = Path(script_path)
        if not sp.is_file():
            return {"error": f"script not found: {script_path}"}
        js = sp.read_text()

    events: list[dict[str, Any]] = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            events.append(msg.get("payload"))
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        device = frida.get_local_device()
        pid = device.spawn([binary_path])
        session = device.attach(pid)

        if js:
            script = _create_script(session, js)
            script.on("message", on_message)
            script.load()

        device.resume(pid)
        time.sleep(duration_seconds)

        if js:
            script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"spawn_and_attach failed: {e}", "events_collected": len(events)}

    return {
        "binary_path": binary_path,
        "pid": pid,
        "duration_seconds": duration_seconds,
        "script_path": script_path,
        "event_count": len(events),
        "events": events[:200],
        "events_truncated": len(events) > 200,
    }
