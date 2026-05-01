"""fuzzmind-frida-mcp -- cloak tools."""
from __future__ import annotations

from typing import Any
import json

from .._core import INSTALL_HINT, _load_frida, _run_script


def cloak_thread(target: str, thread_id: int | None = None) -> dict[str, Any]:
    """Hide a thread from process-internal detection using Cloak API.

    *thread_id*: OS thread id. If None, hides the current thread.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    tid_expr = str(thread_id) if thread_id is not None else "Process.getCurrentThreadId()"

    js = f"""
    'use strict';
    try {{
        var tid = {tid_expr};
        Cloak.addThread(tid);
        send({{type: 'cloak_thread', thread_id: tid, ok: true}});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def cloak_range(target: str, address: str, size: int) -> dict[str, Any]:
    """Hide a memory range from detection using Cloak API.

    *address*: base address (hex string).
    *size*: range size in bytes.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        Cloak.addRange({{base: ptr(address), size: {size}}});
        send({{type: 'cloak_range', address: address, size: {size}, ok: true}});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def cloak_fd(target: str, fd: int) -> dict[str, Any]:
    """Hide a file descriptor from detection using Cloak API.

    *fd*: file descriptor number to cloak.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = f"""
    'use strict';
    try {{
        Cloak.addFileDescriptor({fd});
        send({{type: 'cloak_fd', fd: {fd}, ok: true}});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")
