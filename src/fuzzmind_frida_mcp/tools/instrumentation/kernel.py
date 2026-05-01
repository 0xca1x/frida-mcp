"""fuzzmind-frida-mcp -- kernel tools."""
from __future__ import annotations

from typing import Any
import json
import time

from .._core import INSTALL_HINT, _create_script, _load_frida


def kernel_read(address: str, length: int) -> dict[str, Any]:
    """Read kernel memory at *address* for *length* bytes.

    Requires Frida kernel access (jailbroken iOS or custom kext).
    Returns hex-encoded bytes.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    js = f"""
    'use strict';
    try {{
        if (!Kernel.available) {{
            send({{type: 'error', message: 'Kernel API not available (requires kernel access)'}});
        }} else {{
            var address = {address_js};
            var data = Kernel.readByteArray(ptr(address), {length});
            send({{type: 'kernel_read', address: address, length: {length}}}, data);
        }}
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
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
        session = frida.attach(0)  # kernel
        script = _create_script(session, js)
        script.on("message", on_message)
        script.load()
        time.sleep(1)
        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"kernel_read failed: {e}"}

    result: dict[str, Any] = {"address": address, "length": length, "events": events}
    if binary_chunks:
        result["hex"] = binary_chunks[0].hex()
        result["bytes_read"] = len(binary_chunks[0])
    return result

def kernel_write(address: str, hex_bytes: str) -> dict[str, Any]:
    """Write bytes to kernel memory at *address*.

    *hex_bytes*: hex-encoded bytes (e.g. 'deadbeef').
    Requires Frida kernel access.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    clean = hex_bytes.replace(" ", "")
    byte_array = ",".join(str(b) for b in bytes.fromhex(clean))
    address_js = json.dumps(address)

    js = f"""
    'use strict';
    try {{
        if (!Kernel.available) {{
            send({{type: 'error', message: 'Kernel API not available (requires kernel access)'}});
        }} else {{
            var address = {address_js};
            var bytes = new Uint8Array([{byte_array}]);
            Kernel.writeByteArray(ptr(address), bytes.buffer);
            send({{type: 'kernel_write', address: address, bytes_written: bytes.length}});
        }}
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    try:
        session = frida.attach(0)
        script = _create_script(session, js)
        events: list[dict[str, Any]] = []
        script.on("message", lambda msg, data: events.append(msg.get("payload")) if msg.get("type") == "send" else None)
        script.load()
        time.sleep(1)
        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"kernel_write failed: {e}"}

    return {"address": address, "hex_bytes": clean, "events": events}

def kernel_scan(address: str, size: int, pattern: str) -> dict[str, Any]:
    """Scan kernel memory for a hex pattern.

    *address*: start address (hex string).
    *size*: number of bytes to scan.
    *pattern*: Frida hex pattern (e.g. '48 8b ?? c3').
    Requires Frida kernel access.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    pattern_js = json.dumps(pattern)
    js = f"""
    'use strict';
    try {{
        if (!Kernel.available) {{
            send({{type: 'error', message: 'Kernel API not available (requires kernel access)'}});
        }} else {{
            var address = {address_js};
            var pattern = {pattern_js};
            var matches = Kernel.scanSync(ptr(address), {size}, pattern);
            send({{
                type: 'kernel_scan',
                address: address,
                size: {size},
                pattern: pattern,
                matches: matches.map(function(m) {{ return {{address: m.address.toString(), size: m.size}}; }}).slice(0, 500),
                total_matches: matches.length
            }});
        }}
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    try:
        session = frida.attach(0)
        script = _create_script(session, js)
        events: list[dict[str, Any]] = []
        script.on("message", lambda msg, data: events.append(msg.get("payload")) if msg.get("type") == "send" else None)
        script.load()
        time.sleep(2)
        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"kernel_scan failed: {e}"}

    return {"address": address, "size": size, "pattern": pattern, "events": events}

def kernel_enumerate_modules() -> dict[str, Any]:
    """Enumerate kernel modules (kexts / kernel extensions).

    Requires Frida kernel access.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = """
    'use strict';
    try {
        if (!Kernel.available) {
            send({type: 'error', message: 'Kernel API not available (requires kernel access)'});
        } else {
            var modules = Kernel.enumerateModules();
            send({
                type: 'kernel_modules',
                modules: modules.map(function(m) {
                    return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
                }),
                count: modules.length
            });
        }
    } catch (e) {
        send({type: 'error', message: e.message});
    }
    """
    try:
        session = frida.attach(0)
        script = _create_script(session, js)
        events: list[dict[str, Any]] = []
        script.on("message", lambda msg, data: events.append(msg.get("payload")) if msg.get("type") == "send" else None)
        script.load()
        time.sleep(1)
        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"kernel_enumerate_modules failed: {e}"}

    return {"events": events}
