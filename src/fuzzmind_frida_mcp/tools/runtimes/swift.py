"""fuzzmind-frida-mcp -- swift tools."""
from __future__ import annotations

from typing import Any
import time

from .._core import INSTALL_HINT, _js_literal, _load_frida, _run_script


def swift_demangle(
    target: str,
    symbol: str,
) -> dict[str, Any]:
    """Demangle a Swift symbol using the in-process Swift runtime.

    `target`: process name or pid (string) that has Swift runtime loaded.
    `symbol`: mangled Swift symbol (e.g. '$s4MyApp...').
    Returns the demangled human-readable name.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    symbol_js = _js_literal(symbol)

    js = f"""
    'use strict';
    try {{
        const swiftDemanglePtr = _fm_find_export('libswiftCore.dylib', 'swift_demangle');
        if (swiftDemanglePtr === null) {{
            send({{type: 'error', message: 'swift_demangle not found — Swift runtime not loaded in target'}});
        }} else {{
            const swift_demangle = new NativeFunction(
                swiftDemanglePtr,
                'pointer',
                ['pointer', 'size_t', 'pointer', 'pointer', 'int32']
            );
            const input = Memory.allocUtf8String({symbol_js});
            const result = swift_demangle(input, 0, ptr(0), ptr(0), 0);
            if (result.isNull()) {{
                send({{type: 'swift_demangle', symbol: {symbol_js}, demangled: null, ok: false, message: 'demangle returned null'}});
            }} else {{
                const demangled = result.readUtf8String();
                send({{type: 'swift_demangle', symbol: {symbol_js}, demangled: demangled, ok: true}});
            }}
        }}
    }} catch(e) {{
        send({{type: 'error', message: 'swift_demangle failed: ' + e.message + ' — Swift runtime may not be loaded in target'}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def api_resolver(
    target: str,
    query: str,
    type: str = "objc",
) -> dict[str, Any]:
    """Resolve API symbols using Frida's ApiResolver.

    `target`: process name or pid (string).
    `query`: match pattern, e.g. '-[NSURL *]' (objc) or 'exports:libsystem*!open*' (module).
    `type`: 'objc' or 'module'.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    if type not in ("objc", "module"):
        return {"error": f"invalid resolver type: {type!r} (must be 'objc' or 'module')"}

    type_js = _js_literal(type)
    query_js = _js_literal(query)

    js = f"""
    'use strict';
    try {{
        const resolver = new ApiResolver({type_js});
        const matches = resolver.enumerateMatches({query_js});
        send({{
            type: 'api_resolver',
            resolver_type: {type_js},
            query: {query_js},
            items: matches.slice(0, 2000).map(m => ({{
                name: m.name,
                address: m.address.toString()
            }})),
            count: matches.length,
            truncated: matches.length > 2000
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'api_resolver failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")
