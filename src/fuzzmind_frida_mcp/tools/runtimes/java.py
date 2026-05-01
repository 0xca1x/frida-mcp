"""fuzzmind-frida-mcp -- java tools."""
from __future__ import annotations

from typing import Any
import json
import time

from .._core import INSTALL_HINT, _load_frida, _run_script


def java_list_classes(
    target: str,
    filter: str | None = None,
    limit: int = 500,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Enumerate loaded Java/ART classes in a target process.

    `target`: process name or pid (string).
    `filter`: optional case-insensitive substring to filter class names.
    `limit`: max classes to return (default 500).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_filter = json.dumps(filter.lower()) if filter else "null"

    js = f"""
    'use strict';
    if (!Java.available) {{
        send({{type: 'error', message: Java._fmError || 'Java/ART runtime not available'}});
    }} else Java.perform(function() {{
        var classes = [];
        Java.enumerateLoadedClasses({{
            onMatch: function(name) {{ classes.push(name); }},
            onComplete: function() {{
                var filt = {escaped_filter};
                if (filt) {{
                    classes = classes.filter(function(n) {{
                        return n.toLowerCase().indexOf(filt) !== -1;
                    }});
                }}
                var total = classes.length;
                classes.sort();
                send({{
                    type: 'java_classes',
                    items: classes.slice(0, {int(limit)}),
                    count: total,
                    truncated: total > {int(limit)}
                }});
            }}
        }});
    }});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach", device_id=device_id)

def java_list_methods(
    target: str,
    class_name: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """List declared methods of a Java class.

    `target`: process name or pid (string).
    `class_name`: fully qualified Java class name (e.g. 'javax.crypto.Cipher').
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_cls = json.dumps(class_name)

    js = f"""
    'use strict';
    if (!Java.available) {{
        send({{type: 'error', message: Java._fmError || 'Java/ART runtime not available'}});
    }} else Java.perform(function() {{
        try {{
            var cls = Java.use({escaped_cls});
            var methods = cls.class.getDeclaredMethods().map(function(m) {{
                return m.toString();
            }});
            send({{
                type: 'java_methods',
                class_name: {escaped_cls},
                items: methods,
                count: methods.length
            }});
        }} catch(e) {{
            send({{type: 'error', message: 'java_list_methods failed: ' + e.message}});
        }}
    }});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach", device_id=device_id)

def java_hook_method(
    target: str,
    class_name: str,
    method_name: str,
    duration_seconds: int = 10,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Hook all overloads of a Java method and collect invocations.

    `target`: process name or pid (string).
    `class_name`: fully qualified Java class name.
    `method_name`: method name to hook (all overloads are hooked).
    `duration_seconds`: how long to collect invocations (default 10).

    Each invocation is sent as {method, args: [String]} via send().
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_cls = json.dumps(class_name)
    escaped_method = json.dumps(method_name)

    js = f"""
    'use strict';
    if (!Java.available) {{
        send({{type: 'error', message: Java._fmError || 'Java/ART runtime not available'}});
    }} else Java.perform(function() {{
        try {{
            var cls = Java.use({escaped_cls});
            var target = cls[{escaped_method}];
            if (!target || !target.overloads) {{
                send({{type: 'error', message: 'method not found: ' + {escaped_cls} + '.' + {escaped_method}}});
                return;
            }}
            target.overloads.forEach(function(overload) {{
                overload.implementation = function() {{
                    var argStrs = [];
                    for (var i = 0; i < arguments.length; i++) {{
                        try {{
                            argStrs.push(String(arguments[i]));
                        }} catch(e) {{
                            argStrs.push('<unreadable>');
                        }}
                    }}
                    send({{
                        type: 'java_invocation',
                        class_name: {escaped_cls},
                        method: {escaped_method},
                        args: argStrs,
                        timestamp: Date.now()
                    }});
                    return overload.apply(this, arguments);
                }};
            }});
            send({{type: 'info', message: 'hooked ' + {escaped_cls} + '.' + {escaped_method} + ' (' + target.overloads.length + ' overloads)'}});
        }} catch(e) {{
            send({{type: 'error', message: 'java_hook_method failed: ' + e.message}});
        }}
    }});
    """
    return _run_script(frida, target, js, duration_seconds, mode="attach", device_id=device_id)

def java_call(
    target: str,
    java_js_code: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Execute arbitrary JS inside a Java.perform() block.

    `target`: process name or pid (string).
    `java_js_code`: JavaScript code that will be wrapped in
    `Java.perform(function() { ... })`. Has access to `Java.use()`,
    `Java.choose()`, `send()`, etc.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = f"""
    'use strict';
    if (!Java.available) {{
        send({{type: 'error', message: Java._fmError || 'Java/ART runtime not available'}});
    }} else Java.perform(function() {{
        {java_js_code}
    }});
    """
    return _run_script(frida, target, js, duration_seconds=10, mode="attach", device_id=device_id)

def java_load_dex(
    target: str,
    dex_path: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Dynamically load a DEX file into an Android process.

    Uses `Java.openClassFile().load()` to inject a DEX at runtime.
    The classes defined in the DEX become available for use with
    `Java.use()` after loading.

    `target`: process name or pid (string).
    `dex_path`: path to the .dex file on the target device's filesystem.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_path = json.dumps(dex_path)

    js = f"""
    'use strict';
    if (!Java.available) {{
        send({{type: 'error', message: Java._fmError || 'Java/ART runtime not available'}});
    }} else Java.perform(function() {{
        try {{
            Java.openClassFile({escaped_path}).load();
            send({{
                type: 'java_load_dex',
                path: {escaped_path},
                status: 'loaded'
            }});
        }} catch(e) {{
            send({{type: 'error', message: 'java_load_dex failed: ' + e.message}});
        }}
    }});
    """
    return _run_script(frida, target, js, duration_seconds=10, mode="attach", device_id=device_id)
