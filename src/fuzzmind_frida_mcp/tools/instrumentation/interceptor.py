"""fuzzmind-frida-mcp -- interceptor tools."""
from __future__ import annotations

from typing import Any
import json

from .._core import INSTALL_HINT, _load_frida, _run_script


def intercept_objc_method(
    target: str,
    class_name: str,
    method_name: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook a specific ObjC method, log args on enter. Return captured invocations."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    class_name_js = json.dumps(class_name)
    method_name_js = json.dumps(method_name)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        const className = {class_name_js};
        const methodName = {method_name_js};
        const cls = ObjC.classes[className];
        if (!cls) {{
            send({{type: 'error', message: 'class not found: ' + className}});
        }} else {{
            const method = cls[methodName];
            if (!method) {{
                send({{type: 'error', message: 'method not found: ' + methodName}});
            }} else {{
                Interceptor.attach(method.implementation, {{
                    onEnter: function(args) {{
                        const invocation = {{
                            type: 'invocation',
                            class: className,
                            method: methodName,
                            self: args[0].toString(),
                            sel: args[1].toString(),
                            timestamp: Date.now()
                        }};
                        // Capture up to 6 arguments beyond self/sel
                        for (let i = 2; i < 8; i++) {{
                            try {{
                                invocation['arg' + (i - 2)] = args[i].toString();
                            }} catch(e) {{ break; }}
                        }}
                        send(invocation);
                    }}
                }});
                send({{type: 'info', message: 'hooked ' + className + ' ' + methodName}});
            }}
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def interceptor_replace(
    target: str,
    function_addr: str,
    replacement_js: str,
    revert_after: int = 0,
) -> dict[str, Any]:
    """Replace a native function with a JS NativeCallback using Interceptor.replace.

    Unlike intercept (which logs calls), this completely replaces the
    function implementation. Use with caution.

    `target`: process name or pid (string).
    `function_addr`: hex address of the function to replace.
    `replacement_js`: JS code that creates and returns a NativeCallback.
      Example: 'new NativeCallback(function(arg0) { send("called"); return 0; }, "int", ["pointer"])'
    `revert_after`: if > 0, auto-revert the replacement after this many
      seconds and restore the original function.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    duration = max(revert_after + 2, 5) if revert_after > 0 else 10

    revert_code = ""
    function_addr_js = json.dumps(function_addr)
    if revert_after > 0:
        revert_code = f"""
        setTimeout(function() {{
            Interceptor.revert(ptr(functionAddr));
            send({{type: 'interceptor_reverted', address: functionAddr, after_seconds: {revert_after}}});
        }}, {revert_after * 1000});
        """

    js = f"""
    'use strict';
    try {{
        var functionAddr = {function_addr_js};
        var addr = ptr(functionAddr);
        var replacement = {replacement_js};
        Interceptor.replace(addr, replacement);
        send({{
            type: 'interceptor_replace',
            address: functionAddr,
            revert_after: {revert_after},
            ok: true
        }});
        {revert_code}
    }} catch(e) {{
        send({{type: 'error', message: 'Interceptor.replace failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=duration, mode="attach")

def spoof_return(
    target: str,
    function_name_or_addr: str,
    return_value: str,
) -> dict[str, Any]:
    """Spoof the return value of a function. Classic anti-debug bypass technique.

    Attaches Interceptor.onLeave to the target function and replaces
    its return value with `return_value` on every call.

    `target`: process name or pid (string).
    `function_name_or_addr`: hex address (e.g. '0x1000') or symbol name
      (e.g. 'ptrace', 'isDebuggerAttached').
    `return_value`: value to replace retval with (as a numeric string,
      e.g. '0', '1', '0xffffffff'). Passed to `ptr()`.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_name = json.dumps(function_name_or_addr)
    escaped_retval = json.dumps(return_value)

    js = f"""
    'use strict';
    var target_name = {escaped_name};
    var spoofVal = {escaped_retval};
    var addr = null;
    if (target_name.indexOf('0x') === 0 || target_name.indexOf('0X') === 0) {{
        addr = ptr(target_name);
    }} else {{
        addr = _fm_find_export(null, target_name);
    }}
    if (!addr || addr.isNull()) {{
        send({{type: 'error', message: 'could not resolve function: ' + target_name}});
    }} else {{
        var spoofCount = 0;
        Interceptor.attach(addr, {{
            onLeave: function(retval) {{
                var original = retval.toString();
                retval.replace(ptr(spoofVal));
                spoofCount++;
                if (spoofCount <= 50) {{
                    send({{
                        type: 'spoof_return',
                        function: target_name,
                        original_retval: original,
                        spoofed_retval: spoofVal,
                        call_number: spoofCount,
                        timestamp: Date.now()
                    }});
                }}
            }}
        }});
        send({{
            type: 'info',
            message: 'spoofing return of ' + target_name + ' at ' + addr + ' -> ' + spoofVal
        }});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=30, mode="attach")

def callstack_tracer(
    target: str,
    function_name_or_addr: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Trace call stacks for a specific function.

    Attaches an Interceptor to the target function and captures a full
    symbolicated backtrace on each invocation using
    Thread.backtrace(context, Backtracer.ACCURATE).

    `target`: process name or pid (string).
    `function_name_or_addr`: either a hex address (e.g. '0x1000') or a
      symbol name to resolve via Module.findExportByName (e.g. 'open',
      'xpc_connection_send_message').
    `duration_seconds`: how long to trace (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_name = json.dumps(function_name_or_addr)

    js = f"""
    'use strict';
    var target_name = {escaped_name};
    var addr = null;
    if (target_name.indexOf('0x') === 0 || target_name.indexOf('0X') === 0) {{
        addr = ptr(target_name);
    }} else {{
        addr = _fm_find_export(null, target_name);
    }}
    if (!addr || addr.isNull()) {{
        send({{type: 'error', message: 'could not resolve function: ' + target_name}});
    }} else {{
        var callCount = 0;
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                callCount++;
                if (callCount <= 200) {{
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    var frames = bt.map(function(a) {{
                        var sym = DebugSymbol.fromAddress(a);
                        return {{
                            address: a.toString(),
                            module: sym.moduleName || '<unknown>',
                            name: sym.name || '<unknown>',
                            offset: sym.fileName ? (sym.fileName + ':' + sym.lineNumber) : null
                        }};
                    }});
                    send({{
                        type: 'callstack',
                        function: target_name,
                        call_number: callCount,
                        tid: this.threadId,
                        frames: frames,
                        timestamp: Date.now()
                    }});
                }}
            }}
        }});
        send({{type: 'info', message: 'tracing callstacks for ' + target_name + ' at ' + addr}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds, "attach")
