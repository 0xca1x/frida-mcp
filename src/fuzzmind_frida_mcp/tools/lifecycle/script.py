"""fuzzmind-frida-mcp -- script tools."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import shlex
import subprocess
import time

from .._core import (
    INSTALL_HINT,
    _create_script,
    _have_tool,
    _js_literal,
    _load_frida,
    _load_managed_script,
    _registry,
    _require_session,
    _run_cmd,
    _run_script,
)


def _prepare_js(
    js_code: str,
    *,
    parameters: Any | None = None,
    auto_perform: bool = False,
) -> str:
    """Apply CLI-like script conveniences to source before loading."""
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


def inject_script(
    target: str,
    script_path: str,
    duration_seconds: int = 30,
    mode: str = "attach",
    device_id: str | None = None,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    exit_on_error: bool = False,
    kill_on_exit: bool = False,
    output_file: str | None = None,
) -> dict[str, Any]:
    """Run a Frida JS script. `mode` is 'attach' (existing process) or
    'spawn' (start a new process under frida).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    sp = Path(script_path)
    if not sp.is_file():
        return {"error": f"script not found: {script_path}"}
    js = _prepare_js(sp.read_text(), parameters=parameters, auto_perform=auto_perform)

    result = _run_script(
        frida,
        target,
        js,
        duration_seconds,
        mode,
        device_id=device_id,
        runtime=runtime,
        exit_on_error=exit_on_error,
        kill_on_exit=kill_on_exit,
    )
    if output_file:
        Path(output_file).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        result["output_file"] = output_file
    return result


def eval_code(
    target: str,
    js_code: str,
    duration_seconds: int = 5,
    mode: str = "attach",
    device_id: str | None = None,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    exit_on_error: bool = False,
    kill_on_exit: bool = False,
    output_file: str | None = None,
) -> dict[str, Any]:
    """Evaluate inline JavaScript against a target, equivalent to CLI `-e`."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    if not js_code.strip():
        return {"error": "js_code is empty"}

    source = _prepare_js(js_code, parameters=parameters, auto_perform=auto_perform)
    result = _run_script(
        frida,
        target,
        source,
        duration_seconds,
        mode,
        device_id=device_id,
        runtime=runtime,
        exit_on_error=exit_on_error,
        kill_on_exit=kill_on_exit,
    )
    if output_file:
        Path(output_file).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        result["output_file"] = output_file
    return result

def load_script_file(
    target: str,
    script_path: str,
    duration_seconds: int = 10,
    device_id: str | None = None,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    exit_on_error: bool = False,
    kill_on_exit: bool = False,
    output_file: str | None = None,
) -> dict[str, Any]:
    """Read a local .js file and inject it via _run_script().

    Convenience wrapper: reads the JS source from `script_path` on the
    host, then injects it into the target process. Simpler than
    `inject_script` for quick one-off scripts when you already have
    the file path.

    `target`: process name or pid (string).
    `script_path`: local path to a Frida JS file.
    `duration_seconds`: how long to keep the script active (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    sp = Path(script_path)
    if not sp.is_file():
        return {"error": f"script not found: {script_path}"}

    js = _prepare_js(sp.read_text(), parameters=parameters, auto_perform=auto_perform)
    if not js.strip():
        return {"error": f"script is empty: {script_path}"}

    result = _run_script(
        frida,
        target,
        js,
        duration_seconds,
        "attach",
        device_id=device_id,
        runtime=runtime,
        exit_on_error=exit_on_error,
        kill_on_exit=kill_on_exit,
    )
    result["script_path"] = script_path
    if output_file:
        Path(output_file).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        result["output_file"] = output_file
    return result

def script_load(
    js_code: str,
    session_id: str | None = None,
    name: str | None = None,
    kind: str = "script",
    event_limit: int = 1000,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    enable_debugger: bool = False,
    debugger_port: int | None = None,
    exit_on_error: bool = False,
) -> dict[str, Any]:
    """Load a long-running script into a persistent session.

    The script stays loaded until `script_unload` or session disconnect.
    Messages from `send()` and runtime errors are stored in the script event
    queue and can be retrieved with `script_get_events`.
    """
    if not js_code.strip():
        return {"error": "js_code is empty"}

    try:
        fs = _require_session(session_id)
        source = _prepare_js(js_code, parameters=parameters, auto_perform=auto_perform)
        managed = _load_managed_script(
            fs,
            source,
            name=name,
            kind=kind,
            event_limit=event_limit,
            runtime=runtime,
        )
        if enable_debugger:
            managed.script.enable_debugger(port=debugger_port)
        errors = [
            event
            for event in managed.get_events(limit=event_limit)
            if event.get("message_type") == "error"
        ]
        if exit_on_error and errors:
            fs.unload_script(managed.id)
            return {
                "error": "script emitted an error during load",
                "session_id": fs.id,
                "errors": errors,
            }
    except Exception as e:
        return {"error": f"script_load failed: {e}"}

    item = managed.to_dict()
    return {
        "status": "loaded",
        "session_id": fs.id,
        "script_id": managed.id,
        "script": item,
        "runtime": runtime,
        "debugger_enabled": enable_debugger,
        "debugger_port": debugger_port,
    }

def script_load_file(
    script_path: str,
    session_id: str | None = None,
    name: str | None = None,
    kind: str = "script",
    event_limit: int = 1000,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    enable_debugger: bool = False,
    debugger_port: int | None = None,
    exit_on_error: bool = False,
) -> dict[str, Any]:
    """Load a local JavaScript file as a long-running session script."""
    sp = Path(script_path)
    if not sp.is_file():
        return {"error": f"script not found: {script_path}"}

    js_code = sp.read_text()
    result = script_load(
        js_code,
        session_id=session_id,
        name=name or sp.name,
        kind=kind,
        event_limit=event_limit,
        runtime=runtime,
        parameters=parameters,
        auto_perform=auto_perform,
        enable_debugger=enable_debugger,
        debugger_port=debugger_port,
        exit_on_error=exit_on_error,
    )
    result["script_path"] = script_path
    return result

def script_list(
    session_id: str | None = None,
    kind: str | None = None,
) -> dict[str, Any]:
    """List long-running scripts in a session."""
    try:
        fs = _require_session(session_id)
    except RuntimeError as e:
        return {"error": str(e)}

    items = fs.list_scripts(kind=kind)
    return {"session_id": fs.id, "items": items, "count": len(items)}

def script_unload(
    script_id: str,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Unload a long-running script by id."""
    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}

    fs, _managed = found
    if fs.unload_script(script_id):
        return {"status": "unloaded", "session_id": fs.id, "script_id": script_id}
    return {"error": f"script not found: {script_id}", "session_id": fs.id}

def script_reload(
    script_id: str,
    session_id: str | None = None,
    js_code: str | None = None,
    script_path: str | None = None,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
) -> dict[str, Any]:
    """Reload a long-running script, preserving its name and kind."""
    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, old = found

    if script_path is not None:
        sp = Path(script_path)
        if not sp.is_file():
            return {"error": f"script not found: {script_path}"}
        source = sp.read_text()
    elif js_code is not None:
        source = js_code
    else:
        source = old.source

    source = _prepare_js(source, parameters=parameters, auto_perform=auto_perform)
    if not source.strip():
        return {"error": "reload source is empty"}

    try:
        new = _load_managed_script(
            fs,
            source,
            name=old.name,
            kind=old.kind,
            event_limit=old.event_limit,
            runtime=runtime,
        )
        fs.unload_script(old.id)
    except Exception as e:
        return {"error": f"script_reload failed: {e}", "script_id": script_id}

    return {
        "status": "reloaded",
        "session_id": fs.id,
        "old_script_id": script_id,
        "script_id": new.id,
        "script": new.to_dict(),
        "runtime": runtime,
    }

def script_call_rpc(
    script_id: str,
    method: str,
    args: list[Any] | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Call an `rpc.exports` function exposed by a long-running script."""
    if args is not None and not isinstance(args, list):
        return {"error": "args must be a list"}

    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found

    try:
        result = managed.call_rpc(method, args=args)
        return {
            "status": "ok",
            "session_id": fs.id,
            "script_id": managed.id,
            "method": method,
            "result": result,
        }
    except Exception as e:
        return {
            "error": f"script_call_rpc failed: {e}",
            "session_id": fs.id,
            "script_id": managed.id,
            "method": method,
        }

def script_post_message(
    script_id: str,
    message: str | dict | list,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Post a JSON-serialisable message to a long-running script."""
    found = _registry.find_script(script_id, session_id=session_id)
    if found is None:
        return {"error": f"script not found: {script_id}"}
    fs, managed = found

    try:
        managed.post(message)
        return {
            "status": "posted",
            "session_id": fs.id,
            "script_id": managed.id,
            "script_name": managed.name,
        }
    except Exception as e:
        return {"error": f"script_post_message failed: {e}", "script_id": script_id}

def script_get_events(
    script_id: str | None = None,
    session_id: str | None = None,
    kind: str | None = None,
    clear: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """Read queued events from long-running scripts."""
    if script_id is not None:
        found = _registry.find_script(script_id, session_id=session_id)
        if found is None:
            return {"error": f"script not found: {script_id}"}
        fs, managed = found
        events = managed.get_events(limit=limit, clear=clear)
        return {
            "session_id": fs.id,
            "script_id": managed.id,
            "count": len(events),
            "events": events,
            "cleared": clear,
        }

    try:
        fs = _require_session(session_id)
    except RuntimeError as e:
        return {"error": str(e)}

    events = fs.get_events(kind=kind, limit=limit, clear=clear)
    return {
        "session_id": fs.id,
        "kind": kind,
        "count": len(events),
        "events": events,
        "cleared": clear,
    }

def script_clear_events(
    script_id: str | None = None,
    session_id: str | None = None,
    kind: str | None = None,
) -> dict[str, Any]:
    """Clear queued events for one script or a whole session."""
    if script_id is not None:
        found = _registry.find_script(script_id, session_id=session_id)
        if found is None:
            return {"error": f"script not found: {script_id}"}
        fs, managed = found
        cleared = managed.clear_events()
        return {"session_id": fs.id, "script_id": managed.id, "cleared": cleared}

    try:
        fs = _require_session(session_id)
    except RuntimeError as e:
        return {"error": str(e)}

    cleared = fs.clear_events(kind=kind)
    return {"session_id": fs.id, "kind": kind, "cleared": cleared}

def script_export_events(
    output_path: str,
    script_id: str | None = None,
    session_id: str | None = None,
    kind: str | None = None,
    format: str = "jsonl",
    clear: bool = False,
    limit: int = 10000,
) -> dict[str, Any]:
    """Export queued script events to JSON or JSONL."""
    if format not in {"jsonl", "json"}:
        return {"error": "format must be 'jsonl' or 'json'"}

    events_result = script_get_events(
        script_id=script_id,
        session_id=session_id,
        kind=kind,
        clear=clear,
        limit=limit,
    )
    if "error" in events_result:
        return events_result

    events = events_result.get("events", [])
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if format == "jsonl":
        out.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events))
    else:
        out.write_text(json.dumps(events, indent=2, sort_keys=True) + "\n")

    return {
        "status": "exported",
        "output_path": str(out),
        "format": format,
        "event_count": len(events),
        "cleared": clear,
        "session_id": events_result.get("session_id"),
        "script_id": events_result.get("script_id"),
    }

def script_compile(
    script_path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Compile a Frida JS script to bytecode for faster injection.

    Shells out to `frida-compile` to produce an optimised bundle.
    If `output_path` is not given, writes to `<script_path>.compiled.js`.

    `script_path`: path to the source .js file.
    `output_path`: optional path for the compiled output.
    """
    sp = Path(script_path)
    if not sp.is_file():
        return {"error": f"script not found: {script_path}"}

    if not _have_tool("frida-compile"):
        return {"error": "frida-compile not installed. pip install frida-tools", **INSTALL_HINT}

    out = output_path or str(sp.with_suffix(".compiled.js"))
    res = _run_cmd(["frida-compile", str(sp), "-o", out], check=False, timeout=60.0)

    if res.returncode != 0:
        return {
            "error": f"frida-compile failed (exit {res.returncode})",
            "stderr": res.stderr[:2000],
        }

    out_p = Path(out)
    return {
        "status": "compiled",
        "input_path": script_path,
        "output_path": out,
        "input_size": sp.stat().st_size,
        "output_size": out_p.stat().st_size if out_p.is_file() else 0,
    }

def script_eternalize(
    target: str,
    js_code: str,
) -> dict[str, Any]:
    """Inject a script and eternalize it so it survives detach.

    The script is loaded into the target process and then
    `script.eternalize()` is called, so the hooks persist even after
    the Frida session detaches. Useful for long-running instrumentation.

    `target`: process name or pid (string).
    `js_code`: Frida JS code to inject.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    events: list[dict[str, Any]] = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            events.append(msg.get("payload"))
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        device = frida.get_local_device()
        if target.isdigit():
            session = frida.attach(int(target))
        else:
            session = frida.attach(target)

        script = _create_script(session, js_code)
        script.on("message", on_message)
        script.load()

        # Give the script a moment to initialise
        time.sleep(1)

        script.eternalize()

        # Detach cleanly — the script lives on inside the process
        session.detach()

        return {
            "status": "eternalized",
            "target": target,
            "hint": "script persists in-process after detach; re-attach or kill the process to remove it",
            "init_events": events[:50],
        }
    except Exception as e:
        return {"error": f"script_eternalize failed: {e}", "events_collected": len(events)}

def cmodule_compile(
    target: str,
    c_code: str,
    symbols: dict[str, str] | None = None,
    toolchain: str | None = None,
) -> dict[str, Any]:
    """Compile inline C code and load it into the target process via CModule.

    Uses Frida's CModule API to JIT-compile C source inside the target
    process. Optionally links against existing symbols.

    `target`: process name or pid (string).
    `c_code`: C source code to compile.
    `symbols`: optional dict mapping symbol names to hex addresses for
      linking (e.g. {"my_func": "0x100004000"}).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_c = json.dumps(c_code)
    symbols_js = "{}"
    if symbols:
        pairs = ", ".join(f"{json.dumps(k)}: ptr({json.dumps(v)})" for k, v in symbols.items())
        symbols_js = "{" + pairs + "}"
    options_js = "{}" if toolchain is None else json.dumps({"toolchain": toolchain})

    js = f"""
    'use strict';
    try {{
        var cm = new CModule({escaped_c}, {symbols_js}, {options_js});
        send({{
            type: 'cmodule',
            address: cm.toString(),
            toolchain: {json.dumps(toolchain)},
            status: 'compiled'
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'CModule compilation failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=10, mode="attach")

def native_function_call(
    target: str,
    address: str,
    return_type: str,
    arg_types: list[str],
    args: list[str],
) -> dict[str, Any]:
    """Call a native function by address inside the target process.

    Constructs a NativeFunction with the given signature and invokes it.

    `target`: process name or pid (string).
    `address`: hex address of the function (e.g. '0x100004000').
    `return_type`: Frida NativeFunction return type (e.g. 'void', 'int',
      'pointer', 'uint64', 'float', 'double').
    `arg_types`: list of argument types (e.g. ['pointer', 'int']).
    `args`: list of argument values as strings. Pointers as hex strings,
      ints as decimal or hex strings.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_ret = json.dumps(return_type)
    escaped_arg_types = json.dumps(arg_types)

    # Build argument expressions for JS
    arg_exprs = []
    for i, (atype, aval) in enumerate(zip(arg_types, args)):
        escaped_val = json.dumps(aval)
        if atype == "pointer":
            arg_exprs.append(f"ptr({escaped_val})")
        elif atype in ("float", "double"):
            arg_exprs.append(f"parseFloat({escaped_val})")
        else:
            # int, uint, int64, uint64, etc.
            arg_exprs.append(f"parseInt({escaped_val})")
    args_js = ", ".join(arg_exprs) if arg_exprs else ""
    address_js = json.dumps(address)

    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        var fn = new NativeFunction(ptr(address), {escaped_ret}, {escaped_arg_types});
        var result = fn({args_js});
        var resultStr;
        if (typeof result === 'object' && result !== null && result.toString) {{
            resultStr = result.toString();
        }} else {{
            resultStr = String(result);
        }}
        send({{
            type: 'native_call',
            address: address,
            return_type: {escaped_ret},
            result: resultStr,
            status: 'ok'
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'native_function_call failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def inject_library(
    target: str,
    library_path: str,
    entrypoint: str = "",
    data: str = "",
) -> dict[str, Any]:
    """Inject a shared library (.dylib / .so) into a target process.

    Uses Frida's `Device.inject_library_file()` to load the library.
    The library's `entrypoint` function is called with `data` as its
    argument after loading.

    `target`: process name or pid (string).
    `library_path`: path to the .dylib or .so to inject.
    `entrypoint`: optional symbol name to call after load (default: '').
    `data`: optional string argument passed to the entrypoint (default: '').
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    lp = Path(library_path)
    if not lp.is_file():
        return {"error": f"library not found: {library_path}"}

    try:
        device = frida.get_local_device()
        process_target = int(target) if target.isdigit() else target
        lib_id = device.inject_library_file(process_target, str(lp), entrypoint, data)

        return {
            "status": "injected",
            "target": target,
            "library_path": str(lp),
            "entrypoint": entrypoint or "(none)",
            "library_id": lib_id,
        }
    except Exception as e:
        return {"error": f"inject_library failed: {e}"}

def trace_function(
    target: str,
    include: list[str] | None = None,
    duration_seconds: int = 10,
    output_file: str | None = None,
    mode: str = "attach",
    device_id: str | None = None,
    attach_identifier: str | None = None,
    attach_frontmost: bool = False,
    await_pattern: str | None = None,
    runtime: str | None = None,
    include_module: list[str] | None = None,
    exclude_module: list[str] | None = None,
    exclude: list[str] | None = None,
    add: list[str] | None = None,
    include_imports: list[str] | None = None,
    include_module_imports: list[str] | None = None,
    include_objc_method: list[str] | None = None,
    exclude_objc_method: list[str] | None = None,
    include_swift_func: list[str] | None = None,
    exclude_swift_func: list[str] | None = None,
    include_java_method: list[str] | None = None,
    exclude_java_method: list[str] | None = None,
    include_debug_symbol: list[str] | None = None,
    init_session: str | None = None,
    parameters: Any | None = None,
    quiet: bool = False,
    decorate: bool = False,
    ui_host: str | None = None,
    ui_port: int | None = None,
    ui_allow_origin: list[str] | None = None,
) -> dict[str, Any]:
    """Wraps `frida-trace`. `target` is a process name or pid (string).

    `include` is a list of frida-trace `-i` patterns; e.g.
    ['xpc_connection_send_*', 'objc:NSURL*'].
    """
    if not _have_tool("frida-trace"):
        return {"error": "frida-trace not installed", **INSTALL_HINT}

    args: list[str] = ["frida-trace"]
    if device_id:
        args += ["-D", device_id]
    if attach_frontmost:
        args += ["-F"]
    elif attach_identifier:
        args += ["-N", attach_identifier]
    elif await_pattern:
        args += ["-W", await_pattern]
    elif mode == "spawn":
        args += ["-f", target]
    elif target.isdigit():
        args += ["-p", target]
    else:
        args += ["-n", target]

    if runtime is not None:
        args += ["--runtime", runtime]
    for value in include_module or []:
        args += ["-I", value]
    for value in exclude_module or []:
        args += ["-X", value]
    for pat in include or []:
        args += ["-i", pat]
    for value in exclude or []:
        args += ["-x", value]
    for value in add or []:
        args += ["-a", value]
    for value in include_imports or []:
        args += ["-T", value]
    for value in include_module_imports or []:
        args += ["-t", value]
    for value in include_objc_method or []:
        args += ["-m", value]
    for value in exclude_objc_method or []:
        args += ["-M", value]
    for value in include_swift_func or []:
        args += ["-y", value]
    for value in exclude_swift_func or []:
        args += ["-Y", value]
    for value in include_java_method or []:
        args += ["-j", value]
    for value in exclude_java_method or []:
        args += ["-J", value]
    for value in include_debug_symbol or []:
        args += ["-s", value]
    if init_session is not None:
        args += ["-S", init_session]
    if parameters is not None:
        args += ["-P", json.dumps(parameters)]
    if quiet:
        args += ["-q"]
    if decorate:
        args += ["-d"]
    if ui_host is not None:
        args += ["--ui-host", ui_host]
    if ui_port is not None:
        args += ["--ui-port", str(ui_port)]
    for value in ui_allow_origin or []:
        args += ["--ui-allow-origin", value]
    if output_file:
        args += ["-o", output_file]

    stdout = ""
    stderr = ""
    returncode: int | None = None
    timed_out = False
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = proc.communicate(timeout=max(1, float(duration_seconds)))
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
        returncode = proc.returncode
    except FileNotFoundError:
        return {"error": "frida-trace not installed", **INSTALL_HINT}
    except Exception as e:
        return {"error": f"frida-trace failed: {e}"}

    log_lines = stdout.splitlines()

    if output_file:
        Path(output_file).write_text(stdout)

    return {
        "ok": timed_out or returncode in (0, -2, -15),  # timeout means we stopped after requested duration
        "target": target,
        "include": include,
        "args": args,
        "duration_seconds": duration_seconds,
        "returncode": returncode,
        "timed_out": timed_out,
        "log_lines": log_lines[:500],
        "log_truncated": len(log_lines) > 500,
        "stderr": stderr.splitlines()[:100],
        "log_path": output_file,
    }


def discover_run(
    target: str,
    duration_seconds: int = 30,
    mode: str = "attach",
    device_id: str | None = None,
    output_file: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Run official `frida-discover` for a bounded capture window."""
    if not _have_tool("frida-discover"):
        return {"error": "frida-discover not installed or not available in this frida-tools build", **INSTALL_HINT}

    args: list[str] = ["frida-discover"]
    if device_id:
        args += ["-D", device_id]
    if mode == "spawn":
        args += ["-f", target]
    elif target.isdigit():
        args += ["-p", target]
    else:
        args += ["-n", target]
    args += extra_args or []

    res = _run_cmd(args, check=False, timeout=max(5.0, float(duration_seconds)))
    if output_file:
        Path(output_file).write_text(res.stdout)
    return {
        "ok": res.returncode in (0, -1),
        "returncode": res.returncode,
        "target": target,
        "mode": mode,
        "args": args,
        "stdout_lines": res.stdout.splitlines()[:1000],
        "stderr_lines": res.stderr.splitlines()[:200],
        "output_file": output_file,
    }


def gum_graft_run(
    input_path: str,
    output_path: str | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Run official `gum-graft` when available."""
    if not _have_tool("gum-graft"):
        return {"error": "gum-graft not installed or not on PATH", **INSTALL_HINT}
    path = Path(input_path)
    if not path.is_file():
        return {"error": f"input file not found: {input_path}"}

    args = ["gum-graft", *([*extra_args] if extra_args else [])]
    if output_path is not None:
        args += ["-o", output_path]
    args.append(str(path))
    res = _run_cmd(args, check=False, timeout=max(5.0, float(timeout_seconds)))
    return {
        "ok": res.returncode == 0,
        "returncode": res.returncode,
        "input_path": input_path,
        "output_path": output_path,
        "args": args,
        "stdout_lines": res.stdout.splitlines()[:500],
        "stderr_lines": res.stderr.splitlines()[:200],
    }


def cli_options_file_parse(options_file: str) -> dict[str, Any]:
    """Parse a Frida CLI options file into shell-style tokens."""
    path = Path(options_file)
    if not path.is_file():
        return {"error": f"options file not found: {options_file}"}
    tokens: list[str] = []
    for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens.extend(shlex.split(line))
        except ValueError as e:
            return {"error": f"failed to parse line {lineno}: {e}", "line": raw_line}
    return {"options_file": str(path), "tokens": tokens, "count": len(tokens)}


def codeshare_run(
    target: str,
    codeshare_uri: str,
    duration_seconds: int = 30,
    mode: str = "attach",
    device_id: str | None = None,
    runtime: str | None = None,
    quiet: bool = True,
    output_file: str | None = None,
) -> dict[str, Any]:
    """Run an official frida-tools CodeShare script via `frida -c`."""
    if not _have_tool("frida"):
        return {"error": "frida CLI not installed. pip install frida-tools", **INSTALL_HINT}

    args = ["frida"]
    if device_id:
        args += ["-D", device_id]
    if mode == "spawn":
        args += ["-f", target]
    elif target.isdigit():
        args += ["-p", target]
    else:
        args += ["-n", target]
    if runtime is not None:
        args += ["--runtime", runtime]
    args += ["-c", codeshare_uri]
    if quiet:
        args += ["-q", "-t", str(max(1, int(duration_seconds)))]

    res = _run_cmd(args, check=False, timeout=max(5.0, float(duration_seconds) + 15.0))
    if output_file:
        Path(output_file).write_text(res.stdout)
    return {
        "ok": res.returncode == 0,
        "returncode": res.returncode,
        "target": target,
        "mode": mode,
        "codeshare_uri": codeshare_uri,
        "duration_seconds": duration_seconds,
        "stdout_lines": res.stdout.splitlines()[:500],
        "stderr_lines": res.stderr.splitlines()[:200],
        "output_file": output_file,
    }
