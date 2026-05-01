"""Official Frida API wrapper group."""
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any

from .._core import (
    INSTALL_HINT,
    _create_script,
    _get_device,
    _json_safe,
    _load_frida,
    _registry,
    _require_session,
    _run_script,
)
from .common import (
    _BusRecord,
    _PortalRecord,
    _application_summary,
    _bus_records,
    _child_summary,
    _decode_base64,
    _device_summary,
    _official_lock,
    _portal_records,
    _process_summary,
    _service_request_params,
    _spawn_summary,
    _target_value,
)



def module_map_snapshot(target: str, address: str | None = None, name: str | None = None) -> dict[str, Any]:
    """Use GumJS ModuleMap to snapshot modules and optionally find an address/name."""
    query = json.dumps({"address": address, "name": name})
    js = f"""
    'use strict';
    try {{
        const query = {query};
        const map = new ModuleMap();
        let found = null;
        if (query.address) {{
            const m = map.find(ptr(query.address));
            if (m) found = {{ name: m.name, base: m.base.toString(), size: m.size, path: m.path }};
        }}
        if (query.name) {{
            const m = map.findName(query.name);
            if (m) found = {{ name: m.name, base: m.base.toString(), size: m.size, path: m.path }};
        }}
        const values = map.values().map(function(m) {{
            return {{ name: m.name, base: m.base.toString(), size: m.size, path: m.path }};
        }});
        send({{ type: 'module_map', count: values.length, modules: values.slice(0, 1000), found: found }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def memory_copy(target: str, dst: str, src: str, size: int) -> dict[str, Any]:
    """Call Memory.copy()."""
    js = f"""
    'use strict';
    try {{
        Memory.copy(ptr({json.dumps(dst)}), ptr({json.dumps(src)}), {size});
        send({{ type: 'memory_copy', dst: {json.dumps(dst)}, src: {json.dumps(src)}, size: {size}, ok: true }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def memory_scan_sync(target: str, address: str, size: int, pattern: str) -> dict[str, Any]:
    """Call Memory.scanSync()."""
    js = f"""
    'use strict';
    try {{
        const matches = Memory.scanSync(ptr({json.dumps(address)}), {size}, {json.dumps(pattern)});
        send({{
            type: 'memory_scan_sync',
            count: matches.length,
            matches: matches.slice(0, 1000).map(function(m) {{ return {{ address: m.address.toString(), size: m.size }}; }})
        }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def memory_check_code_pointer(target: str, address: str) -> dict[str, Any]:
    """Call Memory.checkCodePointer()."""
    js = f"""
    'use strict';
    try {{
        const checked = Memory.checkCodePointer(ptr({json.dumps(address)}));
        send({{ type: 'memory_check_code_pointer', address: {json.dumps(address)}, checked: checked.toString() }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def memory_dup(target: str, address: str, size: int) -> dict[str, Any]:
    """Call Memory.dup() and return a copy pointer plus bytes."""
    js = f"""
    'use strict';
    try {{
        const copy = Memory.dup(ptr({json.dumps(address)}), {size});
        const data = copy.readByteArray({size});
        send({{
            type: 'memory_dup',
            source: {json.dumps(address)},
            size: {size},
            copy: copy.toString()
        }}, data);
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def module_load(target: str, path: str) -> dict[str, Any]:
    """Call Module.load()."""
    js = f"""
    'use strict';
    try {{
        const m = Module.load({json.dumps(path)});
        send({{ type: 'module_load', name: m.name, base: m.base.toString(), size: m.size, path: m.path }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def module_ensure_initialized(target: str, module_name: str) -> dict[str, Any]:
    """Call Module.ensureInitialized()."""
    js = f"""
    'use strict';
    try {{
        Module.ensureInitialized({json.dumps(module_name)});
        send({{ type: 'module_ensure_initialized', module: {json.dumps(module_name)}, ok: true }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def module_find_global_export_by_name(target: str, name: str) -> dict[str, Any]:
    """Call Module.findGlobalExportByName()."""
    js = f"""
    'use strict';
    try {{
        const address = Module.findGlobalExportByName({json.dumps(name)});
        send({{ type: 'module_find_global_export_by_name', name: {json.dumps(name)}, address: address ? address.toString() : null }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def process_attach_thread_observer(target: str, duration_seconds: int = 10, event_limit: int = 200) -> dict[str, Any]:
    """Call Process.attachThreadObserver() for a bounded observation window."""
    js = f"""
    'use strict';
    try {{
        let count = 0;
        function summarize(t) {{
            return {{ id: t.id, state: t.state, context: Object.fromEntries(Object.entries(t.context || {{}}).map(function (entry) {{
                return [entry[0], entry[1] && entry[1].toString ? entry[1].toString() : entry[1]];
            }})) }};
        }}
        const observer = Process.attachThreadObserver({{
            onAdded(thread) {{
                if (count++ < {event_limit}) {{
                    send({{ type: 'thread_added', thread: summarize(thread) }});
                }}
            }},
            onRemoved(thread) {{
                if (count++ < {event_limit}) {{
                    send({{ type: 'thread_removed', thread: summarize(thread) }});
                }}
            }}
        }});
        setTimeout(function () {{
            observer.detach();
            send({{ type: 'thread_observer_detached', count: count }});
        }}, {max(1, duration_seconds) * 1000});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=max(1, duration_seconds) + 1, mode="attach")


def process_attach_module_observer(target: str, duration_seconds: int = 10, event_limit: int = 200) -> dict[str, Any]:
    """Call Process.attachModuleObserver() for a bounded observation window."""
    js = f"""
    'use strict';
    try {{
        let count = 0;
        function summarize(m) {{
            return {{ name: m.name, base: m.base.toString(), size: m.size, path: m.path }};
        }}
        const observer = Process.attachModuleObserver({{
            onAdded(module) {{
                if (count++ < {event_limit}) send({{ type: 'module_added', module: summarize(module) }});
            }},
            onRemoved(module) {{
                if (count++ < {event_limit}) send({{ type: 'module_removed', module: summarize(module) }});
            }}
        }});
        setTimeout(function () {{
            observer.detach();
            send({{ type: 'module_observer_detached', count: count }});
        }}, {max(1, duration_seconds) * 1000});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=max(1, duration_seconds) + 1, mode="attach")


def gum_script_evaluate(target: str, name: str, source: str) -> dict[str, Any]:
    """Call GumJS Script.evaluate()."""
    js = f"""
    'use strict';
    try {{
        const result = Script.evaluate({json.dumps(name)}, {json.dumps(source)});
        send({{ type: 'script_evaluate', name: {json.dumps(name)}, result: result === undefined ? null : String(result) }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def gum_script_load(target: str, name: str, source: str, duration_seconds: int = 5) -> dict[str, Any]:
    """Call GumJS Script.load() for a bounded period."""
    js = f"""
    'use strict';
    try {{
        const promise = Script.load({json.dumps(name)}, {json.dumps(source)});
        promise.then(function () {{
            send({{ type: 'script_load', name: {json.dumps(name)}, status: 'loaded' }});
        }}).catch(function (e) {{
            send({{ type: 'error', message: e.message }});
        }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=max(1, duration_seconds), mode="attach")


def gum_script_register_source_map(target: str, name: str, source_map_json: str) -> dict[str, Any]:
    """Call GumJS Script.registerSourceMap()."""
    js = f"""
    'use strict';
    try {{
        const sourceMap = JSON.parse({json.dumps(source_map_json)});
        Script.registerSourceMap({json.dumps(name)}, sourceMap);
        send({{ type: 'script_register_source_map', name: {json.dumps(name)}, ok: true }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def interceptor_flush(target: str) -> dict[str, Any]:
    """Call Interceptor.flush()."""
    js = "Interceptor.flush(); send({ type: 'interceptor_flush', ok: true });"
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def interceptor_revert(target: str, address: str) -> dict[str, Any]:
    """Call Interceptor.revert(address)."""
    js = f"""
    'use strict';
    try {{
        Interceptor.revert(ptr({json.dumps(address)}));
        send({{ type: 'interceptor_revert', address: {json.dumps(address)}, ok: true }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def system_function_call(
    target: str,
    address: str,
    return_type: str,
    arg_types: list[str],
    args: list[str],
) -> dict[str, Any]:
    """Call a native function using GumJS SystemFunction."""
    arg_exprs = []
    for atype, value in zip(arg_types, args):
        literal = json.dumps(value)
        if atype == "pointer":
            arg_exprs.append(f"ptr({literal})")
        elif atype in {"float", "double"}:
            arg_exprs.append(f"parseFloat({literal})")
        else:
            arg_exprs.append(f"parseInt({literal})")
    js = f"""
    'use strict';
    try {{
        const fn = new SystemFunction(ptr({json.dumps(address)}), {json.dumps(return_type)}, {json.dumps(arg_types)});
        const result = fn({', '.join(arg_exprs)});
        send({{ type: 'system_function_call', address: {json.dumps(address)}, result: result }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")


def thread_hardware_breakpoint(target: str, thread_id: int, breakpoint_id: int, address: str, unset: bool = False) -> dict[str, Any]:
    """Call Thread.set/unsetHardwareBreakpoint()."""
    method = "unsetHardwareBreakpoint" if unset else "setHardwareBreakpoint"
    args = f"{breakpoint_id}" if unset else f"{breakpoint_id}, ptr({json.dumps(address)})"
    js = f"""
    'use strict';
    try {{
        Thread.{method}({thread_id}, {args});
        send({{ type: 'thread_hardware_breakpoint', method: {json.dumps(method)}, thread_id: {thread_id}, breakpoint_id: {breakpoint_id}, address: {json.dumps(address)} }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def thread_hardware_watchpoint(
    target: str,
    thread_id: int,
    watchpoint_id: int,
    address: str,
    size: int = 1,
    conditions: str = "rw",
    unset: bool = False,
) -> dict[str, Any]:
    """Call Thread.set/unsetHardwareWatchpoint()."""
    method = "unsetHardwareWatchpoint" if unset else "setHardwareWatchpoint"
    args = f"{watchpoint_id}" if unset else f"{watchpoint_id}, ptr({json.dumps(address)}), {size}, {json.dumps(conditions)}"
    js = f"""
    'use strict';
    try {{
        Thread.{method}({thread_id}, {args});
        send({{ type: 'thread_hardware_watchpoint', method: {json.dumps(method)}, thread_id: {thread_id}, watchpoint_id: {watchpoint_id}, address: {json.dumps(address)}, size: {size}, conditions: {json.dumps(conditions)} }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def code_writer_template(arch: str, pc: str | None = None) -> dict[str, Any]:
    """Return a GumJS CodeWriter/Relocator template for an architecture."""
    writer = {
        "arm64": "Arm64Writer",
        "arm": "ArmWriter",
        "thumb": "ThumbWriter",
        "x64": "X86Writer",
        "x86": "X86Writer",
        "mips": "MipsWriter",
    }.get(arch.lower())
    relocator = {
        "arm64": "Arm64Relocator",
        "arm": "ArmRelocator",
        "thumb": "ThumbRelocator",
        "x64": "X86Relocator",
        "x86": "X86Relocator",
        "mips": "MipsRelocator",
    }.get(arch.lower())
    if writer is None:
        return {"error": "unsupported arch", "allowed": ["arm64", "arm", "thumb", "x64", "x86", "mips"]}
    pc_arg = f", {{ pc: ptr({json.dumps(pc)}) }}" if pc else ""
    return {
        "arch": arch,
        "writer": writer,
        "relocator": relocator,
        "js_code": (
            "Memory.patchCode(targetAddress, patchSize, function (code) {\n"
            f"  const writer = new {writer}(code{pc_arg});\n"
            "  // writer.putNop(); writer.putRet(); writer.putBranchAddress(ptr('0x...'));\n"
            "  writer.flush();\n"
            "});\n"
            f"// const relocator = new {relocator}(sourceAddress, writer);\n"
            "// while (relocator.readOne() !== null) relocator.writeOne();\n"
        ),
    }


def kernel_enumerate_ranges(protection: str = "r--") -> dict[str, Any]:
    """Call Kernel.enumerateRanges()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    js = f"""
    'use strict';
    if (!Kernel.available) {{
        send({{ type: 'error', message: 'Kernel API not available' }});
    }} else {{
        const ranges = Kernel.enumerateRanges({json.dumps(protection)});
        send({{ type: 'kernel_ranges', count: ranges.length, ranges: ranges.slice(0, 1000).map(function(r) {{ return {{ base: r.base.toString(), size: r.size, protection: r.protection }}; }}) }});
    }}
    """
    return _run_script(frida, "0", js, duration_seconds=1, mode="attach")


def kernel_enumerate_module_ranges(module_name: str, protection: str = "r--") -> dict[str, Any]:
    """Call Kernel.enumerateModuleRanges()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    js = f"""
    'use strict';
    if (!Kernel.available) {{
        send({{ type: 'error', message: 'Kernel API not available' }});
    }} else {{
        const ranges = Kernel.enumerateModuleRanges({json.dumps(module_name)}, {json.dumps(protection)});
        send({{ type: 'kernel_module_ranges', module: {json.dumps(module_name)}, count: ranges.length, ranges: ranges.slice(0, 1000).map(function(r) {{ return {{ base: r.base.toString(), size: r.size, protection: r.protection }}; }}) }});
    }}
    """
    return _run_script(frida, "0", js, duration_seconds=1, mode="attach")


def kernel_alloc(size: int) -> dict[str, Any]:
    """Call Kernel.alloc()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    js = f"""
    'use strict';
    if (!Kernel.available) {{
        send({{ type: 'error', message: 'Kernel API not available' }});
    }} else {{
        const p = Kernel.alloc({size});
        send({{ type: 'kernel_alloc', address: p.toString(), size: {size} }});
    }}
    """
    return _run_script(frida, "0", js, duration_seconds=1, mode="attach")


def kernel_protect(address: str, size: int, protection: str) -> dict[str, Any]:
    """Call Kernel.protect()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    js = f"""
    'use strict';
    if (!Kernel.available) {{
        send({{ type: 'error', message: 'Kernel API not available' }});
    }} else {{
        const ok = Kernel.protect(ptr({json.dumps(address)}), {size}, {json.dumps(protection)});
        send({{ type: 'kernel_protect', address: {json.dumps(address)}, size: {size}, protection: {json.dumps(protection)}, ok: ok }});
    }}
    """
    return _run_script(frida, "0", js, duration_seconds=1, mode="attach")


def stalker_add_call_probe(target: str, address: str, duration_seconds: int = 10) -> dict[str, Any]:
    """Call Stalker.addCallProbe() and remove the probe before returning."""
    js = f"""
    'use strict';
    try {{
        let count = 0;
        const probeId = Stalker.addCallProbe(ptr({json.dumps(address)}), function (args) {{
            count++;
            if (count <= 100) {{
                send({{ type: 'stalker_call_probe_hit', address: {json.dumps(address)}, count: count, arg0: args[0] ? args[0].toString() : null }});
            }}
        }});
        setTimeout(function () {{
            Stalker.removeCallProbe(probeId);
            send({{ type: 'stalker_call_probe_done', address: {json.dumps(address)}, count: count }});
        }}, {max(1, duration_seconds) * 1000});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=max(1, duration_seconds) + 1, mode="attach")


def stalker_invalidate(target: str, address: str, thread_id: int | None = None) -> dict[str, Any]:
    """Call Stalker.invalidate()."""
    call = (
        f"Stalker.invalidate({thread_id}, ptr({json.dumps(address)}));"
        if thread_id is not None
        else f"Stalker.invalidate(ptr({json.dumps(address)}));"
    )
    js = f"""
    'use strict';
    try {{
        {call}
        send({{ type: 'stalker_invalidate', address: {json.dumps(address)}, thread_id: {json.dumps(thread_id)}, ok: true }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def rust_module_compile(
    target: str,
    rust_code: str,
    symbols: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compile a GumJS RustModule inside the target."""
    symbols_js = "{}"
    if symbols:
        pairs = ", ".join(f"{json.dumps(name)}: ptr({json.dumps(addr)})" for name, addr in symbols.items())
        symbols_js = "{" + pairs + "}"
    js = f"""
    'use strict';
    try {{
        const module = new RustModule({json.dumps(rust_code)}, {symbols_js});
        send({{ type: 'rust_module', status: 'compiled', module: module.toString() }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=10, mode="attach")


def checksum_memory(target: str, checksum_type: str, address: str, size: int) -> dict[str, Any]:
    """Compute a GumJS Checksum over a memory range."""
    js = f"""
    'use strict';
    try {{
        const data = ptr({json.dumps(address)}).readByteArray({size});
        const digest = Checksum.compute({json.dumps(checksum_type)}, data);
        send({{ type: 'checksum_memory', checksum_type: {json.dumps(checksum_type)}, address: {json.dumps(address)}, size: {size}, digest: digest }});
    }} catch (e) {{
        send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")


def worker_template(worker_source: str | None = None) -> dict[str, Any]:
    """Return a GumJS Worker template."""
    source = worker_source or "recv(function (message) { send({ type: 'worker-message', message: message }); });"
    return {
        "kind": "worker",
        "js_code": (
            f"const worker = new Worker({json.dumps(source)}, {{ type: 'string' }});\n"
            "worker.post({ type: 'start' });\n"
            "worker.recv(function (message) {\n"
            "  send({ type: 'worker-event', message: message });\n"
            "});\n"
        ),
    }


def sampler_template(kind: str = "backtrace") -> dict[str, Any]:
    """Return a GumJS Sampler/Profiler template."""
    templates = {
        "backtrace": (
            "const sampler = new BacktraceSampler();\n"
            "const sample = sampler.sample(Process.getCurrentThreadId());\n"
            "send({ type: 'sampler-backtrace', sample: sample.map(DebugSymbol.fromAddress) });\n"
        ),
        "cycle": (
            "const sampler = new CycleSampler();\n"
            "send({ type: 'sampler-cycle', value: sampler.sample(Process.getCurrentThreadId()).toString() });\n"
        ),
        "busy": (
            "const sampler = new BusyCycleSampler();\n"
            "send({ type: 'sampler-busy-cycle', value: sampler.sample(Process.getCurrentThreadId()).toString() });\n"
        ),
    }
    if kind not in templates:
        return {"error": "unsupported sampler kind", "allowed": sorted(templates)}
    return {"kind": kind, "js_code": templates[kind]}
