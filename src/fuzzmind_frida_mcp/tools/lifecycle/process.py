"""fuzzmind-frida-mcp -- process tools."""
from __future__ import annotations

from typing import Any
import json

from .._core import INSTALL_HINT, _have_tool, _load_frida, _run_script


def list_processes(name_filter: str | None = None) -> dict[str, Any]:
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        device = frida.get_local_device()
        procs = device.enumerate_processes()
    except Exception as e:
        return {"error": f"frida enumerate_processes failed: {e}"}

    items = [
        {"pid": p.pid, "name": p.name}
        for p in procs
        if not name_filter or name_filter.lower() in p.name.lower()
    ]
    items.sort(key=lambda r: r["name"].lower())
    result: dict[str, Any] = {"items": items, "count": len(items)}
    if not items and name_filter is None:
        result["warning"] = (
            "Frida returned an empty process list. On macOS this can happen "
            "when the MCP/test process is sandboxed or lacks process-listing permission."
        )
    return result

def check() -> dict[str, Any]:
    frida = _load_frida()
    if frida is None:
        return {"available": False, **INSTALL_HINT}
    info = {"available": True, "core_version": frida.__version__}
    info["frida_ps"] = _have_tool("frida-ps")
    info["frida_trace"] = _have_tool("frida-trace")
    return info

def process_info(target: str) -> dict[str, Any]:
    """Return detailed Process metadata from a target.

    Includes: pid, arch, platform, page/pointer size, code signing policy,
    mainModule info, current/home/tmp dirs, debugger state, and current
    thread id.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var info = {
        type: 'process_info',
        id: Process.id,
        arch: Process.arch,
        platform: Process.platform,
        pageSize: Process.pageSize,
        pointerSize: Process.pointerSize,
        codeSigningPolicy: Process.codeSigningPolicy,
        currentThreadId: Process.getCurrentThreadId()
    };
    try {
        var mm = Process.mainModule;
        info.mainModule = {
            name: mm.name,
            base: mm.base.toString(),
            size: mm.size,
            path: mm.path
        };
    } catch(e) { info.mainModule = null; }
    try { info.currentDir = Process.getCurrentDir(); } catch(e) { info.currentDir = null; }
    try { info.homeDir = Process.getHomeDir(); } catch(e) { info.homeDir = null; }
    try { info.tmpDir = Process.getTmpDir(); } catch(e) { info.tmpDir = null; }
    try { info.debuggerAttached = Process.isDebuggerAttached(); } catch(e) { info.debuggerAttached = null; }
    send(info);
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def target_snapshot(
    target: str,
    device_id: str | None = None,
    spawn: bool = False,
    module_limit: int = 200,
    thread_limit: int = 50,
) -> dict[str, Any]:
    """Collect an agent-friendly target snapshot before deeper analysis.

    This is intended as the first MCP call an agent makes after choosing a
    process/app: it returns process metadata, bridge/runtime availability,
    module and thread samples, and memory-range counts.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    module_limit = max(0, min(module_limit, 1000))
    thread_limit = max(0, min(thread_limit, 500))
    js = f"""
    'use strict';
    const moduleLimit = {module_limit};
    const threadLimit = {thread_limit};
    const errors = [];

    function safe(field, fn, fallback) {{
        try {{
            return fn();
        }} catch (e) {{
            errors.push({{ field: field, message: String(e) }});
            return fallback;
        }}
    }}

    function ptrToString(value) {{
        if (value === null || value === undefined) return null;
        try {{ return value.toString(); }} catch (e) {{ return String(value); }}
    }}

    function moduleToJson(m) {{
        return {{
            name: m.name,
            base: ptrToString(m.base),
            size: m.size,
            path: m.path || null
        }};
    }}

    function threadToJson(t) {{
        const ctx = {{}};
        safe('thread.context', function() {{
            Object.keys(t.context || {{}}).forEach(function(k) {{
                ctx[k] = ptrToString(t.context[k]);
            }});
            return true;
        }}, false);
        return {{
            id: t.id,
            state: t.state,
            context: ctx
        }};
    }}

    const modules = safe('modules', function() {{
        return Process.enumerateModules();
    }}, []);
    const threads = safe('threads', function() {{
        return Process.enumerateThreads();
    }}, []);
    const mainModule = safe('mainModule', function() {{
        return moduleToJson(Process.mainModule);
    }}, null);

    const rangeSummary = {{}};
    ['r--', 'rw-', 'r-x', 'rwx'].forEach(function(protection) {{
        rangeSummary[protection] = safe('ranges.' + protection, function() {{
            const ranges = Process.enumerateRanges(protection);
            let totalSize = 0;
            ranges.forEach(function(r) {{ totalSize += r.size; }});
            return {{ count: ranges.length, total_size: totalSize }};
        }}, {{ count: null, total_size: null }});
    }});

    const runtimes = {{
        objc: {{
            available: !!(typeof ObjC !== 'undefined' && ObjC.available),
            bridge_missing: !!(typeof ObjC !== 'undefined' && ObjC.__fuzzmindMissing)
        }},
        java: {{
            available: !!(typeof Java !== 'undefined' && Java.available),
            bridge_missing: !!(typeof Java !== 'undefined' && Java.__fuzzmindMissing)
        }},
        swift: {{
            available: !!(typeof Swift !== 'undefined' && Swift.available),
            bridge_missing: !!(typeof Swift !== 'undefined' && Swift.__fuzzmindMissing)
        }},
        kernel: {{
            available: !!(typeof Kernel !== 'undefined' && Kernel.available)
        }},
        interceptor: {{ available: typeof Interceptor !== 'undefined' }},
        stalker: {{ available: typeof Stalker !== 'undefined' }},
        apiResolver: {{ available: typeof ApiResolver !== 'undefined' }},
        cModule: {{ available: typeof CModule !== 'undefined' }},
        sqlite: {{ available: typeof SqliteDatabase !== 'undefined' }},
        cloak: {{ available: typeof Cloak !== 'undefined' }}
    }};

    send({{
        type: 'target_snapshot',
        process: {{
            id: safe('process.id', function() {{ return Process.id; }}, null),
            arch: safe('process.arch', function() {{ return Process.arch; }}, null),
            platform: safe('process.platform', function() {{ return Process.platform; }}, null),
            pageSize: safe('process.pageSize', function() {{ return Process.pageSize; }}, null),
            pointerSize: safe('process.pointerSize', function() {{ return Process.pointerSize; }}, null),
            codeSigningPolicy: safe('process.codeSigningPolicy', function() {{ return Process.codeSigningPolicy; }}, null),
            currentThreadId: safe('process.currentThreadId', function() {{ return Process.getCurrentThreadId(); }}, null),
            debuggerAttached: safe('process.debuggerAttached', function() {{ return Process.isDebuggerAttached(); }}, null),
            currentDir: safe('process.currentDir', function() {{ return Process.getCurrentDir(); }}, null),
            homeDir: safe('process.homeDir', function() {{ return Process.getHomeDir(); }}, null),
            tmpDir: safe('process.tmpDir', function() {{ return Process.getTmpDir(); }}, null)
        }},
        runtimes: runtimes,
        mainModule: mainModule,
        modules: {{
            count: modules.length,
            items: modules.slice(0, moduleLimit).map(moduleToJson),
            truncated: modules.length > moduleLimit
        }},
        threads: {{
            count: threads.length,
            items: threads.slice(0, threadLimit).map(threadToJson),
            truncated: threads.length > threadLimit
        }},
        ranges: rangeSummary,
        errors: errors
    }});
    """

    mode = "spawn" if spawn else "attach"
    result = _run_script(
        frida,
        target,
        js,
        duration_seconds=1,
        mode=mode,
        device_id=device_id,
    )
    if "error" in result:
        return result

    snapshot = None
    for event in result.get("events", []):
        if isinstance(event, dict) and event.get("type") == "target_snapshot":
            snapshot = event
            break

    if snapshot is None:
        return {
            "error": "target snapshot did not return a target_snapshot event",
            "raw_result": result,
        }

    snapshot["recommended_next_actions"] = _target_snapshot_recommendations(snapshot)
    return {
        "target": target,
        "device_id": device_id,
        "mode": mode,
        "snapshot": snapshot,
        "event_count": result.get("event_count", 0),
    }

def _target_snapshot_recommendations(snapshot: dict[str, Any]) -> list[str]:
    process = snapshot.get("process") or {}
    runtimes = snapshot.get("runtimes") or {}
    modules = snapshot.get("modules") or {}

    actions = [
        "Use frida_enumerate_modules plus frida_find_export_by_name/frida_find_symbol_by_name to resolve hook targets.",
        "Use frida_script_run_file or frida_interactive_eval for custom Frida JavaScript once candidate APIs are identified.",
    ]
    if modules.get("count"):
        actions.append("Use frida_enumerate_exports or frida_enumerate_imports on interesting modules from this snapshot.")
    if (runtimes.get("objc") or {}).get("available"):
        actions.append("ObjC runtime is available; use frida_objc_classes, frida_dump_class, and frida_intercept_objc_method.")
    if (runtimes.get("java") or {}).get("available"):
        actions.append("Java/ART runtime is available; use frida_java_list_classes and frida_java_hook_method.")
    if (runtimes.get("swift") or {}).get("available"):
        actions.append("Swift bridge is available; use frida_swift_demangle and symbol/API resolver workflows.")
    if (runtimes.get("kernel") or {}).get("available"):
        actions.append("Kernel instrumentation is available; use kernel tools only on explicitly authorized targets.")
    if process.get("codeSigningPolicy") == "required":
        actions.append("Code signing policy is required; prefer Interceptor.attach and symbol tracing before patching code pages.")
    if process.get("platform") == "darwin" and not (runtimes.get("objc") or {}).get("available"):
        actions.append("On Darwin targets without ObjC, start with native module/export analysis instead of ObjC APIs.")

    bridge_missing = [
        name
        for name in ("objc", "java", "swift")
        if (runtimes.get(name) or {}).get("bridge_missing")
    ]
    if bridge_missing:
        actions.append(
            "Bridge package stubs are active for "
            + ", ".join(bridge_missing)
            + "; install the matching Frida bridge package to use those high-level runtime APIs."
        )
    return actions

def enumerate_threads(target: str) -> dict[str, Any]:
    """List all threads in a target process with state and register context.

    `target`: process name or pid (string).
    Returns thread id, state, and key register values (pc, sp) for each.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = """
    'use strict';
    var threads = Process.enumerateThreads();
    send({
        type: 'threads',
        items: threads.map(function(t) {
            var ctx = {};
            try {
                ctx.pc = t.context.pc.toString();
                ctx.sp = t.context.sp.toString();
            } catch(e) {}
            return {
                id: t.id,
                state: t.state,
                context: ctx
            };
        }),
        count: threads.length
    });
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def enumerate_modules(target: str) -> dict[str, Any]:
    """Attach to process, run Process.enumerateModules(), return module list."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = """
    'use strict';
    const mods = Process.enumerateModules();
    send({
        type: 'modules',
        items: mods.map(m => ({
            name: m.name,
            base: m.base.toString(),
            size: m.size,
            path: m.path
        })),
        count: mods.length
    });
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def enumerate_exports(target: str, module_name: str) -> dict[str, Any]:
    """Attach to process, enumerate exports from a specific module."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    module_name_js = json.dumps(module_name)
    js = f"""
    'use strict';
    const moduleName = {module_name_js};
    const mod = Process.findModuleByName(moduleName);
    if (!mod) {{
        send({{type: 'error', message: 'module not found: ' + moduleName}});
    }} else {{
        const exports = mod.enumerateExports();
        send({{
            type: 'exports',
            module: moduleName,
            items: exports.slice(0, 5000).map(e => ({{
                name: e.name,
                type: e.type,
                address: e.address.toString()
            }})),
            count: exports.length,
            truncated: exports.length > 5000
        }});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def enumerate_imports(
    target: str,
    module_name: str,
    filter: str | None = None,
    limit: int = 1000,
) -> dict[str, Any]:
    """Enumerate imports of a module inside a target process.

    `target`: process name or pid (string).
    `module_name`: module to query (e.g. 'Safari', 'libsystem_kernel.dylib').
    `filter`: optional case-insensitive name substring filter.
    `limit`: max imports to return (default 1000).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    filter_js = ""
    if filter:
        filter_js = (
            "imports = imports.filter(function(i) { "
            f"return i.name && i.name.toLowerCase().indexOf({json.dumps(filter.lower())}) !== -1; "
            "});"
        )

    module_name_js = json.dumps(module_name)
    js = f"""
    'use strict';
    var moduleName = {module_name_js};
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {{
        send({{type: 'error', message: 'module not found: ' + moduleName}});
    }} else {{
        var imports = mod.enumerateImports();
        {filter_js}
        send({{
            type: 'imports',
            module: moduleName,
            items: imports.slice(0, {limit}).map(function(i) {{
                return {{
                    type: i.type,
                    name: i.name,
                    module: i.module || null,
                    address: i.address ? i.address.toString() : null,
                    slot: i.slot ? i.slot.toString() : null
                }};
            }}),
            count: imports.length,
            truncated: imports.length > {limit}
        }});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def enumerate_symbols(
    target: str,
    module_name: str | None = None,
    filter: str | None = None,
    limit: int = 1000,
) -> dict[str, Any]:
    """List all symbols (not just exports) from a module.

    Unlike `enumerate_exports`, this returns all symbol types including
    local/debug symbols when available.

    `target`: process name or pid (string).
    `module_name`: module to enumerate symbols from. If None, uses the
      main executable module.
    `filter`: optional case-insensitive substring to filter symbol names.
    `limit`: max symbols to return (default 1000).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    if module_name:
        escaped_mod = json.dumps(module_name)
        mod_expr = f"Process.findModuleByName({escaped_mod})"
    else:
        mod_expr = "Process.enumerateModules()[0]"

    escaped_filter = json.dumps(filter.lower()) if filter else "null"

    js = f"""
    'use strict';
    var mod = {mod_expr};
    if (!mod) {{
        send({{type: 'error', message: 'module not found'}});
    }} else {{
        var syms = mod.enumerateSymbols();
        var filt = {escaped_filter};
        if (filt) {{
            syms = syms.filter(function(s) {{
                return s.name.toLowerCase().indexOf(filt) !== -1;
            }});
        }}
        var total = syms.length;
        send({{
            type: 'symbols',
            module: mod.name,
            items: syms.slice(0, {int(limit)}).map(function(s) {{
                return {{
                    address: s.address.toString(),
                    name: s.name,
                    type: s.type,
                    isGlobal: s.isGlobal
                }};
            }}),
            count: total,
            truncated: total > {int(limit)}
        }});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def enumerate_sections(target: str, module_name: str) -> dict[str, Any]:
    """Enumerate sections of a module inside a target process.

    Returns name, base address, size, and protection for each section.

    `target`: process name or pid (string).
    `module_name`: module to query (e.g. 'CoreAudio', 'libsystem_c.dylib').
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    module_name_js = json.dumps(module_name)
    js = f"""
    'use strict';
    var moduleName = {module_name_js};
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {{
        send({{type: 'error', message: 'module not found: ' + moduleName}});
    }} else {{
        var sections = mod.enumerateSections();
        send({{
            type: 'sections',
            module: moduleName,
            items: sections.map(function(s) {{
                return {{
                    id: s.id,
                    name: s.name,
                    address: s.address.toString(),
                    size: s.size,
                    protection: s.protection
                }};
            }}),
            count: sections.length
        }});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def enumerate_dependencies(target: str, module_name: str) -> dict[str, Any]:
    """Enumerate dependencies of a module inside a target process.

    `target`: process name or pid (string).
    `module_name`: module to query.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    module_name_js = json.dumps(module_name)
    js = f"""
    'use strict';
    var moduleName = {module_name_js};
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {{
        send({{type: 'error', message: 'module not found: ' + moduleName}});
    }} else {{
        var deps = mod.enumerateDependencies();
        send({{
            type: 'dependencies',
            module: moduleName,
            items: deps.map(function(d) {{
                return {{
                    name: d.name,
                    type: d.type
                }};
            }}),
            count: deps.length
        }});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def enumerate_malloc_ranges(
    target: str,
    filter: str = "rw-",
) -> dict[str, Any]:
    """Enumerate malloc ranges in a target process, filtered by protection.

    `target`: process name or pid (string).
    `filter`: protection string filter (default 'rw-'). Frida returns
      ranges whose protection is a superset of the specified value.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    filter_js = json.dumps(filter)
    js = f"""
    'use strict';
    try {{
        var protectionFilter = {filter_js};
        var ranges = Process.enumerateMallocRanges(protectionFilter);
        send({{
            type: 'malloc_ranges',
            protection_filter: protectionFilter,
            items: ranges.slice(0, 2000).map(function(r) {{
                return {{
                    base: r.base.toString(),
                    size: r.size,
                    protection: r.protection
                }};
            }}),
            count: ranges.length,
            truncated: ranges.length > 2000
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'enumerateMallocRanges failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def find_export_by_name(
    target: str,
    module_name: str | None,
    export_name: str,
) -> dict[str, Any]:
    """Find a single export by name, optionally scoped to a module.

    `target`: process name or pid (string).
    `module_name`: module to search in, or None to search all modules.
    `export_name`: name of the export to find.
    Returns the address of the export.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    name_js = json.dumps(export_name)
    if module_name:
        mod_js = json.dumps(module_name)
        js = f"""
        var mod = Process.findModuleByName({mod_js});
        if (mod) {{
            var addr = mod.findExportByName({name_js});
            if (addr) {{
                send({{type: 'export_found', module: mod.name, name: {name_js}, address: addr.toString()}});
            }} else {{
                send({{type: 'error', message: 'export not found: ' + {name_js} + ' in ' + {mod_js}}});
            }}
        }} else {{
            send({{type: 'error', message: 'module not found: ' + {mod_js}}});
        }}
        """
    else:
        js = f"""
        var addr = null;
        Process.enumerateModules().some(function(m) {{
            var e = m.findExportByName({name_js});
            if (e) {{ addr = e; send({{type: 'export_found', module: m.name, name: {name_js}, address: e.toString()}}); return true; }}
            return false;
        }});
        if (!addr) send({{type: 'error', message: 'export not found in any module: ' + {name_js}}});
        """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def find_symbol_by_name(
    target: str,
    module_name: str,
    symbol_name: str,
) -> dict[str, Any]:
    """Find a symbol by name within a specific module.

    Unlike find_export_by_name, this uses Process.findModuleByName().findSymbolByName()
    which can locate non-exported symbols when available.

    `target`: process name or pid (string).
    `module_name`: module to search.
    `symbol_name`: symbol name to find.
    Returns address and type of the symbol.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    module_name_js = json.dumps(module_name)
    symbol_name_js = json.dumps(symbol_name)
    js = f"""
    'use strict';
    var moduleName = {module_name_js};
    var symbolName = {symbol_name_js};
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {{
        send({{type: 'error', message: 'module not found: ' + moduleName}});
    }} else {{
        try {{
            var sym = mod.findSymbolByName(symbolName);
            if (sym) {{
                send({{
                    type: 'symbol_found',
                    module: moduleName,
                    name: symbolName,
                    address: sym.toString()
                }});
            }} else {{
                send({{type: 'error', message: 'symbol not found: ' + symbolName + ' in ' + moduleName}});
            }}
        }} catch(e) {{
            send({{type: 'error', message: 'findSymbolByName failed: ' + e.message}});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def resolve_debug_symbol(target: str, address: str) -> dict[str, Any]:
    """Resolve a debug symbol from an address via DebugSymbol.fromAddress.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100004000').
    Returns name, moduleName, fileName, lineNumber.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        var sym = DebugSymbol.fromAddress(ptr(address));
        send({{
            type: 'debug_symbol',
            address: address,
            name: sym.name,
            moduleName: sym.moduleName,
            fileName: sym.fileName,
            lineNumber: sym.lineNumber,
            toString: sym.toString()
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'DebugSymbol.fromAddress failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def find_functions_named(target: str, name: str) -> dict[str, Any]:
    """Find all functions with an exact name via DebugSymbol.findFunctionsNamed.

    `target`: process name or pid (string).
    `name`: exact function name to search for.
    Returns list of matching addresses.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    name_js = json.dumps(name)
    js = f"""
    'use strict';
    try {{
        var name = {name_js};
        var addrs = DebugSymbol.findFunctionsNamed(name);
        send({{
            type: 'functions_named',
            name: name,
            addresses: addrs.map(function(a) {{ return a.toString(); }}),
            count: addrs.length
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'findFunctionsNamed failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def find_functions_matching(target: str, glob: str) -> dict[str, Any]:
    """Find functions matching a glob pattern via DebugSymbol.findFunctionsMatching.

    `target`: process name or pid (string).
    `glob`: glob pattern (e.g. '*xpc*send*', 'objc_msg*').
    Returns matching addresses with symbolicated names.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    glob_js = json.dumps(glob)
    js = f"""
    'use strict';
    try {{
        var glob = {glob_js};
        var addrs = DebugSymbol.findFunctionsMatching(glob);
        var results = addrs.slice(0, 1000).map(function(a) {{
            var sym = DebugSymbol.fromAddress(a);
            return {{
                address: a.toString(),
                name: sym.name,
                moduleName: sym.moduleName
            }};
        }});
        send({{
            type: 'functions_matching',
            glob: glob,
            items: results,
            count: addrs.length,
            truncated: addrs.length > 1000
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'findFunctionsMatching failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def load_debug_symbols(target: str, path: str) -> dict[str, Any]:
    """Load debug symbols from a file (e.g. dSYM) into the target process.

    `target`: process name or pid (string).
    `path`: path to the debug symbol file to load.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    path_js = json.dumps(path)
    js = f"""
    'use strict';
    try {{
        var path = {path_js};
        DebugSymbol.load(path);
        send({{
            type: 'debug_symbols_loaded',
            path: path,
            ok: true
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'DebugSymbol.load failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")
