"""fuzzmind-frida-mcp -- stalker tools."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import time

from .._core import INSTALL_HINT, _get_device, _load_frida, _run_script


def stalker_coverage(
    target: str,
    module_filter: str | None = None,
    duration_seconds: int = 10,
    output_file: str | None = None,
) -> dict[str, Any]:
    """Attach Stalker to collect basic-block coverage. Returns unique block addresses."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    module_check = ""
    if module_filter:
        module_check = f"""
        const mod = Process.findModuleByName("{module_filter}");
        if (!mod) {{
            send({{type: 'error', message: 'module not found: {module_filter}'}});
        }}
        const modBase = mod.base;
        const modEnd = modBase.add(mod.size);
        """

    js = f"""
    'use strict';
    const seen = new Set();
    {module_check}
    Stalker.follow(Process.getCurrentThreadId(), {{
        events: {{
            block: true
        }},
        onReceive: function(events) {{
            const parsed = Stalker.parse(events, {{annotate: false, stringify: false}});
            for (const ev of parsed) {{
                const addr = ev[0];
                {"const p = ptr(addr); if (p.compare(modBase) >= 0 && p.compare(modEnd) < 0) seen.add(addr.toString());" if module_filter else "seen.add(addr.toString());"}
            }}
        }}
    }});
    setTimeout(function() {{
        Stalker.unfollow(Process.getCurrentThreadId());
        Stalker.flush();
        const blocks = Array.from(seen);
        send({{type: 'coverage', blocks: blocks.slice(0, 50000), count: blocks.length}});
    }}, {int(duration_seconds * 1000)});
    """

    result = _run_script(frida, target, js, duration_seconds + 2, "attach")

    if output_file and "events" in result:
        coverage_data = [e for e in result.get("events", []) if isinstance(e, dict) and e.get("type") == "coverage"]
        if coverage_data:
            Path(output_file).write_text(json.dumps(coverage_data[0], indent=2))
            result["log_path"] = output_file

    return result

def stalker_configure(
    target: str,
    thread_id: int,
    options_json: str,
) -> dict[str, Any]:
    """Configure and start Stalker with advanced options on a specific thread.

    Provides finer control than stalker_coverage: custom event types,
    exclude ranges, and optional transform callback.

    `target`: process name or pid (string).
    `thread_id`: thread id to stalk (from enumerate_threads).
    `options_json`: JSON string of Stalker.follow options. Supported keys:
      - events: {call: bool, ret: bool, exec: bool, block: bool, compile: bool}
      - excludeRanges: [{base: "0x...", size: N}, ...]
      - onReceiveJs: optional JS code body for onReceive(events). Has access
        to `events` (raw), `Stalker.parse(events)`, and `send()`.
      - duration_seconds: how long to stalk (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    try:
        opts = json.loads(options_json)
    except json.JSONDecodeError as e:
        return {"error": f"invalid options_json: {e}"}

    events_cfg = opts.get("events", {"block": True})
    events_js = json.dumps(events_cfg)

    exclude_ranges = opts.get("excludeRanges", [])
    exclude_js = ""
    if exclude_ranges:
        ranges_code = ", ".join(
            f'{{base: ptr("{r["base"]}"), size: {r["size"]}}}'
            for r in exclude_ranges
        )
        exclude_js = f"Stalker.exclude([{ranges_code}]);"

    on_receive_body = opts.get(
        "onReceiveJs",
        """
        var parsed = Stalker.parse(events, {annotate: true, stringify: true});
        send({type: 'stalker_events', count: parsed.length, sample: parsed.slice(0, 100)});
        """,
    )

    duration = opts.get("duration_seconds", 10)

    js = f"""
    'use strict';
    try {{
        {exclude_js}
        var collected = [];
        Stalker.follow({thread_id}, {{
            events: {events_js},
            onReceive: function(events) {{
                {on_receive_body}
            }}
        }});
        setTimeout(function() {{
            Stalker.unfollow({thread_id});
            Stalker.flush();
            send({{type: 'stalker_configure_done', thread_id: {thread_id}, ok: true}});
        }}, {duration * 1000});
    }} catch(e) {{
        send({{type: 'error', message: 'Stalker.follow failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=duration + 2, mode="attach")

def spawn_gating(
    device_id: str | None = None,
    duration_seconds: int = 30,
) -> dict[str, Any]:
    """Enable spawn gating to intercept all new process spawns.

    Activates device-level spawn gating for `duration_seconds`. Every
    process that starts during this window is captured before it runs.
    Returns a list of intercepted spawn events.

    `device_id`: optional Frida device id; defaults to local device.
    `duration_seconds`: how long to gate spawns (default 30, max 120).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    duration_seconds = min(duration_seconds, 120)
    spawns: list[dict[str, Any]] = []

    def on_spawn_added(spawn):
        spawns.append({
            "pid": spawn.pid,
            "identifier": getattr(spawn, "identifier", None),
            "ts": time.time(),
        })

    try:
        device = _get_device(frida, device_id)
        device.on("spawn-added", on_spawn_added)
        device.enable_spawn_gating()

        time.sleep(duration_seconds)

        device.disable_spawn_gating()

        # Resume any spawns we captured (so we don't leave processes frozen)
        pending = device.enumerate_pending_spawn()
        resumed = []
        for s in pending:
            try:
                device.resume(s.pid)
                resumed.append(s.pid)
            except Exception:
                pass

        return {
            "status": "completed",
            "device": device.name,
            "duration_seconds": duration_seconds,
            "spawns_captured": len(spawns),
            "spawns": spawns[:200],
            "spawns_truncated": len(spawns) > 200,
            "resumed_pids": resumed,
        }
    except Exception as e:
        # Try to clean up
        try:
            device.disable_spawn_gating()
        except Exception:
            pass
        return {"error": f"spawn_gating failed: {e}", "spawns_collected": len(spawns)}

def child_process_trap(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Monitor child process creation by hooking spawn/fork/exec APIs.

    Hooks:
    - macOS/Linux: posix_spawn, posix_spawnp, fork, execve, system

    Captures child PID, command line, and arguments for each spawned process.

    `target`: process name or pid (string).
    `duration_seconds`: how long to monitor (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var hooked = [];

    // ---- posix_spawn / posix_spawnp ----
    ['posix_spawn', 'posix_spawnp'].forEach(function(name) {
        try {
            var fn = _fm_find_export('libsystem_kernel.dylib', name);
            if (!fn) fn = _fm_find_export(null, name);
            if (fn) {
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        this._pidPtr = args[0];
                        this._path = args[1].readUtf8String();
                        // args[4] = argv (null-terminated array of char*)
                        var argv = [];
                        var argvPtr = args[4];
                        if (!argvPtr.isNull()) {
                            for (var i = 0; i < 20; i++) {
                                var argPtr = argvPtr.add(i * Process.pointerSize).readPointer();
                                if (argPtr.isNull()) break;
                                try { argv.push(argPtr.readUtf8String()); } catch(e) { break; }
                            }
                        }
                        this._argv = argv;
                    },
                    onLeave: function(retval) {
                        var childPid = -1;
                        if (retval.toInt32() === 0 && !this._pidPtr.isNull()) {
                            try { childPid = this._pidPtr.readS32(); } catch(e) {}
                        }
                        send({
                            type: 'child_process',
                            api: name,
                            path: this._path,
                            argv: this._argv,
                            child_pid: childPid,
                            status: retval.toInt32(),
                            timestamp: Date.now()
                        });
                    }
                });
                hooked.push(name);
            }
        } catch(e) {}
    });

    // ---- fork ----
    try {
        var forkFn = _fm_find_export('libsystem_kernel.dylib', 'fork');
        if (!forkFn) forkFn = _fm_find_export(null, 'fork');
        if (forkFn) {
            Interceptor.attach(forkFn, {
                onLeave: function(retval) {
                    var pid = retval.toInt32();
                    if (pid > 0) {
                        send({
                            type: 'child_process',
                            api: 'fork',
                            child_pid: pid,
                            timestamp: Date.now()
                        });
                    }
                }
            });
            hooked.push('fork');
        }
    } catch(e) {}

    // ---- execve ----
    try {
        var execveFn = _fm_find_export('libsystem_kernel.dylib', 'execve');
        if (!execveFn) execveFn = _fm_find_export(null, 'execve');
        if (execveFn) {
            Interceptor.attach(execveFn, {
                onEnter: function(args) {
                    var path = args[0].readUtf8String();
                    var argv = [];
                    var argvPtr = args[1];
                    if (!argvPtr.isNull()) {
                        for (var i = 0; i < 20; i++) {
                            var argPtr = argvPtr.add(i * Process.pointerSize).readPointer();
                            if (argPtr.isNull()) break;
                            try { argv.push(argPtr.readUtf8String()); } catch(e) { break; }
                        }
                    }
                    // Read envp keys (first 10)
                    var envKeys = [];
                    var envpPtr = args[2];
                    if (!envpPtr.isNull()) {
                        for (var j = 0; j < 10; j++) {
                            var envPtr = envpPtr.add(j * Process.pointerSize).readPointer();
                            if (envPtr.isNull()) break;
                            try {
                                var envStr = envPtr.readUtf8String();
                                var eqIdx = envStr.indexOf('=');
                                envKeys.push(eqIdx > 0 ? envStr.substring(0, eqIdx) : envStr);
                            } catch(e) { break; }
                        }
                    }
                    send({
                        type: 'child_process',
                        api: 'execve',
                        path: path,
                        argv: argv,
                        env_keys: envKeys,
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('execve');
        }
    } catch(e) {}

    // ---- system() ----
    try {
        var systemFn = _fm_find_export('libsystem_c.dylib', 'system');
        if (!systemFn) systemFn = _fm_find_export(null, 'system');
        if (systemFn) {
            Interceptor.attach(systemFn, {
                onEnter: function(args) {
                    var cmd = args[0].readUtf8String();
                    send({
                        type: 'child_process',
                        api: 'system',
                        command: cmd,
                        timestamp: Date.now()
                    });
                },
                onLeave: function(retval) {
                    send({
                        type: 'child_process_result',
                        api: 'system',
                        exit_status: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('system');
        }
    } catch(e) {}

    send({type: 'child_process_trap', hooked_apis: hooked, count: hooked.length});
    """
    return _run_script(frida, target, js, duration_seconds, "attach")
