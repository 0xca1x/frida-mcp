"""fuzzmind-frida-mcp -- platform_linux tools."""
from __future__ import annotations

from typing import Any
import json

from .._core import INSTALL_HINT, _load_frida, _run_script


def linux_syscall_hook(
    target: str,
    syscall_names: list[str],
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook libc syscall wrappers on a Linux target.

    Hooks the specified libc wrapper functions (open, read, write,
    connect, execve, mmap, socket, etc.) and logs their arguments.
    Falls back to null-module resolution if not found in libc.so.6.

    `target`: process name or pid (string).
    `syscall_names`: list of syscall wrapper names to hook
      (e.g. ["open", "read", "write", "connect", "execve"]).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    names_js = json.dumps(syscall_names)
    js = r"""
    'use strict';
    var names = """ + names_js + r""";
    var libcNames = ['libc.so.6', 'libc.so', 'libc.musl-x86_64.so.1', 'libc.musl-aarch64.so.1'];
    var hooked = [];

    // Specific argument extraction for common syscalls
    var argExtractors = {
        'open': function(args) {
            return {path: args[0].readUtf8String(), flags: args[1].toInt32(), mode: args[2].toInt32()};
        },
        'openat': function(args) {
            return {dirfd: args[0].toInt32(), path: args[1].readUtf8String(), flags: args[2].toInt32()};
        },
        'read': function(args) {
            return {fd: args[0].toInt32(), buf: args[1].toString(), count: args[2].toInt32()};
        },
        'write': function(args) {
            var data = '';
            try {
                var len = Math.min(args[2].toInt32(), 256);
                data = args[1].readUtf8String(len);
            } catch(e) { data = '<binary>'; }
            return {fd: args[0].toInt32(), data_preview: data, count: args[2].toInt32()};
        },
        'connect': function(args) {
            var fd = args[0].toInt32();
            var family = args[1].readU16();
            var info = {fd: fd, sa_family: family};
            if (family === 2) {  // AF_INET
                var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
                var ip = args[1].add(4).readU8() + '.' + args[1].add(5).readU8() + '.' + args[1].add(6).readU8() + '.' + args[1].add(7).readU8();
                info.port = port;
                info.ip = ip;
            }
            return info;
        },
        'execve': function(args) {
            var path = args[0].readUtf8String();
            var argv = [];
            var argvPtr = args[1];
            if (!argvPtr.isNull()) {
                for (var i = 0; i < 20; i++) {
                    var p = argvPtr.add(i * Process.pointerSize).readPointer();
                    if (p.isNull()) break;
                    try { argv.push(p.readUtf8String()); } catch(e) { break; }
                }
            }
            return {path: path, argv: argv};
        },
        'mmap': function(args) {
            return {addr: args[0].toString(), length: args[1].toInt32(), prot: args[2].toInt32(), flags: args[3].toInt32(), fd: args[4].toInt32(), offset: args[5].toInt32()};
        },
        'socket': function(args) {
            return {domain: args[0].toInt32(), type: args[1].toInt32(), protocol: args[2].toInt32()};
        }
    };

    names.forEach(function(name) {
        var addr = null;
        for (var i = 0; i < libcNames.length; i++) {
            try {
                addr = _fm_find_export(libcNames[i], name);
                if (addr) break;
            } catch(e) {}
        }
        if (!addr) {
            try { addr = _fm_find_export(null, name); } catch(e) {}
        }
        if (addr) {
            try {
                var extractor = argExtractors[name];
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        var info = {type: 'syscall', name: name, timestamp: Date.now()};
                        if (extractor) {
                            try {
                                var extracted = extractor(args);
                                for (var k in extracted) info[k] = extracted[k];
                            } catch(e) {
                                info.args_error = e.message;
                            }
                        } else {
                            var rawArgs = [];
                            for (var j = 0; j < 4; j++) {
                                try { rawArgs.push(args[j].toString()); } catch(e) { break; }
                            }
                            info.args = rawArgs;
                        }
                        send(info);
                    }
                });
                hooked.push(name);
            } catch(e) {}
        }
    });
    send({type: 'info', message: 'linux_syscall_hook hooked: ' + hooked.join(', '), not_found: names.filter(function(n) { return hooked.indexOf(n) === -1; })});
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def linux_preload_detect(target: str) -> dict[str, Any]:
    """Detect LD_PRELOAD and suspicious library injections on Linux.

    Checks the target process for:
    - LD_PRELOAD environment variable
    - /etc/ld.so.preload file contents
    - Loaded libraries that don't match standard paths
    - Libraries with suspicious names or locations

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var findings = {
        ld_preload_env: null,
        ld_so_preload_file: null,
        suspicious_libraries: [],
        all_libraries: []
    };

    // Check LD_PRELOAD via /proc/self/environ
    try {
        var fd = new NativeFunction(_fm_find_export(null, 'open'), 'int', ['pointer', 'int']);
        var readFn = new NativeFunction(_fm_find_export(null, 'read'), 'int', ['int', 'pointer', 'int']);
        var closeFn = new NativeFunction(_fm_find_export(null, 'close'), 'int', ['int']);

        var envPath = Memory.allocUtf8String('/proc/self/environ');
        var envFd = fd(envPath, 0);  // O_RDONLY
        if (envFd >= 0) {
            var buf = Memory.alloc(8192);
            var n = readFn(envFd, buf, 8192);
            closeFn(envFd);
            if (n > 0) {
                var envStr = buf.readUtf8String(n);
                var envVars = envStr.split('\x00');
                for (var i = 0; i < envVars.length; i++) {
                    if (envVars[i].indexOf('LD_PRELOAD=') === 0) {
                        findings.ld_preload_env = envVars[i].substring(11);
                    }
                }
            }
        }
    } catch(e) {}

    // Check /etc/ld.so.preload
    try {
        var preloadPath = Memory.allocUtf8String('/etc/ld.so.preload');
        var preFd = fd(preloadPath, 0);
        if (preFd >= 0) {
            var preBuf = Memory.alloc(4096);
            var preN = readFn(preFd, preBuf, 4096);
            closeFn(preFd);
            if (preN > 0) {
                findings.ld_so_preload_file = preBuf.readUtf8String(preN).trim();
            }
        } else {
            findings.ld_so_preload_file = '<file not found or not readable>';
        }
    } catch(e) {}

    // Enumerate loaded libraries and flag suspicious ones
    var standardPrefixes = ['/lib', '/usr/lib', '/lib64', '/usr/lib64', '/usr/local/lib',
                            '/system/lib', '/vendor/lib', '/apex/'];
    var mods = Process.enumerateModules();
    mods.forEach(function(m) {
        var info = {name: m.name, path: m.path, base: m.base.toString(), size: m.size};
        findings.all_libraries.push({name: m.name, path: m.path});

        var isStandard = false;
        for (var j = 0; j < standardPrefixes.length; j++) {
            if (m.path.indexOf(standardPrefixes[j]) === 0) {
                isStandard = true;
                break;
            }
        }

        if (!isStandard && m.path.length > 0 && m.path !== '[vdso]') {
            info.reason = 'non-standard path';
            findings.suspicious_libraries.push(info);
        }
        // Flag libs in /tmp, /dev/shm, or with memfd paths
        if (m.path.indexOf('/tmp/') === 0 || m.path.indexOf('/dev/shm/') === 0 || m.path.indexOf('memfd:') !== -1) {
            info.reason = 'suspicious location (' + m.path + ')';
            if (findings.suspicious_libraries.indexOf(info) === -1)
                findings.suspicious_libraries.push(info);
        }
    });

    send({
        type: 'preload_detect',
        ld_preload_env: findings.ld_preload_env,
        ld_so_preload_file: findings.ld_so_preload_file,
        suspicious_libraries: findings.suspicious_libraries,
        total_libraries: findings.all_libraries.length,
        suspicious_count: findings.suspicious_libraries.length,
        timestamp: Date.now()
    });
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def linux_dbus_intercept(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Intercept D-Bus method calls in a Linux target process.

    Hooks dbus_message_new_method_call and dbus_connection_send in
    libdbus-1.so. Captures destination, interface, member (method),
    path, and message type for outgoing D-Bus messages.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var hooked = [];
    var dbusLibs = ['libdbus-1.so', 'libdbus-1.so.3', 'libdbus-1.so.3.19.0'];
    var gio = ['libgio-2.0.so', 'libgio-2.0.so.0'];

    function findExport(names, fn) {
        for (var i = 0; i < names.length; i++) {
            try {
                var addr = _fm_find_export(names[i], fn);
                if (addr) return addr;
            } catch(e) {}
        }
        try { return _fm_find_export(null, fn); } catch(e) {}
        return null;
    }

    // ---- dbus_message_new_method_call ----
    var newMethodCall = findExport(dbusLibs, 'dbus_message_new_method_call');
    if (newMethodCall) {
        Interceptor.attach(newMethodCall, {
            onEnter: function(args) {
                var dest = null, path = null, iface = null, method = null;
                try { dest = args[0].readUtf8String(); } catch(e) {}
                try { path = args[1].readUtf8String(); } catch(e) {}
                try { iface = args[2].readUtf8String(); } catch(e) {}
                try { method = args[3].readUtf8String(); } catch(e) {}
                send({
                    type: 'dbus_call',
                    api: 'dbus_message_new_method_call',
                    destination: dest,
                    path: path,
                    interface: iface,
                    method: method,
                    timestamp: Date.now()
                });
            }
        });
        hooked.push('dbus_message_new_method_call');
    }

    // ---- dbus_connection_send ----
    var connSend = findExport(dbusLibs, 'dbus_connection_send');
    if (connSend) {
        Interceptor.attach(connSend, {
            onEnter: function(args) {
                send({
                    type: 'dbus_send',
                    api: 'dbus_connection_send',
                    connection: args[0].toString(),
                    message: args[1].toString(),
                    timestamp: Date.now()
                });
            }
        });
        hooked.push('dbus_connection_send');
    }

    // ---- GIO: g_dbus_connection_call (if using GLib/GIO D-Bus) ----
    var gCall = findExport(gio, 'g_dbus_connection_call');
    if (gCall) {
        Interceptor.attach(gCall, {
            onEnter: function(args) {
                var busName = null, objPath = null, iface = null, method = null;
                try { busName = args[1].readUtf8String(); } catch(e) {}
                try { objPath = args[2].readUtf8String(); } catch(e) {}
                try { iface = args[3].readUtf8String(); } catch(e) {}
                try { method = args[4].readUtf8String(); } catch(e) {}
                send({
                    type: 'dbus_call',
                    api: 'g_dbus_connection_call',
                    bus_name: busName,
                    object_path: objPath,
                    interface: iface,
                    method: method,
                    timestamp: Date.now()
                });
            }
        });
        hooked.push('g_dbus_connection_call');
    }

    if (hooked.length === 0) {
        send({type: 'error', message: 'No D-Bus libraries found in process (libdbus-1.so / libgio-2.0.so not loaded)'});
    } else {
        send({type: 'info', message: 'dbus_intercept hooked: ' + hooked.join(', ')});
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def linux_got_hook(
    target: str,
    module_name: str,
    function_name: str,
    replacement_addr: str | None = None,
) -> dict[str, Any]:
    """Overwrite a GOT/PLT entry in a Linux target process.

    Finds the GOT entry for `function_name` in `module_name` and either
    replaces it with `replacement_addr` or installs a logging trampoline
    that logs calls and forwards to the original implementation.

    `target`: process name or pid (string).
    `module_name`: ELF module name (e.g. 'myapp', 'libssl.so').
    `function_name`: function name whose GOT entry to overwrite.
    `replacement_addr`: optional hex address for the replacement. If not
      given, installs a logging hook that logs calls and passes through.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    safe_module = json.dumps(module_name)
    safe_func = json.dumps(function_name)
    repl_js = json.dumps(replacement_addr) if replacement_addr else "null"
    js = r"""
    'use strict';
    var modName = """ + safe_module + r""";
    var funcName = """ + safe_func + r""";
    var replAddr = """ + repl_js + r""";

    try {
        var mod = Process.findModuleByName(modName);
        if (!mod) {
            // Try partial match
            var mods = Process.enumerateModules();
            for (var i = 0; i < mods.length; i++) {
                if (mods[i].name.toLowerCase().indexOf(modName.toLowerCase()) !== -1) {
                    mod = mods[i];
                    break;
                }
            }
        }
        if (!mod) {
            send({type: 'error', message: 'module not found: ' + modName});
        } else {
            // Enumerate imports to find the GOT entry
            var imports = mod.enumerateImports();
            var gotEntry = null;
            for (var j = 0; j < imports.length; j++) {
                if (imports[j].name === funcName) {
                    gotEntry = imports[j];
                    break;
                }
            }

            if (!gotEntry) {
                send({type: 'error', message: 'GOT entry for ' + funcName + ' not found in ' + mod.name});
            } else {
                var gotSlot = gotEntry.slot;
                var originalTarget = ptr(gotSlot).readPointer();

                if (replAddr) {
                    // Direct replacement
                    Memory.protect(ptr(gotSlot), Process.pointerSize, 'rw-');
                    ptr(gotSlot).writePointer(ptr(replAddr));
                    var newTarget = ptr(gotSlot).readPointer();
                    send({
                        type: 'got_hook',
                        status: 'replaced',
                        module: mod.name,
                        function: funcName,
                        got_slot: gotSlot.toString(),
                        original_target: originalTarget.toString(),
                        new_target: newTarget.toString(),
                        timestamp: Date.now()
                    });
                } else {
                    // Install logging trampoline via Interceptor
                    Interceptor.attach(originalTarget, {
                        onEnter: function(args) {
                            var callArgs = [];
                            for (var k = 0; k < 4; k++) {
                                try { callArgs.push(args[k].toString()); } catch(e) { break; }
                            }
                            send({
                                type: 'got_call',
                                module: mod.name,
                                function: funcName,
                                args: callArgs,
                                timestamp: Date.now()
                            });
                        }
                    });
                    send({
                        type: 'got_hook',
                        status: 'logging',
                        module: mod.name,
                        function: funcName,
                        got_slot: gotSlot.toString(),
                        target_address: originalTarget.toString(),
                        timestamp: Date.now()
                    });
                }
            }
        }
    } catch(e) {
        send({type: 'error', message: 'got_hook failed: ' + e.message});
    }
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def linux_seccomp_detect(target: str) -> dict[str, Any]:
    """Detect seccomp sandbox status in a Linux target process.

    Checks if the process has seccomp filters active by reading
    /proc/self/status and calling prctl(PR_GET_SECCOMP). Reports
    the seccomp mode (disabled, strict, filter) and any related
    process status fields.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var results = {};

    // Method 1: Read /proc/self/status for Seccomp field
    try {
        var open = new NativeFunction(_fm_find_export(null, 'open'), 'int', ['pointer', 'int']);
        var readFn = new NativeFunction(_fm_find_export(null, 'read'), 'int', ['int', 'pointer', 'int']);
        var closeFn = new NativeFunction(_fm_find_export(null, 'close'), 'int', ['int']);

        var statusPath = Memory.allocUtf8String('/proc/self/status');
        var fd = open(statusPath, 0);
        if (fd >= 0) {
            var buf = Memory.alloc(8192);
            var n = readFn(fd, buf, 8192);
            closeFn(fd);
            if (n > 0) {
                var statusStr = buf.readUtf8String(n);
                var lines = statusStr.split('\n');
                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i];
                    if (line.indexOf('Seccomp:') === 0) {
                        var mode = parseInt(line.split(':')[1].trim());
                        var modeNames = {0: 'disabled', 1: 'strict', 2: 'filter'};
                        results.seccomp_mode = mode;
                        results.seccomp_mode_name = modeNames[mode] || 'unknown';
                    }
                    if (line.indexOf('Seccomp_filters:') === 0) {
                        results.seccomp_filters_count = parseInt(line.split(':')[1].trim());
                    }
                    if (line.indexOf('NoNewPrivs:') === 0) {
                        results.no_new_privs = parseInt(line.split(':')[1].trim()) !== 0;
                    }
                }
            }
        }
    } catch(e) {
        results.proc_status_error = e.message;
    }

    // Method 2: prctl(PR_GET_SECCOMP) = 21
    try {
        var prctl = new NativeFunction(_fm_find_export(null, 'prctl'), 'int', ['int', 'int', 'int', 'int', 'int']);
        var PR_GET_SECCOMP = 21;
        var seccompStatus = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
        results.prctl_seccomp = seccompStatus;
        var prctlNames = {0: 'disabled', 1: 'strict', 2: 'filter'};
        results.prctl_seccomp_name = prctlNames[seccompStatus] || 'unknown/error';
    } catch(e) {
        results.prctl_error = e.message;
    }

    // Method 3: Check /proc/self/seccomp (older kernels)
    try {
        var seccompPath = Memory.allocUtf8String('/proc/self/seccomp');
        var fd2 = open(seccompPath, 0);
        if (fd2 >= 0) {
            var buf2 = Memory.alloc(64);
            var n2 = readFn(fd2, buf2, 64);
            closeFn(fd2);
            if (n2 > 0) {
                results.proc_seccomp = buf2.readUtf8String(n2).trim();
            }
        }
    } catch(e) {}

    results.type = 'seccomp_detect';
    results.is_sandboxed = (results.seccomp_mode || 0) > 0 || (results.prctl_seccomp || 0) > 0;
    results.timestamp = Date.now();
    send(results);
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")
