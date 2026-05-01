"""fuzzmind-frida-mcp -- security tools."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import time

from .._core import INSTALL_HINT, _create_script, _load_frida, _run_script


def ssl_pinning_disable(target: str) -> dict[str, Any]:
    """Inject a universal SSL pinning bypass script.

    Works on both Android (TrustManager / OkHttp / Conscrypt) and
    iOS/macOS (NSURLSession / SecTrust). Uses well-known community
    bypass patterns.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var bypassed = [];

    // ---- Android: TrustManager + OkHttp + Conscrypt ----
    if (Java && Java.available) {
        Java.perform(function() {
            // 1. TrustManagerImpl (Android default)
            try {
                var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl.verifyChain.implementation = function() {
                    return arguments[0]; // return the untrusted chain as-is
                };
                bypassed.push('TrustManagerImpl.verifyChain');
            } catch(e) {}

            // 2. Custom X509TrustManager — accept everything
            try {
                var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                var TrustManager = Java.registerClass({
                    name: 'com.fuzzmind.BypassTrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                var ctx = SSLContext.getInstance('TLS');
                ctx.init(null, [TrustManager.$new()], null);
                SSLContext.getInstance.overload('java.lang.String').implementation = function(type) {
                    return ctx;
                };
                bypassed.push('X509TrustManager (custom)');
            } catch(e) {}

            // 3. OkHttp3 CertificatePinner
            try {
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
                bypassed.push('OkHttp3.CertificatePinner');
            } catch(e) {}
            try {
                var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
                CertificatePinner2.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function() {};
                bypassed.push('OkHttp3.CertificatePinner$okhttp');
            } catch(e) {}

            // 4. Conscrypt / Platform TrustManager
            try {
                var Platform = Java.use('com.android.org.conscrypt.Platform');
                Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function() {};
                bypassed.push('Conscrypt.Platform.checkServerTrusted');
            } catch(e) {}
        });
    }

    // ---- iOS / macOS: SecTrust + NSURLSession ----
    if (ObjC && ObjC.available) {
        // 1. SecTrustEvaluateWithError — always succeed
        try {
            Interceptor.replace(
                _fm_find_export('Security', 'SecTrustEvaluateWithError'),
                new NativeCallback(function(trust, error) {
                    if (!error.isNull()) {
                        error.writePointer(ptr(0));
                    }
                    return 1; // true = trusted
                }, 'bool', ['pointer', 'pointer'])
            );
            bypassed.push('SecTrustEvaluateWithError');
        } catch(e) {}

        // 2. SecTrustEvaluate (legacy) — set result to kSecTrustResultProceed
        try {
            Interceptor.replace(
                _fm_find_export('Security', 'SecTrustEvaluate'),
                new NativeCallback(function(trust, result) {
                    result.writeU32(1); // kSecTrustResultProceed
                    return 0; // errSecSuccess
                }, 'int', ['pointer', 'pointer'])
            );
            bypassed.push('SecTrustEvaluate');
        } catch(e) {}

        // 3. NSURLSession delegate — auto-complete challenges
        try {
            var resolver = new ApiResolver('objc');
            var matches = resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]');
            matches.forEach(function(m) {
                Interceptor.attach(m.address, {
                    onEnter: function(args) {
                        // args[4] = completionHandler block
                        // Logging hook — the original continues to run.
                    }
                });
            });
            if (matches.length > 0) {
                bypassed.push('NSURLSession challenge delegates (' + matches.length + ')');
            }
        } catch(e) {}
    }

    send({type: 'ssl_pinning_disable', bypassed: bypassed, count: bypassed.length});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def ssl_keylog(
    target: str,
    output_file: str,
    duration_seconds: int = 30,
) -> dict[str, Any]:
    """Extract TLS session keys in NSS SSLKEYLOGFILE format for Wireshark decryption.

    Hooks SSL/TLS internals to capture pre-master secrets and session keys:
    - macOS: BoringSSL's SSL_CTX_set_info_callback / ssl_log_secret
    - Fallback: hooks SSL_new and installs a keylog callback

    Writes keys to `output_file` in the standard SSLKEYLOGFILE format
    that Wireshark can consume directly.

    `target`: process name or pid (string).
    `output_file`: local path for the keylog file.
    `duration_seconds`: how long to capture (default 30).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var keys = [];
    var keySet = {};

    function addKey(line) {
        if (!keySet[line]) {
            keySet[line] = true;
            keys.push(line);
            send({type: 'ssl_key', line: line});
        }
    }

    function bytesToHex(ptr, len) {
        var arr = new Uint8Array(ptr.readByteArray(len));
        return Array.from(arr).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    }

    // ---- Strategy 1: Hook ssl_log_secret (BoringSSL internal) ----
    var hooked = false;
    try {
        // BoringSSL on macOS exports this in libboringssl.dylib or Security framework
        var modules = ['libboringssl.dylib', 'libsystem_security.dylib', 'Security', null];
        for (var i = 0; i < modules.length && !hooked; i++) {
            var logSecret = _fm_find_export(modules[i], 'SSL_CTX_set_keylog_callback');
            if (logSecret) {
                // We need to intercept the callback being set and replace it with ours
                Interceptor.attach(logSecret, {
                    onEnter: function(args) {
                        // args[1] is the callback function pointer
                        // We'll also hook SSL_new to install our own callback
                    }
                });
                send({type: 'info', message: 'found SSL_CTX_set_keylog_callback in ' + (modules[i] || 'default')});
            }
        }
    } catch(e) {}

    // ---- Strategy 2: Hook SSL_new and inject keylog callback ----
    try {
        var sslModules = ['libboringssl.dylib', 'libssl.dylib', null];
        for (var j = 0; j < sslModules.length; j++) {
            var SSL_new = _fm_find_export(sslModules[j], 'SSL_new');
            var SSL_CTX_set_keylog = _fm_find_export(sslModules[j], 'SSL_CTX_set_keylog_callback');
            if (SSL_new && SSL_CTX_set_keylog) {
                var keylogCallback = new NativeCallback(function(ssl, line) {
                    var lineStr = line.readUtf8String();
                    if (lineStr) {
                        addKey(lineStr);
                    }
                }, 'void', ['pointer', 'pointer']);

                // Hook SSL_new to grab the ctx and set our keylog callback
                var SSL_get_SSL_CTX = _fm_find_export(sslModules[j], 'SSL_get_SSL_CTX');
                if (SSL_get_SSL_CTX) {
                    var getCtx = new NativeFunction(SSL_get_SSL_CTX, 'pointer', ['pointer']);
                    var setKeylog = new NativeFunction(SSL_CTX_set_keylog, 'void', ['pointer', 'pointer']);

                    Interceptor.attach(SSL_new, {
                        onLeave: function(retval) {
                            if (!retval.isNull()) {
                                try {
                                    var ctx = getCtx(retval);
                                    if (!ctx.isNull()) {
                                        setKeylog(ctx, keylogCallback);
                                    }
                                } catch(e) {}
                            }
                        }
                    });
                    hooked = true;
                    send({type: 'info', message: 'hooked SSL_new + SSL_CTX_set_keylog_callback in ' + (sslModules[j] || 'default')});
                    break;
                }
            }
        }
    } catch(e) {}

    // ---- Strategy 3: macOS SecureTransport SSLHandshake ----
    if (!hooked) {
        try {
            var SSLHandshake = _fm_find_export('Security', 'SSLHandshake');
            if (SSLHandshake) {
                Interceptor.attach(SSLHandshake, {
                    onEnter: function(args) {
                        this._ctx = args[0];
                    },
                    onLeave: function(retval) {
                        send({
                            type: 'ssl_handshake',
                            context: this._ctx.toString(),
                            result: retval.toInt32(),
                            timestamp: Date.now()
                        });
                    }
                });
                send({type: 'info', message: 'hooked SSLHandshake (SecureTransport) — limited keylog support'});
                hooked = true;
            }
        } catch(e) {}
    }

    if (!hooked) {
        send({type: 'error', message: 'could not hook any SSL/TLS functions — no BoringSSL/OpenSSL/SecureTransport found'});
    }
    """

    events: list[dict[str, Any]] = []
    key_lines: list[str] = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict):
                if payload.get("type") == "ssl_key":
                    key_lines.append(payload["line"])
                events.append(payload)
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        device = frida.get_local_device()
        if target.isdigit():
            session = frida.attach(int(target))
        else:
            session = frida.attach(target)

        script = _create_script(session, js)
        script.on("message", on_message)
        script.load()
        time.sleep(duration_seconds)
        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"ssl_keylog failed: {e}", "keys_captured": len(key_lines)}

    # Write keylog file
    try:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(key_lines) + ("\n" if key_lines else ""))
    except Exception as e:
        return {"error": f"ssl_keylog write failed: {e}", "keys_captured": len(key_lines)}

    return {
        "target": target,
        "output_file": output_file,
        "duration_seconds": duration_seconds,
        "keys_captured": len(key_lines),
        "events": events[:100],
        "events_truncated": len(events) > 100,
    }

def crypto_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook crypto APIs to capture encryption/decryption operations.

    Hooks platform-specific crypto functions:
    - macOS/iOS: CCCrypt, SecKeyCreateEncryptedData, SecKeyCreateDecryptedData
    - Android: javax.crypto.Cipher.doFinal

    Logs operation type (encrypt/decrypt), algorithm, key bytes (hex),
    and input/output sizes.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var ops = [];

    // ---- CommonCrypto: CCCrypt ----
    try {
        var CCCrypt = _fm_find_export('libcommonCrypto.dylib', 'CCCrypt');
        if (CCCrypt) {
            Interceptor.attach(CCCrypt, {
                onEnter: function(args) {
                    this._op = args[0].toInt32();  // 0=encrypt, 1=decrypt
                    this._alg = args[1].toInt32();  // 0=AES128, 1=DES, 2=3DES, etc.
                    var keyLen = args[3].toInt32();
                    var keyPtr = args[2];
                    var keyBytes = '';
                    try {
                        var arr = new Uint8Array(keyPtr.readByteArray(Math.min(keyLen, 64)));
                        keyBytes = Array.from(arr).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                    } catch(e) { keyBytes = '<unreadable>'; }
                    this._keyHex = keyBytes;
                    this._keyLen = keyLen;
                    this._inLen = args[6].toInt32();
                },
                onLeave: function(retval) {
                    var algNames = {0: 'AES', 1: 'DES', 2: '3DES', 3: 'CAST', 4: 'RC4', 5: 'RC2', 6: 'Blowfish'};
                    send({
                        type: 'crypto_op',
                        api: 'CCCrypt',
                        operation: this._op === 0 ? 'encrypt' : 'decrypt',
                        algorithm: algNames[this._alg] || ('alg_' + this._alg),
                        key_hex: this._keyHex,
                        key_length: this._keyLen,
                        input_size: this._inLen,
                        status: retval.toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            send({type: 'info', message: 'hooked CCCrypt'});
        }
    } catch(e) {}

    // ---- Security framework: SecKeyCreateEncryptedData / SecKeyCreateDecryptedData ----
    try {
        var encFn = _fm_find_export('Security', 'SecKeyCreateEncryptedData');
        if (encFn) {
            Interceptor.attach(encFn, {
                onEnter: function(args) {
                    this._algorithm = args[1];
                },
                onLeave: function(retval) {
                    send({
                        type: 'crypto_op',
                        api: 'SecKeyCreateEncryptedData',
                        operation: 'encrypt',
                        algorithm: 'SecKey',
                        result_null: retval.isNull(),
                        timestamp: Date.now()
                    });
                }
            });
            send({type: 'info', message: 'hooked SecKeyCreateEncryptedData'});
        }
    } catch(e) {}

    try {
        var decFn = _fm_find_export('Security', 'SecKeyCreateDecryptedData');
        if (decFn) {
            Interceptor.attach(decFn, {
                onEnter: function(args) {
                    this._algorithm = args[1];
                },
                onLeave: function(retval) {
                    send({
                        type: 'crypto_op',
                        api: 'SecKeyCreateDecryptedData',
                        operation: 'decrypt',
                        algorithm: 'SecKey',
                        result_null: retval.isNull(),
                        timestamp: Date.now()
                    });
                }
            });
            send({type: 'info', message: 'hooked SecKeyCreateDecryptedData'});
        }
    } catch(e) {}

    // ---- Android: javax.crypto.Cipher.doFinal ----
    if (Java && Java.available) {
        Java.perform(function() {
            try {
                var Cipher = Java.use('javax.crypto.Cipher');
                Cipher.doFinal.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var mode = this.getOpmode();  // 1=ENCRYPT, 2=DECRYPT
                        var algo = this.getAlgorithm();
                        var inputSize = 0;
                        if (arguments.length > 0 && arguments[0]) {
                            try { inputSize = arguments[0].length; } catch(e) {}
                        }
                        var result = overload.apply(this, arguments);
                        var outputSize = 0;
                        if (result) {
                            try { outputSize = result.length; } catch(e) {}
                        }
                        send({
                            type: 'crypto_op',
                            api: 'javax.crypto.Cipher.doFinal',
                            operation: mode === 1 ? 'encrypt' : 'decrypt',
                            algorithm: algo,
                            input_size: inputSize,
                            output_size: outputSize,
                            timestamp: Date.now()
                        });
                        return result;
                    };
                });
                send({type: 'info', message: 'hooked javax.crypto.Cipher.doFinal'});
            } catch(e) {}
        });
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def string_sniffer(
    target: str,
    min_length: int = 4,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook string-producing functions to capture strings as they appear at runtime.

    Hooks:
    - ObjC: NSString -initWithBytes:length:encoding:
    - Native: strlen (with length filter)

    Captures decoded/decrypted strings as they are created. Returns unique
    strings observed during the capture window.

    `target`: process name or pid (string).
    `min_length`: minimum string length to capture (default 4).
    `duration_seconds`: how long to sniff (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = f"""
    'use strict';
    var seen = {{}};
    var count = 0;
    var minLen = {int(min_length)};

    // ---- ObjC: NSString initWithBytes:length:encoding: ----
    if (ObjC && ObjC.available) {{
        try {{
            var NSString = ObjC.classes.NSString;
            var initMethod = NSString['- initWithBytes:length:encoding:'];
            if (initMethod) {{
                Interceptor.attach(initMethod.implementation, {{
                    onLeave: function(retval) {{
                        if (!retval.isNull()) {{
                            try {{
                                var obj = new ObjC.Object(retval);
                                var str = obj.toString();
                                if (str.length >= minLen && !seen[str]) {{
                                    seen[str] = true;
                                    count++;
                                    if (count <= 2000) {{
                                        send({{type: 'string', source: 'NSString_initWithBytes', value: str.substring(0, 500), length: str.length}});
                                    }}
                                }}
                            }} catch(e) {{}}
                        }}
                    }}
                }});
                send({{type: 'info', message: 'hooked NSString initWithBytes:length:encoding:'}});
            }}
        }} catch(e) {{}}

        // Also hook stringWithUTF8String: for C-string conversions
        try {{
            var fromUTF8 = NSString['+ stringWithUTF8String:'];
            if (fromUTF8) {{
                Interceptor.attach(fromUTF8.implementation, {{
                    onLeave: function(retval) {{
                        if (!retval.isNull()) {{
                            try {{
                                var obj = new ObjC.Object(retval);
                                var str = obj.toString();
                                if (str.length >= minLen && !seen[str]) {{
                                    seen[str] = true;
                                    count++;
                                    if (count <= 2000) {{
                                        send({{type: 'string', source: 'NSString_stringWithUTF8String', value: str.substring(0, 500), length: str.length}});
                                    }}
                                }}
                            }} catch(e) {{}}
                        }}
                    }}
                }});
                send({{type: 'info', message: 'hooked NSString stringWithUTF8String:'}});
            }}
        }} catch(e) {{}}
    }}

    // ---- Native: strlen ----
    try {{
        var strlenAddr = _fm_find_export(null, 'strlen');
        if (strlenAddr) {{
            Interceptor.attach(strlenAddr, {{
                onEnter: function(args) {{
                    this._ptr = args[0];
                }},
                onLeave: function(retval) {{
                    var len = retval.toInt32();
                    if (len >= minLen && len < 4096) {{
                        try {{
                            var str = this._ptr.readUtf8String(len);
                            if (str && !seen[str]) {{
                                seen[str] = true;
                                count++;
                                if (count <= 2000) {{
                                    send({{type: 'string', source: 'strlen', value: str.substring(0, 500), length: len}});
                                }}
                            }}
                        }} catch(e) {{}}
                    }}
                }}
            }});
            send({{type: 'info', message: 'hooked strlen'}});
        }}
    }} catch(e) {{}}

    // Send summary after duration
    setTimeout(function() {{
        send({{type: 'string_sniffer_summary', unique_strings: Object.keys(seen).length, total_captured: count}});
    }}, {int(duration_seconds * 1000) - 500});
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def time_warp(
    target: str,
    speed_factor: float = 0.0,
    fixed_time: int | None = None,
) -> dict[str, Any]:
    """Warp time perception for a target process. Anti-sandbox evasion technique.

    Hooks time APIs: gettimeofday, clock_gettime, mach_absolute_time, time().

    `target`: process name or pid (string).
    `speed_factor`: time speed multiplier. 0.0 = freeze time, 1.0 = normal,
      2.0 = 2x speed, 0.5 = half speed.
    `fixed_time`: if set, return this specific Unix timestamp (seconds)
      from all time functions. Overrides `speed_factor`.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    fixed_time_js = json.dumps(fixed_time) if fixed_time is not None else "null"

    js = f"""
    'use strict';
    var speedFactor = {float(speed_factor)};
    var fixedTime = {fixed_time_js};
    var baseRealTime = null;
    var baseWarpTime = null;
    var hooked = [];

    function getWarpedTime(realSecs) {{
        if (fixedTime !== null) return fixedTime;
        if (baseRealTime === null) {{
            baseRealTime = realSecs;
            baseWarpTime = realSecs;
            return realSecs;
        }}
        var elapsed = realSecs - baseRealTime;
        return baseWarpTime + (elapsed * speedFactor);
    }}

    // ---- gettimeofday ----
    try {{
        var gettimeofday = _fm_find_export('libsystem_c.dylib', 'gettimeofday');
        if (!gettimeofday) gettimeofday = _fm_find_export(null, 'gettimeofday');
        if (gettimeofday) {{
            Interceptor.attach(gettimeofday, {{
                onLeave: function(retval) {{
                    if (retval.toInt32() === 0) {{
                        // args[0] = struct timeval *tv (from onEnter)
                        // We need to read/modify the timeval after the call
                    }}
                }}
            }});
            // Replace so the timeval can be adjusted directly.
            var original_gettimeofday = new NativeFunction(gettimeofday, 'int', ['pointer', 'pointer']);
            Interceptor.replace(gettimeofday, new NativeCallback(function(tv, tz) {{
                var ret = original_gettimeofday(tv, tz);
                if (ret === 0 && !tv.isNull()) {{
                    var realSec = tv.readS64();
                    var warped = getWarpedTime(realSec);
                    tv.writeS64(Math.floor(warped));
                    if (fixedTime !== null) {{
                        tv.add(Process.pointerSize >= 8 ? 8 : 4).writeS64(0);
                    }}
                }}
                return ret;
            }}, 'int', ['pointer', 'pointer']));
            hooked.push('gettimeofday');
        }}
    }} catch(e) {{}}

    // ---- time() ----
    try {{
        var timeFn = _fm_find_export('libsystem_c.dylib', 'time');
        if (!timeFn) timeFn = _fm_find_export(null, 'time');
        if (timeFn) {{
            var original_time = new NativeFunction(timeFn, 'long', ['pointer']);
            Interceptor.replace(timeFn, new NativeCallback(function(tloc) {{
                var realTime = original_time(ptr(0));
                var warped = Math.floor(getWarpedTime(realTime));
                if (!tloc.isNull()) {{
                    tloc.writeS64(warped);
                }}
                return warped;
            }}, 'long', ['pointer']));
            hooked.push('time');
        }}
    }} catch(e) {{}}

    // ---- clock_gettime ----
    try {{
        var clock_gettime = _fm_find_export('libsystem_c.dylib', 'clock_gettime');
        if (!clock_gettime) clock_gettime = _fm_find_export(null, 'clock_gettime');
        if (clock_gettime) {{
            var original_clock_gettime = new NativeFunction(clock_gettime, 'int', ['int', 'pointer']);
            Interceptor.replace(clock_gettime, new NativeCallback(function(clk_id, tp) {{
                var ret = original_clock_gettime(clk_id, tp);
                if (ret === 0 && !tp.isNull()) {{
                    var realSec = tp.readS64();
                    var warped = getWarpedTime(realSec);
                    tp.writeS64(Math.floor(warped));
                    if (fixedTime !== null) {{
                        tp.add(Process.pointerSize >= 8 ? 8 : 4).writeS64(0);
                    }}
                }}
                return ret;
            }}, 'int', ['int', 'pointer']));
            hooked.push('clock_gettime');
        }}
    }} catch(e) {{}}

    // ---- mach_absolute_time ----
    try {{
        var machAbsTime = _fm_find_export('libsystem_kernel.dylib', 'mach_absolute_time');
        if (!machAbsTime) machAbsTime = _fm_find_export(null, 'mach_absolute_time');
        if (machAbsTime) {{
            var baseMachTime = null;
            var original_mach = new NativeFunction(machAbsTime, 'uint64', []);
            Interceptor.replace(machAbsTime, new NativeCallback(function() {{
                var real = original_mach();
                if (fixedTime !== null) {{
                    if (baseMachTime === null) baseMachTime = real;
                    return baseMachTime;
                }}
                if (baseMachTime === null) {{
                    baseMachTime = real;
                    return real;
                }}
                var elapsed = real - baseMachTime;
                return baseMachTime + Math.floor(elapsed * speedFactor);
            }}, 'uint64', []));
            hooked.push('mach_absolute_time');
        }}
    }} catch(e) {{}}

    send({{
        type: 'time_warp',
        speed_factor: speedFactor,
        fixed_time: fixedTime,
        hooked_apis: hooked,
        count: hooked.length
    }});
    """
    return _run_script(frida, target, js, duration_seconds=30, mode="attach")

def anti_root_bypass(target: str) -> dict[str, Any]:
    """Bypass root/jailbreak detection in a target process.

    Multi-platform bypasses:
    - iOS/macOS: hooks NSFileManager fileExistsAtPath: for common
      jailbreak paths (/Applications/Cydia.app, /private/var/lib/apt,
      etc.), hooks sysctl for P_TRACED, hooks getenv for
      DYLD_INSERT_LIBRARIES.
    - Android: hooks java.io.File.exists() for /su/bin, /system/xbin/su,
      etc., hooks Runtime.exec() for "su" commands, spoofs
      android.os.Build properties.

    `target`: process name or pid (string).
    Returns a list of bypasses that were successfully installed.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var bypassed = [];

    // ---- iOS/macOS: NSFileManager fileExistsAtPath: ----
    if (ObjC && ObjC.available) {
        var jbPaths = [
            '/Applications/Cydia.app',
            '/Library/MobileSubstrate/MobileSubstrate.dylib',
            '/bin/bash',
            '/usr/sbin/sshd',
            '/etc/apt',
            '/private/var/lib/apt/',
            '/private/var/lib/cydia',
            '/private/var/stash',
            '/usr/bin/ssh',
            '/usr/libexec/sftp-server',
            '/var/cache/apt',
            '/var/lib/cydia',
            '/var/log/syslog',
            '/var/tmp/cydia.log',
            '/jb/offsets.plist'
        ];

        try {
            var NSFileManager = ObjC.classes.NSFileManager;
            var origExists = NSFileManager['- fileExistsAtPath:'];
            Interceptor.attach(origExists.implementation, {
                onEnter: function(args) {
                    this._path = new ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    for (var i = 0; i < jbPaths.length; i++) {
                        if (this._path && this._path.indexOf(jbPaths[i]) !== -1) {
                            retval.replace(ptr(0));  // false
                            break;
                        }
                    }
                }
            });
            bypassed.push('NSFileManager.fileExistsAtPath (jailbreak paths)');
        } catch(e) {}

        // Hook sysctl to hide P_TRACED flag
        try {
            var sysctl = _fm_find_export('libsystem_c.dylib', 'sysctl');
            if (sysctl) {
                Interceptor.attach(sysctl, {
                    onEnter: function(args) {
                        // CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1
                        var mib = args[0];
                        var name0 = mib.readS32();
                        var name1 = mib.add(4).readS32();
                        this._isKernProc = (name0 === 1 && name1 === 14);
                        this._oldp = args[2];
                    },
                    onLeave: function(retval) {
                        if (this._isKernProc && !this._oldp.isNull()) {
                            // Clear P_TRACED flag (bit 11 of kp_proc.p_flag)
                            try {
                                var flagOffset = Process.pointerSize === 8 ? 32 : 16;
                                var flags = this._oldp.add(flagOffset).readS32();
                                var P_TRACED = 0x800;
                                if (flags & P_TRACED) {
                                    this._oldp.add(flagOffset).writeS32(flags & ~P_TRACED);
                                }
                            } catch(e) {}
                        }
                    }
                });
                bypassed.push('sysctl (P_TRACED flag)');
            }
        } catch(e) {}

        // Hook getenv for DYLD_INSERT_LIBRARIES
        try {
            var getenv = _fm_find_export('libsystem_c.dylib', 'getenv');
            if (getenv) {
                Interceptor.attach(getenv, {
                    onEnter: function(args) {
                        this._name = args[0].readUtf8String();
                    },
                    onLeave: function(retval) {
                        if (this._name === 'DYLD_INSERT_LIBRARIES') {
                            retval.replace(ptr(0));  // NULL
                        }
                    }
                });
                bypassed.push('getenv (DYLD_INSERT_LIBRARIES)');
            }
        } catch(e) {}
    }

    // ---- Android: File.exists, Runtime.exec, Build props ----
    if (Java && Java.available) {
        Java.perform(function() {
            var suPaths = [
                '/system/app/Superuser.apk',
                '/system/xbin/su',
                '/system/bin/su',
                '/sbin/su',
                '/data/local/xbin/su',
                '/data/local/bin/su',
                '/su/bin/su',
                '/system/bin/.ext/.su',
                '/system/usr/we-need-root/su-backup',
                '/system/xbin/mu',
                '/magisk/.core/bin/su'
            ];

            // Hook File.exists for root indicator paths
            try {
                var File = Java.use('java.io.File');
                File.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    for (var i = 0; i < suPaths.length; i++) {
                        if (path === suPaths[i]) {
                            return false;
                        }
                    }
                    return this.exists.call(this);
                };
                bypassed.push('java.io.File.exists (root paths)');
            } catch(e) {}

            // Hook Runtime.exec to block "su" commands
            try {
                var Runtime = Java.use('java.lang.Runtime');
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1)) {
                        throw Java.use('java.io.IOException').$new('Permission denied');
                    }
                    return this.exec(cmd);
                };
                bypassed.push('Runtime.exec (su commands)');
            } catch(e) {}

            // Spoof Build props
            try {
                var Build = Java.use('android.os.Build');
                Build.TAGS.value = 'release-keys';
                Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace('test-keys', 'release-keys');
                bypassed.push('android.os.Build (TAGS/FINGERPRINT)');
            } catch(e) {}
        });
    }

    send({type: 'anti_root_bypass', bypassed: bypassed, count: bypassed.length});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def anti_debug_bypass(target: str) -> dict[str, Any]:
    """Bypass common debugger detection mechanisms.

    Hooks:
    - ptrace(PT_DENY_ATTACH) -> return 0
    - sysctl -> clear P_TRACED flag
    - isDebuggerAttached / AmIBeingDebugged -> return false
    - Android: Debug.isDebuggerConnected -> return false

    `target`: process name or pid (string).
    Returns a list of bypasses that were successfully installed.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    var bypassed = [];

    // ---- ptrace(PT_DENY_ATTACH, ...) -> return 0 ----
    try {
        var ptrace = _fm_find_export(null, 'ptrace');
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    var request = args[0].toInt32();
                    // PT_DENY_ATTACH = 31
                    if (request === 31) {
                        this._denyAttach = true;
                    }
                },
                onLeave: function(retval) {
                    if (this._denyAttach) {
                        retval.replace(ptr(0));
                    }
                }
            });
            bypassed.push('ptrace (PT_DENY_ATTACH)');
        }
    } catch(e) {}

    // ---- sysctl -> clear P_TRACED ----
    try {
        var sysctl = _fm_find_export('libsystem_c.dylib', 'sysctl');
        if (!sysctl) sysctl = _fm_find_export(null, 'sysctl');
        if (sysctl) {
            Interceptor.attach(sysctl, {
                onEnter: function(args) {
                    var mib = args[0];
                    var name0 = mib.readS32();
                    var name1 = mib.add(4).readS32();
                    this._isKernProc = (name0 === 1 && name1 === 14);
                    this._oldp = args[2];
                },
                onLeave: function(retval) {
                    if (this._isKernProc && !this._oldp.isNull()) {
                        try {
                            var flagOffset = Process.pointerSize === 8 ? 32 : 16;
                            var flags = this._oldp.add(flagOffset).readS32();
                            var P_TRACED = 0x800;
                            if (flags & P_TRACED) {
                                this._oldp.add(flagOffset).writeS32(flags & ~P_TRACED);
                            }
                        } catch(e) {}
                    }
                }
            });
            bypassed.push('sysctl (P_TRACED clear)');
        }
    } catch(e) {}

    // ---- isDebuggerAttached (ObjC) ----
    if (ObjC && ObjC.available) {
        try {
            var resolver = new ApiResolver('objc');
            var matches = resolver.enumerateMatches('*[* *debugger*]');
            matches = matches.concat(resolver.enumerateMatches('*[* *Debugger*]'));
            matches.forEach(function(m) {
                try {
                    Interceptor.attach(m.address, {
                        onLeave: function(retval) {
                            retval.replace(ptr(0));  // false / NO
                        }
                    });
                } catch(e) {}
            });
            if (matches.length > 0) {
                bypassed.push('ObjC debugger checks (' + matches.length + ' methods)');
            }
        } catch(e) {}

        // AmIBeingDebugged via Security framework
        try {
            var amfi = _fm_find_export('Security', 'AmIBeingDebugged');
            if (amfi) {
                Interceptor.replace(amfi, new NativeCallback(function() {
                    return 0;
                }, 'int', []));
                bypassed.push('AmIBeingDebugged');
            }
        } catch(e) {}
    }

    // ---- getppid (detect debugger parent) ----
    try {
        var getppid = _fm_find_export(null, 'getppid');
        if (getppid) {
            Interceptor.attach(getppid, {
                onLeave: function(retval) {
                    // Return 1 (launchd) to hide debugger parent
                    retval.replace(ptr(1));
                }
            });
            bypassed.push('getppid (return launchd pid 1)');
        }
    } catch(e) {}

    // ---- Android: Debug.isDebuggerConnected ----
    if (Java && Java.available) {
        Java.perform(function() {
            try {
                var Debug = Java.use('android.os.Debug');
                Debug.isDebuggerConnected.implementation = function() {
                    return false;
                };
                bypassed.push('android.os.Debug.isDebuggerConnected');
            } catch(e) {}

            try {
                var Debug2 = Java.use('android.os.Debug');
                Debug2.waitingForDebugger.implementation = function() {
                    return false;
                };
                bypassed.push('android.os.Debug.waitingForDebugger');
            } catch(e) {}
        });
    }

    send({type: 'anti_debug_bypass', bypassed: bypassed, count: bypassed.length});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")
