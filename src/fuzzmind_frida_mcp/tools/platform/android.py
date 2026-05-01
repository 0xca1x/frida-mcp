"""fuzzmind-frida-mcp -- platform_android tools."""
from __future__ import annotations

from typing import Any
import json
import time

from .._core import INSTALL_HINT, _load_frida, _run_script


def android_content_provider_hook(
    target: str,
    authority: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook ContentResolver operations for a specific authority on Android.

    Hooks ContentResolver.query, insert, update, and delete. Filters by
    the specified authority URI prefix. Logs URI, projection/selection,
    and result counts.

    `target`: process name or pid (string).
    `authority`: content provider authority to monitor (e.g. 'com.example.provider').
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    safe_authority = json.dumps(authority)
    js = r"""
    'use strict';
    var targetAuthority = """ + safe_authority + r""";

    if (Java && Java.available) {
        Java.perform(function() {
            try {
                var ContentResolver = Java.use('android.content.ContentResolver');
                var Uri = Java.use('android.net.Uri');

                // Hook query
                ContentResolver.query.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var uri = arguments[0] ? arguments[0].toString() : '';
                        var result = overload.apply(this, arguments);
                        if (uri.indexOf(targetAuthority) !== -1) {
                            var count = -1;
                            if (result) { try { count = result.getCount(); } catch(e) {} }
                            send({
                                type: 'content_provider',
                                op: 'query',
                                uri: uri,
                                result_count: count,
                                timestamp: Date.now()
                            });
                        }
                        return result;
                    };
                });

                // Hook insert
                ContentResolver.insert.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var uri = arguments[0] ? arguments[0].toString() : '';
                        var result = overload.apply(this, arguments);
                        if (uri.indexOf(targetAuthority) !== -1) {
                            send({
                                type: 'content_provider',
                                op: 'insert',
                                uri: uri,
                                result_uri: result ? result.toString() : null,
                                timestamp: Date.now()
                            });
                        }
                        return result;
                    };
                });

                // Hook update
                ContentResolver.update.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var uri = arguments[0] ? arguments[0].toString() : '';
                        var result = overload.apply(this, arguments);
                        if (uri.indexOf(targetAuthority) !== -1) {
                            send({
                                type: 'content_provider',
                                op: 'update',
                                uri: uri,
                                rows_affected: result,
                                timestamp: Date.now()
                            });
                        }
                        return result;
                    };
                });

                // Hook delete
                ContentResolver['delete'].overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var uri = arguments[0] ? arguments[0].toString() : '';
                        var result = overload.apply(this, arguments);
                        if (uri.indexOf(targetAuthority) !== -1) {
                            send({
                                type: 'content_provider',
                                op: 'delete',
                                uri: uri,
                                rows_affected: result,
                                timestamp: Date.now()
                            });
                        }
                        return result;
                    };
                });

                send({type: 'info', message: 'content_provider hooks installed for authority: ' + targetAuthority});
            } catch(e) {
                send({type: 'error', message: 'content_provider hook failed: ' + e.message});
            }
        });
    } else {
        send({type: 'error', message: 'Java/ART runtime not available (not Android)'});
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def android_intent_intercept(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Intercept Android Intent dispatching: startActivity, sendBroadcast, startService.

    Hooks Activity.startActivity, ContextWrapper.sendBroadcast, and
    ContextWrapper.startService. Logs the Intent action, extras bundle
    keys, component name, categories, and data URI.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';

    if (Java && Java.available) {
        Java.perform(function() {
            try {
                function extractIntent(intent) {
                    if (!intent) return {action: null};
                    var info = {};
                    try { info.action = intent.getAction(); } catch(e) {}
                    try {
                        var comp = intent.getComponent();
                        if (comp) info.component = comp.toString();
                    } catch(e) {}
                    try {
                        var data = intent.getData();
                        if (data) info.data_uri = data.toString();
                    } catch(e) {}
                    try {
                        var cats = intent.getCategories();
                        if (cats) {
                            var arr = [];
                            var iter = cats.iterator();
                            while (iter.hasNext()) arr.push(iter.next().toString());
                            info.categories = arr;
                        }
                    } catch(e) {}
                    try {
                        var extras = intent.getExtras();
                        if (extras) {
                            var keys = extras.keySet();
                            var keyArr = [];
                            var iter2 = keys.iterator();
                            while (iter2.hasNext()) keyArr.push(iter2.next().toString());
                            info.extra_keys = keyArr;
                        }
                    } catch(e) {}
                    return info;
                }

                // Hook startActivity
                var Activity = Java.use('android.app.Activity');
                Activity.startActivity.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var intentInfo = extractIntent(arguments[0]);
                        send({
                            type: 'intent',
                            dispatch: 'startActivity',
                            intent: intentInfo,
                            timestamp: Date.now()
                        });
                        return overload.apply(this, arguments);
                    };
                });

                // Hook sendBroadcast
                var ContextWrapper = Java.use('android.content.ContextWrapper');
                ContextWrapper.sendBroadcast.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var intentInfo = extractIntent(arguments[0]);
                        send({
                            type: 'intent',
                            dispatch: 'sendBroadcast',
                            intent: intentInfo,
                            timestamp: Date.now()
                        });
                        return overload.apply(this, arguments);
                    };
                });

                // Hook startService
                ContextWrapper.startService.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var intentInfo = extractIntent(arguments[0]);
                        send({
                            type: 'intent',
                            dispatch: 'startService',
                            intent: intentInfo,
                            timestamp: Date.now()
                        });
                        return overload.apply(this, arguments);
                    };
                });

                send({type: 'info', message: 'intent intercept hooks installed (startActivity, sendBroadcast, startService)'});
            } catch(e) {
                send({type: 'error', message: 'intent intercept failed: ' + e.message});
            }
        });
    } else {
        send({type: 'error', message: 'Java/ART runtime not available (not Android)'});
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def android_shared_prefs_dump(
    target: str,
    pref_name: str | None = None,
) -> dict[str, Any]:
    """Dump SharedPreferences key-value pairs from an Android process.

    Reads SharedPreferences via Context.getSharedPreferences(). If
    `pref_name` is given, reads that specific preferences file. Otherwise
    attempts to discover and read common preference file names.

    `target`: process name or pid (string).
    `pref_name`: optional SharedPreferences file name (without .xml).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    safe_pref = json.dumps(pref_name) if pref_name else "null"
    js = r"""
    'use strict';

    if (Java && Java.available) {
        Java.perform(function() {
            try {
                var ActivityThread = Java.use('android.app.ActivityThread');
                var app = ActivityThread.currentApplication();
                if (!app) {
                    send({type: 'error', message: 'could not get application context'});
                    return;
                }
                var ctx = app.getApplicationContext();
                var prefName = """ + safe_pref + r""";
                var results = [];

                function dumpPrefs(name) {
                    try {
                        var MODE_PRIVATE = 0;
                        var prefs = ctx.getSharedPreferences(name, MODE_PRIVATE);
                        var allEntries = prefs.getAll();
                        var keys = allEntries.keySet().iterator();
                        var entries = {};
                        var count = 0;
                        while (keys.hasNext() && count < 500) {
                            var key = keys.next().toString();
                            try {
                                var val = allEntries.get(key);
                                entries[key] = val !== null ? val.toString() : null;
                            } catch(e) {
                                entries[key] = '<error>';
                            }
                            count++;
                        }
                        return {name: name, entries: entries, count: count};
                    } catch(e) {
                        return {name: name, error: e.message};
                    }
                }

                if (prefName) {
                    results.push(dumpPrefs(prefName));
                } else {
                    // Discover common pref names
                    var pkgName = ctx.getPackageName();
                    var commonNames = [
                        pkgName + '_preferences',
                        'default_preferences',
                        'app_preferences',
                        'settings',
                        'config',
                        pkgName
                    ];
                    // Also try to list files in shared_prefs directory
                    try {
                        var File = Java.use('java.io.File');
                        var prefsDir = new File(ctx.getApplicationInfo().dataDir.value + '/shared_prefs');
                        if (prefsDir.exists()) {
                            var files = prefsDir.listFiles();
                            if (files) {
                                for (var i = 0; i < files.length && i < 20; i++) {
                                    var fname = files[i].getName();
                                    if (fname.endsWith('.xml')) {
                                        var pName = fname.replace('.xml', '');
                                        if (commonNames.indexOf(pName) === -1) {
                                            commonNames.push(pName);
                                        }
                                    }
                                }
                            }
                        }
                    } catch(e) {}

                    commonNames.forEach(function(n) {
                        var r = dumpPrefs(n);
                        if (!r.error && r.count > 0) results.push(r);
                    });
                }

                send({
                    type: 'shared_prefs',
                    prefs: results,
                    total_files: results.length,
                    timestamp: Date.now()
                });
            } catch(e) {
                send({type: 'error', message: 'shared_prefs_dump failed: ' + e.message});
            }
        });
    } else {
        send({type: 'error', message: 'Java/ART runtime not available (not Android)'});
    }
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def android_webview_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook Android WebView methods to capture JS bridge interactions.

    Hooks WebView.addJavascriptInterface, WebView.evaluateJavascript,
    and WebView.loadUrl. Captures JavaScript interface registrations,
    evaluated JS code, and loaded URLs.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';

    if (Java && Java.available) {
        Java.perform(function() {
            try {
                var WebView = Java.use('android.webkit.WebView');
                var hooked = [];

                // Hook addJavascriptInterface
                try {
                    WebView.addJavascriptInterface.implementation = function(obj, name) {
                        send({
                            type: 'webview',
                            method: 'addJavascriptInterface',
                            interface_name: name,
                            object_class: obj ? obj.getClass().getName() : null,
                            timestamp: Date.now()
                        });
                        return this.addJavascriptInterface(obj, name);
                    };
                    hooked.push('addJavascriptInterface');
                } catch(e) {}

                // Hook evaluateJavascript
                try {
                    WebView.evaluateJavascript.implementation = function(script, callback) {
                        send({
                            type: 'webview',
                            method: 'evaluateJavascript',
                            script: script ? script.toString().substring(0, 2000) : null,
                            has_callback: callback !== null,
                            timestamp: Date.now()
                        });
                        return this.evaluateJavascript(script, callback);
                    };
                    hooked.push('evaluateJavascript');
                } catch(e) {}

                // Hook loadUrl (all overloads)
                WebView.loadUrl.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var url = arguments[0] ? arguments[0].toString() : null;
                        send({
                            type: 'webview',
                            method: 'loadUrl',
                            url: url,
                            timestamp: Date.now()
                        });
                        return overload.apply(this, arguments);
                    };
                    hooked.push('loadUrl');
                });

                send({type: 'info', message: 'webview hooks installed: ' + hooked.join(', ')});
            } catch(e) {
                send({type: 'error', message: 'webview hook failed: ' + e.message});
            }
        });
    } else {
        send({type: 'error', message: 'Java/ART runtime not available (not Android)'});
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")

def android_jni_hook(
    target: str,
    function_name: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook JNI functions in an Android target process.

    Hooks specified JNI function (RegisterNatives, FindClass,
    GetMethodID, CallObjectMethod, NewStringUTF, GetStringUTFChars, etc.)
    via libart.so exports. Captures call arguments and return values.

    `target`: process name or pid (string).
    `function_name`: JNI function to hook (e.g. 'RegisterNatives',
      'FindClass', 'GetMethodID', 'CallObjectMethod', 'NewStringUTF').
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    safe_fn = json.dumps(function_name)
    js = r"""
    'use strict';
    var fnName = """ + safe_fn + r""";
    var hooked = false;

    // Map of JNI function names to their hooking logic
    var jniHooks = {
        'RegisterNatives': function(addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    var className = '<unknown>';
                    // args[1] = jclass, args[2] = methods array, args[3] = nMethods
                    var nMethods = args[3].toInt32();
                    send({
                        type: 'jni_call',
                        function: 'RegisterNatives',
                        jclass: args[1].toString(),
                        n_methods: nMethods,
                        timestamp: Date.now()
                    });
                }
            });
        },
        'FindClass': function(addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    try { this._name = args[1].readUtf8String(); } catch(e) { this._name = '<unreadable>'; }
                },
                onLeave: function(retval) {
                    send({
                        type: 'jni_call',
                        function: 'FindClass',
                        class_name: this._name,
                        result: retval.toString(),
                        timestamp: Date.now()
                    });
                }
            });
        },
        'GetMethodID': function(addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    try { this._name = args[2].readUtf8String(); } catch(e) { this._name = '<?>'; }
                    try { this._sig = args[3].readUtf8String(); } catch(e) { this._sig = '<?>'; }
                },
                onLeave: function(retval) {
                    send({
                        type: 'jni_call',
                        function: 'GetMethodID',
                        method_name: this._name,
                        signature: this._sig,
                        result: retval.toString(),
                        timestamp: Date.now()
                    });
                }
            });
        },
        'GetStaticMethodID': function(addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    try { this._name = args[2].readUtf8String(); } catch(e) { this._name = '<?>'; }
                    try { this._sig = args[3].readUtf8String(); } catch(e) { this._sig = '<?>'; }
                },
                onLeave: function(retval) {
                    send({
                        type: 'jni_call',
                        function: 'GetStaticMethodID',
                        method_name: this._name,
                        signature: this._sig,
                        result: retval.toString(),
                        timestamp: Date.now()
                    });
                }
            });
        },
        'NewStringUTF': function(addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    try { this._str = args[1].readUtf8String(); } catch(e) { this._str = '<?>'; }
                },
                onLeave: function(retval) {
                    send({
                        type: 'jni_call',
                        function: 'NewStringUTF',
                        string: this._str,
                        timestamp: Date.now()
                    });
                }
            });
        },
        'GetStringUTFChars': function(addr) {
            Interceptor.attach(addr, {
                onLeave: function(retval) {
                    var str = '<unreadable>';
                    try { str = retval.readUtf8String(); } catch(e) {}
                    send({
                        type: 'jni_call',
                        function: 'GetStringUTFChars',
                        string: str ? str.substring(0, 2000) : null,
                        timestamp: Date.now()
                    });
                }
            });
        },
        'CallObjectMethod': function(addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this._obj = args[1].toString();
                    this._methodId = args[2].toString();
                },
                onLeave: function(retval) {
                    send({
                        type: 'jni_call',
                        function: 'CallObjectMethod',
                        object: this._obj,
                        method_id: this._methodId,
                        result: retval.toString(),
                        timestamp: Date.now()
                    });
                }
            });
        }
    };

    // Default hook for unknown JNI functions
    function defaultHook(addr, name) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var callArgs = [];
                for (var i = 0; i < 4; i++) {
                    try { callArgs.push(args[i].toString()); } catch(e) { break; }
                }
                send({
                    type: 'jni_call',
                    function: name,
                    args: callArgs,
                    timestamp: Date.now()
                });
            }
        });
    }

    // Search in libart.so and linker libraries
    var artLibs = ['libart.so', 'libart-compiler.so', 'libandroid_runtime.so'];
    var addr = null;

    for (var i = 0; i < artLibs.length; i++) {
        try {
            addr = _fm_find_export(artLibs[i], fnName);
            if (addr) break;
        } catch(e) {}
    }
    if (!addr) {
        try { addr = _fm_find_export(null, fnName); } catch(e) {}
    }

    if (addr) {
        try {
            if (jniHooks[fnName]) {
                jniHooks[fnName](addr);
            } else {
                defaultHook(addr, fnName);
            }
            hooked = true;
            send({type: 'info', message: 'JNI hook installed: ' + fnName + ' @ ' + addr});
        } catch(e) {
            send({type: 'error', message: 'JNI hook attach failed: ' + e.message});
        }
    } else {
        // Try to find via _ZN3art prefix (mangled C++ symbols in ART)
        var artMod = Process.findModuleByName('libart.so');
        if (artMod) {
            var exports = artMod.enumerateExports();
            for (var j = 0; j < exports.length; j++) {
                if (exports[j].name.indexOf(fnName) !== -1) {
                    try {
                        defaultHook(exports[j].address, exports[j].name);
                        hooked = true;
                        send({type: 'info', message: 'JNI hook installed (mangled): ' + exports[j].name});
                        break;
                    } catch(e) {}
                }
            }
        }
        if (!hooked) {
            send({type: 'error', message: 'JNI function not found: ' + fnName + ' (not Android or libart not loaded)'});
        }
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")
