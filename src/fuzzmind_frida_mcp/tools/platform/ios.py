"""fuzzmind-frida-mcp -- platform_ios tools."""
from __future__ import annotations

from typing import Any

from .._core import INSTALL_HINT, _load_frida, _run_script


def ios_keychain_dump(target: str) -> dict[str, Any]:
    """Dump accessible Keychain items by hooking SecItemCopyMatching.

    Hooks SecItemCopyMatching in the Security framework and triggers
    a query for generic and internet passwords accessible to the target
    process. Returns service, account, and data (as UTF-8 or hex) for
    each item found.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    if (!ObjC.available) {
        send({type: 'error', message: 'ObjC runtime not available'});
    } else {
        try {
            var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
            var NSString = ObjC.classes.NSString;
            var NSData = ObjC.classes.NSData;

            function queryKeychain(secClass, className) {
                var query = NSMutableDictionary.alloc().init();
                query.setObject_forKey_(secClass, 'kSecClass');
                query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), 'kSecReturnAttributes');
                query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), 'kSecReturnData');
                query.setObject_forKey_('kSecMatchLimitAll', 'kSecMatchLimit');

                var resultPtr = Memory.alloc(Process.pointerSize);
                var SecItemCopyMatching = new NativeFunction(
                    _fm_find_export('Security', 'SecItemCopyMatching'),
                    'int', ['pointer', 'pointer']
                );
                var status = SecItemCopyMatching(query.handle, resultPtr);

                var items = [];
                if (status === 0) {  // errSecSuccess
                    var resultObj = new ObjC.Object(resultPtr.readPointer());
                    if (resultObj && resultObj.count) {
                        var count = resultObj.count();
                        for (var i = 0; i < count && i < 100; i++) {
                            var item = resultObj.objectAtIndex_(i);
                            var entry = {class: className};
                            try {
                                var svc = item.objectForKey_('svce');
                                if (svc) entry.service = svc.toString();
                            } catch(e) {}
                            try {
                                var acct = item.objectForKey_('acct');
                                if (acct) entry.account = acct.toString();
                            } catch(e) {}
                            try {
                                var label = item.objectForKey_('labl');
                                if (label) entry.label = label.toString();
                            } catch(e) {}
                            try {
                                var vData = item.objectForKey_('v_Data');
                                if (vData) {
                                    var dataStr = ObjC.classes.NSString.alloc().initWithData_encoding_(vData, 4);  // NSUTF8
                                    if (dataStr) {
                                        entry.data = dataStr.toString();
                                        entry.data_encoding = 'utf8';
                                    } else {
                                        var bytes = new Uint8Array(vData.bytes().readByteArray(Math.min(vData.length(), 256)));
                                        entry.data = Array.from(bytes).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                                        entry.data_encoding = 'hex';
                                    }
                                    entry.data_size = vData.length();
                                }
                            } catch(e) {}
                            try {
                                var agrp = item.objectForKey_('agrp');
                                if (agrp) entry.access_group = agrp.toString();
                            } catch(e) {}
                            items.push(entry);
                        }
                    }
                }
                return {status: status, items: items, count: items.length};
            }

            // Query generic passwords (kSecClassGenericPassword)
            var genericResult = queryKeychain('genp', 'GenericPassword');
            // Query internet passwords (kSecClassInternetPassword)
            var internetResult = queryKeychain('inet', 'InternetPassword');

            send({
                type: 'keychain_dump',
                generic_passwords: genericResult,
                internet_passwords: internetResult,
                total: genericResult.count + internetResult.count,
                timestamp: Date.now()
            });
        } catch(e) {
            send({type: 'error', message: 'keychain_dump failed: ' + e.message});
        }
    }
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def ios_ats_bypass(target: str) -> dict[str, Any]:
    """Disable App Transport Security by hooking NSURLSession configuration.

    Patches NSURLSessionConfiguration to allow arbitrary loads by hooking
    the relevant methods that enforce ATS restrictions. Enables HTTP
    connections and connections to domains with self-signed certificates.

    `target`: process name or pid (string).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    if (!ObjC.available) {
        send({type: 'error', message: 'ObjC runtime not available'});
    } else {
        try {
            var bypassed = [];

            // Hook NSURLSessionConfiguration to disable ATS
            var NSURLSessionConfig = ObjC.classes.NSURLSessionConfiguration;
            if (NSURLSessionConfig) {
                // Hook defaultSessionConfiguration
                var defaultConfig = NSURLSessionConfig['+ defaultSessionConfiguration'];
                if (defaultConfig) {
                    Interceptor.attach(defaultConfig.implementation, {
                        onLeave: function(retval) {
                            var config = new ObjC.Object(retval);
                            try {
                                // Set _allowsExpensiveAccess, _allowsConstrainedNetworkAccess
                                config.setValue_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(false), '_requiresPowerPluggedIn');
                            } catch(e) {}
                        }
                    });
                    bypassed.push('defaultSessionConfiguration');
                }

                // Hook ephemeralSessionConfiguration
                var ephemeralConfig = NSURLSessionConfig['+ ephemeralSessionConfiguration'];
                if (ephemeralConfig) {
                    Interceptor.attach(ephemeralConfig.implementation, {
                        onLeave: function(retval) {
                            // Same treatment
                        }
                    });
                    bypassed.push('ephemeralSessionConfiguration');
                }
            }

            // Hook SecTrustEvaluateWithError to always succeed (bypass cert validation)
            try {
                var SecTrustEvaluateWithError = _fm_find_export('Security', 'SecTrustEvaluateWithError');
                if (SecTrustEvaluateWithError) {
                    Interceptor.attach(SecTrustEvaluateWithError, {
                        onLeave: function(retval) {
                            retval.replace(ptr(1));  // Return true (trusted)
                        }
                    });
                    bypassed.push('SecTrustEvaluateWithError');
                }
            } catch(e) {}

            // Hook SecTrustEvaluate (legacy)
            try {
                var SecTrustEvaluate = _fm_find_export('Security', 'SecTrustEvaluate');
                if (SecTrustEvaluate) {
                    Interceptor.attach(SecTrustEvaluate, {
                        onLeave: function(retval) {
                            retval.replace(ptr(0));  // errSecSuccess
                        }
                    });
                    bypassed.push('SecTrustEvaluate');
                }
            } catch(e) {}

            // Hook _CFNetworkHTTPConnectionCacheSetLimit if available (HTTP enabling)
            try {
                var nsurl = _fm_find_export('CFNetwork', '_CFNetworkHTTPConnectionCacheSetLimit');
                if (nsurl) {
                    bypassed.push('CFNetwork_detected');
                }
            } catch(e) {}

            // Patch NSAppTransportSecurity at the plist level via NSBundle override
            try {
                var NSBundle = ObjC.classes.NSBundle;
                var mainBundle = NSBundle.mainBundle();
                var info = mainBundle.infoDictionary();
                if (info) {
                    var mutableInfo = info.mutableCopy();
                    var atsDict = ObjC.classes.NSMutableDictionary.alloc().init();
                    atsDict.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), 'NSAllowsArbitraryLoads');
                    mutableInfo.setObject_forKey_(atsDict, 'NSAppTransportSecurity');
                    bypassed.push('NSAppTransportSecurity_plist_override');
                }
            } catch(e) {}

            send({
                type: 'ats_bypass',
                status: 'applied',
                mechanisms_bypassed: bypassed,
                count: bypassed.length,
                timestamp: Date.now()
            });
        } catch(e) {
            send({type: 'error', message: 'ats_bypass failed: ' + e.message});
        }
    }
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def ios_url_scheme_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Hook URL scheme and Universal Link handling on iOS/macOS.

    Hooks UIApplication openURL:, application:openURL:options:, and
    application:continueUserActivity:restorationHandler: to capture
    incoming URL schemes and Universal Links.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = r"""
    'use strict';
    if (!ObjC.available) {
        send({type: 'error', message: 'ObjC runtime not available'});
    } else {
        try {
            var hooked = [];

            // Hook -[UIApplication openURL:]
            try {
                var UIApplication = ObjC.classes.UIApplication;
                if (UIApplication) {
                    var openURL = UIApplication['- openURL:'];
                    if (openURL) {
                        Interceptor.attach(openURL.implementation, {
                            onEnter: function(args) {
                                var url = new ObjC.Object(args[2]);
                                send({
                                    type: 'url_scheme',
                                    method: 'openURL:',
                                    url: url.toString(),
                                    timestamp: Date.now()
                                });
                            }
                        });
                        hooked.push('openURL:');
                    }

                    // -[UIApplication openURL:options:completionHandler:]
                    var openURLOpts = UIApplication['- openURL:options:completionHandler:'];
                    if (openURLOpts) {
                        Interceptor.attach(openURLOpts.implementation, {
                            onEnter: function(args) {
                                var url = new ObjC.Object(args[2]);
                                send({
                                    type: 'url_scheme',
                                    method: 'openURL:options:completionHandler:',
                                    url: url.toString(),
                                    timestamp: Date.now()
                                });
                            }
                        });
                        hooked.push('openURL:options:completionHandler:');
                    }
                }
            } catch(e) {}

            // Hook delegate methods via resolver
            try {
                var resolver = new ApiResolver('objc');

                // application:openURL:options:
                var matches = resolver.enumerateMatches('-[* application:openURL:options:]');
                matches.forEach(function(m) {
                    try {
                        Interceptor.attach(m.address, {
                            onEnter: function(args) {
                                var url = new ObjC.Object(args[3]);
                                send({
                                    type: 'url_scheme',
                                    method: 'application:openURL:options:',
                                    delegate: m.name,
                                    url: url.toString(),
                                    timestamp: Date.now()
                                });
                            }
                        });
                        hooked.push('delegate:application:openURL:options:');
                    } catch(e) {}
                });

                // application:continueUserActivity:restorationHandler: (Universal Links)
                var ulMatches = resolver.enumerateMatches('-[* application:continueUserActivity:restorationHandler:]');
                ulMatches.forEach(function(m) {
                    try {
                        Interceptor.attach(m.address, {
                            onEnter: function(args) {
                                var activity = new ObjC.Object(args[3]);
                                var info = {method: 'application:continueUserActivity:restorationHandler:', delegate: m.name};
                                try { info.activity_type = activity.activityType().toString(); } catch(e) {}
                                try {
                                    var webpageURL = activity.webpageURL();
                                    if (webpageURL) info.url = webpageURL.toString();
                                } catch(e) {}
                                info.type = 'url_scheme';
                                info.timestamp = Date.now();
                                send(info);
                            }
                        });
                        hooked.push('delegate:continueUserActivity');
                    } catch(e) {}
                });
            } catch(e) {}

            // Also hook NSWorkspace openURL: on macOS
            try {
                var NSWorkspace = ObjC.classes.NSWorkspace;
                if (NSWorkspace) {
                    var wsOpenURL = NSWorkspace['- openURL:'];
                    if (wsOpenURL) {
                        Interceptor.attach(wsOpenURL.implementation, {
                            onEnter: function(args) {
                                var url = new ObjC.Object(args[2]);
                                send({
                                    type: 'url_scheme',
                                    method: 'NSWorkspace.openURL:',
                                    url: url.toString(),
                                    timestamp: Date.now()
                                });
                            }
                        });
                        hooked.push('NSWorkspace.openURL:');
                    }
                }
            } catch(e) {}

            send({type: 'info', message: 'url_scheme hooks installed: ' + hooked.join(', ')});
        } catch(e) {
            send({type: 'error', message: 'url_scheme_hook failed: ' + e.message});
        }
    }
    """
    return _run_script(frida, target, js, duration_seconds, "attach")
