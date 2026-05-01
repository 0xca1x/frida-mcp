"""fuzzmind-frida-mcp -- objc tools."""
from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any
import json
import re

from .._core import INSTALL_HINT, _load_frida, _run_script


def objc_classes(target: str, name_pattern: str = "*") -> dict[str, Any]:
    """Enumerate ObjC classes in a target process matching `name_pattern`."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    pattern_js = json.dumps(re.escape(name_pattern).replace("\\*", ".*"))
    js = f"""
    'use strict';
    if (ObjC.available) {{
        const matches = ObjC.classes;
        const names = Object.keys(matches);
        const filtered = names.filter(n => n.match(new RegExp({pattern_js}, 'i')));
        send({{type: 'classes', items: filtered.slice(0, 1000), total: filtered.length}});
    }} else {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def objc_choose(
    target: str,
    class_name: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Find live ObjC instances of a class on the heap.

    Uses ObjC.chooseSync() to locate instances. Returns addresses and
    short descriptions.

    `target`: process name or pid (string).
    `class_name`: exact ObjC class name (e.g. 'NSMutableArray').
    `limit`: max instances to return (default 100).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    class_name_js = json.dumps(class_name)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        var cls = ObjC.classes[{class_name_js}];
        if (!cls) {{
            send({{type: 'error', message: 'class not found: ' + {class_name_js}}});
        }} else {{
            var instances = ObjC.chooseSync(cls);
            var items = instances.slice(0, {limit}).map(function(obj) {{
                var desc = '<no description>';
                try {{ desc = obj.toString().substring(0, 300); }} catch(e) {{}}
                return {{
                    address: obj.handle.toString(),
                    className: obj.$className,
                    description: desc
                }};
            }});
            send({{
                type: 'objc_choose',
                class_name: {class_name_js},
                items: items,
                count: instances.length,
                truncated: instances.length > {limit}
            }});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def objc_register_class(
    target: str,
    name: str,
    super_class: str,
    methods_js: str,
) -> dict[str, Any]:
    """Register a new ObjC class at runtime via ObjC.registerClass.

    `target`: process name or pid (string).
    `name`: class name for the new class.
    `super_class`: name of the superclass (e.g. 'NSObject').
    `methods_js`: JS object literal for methods, e.g.
      '{ "- description": function() { return ObjC.classes.NSString.stringWithString_("my class"); } }'
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    name_js = json.dumps(name)
    super_class_js = json.dumps(super_class)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        try {{
            var sup = ObjC.classes[{super_class_js}];
            if (!sup) {{
                send({{type: 'error', message: 'superclass not found: ' + {super_class_js}}});
            }} else {{
                var methods = {methods_js};
                var Cls = ObjC.registerClass({{
                    name: {name_js},
                    super: sup,
                    methods: methods
                }});
                send({{
                    type: 'objc_register_class',
                    name: {name_js},
                    super_class: {super_class_js},
                    handle: Cls.handle.toString(),
                    ok: true
                }});
            }}
        }} catch(e) {{
            send({{type: 'error', message: 'ObjC.registerClass failed: ' + e.message}});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def objc_create_block(
    target: str,
    return_type: str,
    arg_types: list[str],
    js_body: str,
) -> dict[str, Any]:
    """Create an ObjC block at runtime via new ObjC.Block.

    `target`: process name or pid (string).
    `return_type`: return type string (e.g. 'void', 'int', 'object').
    `arg_types`: list of argument type strings.
    `js_body`: JavaScript function body for the block implementation.
    Returns the handle (address) of the created block.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    return_type_js = json.dumps(return_type)
    types_js = json.dumps(arg_types)

    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        try {{
            var block = new ObjC.Block({{
                retType: {return_type_js},
                argTypes: {types_js},
                implementation: function() {{
                    {js_body}
                }}
            }});
            send({{
                type: 'objc_create_block',
                handle: block.handle.toString(),
                retType: {return_type_js},
                argTypes: {types_js},
                ok: true
            }});
        }} catch(e) {{
            send({{type: 'error', message: 'ObjC.Block creation failed: ' + e.message}});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def objc_schedule(target: str, js_code: str) -> dict[str, Any]:
    """Schedule JavaScript to run on the ObjC main thread dispatch queue.

    Uses ObjC.schedule(ObjC.mainQueue, ...) to execute code on the main
    thread. Useful for calling UIKit/AppKit APIs that must run on main.

    `target`: process name or pid (string).
    `js_code`: JavaScript code to execute on the main queue.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        try {{
            ObjC.schedule(ObjC.mainQueue, function() {{
                try {{
                    {js_code}
                    send({{type: 'objc_schedule', ok: true, message: 'executed on main queue'}});
                }} catch(innerE) {{
                    send({{type: 'error', message: 'scheduled code failed: ' + innerE.message}});
                }}
            }});
        }} catch(e) {{
            send({{type: 'error', message: 'ObjC.schedule failed: ' + e.message}});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def objc_inspect_object(target: str, address: str) -> dict[str, Any]:
    """Inspect an ObjC object at a given address.

    Wraps the address with ObjC.Object and extracts class name, methods,
    and instance variable names.

    `target`: process name or pid (string).
    `address`: hex address of the ObjC object (e.g. '0x600000c00180').
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        try {{
            var obj = new ObjC.Object(ptr({address_js}));
            var methods = [];
            try {{ methods = obj.$methods.slice(0, 200); }} catch(e) {{}}
            var ownMethods = [];
            try {{ ownMethods = obj.$ownMethods.slice(0, 200); }} catch(e) {{}}
            var ivars = {{}};
            try {{
                var ivarNames = Object.keys(obj.$ivars);
                ivarNames.slice(0, 50).forEach(function(name) {{
                    try {{
                        var val = obj.$ivars[name];
                        ivars[name] = val !== null && val !== undefined ? val.toString().substring(0, 200) : null;
                    }} catch(e) {{
                        ivars[name] = '<error: ' + e.message + '>';
                    }}
                }});
            }} catch(e) {{}}
            var desc = '<no description>';
            try {{ desc = obj.toString().substring(0, 500); }} catch(e) {{}}
            send({{
                type: 'objc_inspect',
                address: {address_js},
                className: obj.$className,
                superClass: obj.$superClass ? obj.$superClass.$className : null,
                description: desc,
                ownMethods: ownMethods,
                methods: methods,
                methods_truncated: obj.$methods.length > 200,
                ivars: ivars
            }});
        }} catch(e) {{
            send({{type: 'error', message: 'ObjC.Object inspect failed: ' + e.message}});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def objc_call_method(
    target: str,
    address: str,
    selector: str,
    args_json: str | None = None,
) -> dict[str, Any]:
    """Call an ObjC method on an object at a given address.

    Constructs an ObjC.Object wrapper and invokes the specified selector.

    `target`: process name or pid (string).
    `address`: hex address of the ObjC object.
    `selector`: ObjC selector name (e.g. 'description', 'count',
      'objectForKey_'). Use underscores for colons in multi-arg selectors.
    `args_json`: optional JSON array of arguments (strings, numbers).
      Use ObjC.classes.NSString.stringWithString_("...") syntax for
      ObjC objects in the JS evaluation context.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    if args_json:
        try:
            args = json.loads(args_json)
        except json.JSONDecodeError as e:
            return {"error": f"invalid args_json: {e}"}
        if not isinstance(args, list):
            return {"error": "invalid args_json: expected a JSON array"}
        args_js = json.dumps(args)
    else:
        args_js = "[]"

    address_js = json.dumps(address)
    selector_js = json.dumps(selector)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        try {{
            var obj = new ObjC.Object(ptr({address_js}));
            var args = {args_js};
            var selector = {selector_js};
            var result;
            if (args.length === 0) {{
                result = obj[selector]();
            }} else if (args.length === 1) {{
                result = obj[selector](args[0]);
            }} else if (args.length === 2) {{
                result = obj[selector](args[0], args[1]);
            }} else if (args.length === 3) {{
                result = obj[selector](args[0], args[1], args[2]);
            }} else {{
                result = obj[selector].apply(obj, args);
            }}
            var resultStr = '<void>';
            try {{
                if (result !== undefined && result !== null) {{
                    resultStr = result.toString().substring(0, 2000);
                }}
            }} catch(e) {{ resultStr = '<toString failed>'; }}
            send({{
                type: 'objc_call_method',
                address: {address_js},
                className: obj.$className,
                selector: selector,
                result: resultStr,
                ok: true
            }});
        }} catch(e) {{
            send({{type: 'error', message: 'ObjC method call failed: ' + e.message}});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def objc_list_protocols(target: str) -> dict[str, Any]:
    """List all registered ObjC protocols in a target process.

    `target`: process name or pid (string).
    Returns protocol names.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    js = """
    'use strict';
    if (!ObjC.available) {
        send({type: 'error', message: 'ObjC runtime not available'});
    } else {
        var names = Object.keys(ObjC.protocols);
        send({
            type: 'objc_protocols',
            items: names.sort(),
            count: names.length
        });
    }
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def dump_class(target: str, class_name: str) -> dict[str, Any]:
    """Dump full class structure: methods, properties, ivars.

    `target`: process name or pid (string).
    `class_name`: exact ObjC class name.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    class_name_js = json.dumps(class_name)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        var cls = ObjC.classes[{class_name_js}];
        if (!cls) {{
            send({{type: 'error', message: 'class not found: ' + {class_name_js}}});
        }} else {{
            var methods = cls.$ownMethods || [];
            var protocols = [];
            try {{ protocols = cls.$protocols ? Object.keys(cls.$protocols) : []; }} catch(e) {{}}
            var ivars = [];
            try {{
                if (cls.$ivars) {{
                    ivars = Object.keys(cls.$ivars);
                }}
            }} catch(e) {{}}
            var superClass = null;
            try {{ superClass = cls.$superClass ? cls.$superClass.$className : null; }} catch(e) {{}}

            send({{
                type: 'class_dump',
                class_name: {class_name_js},
                super_class: superClass,
                methods: methods.slice(0, 500),
                method_count: methods.length,
                methods_truncated: methods.length > 500,
                protocols: protocols,
                ivars: ivars
            }});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def xpc_intercept(
    target: str,
    duration_seconds: int = 30,
    output_file: str | None = None,
) -> dict[str, Any]:
    """xpcspy-style XPC message capture using the bundled JS script."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    # Load bundled script
    js_path = resources.files("fuzzmind_frida_mcp.scripts") / "xpc_intercept.js"
    js = js_path.read_text()

    result = _run_script(frida, target, js, duration_seconds, "attach")

    if output_file and "events" in result:
        Path(output_file).write_text(json.dumps(result["events"], indent=2))
        result["log_path"] = output_file

    return result
