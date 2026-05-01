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



def java_enumerate_class_loaders(target: str, duration_seconds: int = 5) -> dict[str, Any]:
    """Call Java.enumerateClassLoaders()."""
    js = """
    'use strict';
    Java.perform(function () {
      const loaders = [];
      Java.enumerateClassLoaders({
        onMatch: function (loader) { loaders.push(loader.toString()); },
        onComplete: function () { send({ type: 'java_class_loaders', count: loaders.length, loaders: loaders.slice(0, 1000) }); }
      });
    });
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=max(1, duration_seconds), mode="attach")


def java_choose(target: str, class_name: str, limit: int = 100, duration_seconds: int = 5) -> dict[str, Any]:
    """Call Java.choose()."""
    js = f"""
    'use strict';
    Java.perform(function () {{
      const items = [];
      Java.choose({json.dumps(class_name)}, {{
        onMatch: function (instance) {{
          if (items.length < {max(1, limit)}) items.push(instance.toString());
        }},
        onComplete: function () {{ send({{ type: 'java_choose', class_name: {json.dumps(class_name)}, count: items.length, items: items }}); }}
      }});
    }});
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=max(1, duration_seconds), mode="attach")


def java_backtrace(target: str, duration_seconds: int = 3) -> dict[str, Any]:
    """Capture a Java.backtrace() from Java.perform()."""
    js = """
    'use strict';
    Java.perform(function () {
      const trace = Java.backtrace({ limit: 64 });
      send({ type: 'java_backtrace', id: trace.id, frames: trace.frames });
    });
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=max(1, duration_seconds), mode="attach")


def java_deoptimize(target: str, mode: str = "everything") -> dict[str, Any]:
    """Call Java.deoptimizeEverything() or Java.deoptimizeBootImage()."""
    if mode not in {"everything", "boot-image"}:
        return {"error": "mode must be 'everything' or 'boot-image'"}
    call = "Java.deoptimizeEverything()" if mode == "everything" else "Java.deoptimizeBootImage()"
    js = f"""
    'use strict';
    Java.perform(function () {{
      {call};
      send({{ type: 'java_deoptimize', mode: {json.dumps(mode)}, ok: true }});
    }});
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")


def objc_implement_template(class_name: str, selector: str, return_type: str = "void", arg_types: list[str] | None = None) -> dict[str, Any]:
    """Return an ObjC.implement() replacement template."""
    arg_types = arg_types or ["pointer", "pointer"]
    return {
        "class_name": class_name,
        "selector": selector,
        "js_code": (
            f"const cls = ObjC.classes[{json.dumps(class_name)}];\n"
            f"const method = cls[{json.dumps(selector)}];\n"
            "const original = method.implementation;\n"
            "method.implementation = ObjC.implement(method, function () {\n"
            "  send({ type: 'objc-implement-hit', selector: " + json.dumps(selector) + " });\n"
            f"  const fn = new NativeFunction(original, {json.dumps(return_type)}, {json.dumps(arg_types)});\n"
            "  return fn.apply(null, arguments);\n"
            "});\n"
        ),
    }


def objc_bind_data(target: str, object_address: str, data: dict[str, Any]) -> dict[str, Any]:
    """Call ObjC.bind() and ObjC.getBoundData() for an object."""
    js = f"""
    'use strict';
    try {{
      if (!ObjC.available) throw new Error('ObjC runtime not available');
      const object = new ObjC.Object(ptr({json.dumps(object_address)}));
      const data = {json.dumps(data)};
      ObjC.bind(object, data);
      send({{ type: 'objc_bind_data', object: object.toString(), data: ObjC.getBoundData(object) }});
    }} catch (e) {{
      send({{ type: 'error', message: e.message }});
    }}
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    return _run_script(frida, target, js, duration_seconds=1, mode="attach")
