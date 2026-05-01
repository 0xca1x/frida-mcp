"""Java, ObjC, Swift, and runtime-focused MCP tools."""
from __future__ import annotations

from typing import Any

from fuzzmind_frida_mcp import tools as _f
from fuzzmind_frida_mcp.toolsets._helpers import register_module_tools


def frida_xpc_intercept(
    target: str,
    duration_seconds: int = 30,
    output_file: str | None = None,
) -> dict:
    """xpcspy-style XPC message capture using a bundled script.

    Hooks `xpc_connection_send_message` (+ reply variants) and renders each
    message via `xpc_copy_description`. Best-effort on the receive side.
    """
    return _f.xpc_intercept(
        target,
        duration_seconds=duration_seconds,
        output_file=output_file,
    )


def frida_objc_classes(target: str, name_pattern: str = "*") -> dict:
    """Enumerate ObjC class names in a target process matching `name_pattern`
    (glob-ish; `*` becomes `.*` for regex match).
    """
    return _f.objc_classes(target, name_pattern=name_pattern)


def frida_intercept_objc_method(
    target: str,
    class_name: str,
    method_name: str,
    duration_seconds: int = 10,
) -> dict:
    """Hook a specific ObjC method via Interceptor and log invocations.

    `class_name`: e.g. 'NSFileManager'.
    `method_name`: e.g. '- contentsOfDirectoryAtPath:error:'.
    Captures arguments (up to 6 beyond self/sel) on each call for
    `duration_seconds`.
    """
    return _f.intercept_objc_method(
        target,
        class_name=class_name,
        method_name=method_name,
        duration_seconds=duration_seconds,
    )


def frida_api_resolver(
    target: str,
    query: str,
    type: str = "objc",
) -> dict:
    """Resolve API symbols using Frida's ApiResolver.

    `target`: process name or pid (string).
    `query`: match pattern. ObjC: '-[NSURL *]', '+[NSData *]'.
      Module: 'exports:libsystem*!open*'.
    `type`: 'objc' or 'module'.
    """
    return _f.api_resolver(target, query=query, type=type)


def frida_swift_demangle(
    target: str,
    symbol: str,
) -> dict:
    """Demangle a Swift symbol using the in-process Swift runtime.

    `target`: process name or pid that has the Swift runtime loaded.
    `symbol`: mangled name (e.g. '$s4MyApp0A8DelegateC11applicationSo...').
    Calls `swift_demangle` from libswiftCore.dylib inside the target.
    """
    return _f.swift_demangle(target, symbol=symbol)


def frida_heap_search(target: str, class_name: str) -> dict:
    """Search the heap for live ObjC instances of a class.

    `target`: process name or pid (string).
    `class_name`: exact ObjC class name (e.g. 'NSMutableDictionary').
    Returns addresses and short descriptions of found instances.
    """
    return _f.heap_search(target, class_name=class_name)


def frida_dump_class(target: str, class_name: str) -> dict:
    """Dump full ObjC class structure: methods, protocols, ivars.

    `target`: process name or pid (string).
    `class_name`: exact ObjC class name. Returns own methods,
    superclass, protocols, and instance variables.
    """
    return _f.dump_class(target, class_name=class_name)


def frida_java_list_classes(
    target: str,
    filter: str | None = None,
    limit: int = 500,
    device_id: str | None = None,
) -> dict:
    """Enumerate loaded Java/ART classes in a target process.

    `target`: process name or pid (string).
    `filter`: optional case-insensitive substring to filter class names
    (e.g. 'crypto', 'javax.net').
    `limit`: max classes to return (default 500).
    Requires Java/ART runtime in the target (Android app or JVM process).
    """
    return _f.java_list_classes(target, filter=filter, limit=limit, device_id=device_id)


def frida_java_list_methods(
    target: str,
    class_name: str,
    device_id: str | None = None,
) -> dict:
    """List declared methods of a Java class.

    `target`: process name or pid (string).
    `class_name`: fully qualified Java class name
    (e.g. 'javax.crypto.Cipher', 'android.app.Activity').
    Returns method signatures as strings.
    """
    return _f.java_list_methods(target, class_name=class_name, device_id=device_id)


def frida_java_hook_method(
    target: str,
    class_name: str,
    method_name: str,
    duration_seconds: int = 10,
    device_id: str | None = None,
) -> dict:
    """Hook all overloads of a Java method and collect invocations.

    `target`: process name or pid (string).
    `class_name`: fully qualified Java class name.
    `method_name`: method name to hook.
    `duration_seconds`: how long to collect (default 10).

    Hooks every overload. Each call is captured as
    {class_name, method, args: [String], timestamp}.
    """
    return _f.java_hook_method(
        target,
        class_name=class_name,
        method_name=method_name,
        duration_seconds=duration_seconds,
        device_id=device_id,
    )


def frida_java_call(
    target: str,
    java_js_code: str,
    device_id: str | None = None,
) -> dict:
    """Execute arbitrary JS inside a Java.perform() block.

    `target`: process name or pid (string).
    `java_js_code`: JavaScript code auto-wrapped in
    `Java.perform(function() { <your code> })`.
    Use `Java.use()`, `Java.choose()`, `send()`, etc. directly.
    Returns collected send() messages.
    """
    return _f.java_call(target, java_js_code=java_js_code, device_id=device_id)


def frida_java_load_dex(
    target: str,
    dex_path: str,
    device_id: str | None = None,
) -> dict:
    """Dynamically load a DEX file into an Android process at runtime.

    Uses `Java.openClassFile().load()` to inject classes from the DEX.
    After loading, the new classes are available via `Java.use()`.

    `target`: process name or pid (string).
    `dex_path`: path to the .dex file on the target device filesystem.
    """
    return _f.java_load_dex(target, dex_path=dex_path, device_id=device_id)


def frida_objc_choose(
    target: str,
    class_name: str,
    limit: int = 100,
) -> dict:
    """Find live ObjC instances of a class on the heap via ObjC.chooseSync.

    `target`: process name or pid (string).
    `class_name`: exact ObjC class name (e.g. 'NSMutableArray').
    `limit`: max instances to return (default 100).
    """
    return _f.objc_choose(target, class_name=class_name, limit=limit)


def frida_objc_register_class(
    target: str,
    name: str,
    super_class: str,
    methods_js: str,
) -> dict:
    """Register a new ObjC class at runtime via ObjC.registerClass.

    `target`: process name or pid (string).
    `name`: class name for the new class.
    `super_class`: name of the superclass (e.g. 'NSObject').
    `methods_js`: JS object literal for methods.
    """
    return _f.objc_register_class(target, name=name, super_class=super_class, methods_js=methods_js)


def frida_objc_create_block(
    target: str,
    return_type: str,
    arg_types: list[str],
    js_body: str,
) -> dict:
    """Create an ObjC block at runtime via new ObjC.Block.

    `target`: process name or pid (string).
    `return_type`: return type (e.g. 'void', 'int', 'object').
    `arg_types`: list of argument type strings.
    `js_body`: JavaScript function body for the block implementation.
    Returns the block's handle address.
    """
    return _f.objc_create_block(target, return_type=return_type, arg_types=arg_types, js_body=js_body)


def frida_objc_schedule(target: str, js_code: str) -> dict:
    """Schedule JavaScript to run on the ObjC main thread dispatch queue.

    Uses ObjC.schedule(ObjC.mainQueue, ...) for UI/AppKit-safe execution.

    `target`: process name or pid (string).
    `js_code`: JavaScript code to execute on the main queue.
    """
    return _f.objc_schedule(target, js_code=js_code)


def frida_objc_inspect_object(target: str, address: str) -> dict:
    """Inspect an ObjC object at a given address.

    Wraps the pointer with ObjC.Object and extracts class name, methods,
    ivars, and description.

    `target`: process name or pid (string).
    `address`: hex address of the ObjC object.
    """
    return _f.objc_inspect_object(target, address=address)


def frida_objc_call_method(
    target: str,
    address: str,
    selector: str,
    args_json: str | None = None,
) -> dict:
    """Call an ObjC method on an object at a given address.

    `target`: process name or pid (string).
    `address`: hex address of the ObjC object.
    `selector`: ObjC selector (e.g. 'description', 'count',
      'objectForKey_'). Use underscores for colons.
    `args_json`: optional JSON array of arguments.
    """
    return _f.objc_call_method(target, address=address, selector=selector, args_json=args_json)


def frida_objc_list_protocols(target: str) -> dict:
    """List all registered ObjC protocols in a target process.

    `target`: process name or pid (string).
    Returns sorted protocol names.
    """
    return _f.objc_list_protocols(target)




def frida_java_enumerate_class_loaders(target: str, duration_seconds: int = 5) -> dict:
    """Call Java.enumerateClassLoaders()."""
    return _f.java_enumerate_class_loaders(target, duration_seconds=duration_seconds)


def frida_java_choose(target: str, class_name: str, limit: int = 100, duration_seconds: int = 5) -> dict:
    """Call Java.choose()."""
    return _f.java_choose(target, class_name=class_name, limit=limit, duration_seconds=duration_seconds)


def frida_java_backtrace(target: str, duration_seconds: int = 3) -> dict:
    """Capture Java.backtrace() inside Java.perform()."""
    return _f.java_backtrace(target, duration_seconds=duration_seconds)


def frida_java_deoptimize(target: str, mode: str = "everything") -> dict:
    """Call Java.deoptimizeEverything() or Java.deoptimizeBootImage()."""
    return _f.java_deoptimize(target, mode=mode)


def frida_objc_implement_template(
    class_name: str,
    selector: str,
    return_type: str = "void",
    arg_types: list[str] | None = None,
) -> dict:
    """Generate an ObjC.implement() method replacement template."""
    return _f.objc_implement_template(class_name, selector=selector, return_type=return_type, arg_types=arg_types)


def frida_objc_bind_data(target: str, object_address: str, data: dict[str, Any]) -> dict:
    """Call ObjC.bind() and ObjC.getBoundData()."""
    return _f.objc_bind_data(target, object_address=object_address, data=data)
def register_runtime_tools(mcp) -> None:
    """Register runtimes tools with FastMCP."""
    register_module_tools(mcp, globals())
