"""Device, process, session, and script lifecycle MCP tools."""
from __future__ import annotations

from typing import Any

from fuzzmind_frida_mcp import tools as _f
from fuzzmind_frida_mcp.toolsets._helpers import register_module_tools


def frida_check() -> dict:
    """Verify frida + frida-tools install state and version."""
    return _f.check()


def frida_list_processes(name_filter: str | None = None) -> dict:
    """Enumerate running processes via Frida's local device.

    Equivalent to `frida-ps`, with an optional case-insensitive name substring filter.
    """
    return _f.list_processes(name_filter=name_filter)


def frida_script_run_file(
    target: str,
    script_path: str,
    duration_seconds: int = 30,
    mode: str = "attach",
    device_id: str | None = None,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    exit_on_error: bool = False,
    kill_on_exit: bool = False,
    output_file: str | None = None,
) -> dict:
    """Run a Frida JS script against a process.

    `mode`: 'attach' (default — process already running) or 'spawn' (start
    a new process; pass full command in `target`).
    Collects `send(...)` messages from the script and returns them.
    """
    return _f.inject_script(
        target,
        script_path,
        duration_seconds=duration_seconds,
        mode=mode,
        device_id=device_id,
        runtime=runtime,
        parameters=parameters,
        auto_perform=auto_perform,
        exit_on_error=exit_on_error,
        kill_on_exit=kill_on_exit,
        output_file=output_file,
    )


def frida_eval(
    target: str,
    js_code: str,
    duration_seconds: int = 5,
    mode: str = "attach",
    device_id: str | None = None,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    exit_on_error: bool = False,
    kill_on_exit: bool = False,
    output_file: str | None = None,
) -> dict:
    """Evaluate inline JavaScript against a target, equivalent to CLI `-e`."""
    return _f.eval_code(
        target,
        js_code,
        duration_seconds=duration_seconds,
        mode=mode,
        device_id=device_id,
        runtime=runtime,
        parameters=parameters,
        auto_perform=auto_perform,
        exit_on_error=exit_on_error,
        kill_on_exit=kill_on_exit,
        output_file=output_file,
    )


def frida_enumerate_modules(target: str) -> dict:
    """List all loaded modules in a target process.

    Returns name, base address, size, and file path for each module.
    `target`: process name or pid (string).
    """
    return _f.enumerate_modules(target)


def frida_enumerate_exports(target: str, module_name: str) -> dict:
    """List exported symbols from a specific module in a target process.

    `module_name`: e.g. 'libsystem_kernel.dylib'.
    Returns name, type ('function' or 'variable'), and address.
    """
    return _f.enumerate_exports(target, module_name=module_name)


def frida_list_devices() -> dict:
    """List all available Frida devices (USB, remote, local).

    Useful for discovering connected devices before specifying a
    `device_id` in other tools. Returns id, name, and type for each.
    """
    return _f.list_devices()


def frida_get_device_info(device_id: str | None = None) -> dict:
    """Get info about a specific Frida device or the default local device.

    `device_id`: optional device id from `frida_list_devices`. Defaults
    to the local macOS device. Returns device metadata and running
    process count.
    """
    return _f.get_device_info(device_id=device_id)


def frida_connect(
    target: str = "",
    device_id: str | None = None,
    spawn: bool = False,
    attach_identifier: str | None = None,
    attach_frontmost: bool = False,
    await_pattern: str | None = None,
    await_timeout: float = 30.0,
    argv: list[str] | None = None,
    env: dict[str, str] | None = None,
    envp: dict[str, str] | None = None,
    cwd: str | None = None,
    stdio: str | None = None,
    aux: dict[str, Any] | None = None,
    realm: str | None = None,
    persist_timeout: int | None = None,
    pause: bool = False,
    kill_on_disconnect: bool = False,
) -> dict:
    """Connect/attach to a process and create a persistent Frida session.

    `target`: process name or pid (string). Full binary path when
    `spawn=True`.
    `device_id`: optional device id; defaults to local device.
    `spawn`: if True, spawn the process under Frida instead of
    attaching to an existing one.

    Returns a `session_id` for use with session-based tools (hooks,
    hook messages, etc.). The session stays alive until explicitly
    disconnected.
    """
    return _f.connect(
        target,
        device_id=device_id,
        spawn=spawn,
        attach_identifier=attach_identifier,
        attach_frontmost=attach_frontmost,
        await_pattern=await_pattern,
        await_timeout=await_timeout,
        argv=argv,
        env=env,
        envp=envp,
        cwd=cwd,
        stdio=stdio,
        aux=aux,
        realm=realm,
        persist_timeout=persist_timeout,
        pause=pause,
        kill_on_disconnect=kill_on_disconnect,
    )


def frida_await_spawn(
    pattern: str,
    device_id: str | None = None,
    timeout_seconds: float = 30.0,
    attach: bool = True,
    resume: bool = True,
    resume_unmatched: bool = True,
    realm: str | None = None,
    persist_timeout: int | None = None,
    kill_on_disconnect: bool = False,
) -> dict:
    """Wait for a spawn matching `pattern`, optionally attach and resume."""
    return _f.await_spawn(
        pattern,
        device_id=device_id,
        timeout_seconds=timeout_seconds,
        attach=attach,
        resume=resume,
        resume_unmatched=resume_unmatched,
        realm=realm,
        persist_timeout=persist_timeout,
        kill_on_disconnect=kill_on_disconnect,
    )


def frida_disconnect(session_id: str | None = None) -> dict:
    """Disconnect from the current or a specified Frida session.

    `session_id`: optional; defaults to the active session. Detaches
    from the process and unloads all persistent hooks.
    """
    return _f.disconnect(session_id=session_id)


def frida_list_sessions() -> dict:
    """List all active Frida sessions.

    Shows session id, target, pid, device, whether each is the active
    session, and whether the underlying Frida connection is still alive.
    """
    return _f.list_sessions()


def frida_switch_session(session_id: str) -> dict:
    """Switch the active Frida session.

    `session_id`: id of the session to activate (from
    `frida_list_sessions`). Subsequent session-based tool calls
    (hooks, messages) will operate on this session.
    """
    return _f.switch_session(session_id=session_id)


def frida_is_connected() -> dict:
    """Check if the current Frida session is alive.

    Returns connection status, session id, target, pid, and device
    name. Useful as a health-check before running session-based tools.
    """
    return _f.is_connected()


def frida_session_get_events(
    session_id: str | None = None,
    clear: bool = False,
    limit: int = 100,
) -> dict:
    """Read lifecycle events for a persistent Frida session."""
    return _f.session_get_events(session_id=session_id, clear=clear, limit=limit)


def frida_session_clear_events(session_id: str | None = None) -> dict:
    """Clear lifecycle events for a persistent Frida session."""
    return _f.session_clear_events(session_id=session_id)


def frida_script_load(
    js_code: str,
    session_id: str | None = None,
    name: str | None = None,
    kind: str = "script",
    event_limit: int = 1000,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    enable_debugger: bool = False,
    debugger_port: int | None = None,
    exit_on_error: bool = False,
) -> dict:
    """Load a long-running Frida script into a persistent session.

    The script remains loaded until explicitly unloaded or the session
    disconnects. Use `send()` in JavaScript to emit events, `recv()` to
    receive messages, and `rpc.exports` to expose callable functions.
    """
    return _f.script_load(
        js_code,
        session_id=session_id,
        name=name,
        kind=kind,
        event_limit=event_limit,
        runtime=runtime,
        parameters=parameters,
        auto_perform=auto_perform,
        enable_debugger=enable_debugger,
        debugger_port=debugger_port,
        exit_on_error=exit_on_error,
    )


def frida_script_load_file(
    script_path: str,
    session_id: str | None = None,
    name: str | None = None,
    kind: str = "script",
    event_limit: int = 1000,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    enable_debugger: bool = False,
    debugger_port: int | None = None,
    exit_on_error: bool = False,
) -> dict:
    """Load a local JavaScript file as a long-running Frida script."""
    return _f.script_load_file(
        script_path,
        session_id=session_id,
        name=name,
        kind=kind,
        event_limit=event_limit,
        runtime=runtime,
        parameters=parameters,
        auto_perform=auto_perform,
        enable_debugger=enable_debugger,
        debugger_port=debugger_port,
        exit_on_error=exit_on_error,
    )


def frida_script_list(
    session_id: str | None = None,
    kind: str | None = None,
) -> dict:
    """List long-running scripts loaded in a persistent session."""
    return _f.script_list(session_id=session_id, kind=kind)


def frida_script_unload(
    script_id: str,
    session_id: str | None = None,
) -> dict:
    """Unload a long-running script by `script_id`."""
    return _f.script_unload(script_id, session_id=session_id)


def frida_script_reload(
    script_id: str,
    session_id: str | None = None,
    js_code: str | None = None,
    script_path: str | None = None,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
) -> dict:
    """Reload a long-running script, preserving its name and kind."""
    return _f.script_reload(
        script_id,
        session_id=session_id,
        js_code=js_code,
        script_path=script_path,
        runtime=runtime,
        parameters=parameters,
        auto_perform=auto_perform,
    )


def frida_script_call_rpc(
    script_id: str,
    method: str,
    args: list | None = None,
    session_id: str | None = None,
) -> dict:
    """Call a function exposed through `rpc.exports` by a loaded script."""
    return _f.script_call_rpc(script_id, method=method, args=args, session_id=session_id)


def frida_script_post_message(
    script_id: str,
    message: str | dict | list,
    session_id: str | None = None,
) -> dict:
    """Post a JSON-serialisable message to a long-running script."""
    return _f.script_post_message(script_id, message=message, session_id=session_id)


def frida_script_get_events(
    script_id: str | None = None,
    session_id: str | None = None,
    kind: str | None = None,
    clear: bool = False,
    limit: int = 100,
) -> dict:
    """Read queued events emitted by long-running scripts."""
    return _f.script_get_events(
        script_id=script_id,
        session_id=session_id,
        kind=kind,
        clear=clear,
        limit=limit,
    )


def frida_script_clear_events(
    script_id: str | None = None,
    session_id: str | None = None,
    kind: str | None = None,
) -> dict:
    """Clear queued events for one script or a whole session."""
    return _f.script_clear_events(script_id=script_id, session_id=session_id, kind=kind)


def frida_script_export_events(
    output_path: str,
    script_id: str | None = None,
    session_id: str | None = None,
    kind: str | None = None,
    format: str = "jsonl",
    clear: bool = False,
    limit: int = 10000,
) -> dict:
    """Export queued script events to JSON or JSONL."""
    return _f.script_export_events(
        output_path,
        script_id=script_id,
        session_id=session_id,
        kind=kind,
        format=format,
        clear=clear,
        limit=limit,
    )


def frida_get_module_base(target: str, module_name: str) -> dict:
    """Get base address of a module by name (partial match supported).

    `target`: process name or pid (string).
    `module_name`: full or partial module name (case-insensitive).
    Returns the first matching module's name, base address, size, and path.
    """
    return _f.get_module_base(target, module_name=module_name)


def frida_get_frontmost_app(device_id: str | None = None) -> dict:
    """Get the frontmost (foreground) application on a device.

    `device_id`: optional Frida device id (from `frida_list_devices`);
    defaults to local device. Returns {identifier, name, pid}.
    Useful on iOS/Android to identify the currently visible app.
    """
    return _f.get_frontmost_app(device_id=device_id)


def frida_launch_app(
    identifier: str,
    device_id: str | None = None,
) -> dict:
    """Spawn and resume an application by bundle/package identifier.

    `identifier`: app bundle id (iOS/macOS) or package name (Android),
    e.g. 'com.apple.Safari' or 'com.example.app'.
    `device_id`: optional Frida device id; defaults to local device.

    Uses Frida's `device.spawn()` + `device.resume()` to launch the
    app fresh. Returns {pid, identifier, status}.
    """
    return _f.launch_app(identifier, device_id=device_id)


def frida_kill_app(
    target: str,
    device_id: str | None = None,
) -> dict:
    """Kill a process by PID or name on a device.

    `target`: integer PID (as string) or process name. If a name is
    given, the process list is searched (exact match first, then
    substring). `device_id`: optional; defaults to local device.
    """
    return _f.kill_app(target, device_id=device_id)


def frida_cli_compile_bundle(
    script_path: str,
    output_path: str | None = None,
) -> dict:
    """Compile a Frida JS script to bytecode for faster injection.

    Shells out to `frida-compile`. Produces an optimised bundle that
    loads faster than raw JS.

    `script_path`: path to the source .js file.
    `output_path`: optional output path (default: `<script>.compiled.js`).
    """
    return _f.script_compile(script_path, output_path=output_path)


def frida_script_eternalize(
    target: str,
    js_code: str,
) -> dict:
    """Inject a script and eternalize it so it survives session detach.

    After `script.eternalize()`, the hooks live on inside the target
    process even after the Frida session disconnects. Only killing the
    target process removes the instrumentation.

    `target`: process name or pid (string).
    `js_code`: Frida JS code to inject and eternalize.
    """
    return _f.script_eternalize(target, js_code=js_code)


def frida_inject_library(
    target: str,
    library_path: str,
    entrypoint: str = "",
    data: str = "",
) -> dict:
    """Inject a shared library (.dylib / .so) into a target process.

    Uses Frida's `inject_library_file()` to load the library. The
    library's `entrypoint` function (if specified) is called with
    `data` as its argument.

    `target`: process name or pid (string).
    `library_path`: path to the .dylib or .so to inject.
    `entrypoint`: optional symbol to call after load.
    `data`: optional string argument for the entrypoint.
    """
    return _f.inject_library(target, library_path=library_path, entrypoint=entrypoint, data=data)


def frida_enumerate_threads(target: str) -> dict:
    """List all threads in a target process with state and registers.

    `target`: process name or pid (string).
    Returns thread id, state (running/stopped/waiting), and key register
    values (pc, sp) for each thread.
    """
    return _f.enumerate_threads(target)


def frida_enumerate_symbols(
    target: str,
    module_name: str | None = None,
    filter: str | None = None,
    limit: int = 1000,
) -> dict:
    """List all symbols (not just exports) from a module.

    Unlike `frida_enumerate_exports`, this includes local and debug
    symbols when available.

    `target`: process name or pid (string).
    `module_name`: module to query (default: main executable).
    `filter`: optional case-insensitive name substring filter.
    `limit`: max symbols to return (default 1000).
    """
    return _f.enumerate_symbols(target, module_name=module_name, filter=filter, limit=limit)


def frida_session_recover(session_id: str | None = None) -> dict:
    """Recover a broken/crashed Frida session by re-attaching.

    Looks up the original target PID/name from the session registry and
    attempts to create a new Frida session to the same process.

    `session_id`: optional; defaults to the current active session.
    """
    return _f.session_recover(session_id=session_id)


def frida_list_apps(device_id: str | None = None) -> dict:
    """List all installed applications on a device (not just running).

    Unlike `frida_list_processes` which only returns running processes,
    this enumerates all installed apps. Returns identifier, name, and
    pid (0 if not running) for each.

    `device_id`: optional Frida device id; defaults to local device.
    """
    return _f.list_apps(device_id=device_id)


def frida_process_info(target: str) -> dict:
    """Get detailed Process metadata: pid, arch, platform, page/pointer sizes,
    code signing policy, mainModule, dirs, debugger state, current thread id.

    `target`: process name or pid (string).
    """
    return _f.process_info(target)


def frida_target_snapshot(
    target: str,
    device_id: str | None = None,
    spawn: bool = False,
    module_limit: int = 200,
    thread_limit: int = 50,
) -> dict:
    """Collect an agent-friendly target snapshot before deeper analysis.

    Returns process metadata, runtime/bridge availability, main module,
    module/thread samples, memory-range counts, and recommended next tools.

    `target`: process name or pid (attach), or command line when `spawn=True`.
    `device_id`: optional Frida device id for USB/remote targets.
    `spawn`: start the target suspended, attach, collect the snapshot, then resume.
    """
    return _f.target_snapshot(
        target,
        device_id=device_id,
        spawn=spawn,
        module_limit=module_limit,
        thread_limit=thread_limit,
    )


def frida_enumerate_imports(
    target: str,
    module_name: str,
    filter: str | None = None,
    limit: int = 1000,
) -> dict:
    """Enumerate imports of a module in a target process.

    `target`: process name or pid (string).
    `module_name`: module to query (e.g. 'Safari', 'libsystem_kernel.dylib').
    `filter`: optional case-insensitive name substring filter.
    `limit`: max imports to return (default 1000).
    """
    return _f.enumerate_imports(target, module_name=module_name, filter=filter, limit=limit)


def frida_enumerate_sections(target: str, module_name: str) -> dict:
    """Enumerate sections (name, base, size, protection) of a module.

    `target`: process name or pid (string).
    `module_name`: module to query (e.g. 'CoreAudio', 'libsystem_c.dylib').
    """
    return _f.enumerate_sections(target, module_name=module_name)


def frida_enumerate_dependencies(target: str, module_name: str) -> dict:
    """Enumerate dependencies of a module in a target process.

    `target`: process name or pid (string).
    `module_name`: module to query.
    """
    return _f.enumerate_dependencies(target, module_name=module_name)


def frida_enumerate_malloc_ranges(
    target: str,
    filter: str = "rw-",
) -> dict:
    """Enumerate malloc heap ranges filtered by memory protection.

    `target`: process name or pid (string).
    `filter`: protection string filter (default 'rw-'). Frida returns
      ranges whose protection is a superset of the specified value.
    """
    return _f.enumerate_malloc_ranges(target, filter=filter)


def frida_find_export_by_name(
    target: str,
    module_name: str | None,
    export_name: str,
) -> dict:
    """Find a single export by name, optionally scoped to a module.

    `target`: process name or pid (string).
    `module_name`: module to search in, or None for all modules.
    `export_name`: export name to find.
    Returns the address of the export.
    """
    return _f.find_export_by_name(target, module_name=module_name, export_name=export_name)


def frida_find_symbol_by_name(
    target: str,
    module_name: str,
    symbol_name: str,
) -> dict:
    """Find a symbol by name within a module (including non-exported symbols).

    `target`: process name or pid (string).
    `module_name`: module to search.
    `symbol_name`: symbol name to find.
    Returns address and type.
    """
    return _f.find_symbol_by_name(target, module_name=module_name, symbol_name=symbol_name)


def frida_resolve_debug_symbol(target: str, address: str) -> dict:
    """Resolve a debug symbol from an address via DebugSymbol.fromAddress.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100004000').
    Returns name, moduleName, fileName, lineNumber.
    """
    return _f.resolve_debug_symbol(target, address=address)


def frida_find_functions_named(target: str, name: str) -> dict:
    """Find all functions with an exact name via DebugSymbol.findFunctionsNamed.

    `target`: process name or pid (string).
    `name`: exact function name to search for.
    Returns list of matching addresses.
    """
    return _f.find_functions_named(target, name=name)


def frida_find_functions_matching(target: str, glob: str) -> dict:
    """Find functions matching a glob pattern via DebugSymbol.findFunctionsMatching.

    `target`: process name or pid (string).
    `glob`: glob pattern (e.g. '*xpc*send*', 'objc_msg*').
    Returns matching addresses with symbolicated names.
    """
    return _f.find_functions_matching(target, glob=glob)


def frida_load_debug_symbols(target: str, path: str) -> dict:
    """Load debug symbols from a file (e.g. dSYM) into the target.

    `target`: process name or pid (string).
    `path`: path to the debug symbol file to load.
    """
    return _f.load_debug_symbols(target, path=path)


def frida_resume_process(target_pid: int, device_id: str | None = None) -> dict:
    """Resume a suspended process by PID.

    Standalone resume for processes spawned but not yet resumed.

    `target_pid`: integer process ID.
    `device_id`: optional Frida device id; defaults to local device.
    """
    return _f.resume_process(target_pid, device_id=device_id)


def frida_interactive_eval(
    session_id: str,
    js_code: str,
    runtime: str | None = None,
    parameters: Any | None = None,
    auto_perform: bool = False,
    exit_on_error: bool = False,
) -> dict:
    """Execute arbitrary JS in an existing persistent Frida session (REPL).

    Reuses a persistent session so hooks and state remain. Unlike
    inject_script, this creates a one-shot script, collects messages,
    and unloads without disturbing the session.

    `session_id`: session id from `frida_connect` / `frida_list_sessions`.
    `js_code`: JavaScript to evaluate. Use `send()` to return data.
    """
    return _f.interactive_eval(
        session_id=session_id,
        js_code=js_code,
        runtime=runtime,
        parameters=parameters,
        auto_perform=auto_perform,
        exit_on_error=exit_on_error,
    )


def frida_cli_options_file_parse(options_file: str) -> dict:
    """Parse a Frida CLI `--options-file` into shell-style tokens.

    This is a planning/inspection helper for agents. It does not execute
    the options file.
    """
    return _f.cli_options_file_parse(options_file)


def frida_codeshare_run(
    target: str,
    codeshare_uri: str,
    duration_seconds: int = 30,
    mode: str = "attach",
    device_id: str | None = None,
    runtime: str | None = None,
    quiet: bool = True,
    output_file: str | None = None,
) -> dict:
    """Run an official frida-tools CodeShare script via `frida -c`."""
    return _f.codeshare_run(
        target,
        codeshare_uri=codeshare_uri,
        duration_seconds=duration_seconds,
        mode=mode,
        device_id=device_id,
        runtime=runtime,
        quiet=quiet,
        output_file=output_file,
    )




def frida_device_get_usb(timeout: int = 0) -> dict:
    """Get the first USB Frida device via `frida.get_usb_device()`."""
    return _f.device_get_usb(timeout=timeout)


def frida_device_get_remote() -> dict:
    """Get Frida's default remote device via `frida.get_remote_device()`."""
    return _f.device_get_remote()


def frida_device_get_matching(
    type: str | None = None,
    name_contains: str | None = None,
    timeout: int = 0,
) -> dict:
    """Find a device with DeviceManager.get_device_matching()."""
    return _f.device_get_matching(type=type, name_contains=name_contains, timeout=timeout)


def frida_remote_device_add(
    address: str,
    certificate: str | None = None,
    origin: str | None = None,
    token: str | None = None,
    keepalive_interval: int | None = None,
) -> dict:
    """Add a remote device with official auth/keepalive options."""
    return _f.remote_device_add(
        address,
        certificate=certificate,
        origin=origin,
        token=token,
        keepalive_interval=keepalive_interval,
    )


def frida_remote_device_remove(address: str) -> dict:
    """Remove a remote device from Frida's DeviceManager."""
    return _f.remote_device_remove(address)


def frida_device_query_system_parameters(device_id: str | None = None) -> dict:
    """Call Device.query_system_parameters()."""
    return _f.device_query_system_parameters(device_id=device_id)


def frida_device_override_option(name: str, value: Any, device_id: str | None = None) -> dict:
    """Call Device.override_option(name, value)."""
    return _f.device_override_option(name, value, device_id=device_id)


def frida_device_unpair(device_id: str | None = None) -> dict:
    """Call Device.unpair()."""
    return _f.device_unpair(device_id=device_id)


def frida_device_input(target: str, data_base64: str, device_id: str | None = None) -> dict:
    """Send raw base64-decoded input bytes to a spawned target."""
    return _f.device_input(target, data_base64=data_base64, device_id=device_id)


def frida_device_get_process(target: str, device_id: str | None = None) -> dict:
    """Call Device.get_process()."""
    return _f.device_get_process(target, device_id=device_id)


def frida_device_is_lost(device_id: str | None = None) -> dict:
    """Call Device.is_lost()."""
    return _f.device_is_lost(device_id=device_id)


def frida_inject_library_blob(
    target: str,
    library_base64: str,
    entrypoint: str = "",
    data: str = "",
    device_id: str | None = None,
) -> dict:
    """Inject a library from base64 bytes with Device.inject_library_blob()."""
    return _f.inject_library_blob(
        target,
        library_base64=library_base64,
        entrypoint=entrypoint,
        data=data,
        device_id=device_id,
    )


def frida_spawn_with_options(
    program: str,
    argv: list[str] | None = None,
    env: dict[str, str] | None = None,
    envp: dict[str, str] | None = None,
    cwd: str | None = None,
    stdio: str | None = None,
    aux: dict[str, Any] | None = None,
    device_id: str | None = None,
) -> dict:
    """Spawn without attaching, exposing Device.spawn() options."""
    return _f.spawn_with_options(
        program,
        argv=argv,
        env=env,
        envp=envp,
        cwd=cwd,
        stdio=stdio,
        aux=aux,
        device_id=device_id,
    )


def frida_pending_spawn_list(device_id: str | None = None) -> dict:
    """List Device.enumerate_pending_spawn()."""
    return _f.pending_spawn_list(device_id=device_id)


def frida_pending_children_list(device_id: str | None = None) -> dict:
    """List Device.enumerate_pending_children()."""
    return _f.pending_children_list(device_id=device_id)


def frida_event_subscribe(
    source: str = "device",
    events: list[str] | None = None,
    device_id: str | None = None,
    session_id: str | None = None,
    enable_spawn_gating: bool = False,
    enable_child_gating: bool = False,
) -> dict:
    """Subscribe to official DeviceManager/Device/Session events."""
    return _f.event_subscribe(
        source=source,
        events=events,
        device_id=device_id,
        session_id=session_id,
        enable_spawn_gating=enable_spawn_gating,
        enable_child_gating=enable_child_gating,
    )


def frida_event_get_events(subscription_id: str, clear: bool = False, limit: int = 100) -> dict:
    """Read queued official event subscription events."""
    return _f.event_get_events(subscription_id, clear=clear, limit=limit)


def frida_event_unsubscribe(subscription_id: str) -> dict:
    """Unsubscribe from an official event subscription."""
    return _f.event_unsubscribe(subscription_id)


def frida_bus_attach(device_id: str | None = None) -> dict:
    """Attach to a device bus and start queueing bus messages."""
    return _f.bus_attach(device_id=device_id)


def frida_bus_post(bus_id: str, message: Any, data_base64: str | None = None) -> dict:
    """Post a message on an attached Frida bus."""
    return _f.bus_post(bus_id, message=message, data_base64=data_base64)


def frida_bus_get_events(bus_id: str, clear: bool = False, limit: int = 100) -> dict:
    """Read queued bus events."""
    return _f.bus_get_events(bus_id, clear=clear, limit=limit)


def frida_bus_detach(bus_id: str) -> dict:
    """Forget a bus event queue."""
    return _f.bus_detach(bus_id)


def frida_session_enable_child_gating(session_id: str | None = None) -> dict:
    """Call Session.enable_child_gating()."""
    return _f.session_enable_child_gating(session_id=session_id)


def frida_session_disable_child_gating(session_id: str | None = None) -> dict:
    """Call Session.disable_child_gating()."""
    return _f.session_disable_child_gating(session_id=session_id)


def frida_session_resume(session_id: str | None = None) -> dict:
    """Call Session.resume()."""
    return _f.session_resume(session_id=session_id)


def frida_session_is_detached(session_id: str | None = None) -> dict:
    """Call Session.is_detached()."""
    return _f.session_is_detached(session_id=session_id)


def frida_session_setup_peer_connection(
    session_id: str | None = None,
    stun_server: str | None = None,
    relays: list[dict] | None = None,
) -> dict:
    """Call Session.setup_peer_connection()."""
    return _f.session_setup_peer_connection(session_id=session_id, stun_server=stun_server, relays=relays)


def frida_session_join_portal(
    address: str,
    session_id: str | None = None,
    certificate: str | None = None,
    token: str | None = None,
    acl: list[str] | None = None,
) -> dict:
    """Call Session.join_portal()."""
    return _f.session_join_portal(address, session_id=session_id, certificate=certificate, token=token, acl=acl)


def frida_session_leave_portal(membership_id: str, session_id: str | None = None) -> dict:
    """Terminate a portal membership created by frida_session_join_portal."""
    return _f.session_leave_portal(membership_id, session_id=session_id)


def frida_script_load_bytes(
    data_base64: str,
    session_id: str | None = None,
    name: str | None = None,
    event_limit: int = 1000,
) -> dict:
    """Load compiled script bytes with Session.create_script_from_bytes()."""
    return _f.script_load_bytes(data_base64, session_id=session_id, name=name, event_limit=event_limit)


def frida_session_compile_script(
    js_code: str,
    session_id: str | None = None,
    name: str | None = None,
    runtime: str | None = None,
) -> dict:
    """Compile script source with Session.compile_script()."""
    return _f.session_compile_script(js_code, session_id=session_id, name=name, runtime=runtime)


def frida_session_snapshot_script(
    embed_script: str,
    warmup_script: str | None = None,
    session_id: str | None = None,
    runtime: str | None = None,
) -> dict:
    """Create a script snapshot with Session.snapshot_script()."""
    return _f.session_snapshot_script(embed_script, warmup_script=warmup_script, session_id=session_id, runtime=runtime)


def frida_script_list_exports(script_id: str, session_id: str | None = None) -> dict:
    """List rpc.exports exposed by a loaded script."""
    return _f.script_list_exports(script_id, session_id=session_id)


def frida_script_enable_debugger(script_id: str, port: int | None = None, session_id: str | None = None) -> dict:
    """Enable the Frida script debugger for a loaded script."""
    return _f.script_enable_debugger(script_id, port=port, session_id=session_id)


def frida_script_disable_debugger(script_id: str, session_id: str | None = None) -> dict:
    """Disable the Frida script debugger for a loaded script."""
    return _f.script_disable_debugger(script_id, session_id=session_id)


def frida_script_post_binary(script_id: str, message: Any, data_base64: str, session_id: str | None = None) -> dict:
    """Post a message plus binary data to a loaded script."""
    return _f.script_post_binary(script_id, message=message, data_base64=data_base64, session_id=session_id)


def frida_script_set_log_handler(script_id: str, session_id: str | None = None) -> dict:
    """Queue Script log-handler events for a loaded script."""
    return _f.script_set_log_handler(script_id, session_id=session_id)


def frida_script_get_log_events(
    script_id: str,
    session_id: str | None = None,
    clear: bool = False,
    limit: int = 100,
) -> dict:
    """Read queued Script log-handler events."""
    return _f.script_get_log_events(script_id, session_id=session_id, clear=clear, limit=limit)


def frida_script_get_log_handler(script_id: str, session_id: str | None = None) -> dict:
    """Call Script.get_log_handler()."""
    return _f.script_get_log_handler(script_id, session_id=session_id)


def frida_script_reset_log_handler(script_id: str, session_id: str | None = None) -> dict:
    """Reset Script log handling to the Frida default."""
    return _f.script_reset_log_handler(script_id, session_id=session_id)


def frida_compiler_build(
    entrypoint: str,
    project_root: str | None = None,
    output_format: str | None = None,
    bundle_format: str | None = None,
    type_check: str | None = None,
    source_maps: str | None = None,
    compression: str | None = None,
    platform: str | None = "gum",
    externals: list[str] | None = None,
) -> dict:
    """Build a Frida agent bundle with frida.Compiler.build()."""
    return _f.compiler_build(
        entrypoint,
        project_root=project_root,
        output_format=output_format,
        bundle_format=bundle_format,
        type_check=type_check,
        source_maps=source_maps,
        compression=compression,
        platform=platform,
        externals=externals,
    )


def frida_compiler_watch(
    entrypoint: str,
    project_root: str | None = None,
    output_format: str | None = None,
    bundle_format: str | None = None,
    type_check: str | None = None,
    source_maps: str | None = None,
    compression: str | None = None,
    platform: str | None = "gum",
    externals: list[str] | None = None,
) -> dict:
    """Start Compiler.watch() and queue compiler events."""
    return _f.compiler_watch(
        entrypoint,
        project_root=project_root,
        output_format=output_format,
        bundle_format=bundle_format,
        type_check=type_check,
        source_maps=source_maps,
        compression=compression,
        platform=platform,
        externals=externals,
    )


def frida_compiler_watch_get_events(watch_id: str, clear: bool = False, limit: int = 100) -> dict:
    """Read queued Compiler.watch() events."""
    return _f.compiler_watch_get_events(watch_id, clear=clear, limit=limit)


def frida_compiler_watch_stop(watch_id: str) -> dict:
    """Stop tracking a Compiler.watch() record."""
    return _f.compiler_watch_stop(watch_id)


def frida_package_search(query: str, offset: int | None = None, limit: int | None = None) -> dict:
    """Search Frida packages with PackageManager.search()."""
    return _f.package_search(query, offset=offset, limit=limit)


def frida_package_install(
    project_root: str | None = None,
    role: str | None = None,
    specs: list[str] | None = None,
    omits: list[str] | None = None,
) -> dict:
    """Install Frida packages with PackageManager.install()."""
    return _f.package_install(project_root=project_root, role=role, specs=specs, omits=omits)


def frida_package_registry() -> dict:
    """Read PackageManager.registry."""
    return _f.package_registry()


def frida_portal_start(
    cluster_address: str | None = None,
    cluster_port: int | None = None,
    control_address: str | None = None,
    control_port: int | None = None,
    certificate: str | None = None,
    origin: str | None = None,
    token: str | None = None,
    asset_root: str | None = None,
) -> dict:
    """Create and start a PortalService with EndpointParameters."""
    return _f.portal_start(
        cluster_address=cluster_address,
        cluster_port=cluster_port,
        control_address=control_address,
        control_port=control_port,
        certificate=certificate,
        origin=origin,
        token=token,
        asset_root=asset_root,
    )


def frida_portal_stop(portal_id: str) -> dict:
    """Stop a PortalService."""
    return _f.portal_stop(portal_id)


def frida_portal_broadcast(portal_id: str, message: Any, data_base64: str | None = None) -> dict:
    """Broadcast a message through PortalService."""
    return _f.portal_broadcast(portal_id, message=message, data_base64=data_base64)


def frida_portal_narrowcast(portal_id: str, tag: str, message: Any, data_base64: str | None = None) -> dict:
    """Narrowcast a message by PortalService tag."""
    return _f.portal_narrowcast(portal_id, tag=tag, message=message, data_base64=data_base64)


def frida_portal_post(portal_id: str, connection_id: int, message: Any, data_base64: str | None = None) -> dict:
    """Post a message to one PortalService connection."""
    return _f.portal_post(portal_id, connection_id=connection_id, message=message, data_base64=data_base64)


def frida_portal_tag(portal_id: str, connection_id: int, tag: str) -> dict:
    """Tag a PortalService connection."""
    return _f.portal_tag(portal_id, connection_id=connection_id, tag=tag)


def frida_portal_untag(portal_id: str, connection_id: int, tag: str) -> dict:
    """Remove a PortalService connection tag."""
    return _f.portal_untag(portal_id, connection_id=connection_id, tag=tag)


def frida_portal_enumerate_tags(portal_id: str, connection_id: int) -> dict:
    """List tags for a PortalService connection."""
    return _f.portal_enumerate_tags(portal_id, connection_id=connection_id)


def frida_portal_get_events(portal_id: str, clear: bool = False, limit: int = 100) -> dict:
    """Read queued PortalService lifecycle events."""
    return _f.portal_get_events(portal_id, clear=clear, limit=limit)


def frida_service_request(address: str, params_json: str | None = None, device_id: str | None = None) -> dict:
    """Open a Frida device service and send one request."""
    return _f.service_request(address, params_json=params_json, device_id=device_id)


def frida_open_channel(address: str, device_id: str | None = None) -> dict:
    """Open and close a raw Frida device channel as a readiness probe."""
    return _f.open_channel(address, device_id=device_id)


def frida_channel_open(address: str, device_id: str | None = None) -> dict:
    """Open a raw device channel and keep it for stream operations."""
    return _f.channel_open(address, device_id=device_id)


def frida_channel_read(channel_id: str, size: int = 4096) -> dict:
    """Read bytes from an open device channel."""
    return _f.channel_read(channel_id, size=size)


def frida_channel_write(channel_id: str, data_base64: str, write_all: bool = True) -> dict:
    """Write bytes to an open device channel."""
    return _f.channel_write(channel_id, data_base64=data_base64, write_all=write_all)


def frida_channel_close(channel_id: str) -> dict:
    """Close and forget an open device channel."""
    return _f.channel_close(channel_id)


def frida_service_open(address: str, device_id: str | None = None, activate: bool = True) -> dict:
    """Open a device service and keep it for repeated requests/events."""
    return _f.service_open(address, device_id=device_id, activate=activate)


def frida_service_request_by_id(service_id: str, params_json: str | None = None) -> dict:
    """Send a request through an open device service."""
    return _f.service_request_by_id(service_id, params_json=params_json)


def frida_service_get_events(service_id: str, clear: bool = False, limit: int = 100) -> dict:
    """Read queued events from an open device service."""
    return _f.service_get_events(service_id, clear=clear, limit=limit)


def frida_service_close(service_id: str) -> dict:
    """Cancel and forget an open device service."""
    return _f.service_close(service_id)


def register_lifecycle_tools(mcp) -> None:
    """Register lifecycle tools with FastMCP."""
    register_module_tools(mcp, globals())
