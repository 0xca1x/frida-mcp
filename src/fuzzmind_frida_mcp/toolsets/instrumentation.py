"""Memory, hook, Interceptor, Stalker, Kernel, and profiler MCP tools."""
from __future__ import annotations

from typing import Any

from fuzzmind_frida_mcp import tools as _f
from fuzzmind_frida_mcp.toolsets._helpers import register_module_tools


def frida_trace(
    target: str,
    include: list[str] | None = None,
    duration_seconds: int = 10,
    output_file: str | None = None,
    mode: str = "attach",
    device_id: str | None = None,
    attach_identifier: str | None = None,
    attach_frontmost: bool = False,
    await_pattern: str | None = None,
    runtime: str | None = None,
    include_module: list[str] | None = None,
    exclude_module: list[str] | None = None,
    exclude: list[str] | None = None,
    add: list[str] | None = None,
    include_imports: list[str] | None = None,
    include_module_imports: list[str] | None = None,
    include_objc_method: list[str] | None = None,
    exclude_objc_method: list[str] | None = None,
    include_swift_func: list[str] | None = None,
    exclude_swift_func: list[str] | None = None,
    include_java_method: list[str] | None = None,
    exclude_java_method: list[str] | None = None,
    include_debug_symbol: list[str] | None = None,
    init_session: str | None = None,
    parameters: Any | None = None,
    quiet: bool = False,
    decorate: bool = False,
    ui_host: str | None = None,
    ui_port: int | None = None,
    ui_allow_origin: list[str] | None = None,
) -> dict:
    """`frida-trace -i <patterns> -n/-p <target>` for `duration_seconds`.

    `target`: process name or pid (string).
    `include`: list of `-i` patterns, e.g. `['xpc_connection_send_*', 'objc:NSURL*']`.
    """
    return _f.trace_function(
        target,
        include=include,
        duration_seconds=duration_seconds,
        output_file=output_file,
        mode=mode,
        device_id=device_id,
        attach_identifier=attach_identifier,
        attach_frontmost=attach_frontmost,
        await_pattern=await_pattern,
        runtime=runtime,
        include_module=include_module,
        exclude_module=exclude_module,
        exclude=exclude,
        add=add,
        include_imports=include_imports,
        include_module_imports=include_module_imports,
        include_objc_method=include_objc_method,
        exclude_objc_method=exclude_objc_method,
        include_swift_func=include_swift_func,
        exclude_swift_func=exclude_swift_func,
        include_java_method=include_java_method,
        exclude_java_method=exclude_java_method,
        include_debug_symbol=include_debug_symbol,
        init_session=init_session,
        parameters=parameters,
        quiet=quiet,
        decorate=decorate,
        ui_host=ui_host,
        ui_port=ui_port,
        ui_allow_origin=ui_allow_origin,
    )


def frida_discover(
    target: str,
    duration_seconds: int = 30,
    mode: str = "attach",
    device_id: str | None = None,
    output_file: str | None = None,
    extra_args: list[str] | None = None,
) -> dict:
    """Run official frida-discover for a bounded capture window."""
    return _f.discover_run(
        target,
        duration_seconds=duration_seconds,
        mode=mode,
        device_id=device_id,
        output_file=output_file,
        extra_args=extra_args,
    )


def frida_gum_graft(
    input_path: str,
    output_path: str | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int = 120,
) -> dict:
    """Run official gum-graft when available."""
    return _f.gum_graft_run(
        input_path,
        output_path=output_path,
        extra_args=extra_args,
        timeout_seconds=timeout_seconds,
    )


def frida_stalker_coverage(
    target: str,
    module_filter: str | None = None,
    duration_seconds: int = 10,
    output_file: str | None = None,
) -> dict:
    """Collect basic-block coverage using Frida Stalker.

    Attaches Stalker to the main thread to record unique basic-block addresses
    hit during `duration_seconds`. `module_filter` restricts blocks to a
    specific module (e.g. 'CoreAudio'). Returns {blocks: [...], count: int}.
    """
    return _f.stalker_coverage(
        target,
        module_filter=module_filter,
        duration_seconds=duration_seconds,
        output_file=output_file,
    )


def frida_memory_scan(
    target: str,
    address: str,
    size: int,
    pattern: str,
) -> dict:
    """Scan process memory for a hex pattern.

    `address`: start address as hex string (e.g. '0x100000000').
    `size`: number of bytes to scan.
    `pattern`: frida hex pattern (e.g. '48 8b ?? c3', where ?? is wildcard).
    Returns matching addresses.
    """
    return _f.memory_scan(target, address=address, size=size, pattern=pattern)


def frida_read_memory(
    target: str,
    address: str,
    size: int,
) -> dict:
    """Read raw memory from a target process.

    `address`: hex string (e.g. '0x100000000').
    `size`: bytes to read (capped at 64KB).
    Returns hex dump of the memory region.
    """
    return _f.read_memory(target, address=address, size=size)


def frida_write_memory(
    target: str,
    address: str,
    hex_bytes: str,
) -> dict:
    """Write raw bytes to process memory.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100004000').
    `hex_bytes`: hex-encoded bytes (e.g. 'deadbeef', '90 90 90 90').
    Reads back the written region for verification.
    """
    return _f.write_memory(target, address=address, hex_bytes=hex_bytes)


def frida_memory_protect(
    target: str,
    address: str,
    size: int,
    protection: str,
) -> dict:
    """Change memory protection on a region.

    `target`: process name or pid (string).
    `address`: start address (hex string).
    `size`: region size in bytes.
    `protection`: protection string like 'rwx', 'r-x', 'rw-', '---'.
    """
    return _f.memory_protect(target, address=address, size=size, protection=protection)


def frida_enumerate_ranges(
    target: str,
    protection: str = "r--",
) -> dict:
    """Enumerate memory ranges matching a protection filter.

    `target`: process name or pid (string).
    `protection`: filter like 'r--', 'rwx', 'r-x'. Frida matches ranges
    whose protection is a superset of the specified value.
    Returns base address, size, protection, and backing file (if any).
    """
    return _f.enumerate_ranges(target, protection=protection)


def frida_hook_native_function(
    target: str,
    address: str,
    on_enter_js: str | None = None,
    on_leave_js: str | None = None,
    duration_seconds: int = 10,
) -> dict:
    """Hook a native function by address using Interceptor.attach.

    `target`: process name or pid (string).
    `address`: hex address of the function to hook.
    `on_enter_js`: custom JS for onEnter(args) body. Has `args`, `this.context`,
      `send()`. Leave None for a default that logs arg0-arg2.
    `on_leave_js`: custom JS for onLeave(retval) body. Has `retval`,
      `this.context`, `send()`. Leave None for a default that logs retval.
    `duration_seconds`: how long to keep the hook active (default 10).
    """
    return _f.hook_native_function(
        target,
        address=address,
        on_enter_js=on_enter_js,
        on_leave_js=on_leave_js,
        duration_seconds=duration_seconds,
    )


def frida_install_hook(
    js_code: str,
    name: str | None = None,
    duration_seconds: int = 0,
) -> dict:
    """Install a persistent hook that stays active and collects messages.

    Requires an active session (from `frida_connect`).

    `js_code`: Frida JS to run. Use `send(...)` to emit messages that
    are collected into the hook message buffer.
    `name`: optional label (defaults to 'hook_N').
    `duration_seconds`: auto-unload after N seconds (0 = stay forever).

    Returns a `script_id`; hook events can be retrieved with
    `frida_script_get_events` or the hook-specific `frida_get_hook_messages`.
    """
    return _f.install_hook(js_code, name=name, duration_seconds=duration_seconds)


def frida_get_hook_messages(clear: bool = False) -> dict:
    """Get queued events from persistent hook scripts.

    `clear`: if True, also clear hook event queues after reading.
    """
    return _f.get_hook_messages(clear=clear)


def frida_clear_hook_messages() -> dict:
    """Clear the hook message buffer for the active session."""
    return _f.clear_hook_messages()


def frida_uninstall_hooks() -> dict:
    """Unload all persistent hook scripts in the current session.

    Stops all active hooks and clears the hook list. Messages already
    collected remain in the message buffer until cleared.
    """
    return _f.uninstall_hooks()


def frida_list_hooks() -> dict:
    """List all installed persistent hooks in the current session.

    Returns script ids, names, loaded state, and event counts.
    """
    return _f.list_hooks()


def frida_hook_native_by_offset(
    module: str,
    offset: str,
    name: str | None = None,
) -> dict:
    """Hook a native function by module name + hex offset.

    Requires an active session (from `frida_connect`).

    `module`: module name (partial match, case-insensitive), e.g.
    'CoreAudio', 'libsystem_kernel'.
    `offset`: hex offset within the module, e.g. '0x1a2b'.
    `name`: optional label for the hook.

    Unlike `frida_hook_native_function` which takes an absolute address,
    this resolves the module base at runtime and adds the offset —
    useful when ASLR is in play.
    """
    return _f.hook_native_by_offset(module, offset=offset, name=name)


def frida_callstack_tracer(
    target: str,
    function_name_or_addr: str,
    duration_seconds: int = 10,
) -> dict:
    """Trace call stacks for a specific function, symbolicated.

    Attaches Interceptor to the target function and captures a full
    backtrace on each invocation using Thread.backtrace() with
    DebugSymbol.fromAddress() for symbolication.

    `target`: process name or pid (string).
    `function_name_or_addr`: hex address (e.g. '0x100004000') or
      exported symbol name (e.g. 'open', 'xpc_connection_send_message').
    `duration_seconds`: how long to trace (default 10).

    Returns up to 200 captured call stacks with per-frame module,
    symbol name, and address.
    """
    return _f.callstack_tracer(target, function_name_or_addr=function_name_or_addr, duration_seconds=duration_seconds)


def frida_spoof_return(
    target: str,
    function_name_or_addr: str,
    return_value: str,
) -> dict:
    """Spoof the return value of a function. Classic anti-debug bypass.

    Attaches Interceptor.onLeave and replaces the return value on every
    call. Common uses: bypass ptrace anti-debug, spoof
    isDebuggerAttached, override capability checks.

    `target`: process name or pid (string).
    `function_name_or_addr`: hex address or exported symbol name
      (e.g. 'ptrace', 'sysctl', 'isDebuggerAttached').
    `return_value`: value to force as return (numeric string, e.g.
      '0', '1', '0xffffffff'). Interpreted via ptr().

    Stays active for 30 seconds. Returns confirmation and logs the
    first 50 spoofed calls with original vs. spoofed values.
    """
    return _f.spoof_return(target, function_name_or_addr=function_name_or_addr, return_value=return_value)


def frida_child_process_trap(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """Monitor child process creation by hooking spawn/fork/exec APIs.

    Hooks: posix_spawn, posix_spawnp, fork, execve, system().
    Captures child PID, command line, argv, and environment variable
    keys for each spawned process.

    `target`: process name or pid (string).
    `duration_seconds`: how long to monitor (default 10).

    Useful for: tracing process trees, catching helper tool invocations,
    monitoring sandbox escape attempts, detecting anti-analysis forks.
    """
    return _f.child_process_trap(target, duration_seconds=duration_seconds)


def frida_memory_dump_regions(
    target: str,
    output_dir: str,
    filter_protection: str = "r--",
) -> dict:
    """Dump all readable memory regions from a target process to disk.

    Enumerates memory ranges matching `filter_protection`, reads each
    via Memory.readByteArray(), and saves to individual .bin files in
    `output_dir` named `<base_address>_<size>.bin`.

    `target`: process name or pid (string).
    `output_dir`: local directory for dump files (created if needed).
    `filter_protection`: Frida protection filter (default 'r--').
      Use 'rwx' for only fully writable+executable regions, 'rw-'
      for writable regions, etc.

    Regions larger than 64MB are skipped. 5-minute timeout.
    Returns list of dumped regions with local file paths.
    """
    return _f.memory_dump_regions(target, output_dir=output_dir, filter_protection=filter_protection)


def frida_dump_module(
    target: str,
    module_name: str,
    output_path: str,
) -> dict:
    """Dump a live in-memory module image to disk.

    Reads the full module from process memory and writes raw bytes to
    `output_path`. Critical for unpacking — the dumped image may differ
    from the on-disk binary.

    `target`: process name or pid (string).
    `module_name`: exact or partial module name (e.g. 'CoreAudio').
    `output_path`: local path to write the dumped binary.
    """
    return _f.dump_module(target, module_name=module_name, output_path=output_path)


def frida_spawn_gating(
    device_id: str | None = None,
    duration_seconds: int = 30,
) -> dict:
    """Enable spawn gating to intercept all new process spawns on a device.

    Activates device-level spawn gating. Every process that starts during
    the capture window is intercepted before execution. Captured spawns
    are automatically resumed on completion.

    `device_id`: optional Frida device id; defaults to local device.
    `duration_seconds`: how long to gate spawns (default 30, max 120).
    """
    return _f.spawn_gating(device_id=device_id, duration_seconds=duration_seconds)


def frida_cmodule_compile(
    target: str,
    c_code: str,
    symbols: dict | None = None,
    toolchain: str | None = None,
) -> dict:
    """Compile inline C code and load it into a target process via CModule.

    JIT-compiles C source inside the target process. Useful for writing
    high-performance hooks or callbacks in C instead of JS.

    `target`: process name or pid (string).
    `c_code`: C source code to compile.
    `symbols`: optional dict mapping symbol names to hex addresses for
      linking (e.g. {"my_func": "0x100004000"}).
    """
    return _f.cmodule_compile(target, c_code=c_code, symbols=symbols, toolchain=toolchain)


def frida_native_function_call(
    target: str,
    address: str,
    return_type: str,
    arg_types: list[str],
    args: list[str],
) -> dict:
    """Call a native function by address inside a target process.

    Constructs a NativeFunction with the given signature and invokes it.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100004000').
    `return_type`: return type ('void', 'int', 'pointer', 'uint64', etc.).
    `arg_types`: list of argument types (e.g. ['pointer', 'int']).
    `args`: list of argument values as strings.
    """
    return _f.native_function_call(
        target, address=address, return_type=return_type,
        arg_types=arg_types, args=args,
    )


def frida_memory_alloc(target: str, size: int) -> dict:
    """Allocate memory inside a target process via Memory.alloc.

    `target`: process name or pid (string).
    `size`: bytes to allocate (capped at 10MB).
    Returns the address of the allocated region.
    """
    return _f.memory_alloc(target, size=size)


def frida_memory_patch_code(
    target: str,
    address: str,
    hex_bytes: str,
) -> dict:
    """Patch executable code at an address using Memory.patchCode.

    Handles instruction cache flushing (ARM). Safer than raw write_memory
    for code regions.

    `target`: process name or pid (string).
    `address`: hex address to patch (e.g. '0x100004000').
    `hex_bytes`: hex-encoded bytes (e.g. 'c3', '90909090').
    """
    return _f.memory_patch_code(target, address=address, hex_bytes=hex_bytes)


def frida_memory_query_protection(target: str, address: str) -> dict:
    """Query memory protection at a specific address.

    `target`: process name or pid (string).
    `address`: hex address to query.
    Returns the protection string (e.g. 'rwx', 'r-x', 'rw-').
    """
    return _f.memory_query_protection(target, address=address)


def frida_memory_alloc_string(
    target: str,
    string: str,
    encoding: str = "utf8",
) -> dict:
    """Allocate a string inside a target process.

    `target`: process name or pid (string).
    `string`: the string value to allocate.
    `encoding`: 'utf8' (default), 'utf16', or 'ansi'.
    Returns the address of the allocated string.
    """
    return _f.memory_alloc_string(target, string=string, encoding=encoding)


def frida_memory_access_monitor(
    target: str,
    ranges: list[dict[str, str]],
    duration_seconds: int = 10,
) -> dict:
    """Monitor memory accesses (read/write/execute) on specified ranges.

    Uses MemoryAccessMonitor to capture access events.

    `target`: process name or pid (string).
    `ranges`: list of {base: "0x...", size: N} dicts defining regions.
    `duration_seconds`: how long to monitor (default 10).
    """
    return _f.memory_access_monitor(target, ranges=ranges, duration_seconds=duration_seconds)


def frida_interceptor_replace(
    target: str,
    function_addr: str,
    replacement_js: str,
    revert_after: int = 0,
) -> dict:
    """Replace a native function entirely using Interceptor.replace.

    Unlike intercept (which logs), this replaces the implementation.

    `target`: process name or pid (string).
    `function_addr`: hex address of the function to replace.
    `replacement_js`: JS code returning a NativeCallback.
    `revert_after`: auto-revert after N seconds (0 = keep forever).
    """
    return _f.interceptor_replace(
        target,
        function_addr=function_addr,
        replacement_js=replacement_js,
        revert_after=revert_after,
    )


def frida_stalker_configure(
    target: str,
    thread_id: int,
    options_json: str,
) -> dict:
    """Configure and start Stalker with advanced options on a specific thread.

    Finer control than stalker_coverage: custom event types, exclude
    ranges, and transform callbacks.

    `target`: process name or pid (string).
    `thread_id`: thread id to stalk (from frida_enumerate_threads).
    `options_json`: JSON config with keys: events, excludeRanges,
      onReceiveJs, duration_seconds.
    """
    return _f.stalker_configure(target, thread_id=thread_id, options_json=options_json)


def frida_kernel_read(address: str, length: int) -> dict:
    """Read kernel memory at an address. Requires kernel access.

    `address`: hex address (e.g. '0xffffff8000200000').
    `length`: bytes to read.
    Returns hex-encoded bytes.
    """
    return _f.kernel_read(address, length=length)


def frida_kernel_write(address: str, hex_bytes: str) -> dict:
    """Write raw bytes to kernel memory. Requires kernel access.

    `address`: hex address (e.g. '0xffffff8000200000').
    `hex_bytes`: hex-encoded bytes (e.g. 'deadbeef').
    """
    return _f.kernel_write(address, hex_bytes=hex_bytes)


def frida_kernel_scan(address: str, size: int, pattern: str) -> dict:
    """Scan kernel memory for a hex pattern. Requires kernel access.

    `address`: start address (hex string).
    `size`: number of bytes to scan.
    `pattern`: Frida hex pattern (e.g. '48 8b ?? c3').
    """
    return _f.kernel_scan(address, size=size, pattern=pattern)


def frida_kernel_enumerate_modules() -> dict:
    """Enumerate kernel modules (kexts). Requires kernel access.

    Returns name, base address, size, and path for each kernel module.
    """
    return _f.kernel_enumerate_modules()


def frida_read_typed(target: str, address: str, type: str) -> dict:
    """Read a typed value from process memory.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100004000').
    `type`: one of 'pointer', 's8', 'u8', 's16', 'u16', 's32', 'u32',
      's64', 'u64', 'float', 'double', 'utf8', 'utf16', 'cstring', 'ansi'.
    """
    return _f.read_typed(target, address=address, type=type)


def frida_write_typed(target: str, address: str, type: str, value: str) -> dict:
    """Write a typed value to process memory.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100004000').
    `type`: one of 'pointer', 's8', 'u8', 's16', 'u16', 's32', 'u32',
      's64', 'u64', 'float', 'double', 'utf8', 'utf16', 'cstring', 'ansi'.
    `value`: string representation of the value to write.
    """
    return _f.write_typed(target, address=address, type=type, value=value)


def frida_cloak_thread(target: str, thread_id: int | None = None) -> dict:
    """Hide a thread from in-process detection using Frida Cloak API.

    `target`: process name or pid (string).
    `thread_id`: OS thread id to hide. If None, hides the current thread.
    """
    return _f.cloak_thread(target, thread_id=thread_id)


def frida_cloak_range(target: str, address: str, size: int) -> dict:
    """Hide a memory range from detection using Frida Cloak API.

    `target`: process name or pid (string).
    `address`: base address (hex string).
    `size`: range size in bytes.
    """
    return _f.cloak_range(target, address=address, size=size)


def frida_cloak_fd(target: str, fd: int) -> dict:
    """Hide a file descriptor from detection using Frida Cloak API.

    `target`: process name or pid (string).
    `fd`: file descriptor number to cloak.
    """
    return _f.cloak_fd(target, fd=fd)


def frida_profiler_start(
    target: str,
    addresses: list[str],
    sampler_type: str = "wall_clock",
    duration_seconds: int = 10,
) -> dict:
    """Start profiling specific addresses in the target process.

    `target`: process name or pid (string).
    `addresses`: list of hex addresses to instrument.
    `sampler_type`: 'wall_clock' (default) or 'cycle_count'.
    `duration_seconds`: how long to profile (default 10).
    """
    return _f.profiler_start(
        target, addresses=addresses,
        sampler_type=sampler_type, duration_seconds=duration_seconds,
    )


def frida_profiler_report(target: str) -> dict:
    """Retrieve the profiler report from a previous profiler_start.

    `target`: process name or pid (string). Must have an active profiler
    from a prior `frida_profiler_start` call.
    """
    return _f.profiler_report(target)


def frida_instruction_parse(target: str, address: str) -> dict:
    """Disassemble a single instruction at an address.

    `target`: process name or pid (string).
    `address`: hex address to disassemble.
    Returns mnemonic, operands, size, and instruction string.
    """
    return _f.instruction_parse(target, address=address)


def frida_hexdump(target: str, address: str, length: int = 256) -> dict:
    """Formatted hex dump of memory at an address.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100000000').
    `length`: bytes to dump (default 256, max 4096).
    """
    return _f.hexdump_memory(target, address=address, length=length)


def frida_set_exception_handler(target: str, duration_seconds: int = 10) -> dict:
    """Install an in-process exception handler to catch crashes.

    Hooks Process.setExceptionHandler. Captured exceptions include
    type, faulting address, and full register context.

    `target`: process name or pid (string).
    `duration_seconds`: how long to keep the handler active (default 10).
    """
    return _f.set_exception_handler(target, duration_seconds=duration_seconds)


def frida_run_on_thread(target: str, thread_id: int, js_code: str) -> dict:
    """Execute JavaScript on a specific thread in the target process.

    Uses Process.runOnThread() to schedule execution.

    `target`: process name or pid (string).
    `thread_id`: OS thread id (from frida_enumerate_threads).
    `js_code`: JavaScript code to execute on the thread.
    """
    return _f.run_on_thread(target, thread_id=thread_id, js_code=js_code)




def frida_module_map_snapshot(target: str, address: str | None = None, name: str | None = None) -> dict:
    """Use GumJS ModuleMap to snapshot modules and query address/name."""
    return _f.module_map_snapshot(target, address=address, name=name)


def frida_memory_copy(target: str, dst: str, src: str, size: int) -> dict:
    """Call GumJS Memory.copy()."""
    return _f.memory_copy(target, dst=dst, src=src, size=size)


def frida_memory_scan_sync(target: str, address: str, size: int, pattern: str) -> dict:
    """Call GumJS Memory.scanSync()."""
    return _f.memory_scan_sync(target, address=address, size=size, pattern=pattern)


def frida_memory_check_code_pointer(target: str, address: str) -> dict:
    """Call GumJS Memory.checkCodePointer()."""
    return _f.memory_check_code_pointer(target, address=address)


def frida_memory_dup(target: str, address: str, size: int) -> dict:
    """Call GumJS Memory.dup()."""
    return _f.memory_dup(target, address=address, size=size)


def frida_module_load(target: str, path: str) -> dict:
    """Call GumJS Module.load()."""
    return _f.module_load(target, path=path)


def frida_module_ensure_initialized(target: str, module_name: str) -> dict:
    """Call GumJS Module.ensureInitialized()."""
    return _f.module_ensure_initialized(target, module_name=module_name)


def frida_module_find_global_export_by_name(target: str, name: str) -> dict:
    """Call GumJS Module.findGlobalExportByName()."""
    return _f.module_find_global_export_by_name(target, name=name)


def frida_process_attach_thread_observer(
    target: str,
    duration_seconds: int = 10,
    event_limit: int = 200,
) -> dict:
    """Call GumJS Process.attachThreadObserver() for a bounded window."""
    return _f.process_attach_thread_observer(target, duration_seconds=duration_seconds, event_limit=event_limit)


def frida_process_attach_module_observer(
    target: str,
    duration_seconds: int = 10,
    event_limit: int = 200,
) -> dict:
    """Call GumJS Process.attachModuleObserver() for a bounded window."""
    return _f.process_attach_module_observer(target, duration_seconds=duration_seconds, event_limit=event_limit)


def frida_gum_script_evaluate(target: str, name: str, source: str) -> dict:
    """Call GumJS Script.evaluate()."""
    return _f.gum_script_evaluate(target, name=name, source=source)


def frida_gum_script_load(target: str, name: str, source: str, duration_seconds: int = 5) -> dict:
    """Call GumJS Script.load() for a bounded window."""
    return _f.gum_script_load(target, name=name, source=source, duration_seconds=duration_seconds)


def frida_gum_script_register_source_map(target: str, name: str, source_map_json: str) -> dict:
    """Call GumJS Script.registerSourceMap()."""
    return _f.gum_script_register_source_map(target, name=name, source_map_json=source_map_json)


def frida_interceptor_flush(target: str) -> dict:
    """Call GumJS Interceptor.flush()."""
    return _f.interceptor_flush(target)


def frida_interceptor_revert(target: str, address: str) -> dict:
    """Call GumJS Interceptor.revert()."""
    return _f.interceptor_revert(target, address=address)


def frida_system_function_call(
    target: str,
    address: str,
    return_type: str,
    arg_types: list[str],
    args: list[str],
) -> dict:
    """Call a native function using GumJS SystemFunction."""
    return _f.system_function_call(target, address=address, return_type=return_type, arg_types=arg_types, args=args)


def frida_thread_hardware_breakpoint(
    target: str,
    thread_id: int,
    breakpoint_id: int,
    address: str,
    unset: bool = False,
) -> dict:
    """Set or unset a hardware breakpoint with GumJS Thread API."""
    return _f.thread_hardware_breakpoint(
        target,
        thread_id=thread_id,
        breakpoint_id=breakpoint_id,
        address=address,
        unset=unset,
    )


def frida_thread_hardware_watchpoint(
    target: str,
    thread_id: int,
    watchpoint_id: int,
    address: str,
    size: int = 1,
    conditions: str = "rw",
    unset: bool = False,
) -> dict:
    """Set or unset a hardware watchpoint with GumJS Thread API."""
    return _f.thread_hardware_watchpoint(
        target,
        thread_id=thread_id,
        watchpoint_id=watchpoint_id,
        address=address,
        size=size,
        conditions=conditions,
        unset=unset,
    )


def frida_code_writer_template(arch: str, pc: str | None = None) -> dict:
    """Generate a GumJS CodeWriter/Relocator template."""
    return _f.code_writer_template(arch, pc=pc)


def frida_kernel_enumerate_ranges(protection: str = "r--") -> dict:
    """Call Kernel.enumerateRanges()."""
    return _f.kernel_enumerate_ranges(protection=protection)


def frida_kernel_enumerate_module_ranges(module_name: str, protection: str = "r--") -> dict:
    """Call Kernel.enumerateModuleRanges()."""
    return _f.kernel_enumerate_module_ranges(module_name, protection=protection)


def frida_kernel_alloc(size: int) -> dict:
    """Call Kernel.alloc()."""
    return _f.kernel_alloc(size)


def frida_kernel_protect(address: str, size: int, protection: str) -> dict:
    """Call Kernel.protect()."""
    return _f.kernel_protect(address, size=size, protection=protection)


def frida_stalker_add_call_probe(target: str, address: str, duration_seconds: int = 10) -> dict:
    """Call Stalker.addCallProbe() and remove it before returning."""
    return _f.stalker_add_call_probe(target, address=address, duration_seconds=duration_seconds)


def frida_stalker_invalidate(target: str, address: str, thread_id: int | None = None) -> dict:
    """Call Stalker.invalidate()."""
    return _f.stalker_invalidate(target, address=address, thread_id=thread_id)


def frida_rust_module_compile(target: str, rust_code: str, symbols: dict[str, str] | None = None) -> dict:
    """Compile a GumJS RustModule inside the target."""
    return _f.rust_module_compile(target, rust_code=rust_code, symbols=symbols)


def frida_checksum_memory(target: str, checksum_type: str, address: str, size: int) -> dict:
    """Compute a GumJS Checksum over a target memory range."""
    return _f.checksum_memory(target, checksum_type=checksum_type, address=address, size=size)


def frida_worker_template(worker_source: str | None = None) -> dict:
    """Generate a GumJS Worker template."""
    return _f.worker_template(worker_source=worker_source)


def frida_sampler_template(kind: str = "backtrace") -> dict:
    """Generate a GumJS Sampler template."""
    return _f.sampler_template(kind=kind)
def register_instrumentation_tools(mcp) -> None:
    """Register instrumentation tools with FastMCP."""
    register_module_tools(mcp, globals())
