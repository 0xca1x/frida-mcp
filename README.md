# fuzzmind-frida-mcp

![Version](https://img.shields.io/badge/version-0.1.0-2f81f7)
![MCP](https://img.shields.io/badge/mcp-stdio-00a6a6)
![Frida](https://img.shields.io/badge/frida-17.9.3%20to%20%3C18-f97316)
![Frida Tools](https://img.shields.io/badge/frida--tools-14.8.1%20to%20%3C15-8b5cf6)
![Python](https://img.shields.io/badge/python-3.11%2B-3776ab)
![License](https://img.shields.io/badge/license-MIT-6c757d)

A [Frida](https://frida.re) MCP server for authorized dynamic analysis and application security research. It exposes device/session management, script injection, process and memory inspection, runtime helpers, and platform-focused workflows for macOS, iOS, Android, Windows, Linux, and kernel targets.

## Positioning

This is a broad Frida automation layer for FuzzMind research workflows, not a
minimal general-purpose Frida wrapper. It is designed so MCP-capable agents can
drive long-running Frida sessions, scripts, runtime APIs, platform workflows,
and security recipes with structured tool calls.

The goal is close practical coverage of the Frida Python API, GumJS API,
frida-tools workflows, Gadget setup, and common application-security research
tasks. It does not claim byte-for-byte or 100% behavioral parity with every
Frida CLI interaction, every language binding, or every future upstream API.

For standalone Frida users, the official `frida`, `frida-trace`, and
`frida-tools` CLI remain the smallest interface. This MCP is intentionally
larger because it is also meant to integrate with FuzzMind internal research
products and systems, including Mantis, Corvus, and others. These integrations
are optional and are not required to run this MCP.

## Install

```bash
uv tool install fuzzmind-frida-mcp
# or
pip install fuzzmind-frida-mcp
```

Requires [Frida](https://frida.re). Package dependencies install `frida>=17.9.3,<18` and `frida-tools>=14.8.1,<15`.

## Version support

| Component | Supported version |
|---|---|
| fuzzmind-frida-mcp | 0.1.0 |
| Python | 3.11+ |
| frida | 17.9.3 to <18 |
| frida-tools | 14.8.1 to <15 |

Frida 17+ API users must bundle or provide ObjC/Java/Swift bridge packages when using those high-level runtimes. The MCP injects safe bridge stubs when bridge packages are unavailable, so runtime tools fail with explicit guidance instead of JavaScript `ReferenceError`.

The MCP runtime itself only needs Python Frida bindings and frida-tools. Node.js, TypeScript, and Rust Frida bindings are not required to run this server. ObjC/Java/Swift bridges are optional runtime packages for high-level target APIs; use `frida_bridge_status` to inspect them and `frida_bridge_install` to install them through official `frida-pm` when needed. By default these bridge packages are stored under `~/.fuzzmind/frida-mcp/frida-bridges` (or `FUZZMIND_FRIDA_BRIDGE_ROOT`), so PyPI/uv installations do not need a writable source checkout.

Android frida-server helpers operate on a user-supplied frida-server binary; the MCP does not download platform binaries for you. Gadget helpers generate configs and stage assets, but signing, repackaging, and platform policy changes remain explicit external steps.

## Quick start

### Claude Code

```bash
claude mcp add frida -- fuzzmind-frida-mcp
```

### Codex / OpenCode / generic MCP

This server speaks standard MCP over stdio. It is not tied to Claude Code; use
the same command with Codex, OpenCode, Claude Desktop, or any MCP client that
can launch a stdio server.

```json
{
  "mcpServers": {
    "frida": {
      "command": "fuzzmind-frida-mcp"
    }
  }
}
```

### Run standalone

```bash
fuzzmind-frida-mcp
```

When started by an MCP client, this runs as a stdio server and waits for client
messages. When run directly from an interactive terminal, it prints a short
usage note and exits so stdout is not polluted accidentally. For a local sanity
check:

```bash
fuzzmind-frida-mcp --check
fuzzmind-frida-mcp --diagnose
fuzzmind-frida-mcp --version
```

To force stdio server mode from a terminal:

```bash
fuzzmind-frida-mcp --stdio
```

## Tool catalogue

### Frida CLI option mapping

The MCP exposes Frida CLI-style controls as structured tool arguments instead of requiring an agent to build shell commands:

| Frida CLI option | MCP surface |
|---|---|
| `-D`, `-U`, `-R`, `-H`, certificates, origin, token, keepalive | device/remote tools and `device_id` arguments |
| `-f`, `-p`, `-n`, `-N`, `-F`, `-W` | `frida_connect`, `frida_await_spawn`, `frida_spawn_with_options` |
| `--stdio`, `--aux`, `--realm`, `--pause` | `frida_connect` / `frida_spawn_with_options` arguments |
| `-l`, `-e`, `--runtime`, `--debug`, `-P`, `--auto-perform`, `--exit-on-error` | `frida_script_load`, `frida_script_load_file`, `frida_script_run_file`, `frida_eval`, `frida_interactive_eval` |
| `-C`, `--toolchain` | `frida_cmodule_compile` |
| `-c`, `-O`, `-q`, `-t`, `-o`, `--eternalize`, `--kill-on-exit` | `frida_codeshare_run`, `frida_cli_options_file_parse`, `frida_script_eternalize`, script output/event tools |
| `frida-trace`, `frida-discover`, `gum-graft` | `frida_trace`, `frida_discover`, `frida_gum_graft` |

### Agent workflows

| Tool | Description |
|---|---|
| `frida_target_snapshot` | First-step target snapshot for agents: process metadata, runtime bridges, modules, threads, range counts, and recommended next tools |
| `frida_host_diagnostics` | Inspect local Frida, tool, device, and process-listing readiness |
| `frida_bridge_status` | Check whether Frida 17 ObjC/Java/Swift bridge packages can be bundled |
| `frida_bridge_install` | Install ObjC/Java/Swift bridge packages with official `frida-pm` |
| `frida_gadget_config` | Generate a Frida Gadget configuration |
| `frida_gadget_script_template` | Generate a Gadget-compatible script template |
| `frida_gadget_bundle_assets` | Stage Gadget library, config, and optional script into a packaging directory |
| `frida_android_frida_server_status` | Check Android adb/frida-server readiness without modifying the device |
| `frida_android_frida_server_install` | Push a user-supplied frida-server binary to an Android device |
| `frida_android_frida_server_start` | Start frida-server on an Android device |
| `frida_android_frida_server_stop` | Stop frida-server on an Android device |
| `frida_android_frida_server_setup` | Install, start, and optionally port-forward frida-server |
| `frida_android_port_forward` | Create an adb TCP port forward for frida-server or Gadget |
| `frida_android_port_forward_list` | List adb TCP port forwards |
| `frida_android_port_forward_remove` | Remove an adb TCP port forward |
| `frida_android_device_prepare` | Summarize Android readiness for Frida app analysis |
| `frida_ios_device_prepare` | Summarize iOS/macOS USB-device readiness for Frida app analysis |
| `frida_gumjs_template` | Generate advanced GumJS templates for direct `frida_script_load` use |

### Official Frida APIs

| Tool | Description |
|---|---|
| `frida_device_get_usb` | Resolve the first USB device with `get_usb_device()` |
| `frida_device_get_remote` | Resolve Frida's default remote device |
| `frida_device_get_matching` | Find a device with a DeviceManager predicate |
| `frida_remote_device_add` | Add a remote device with certificate/origin/token/keepalive options |
| `frida_remote_device_remove` | Remove a remote device from DeviceManager |
| `frida_device_query_system_parameters` | Read `Device.query_system_parameters()` |
| `frida_device_override_option` | Set an official Device option override |
| `frida_device_unpair` | Unpair a paired device |
| `frida_device_input` | Send raw stdin bytes to a spawned target |
| `frida_device_get_process` | Resolve a process with `Device.get_process()` |
| `frida_device_is_lost` | Check `Device.is_lost()` |
| `frida_inject_library_blob` | Inject a library from bytes with `Device.inject_library_blob()` |
| `frida_spawn_with_options` | Spawn with argv/env/envp/cwd/stdio/aux without attaching |
| `frida_pending_spawn_list` | List device-level pending spawns |
| `frida_pending_children_list` | List session child-gating pending children |
| `frida_event_subscribe` | Subscribe to DeviceManager, Device, or Session events |
| `frida_event_get_events` | Read queued official event-subscription events |
| `frida_event_unsubscribe` | Remove an official event subscription |
| `frida_bus_attach` | Attach to a device bus and queue bus messages |
| `frida_bus_post` | Post a bus message, optionally with binary data |
| `frida_bus_get_events` | Read queued bus events |
| `frida_bus_detach` | Drop a bus event queue |
| `frida_session_enable_child_gating` | Enable official session child gating |
| `frida_session_disable_child_gating` | Disable official session child gating |
| `frida_session_resume` | Resume a session through `Session.resume()` |
| `frida_session_is_detached` | Check `Session.is_detached()` |
| `frida_session_setup_peer_connection` | Configure peer connection / relay support |
| `frida_session_join_portal` | Join a PortalService from a session |
| `frida_session_leave_portal` | Terminate a portal membership |
| `frida_script_load_bytes` | Load compiled script bytes |
| `frida_session_compile_script` | Compile script source through the active session |
| `frida_session_snapshot_script` | Build a Frida script snapshot |
| `frida_script_list_exports` | List exported RPC methods |
| `frida_script_enable_debugger` | Enable script debugger |
| `frida_script_disable_debugger` | Disable script debugger |
| `frida_script_post_binary` | Post a message with binary data to a script |
| `frida_script_set_log_handler` | Queue Script log handler events |
| `frida_script_get_log_events` | Read queued Script log events |
| `frida_script_get_log_handler` | Inspect the active Script log handler |
| `frida_script_reset_log_handler` | Reset Script logging to the Frida default |
| `frida_compiler_build` | Build a bundle with `frida.Compiler` |
| `frida_compiler_watch` | Start `Compiler.watch()` and queue compiler events |
| `frida_compiler_watch_get_events` | Read queued compiler watch events |
| `frida_compiler_watch_stop` | Stop tracking a compiler watch |
| `frida_package_search` | Search Frida packages with PackageManager |
| `frida_package_install` | Install Frida packages with PackageManager |
| `frida_package_registry` | Read `PackageManager.registry` |
| `frida_portal_start` | Start a PortalService with EndpointParameters |
| `frida_portal_stop` | Stop a PortalService |
| `frida_portal_broadcast` | Broadcast through a PortalService |
| `frida_portal_narrowcast` | Narrowcast through a PortalService tag |
| `frida_portal_post` | Post to one PortalService connection |
| `frida_portal_tag` | Tag a PortalService connection |
| `frida_portal_untag` | Remove a PortalService tag |
| `frida_portal_enumerate_tags` | List PortalService connection tags |
| `frida_portal_get_events` | Read PortalService events |
| `frida_service_request` | Open a device service and send one request |
| `frida_open_channel` | Open a raw device channel readiness probe |
| `frida_channel_open` | Open a raw device channel for repeated IO |
| `frida_channel_read` | Read bytes from an open device channel |
| `frida_channel_write` | Write bytes to an open device channel |
| `frida_channel_close` | Close an open device channel |
| `frida_service_open` | Open a device service for repeated requests/events |
| `frida_service_request_by_id` | Send a request through an open service |
| `frida_service_get_events` | Read queued service events |
| `frida_service_close` | Cancel and forget an open service |
| `frida_module_map_snapshot` | Snapshot/query modules with GumJS ModuleMap |
| `frida_memory_copy` | Copy memory with `Memory.copy()` |
| `frida_memory_scan_sync` | Scan memory synchronously |
| `frida_memory_check_code_pointer` | Validate a code pointer |
| `frida_memory_dup` | Duplicate memory with `Memory.dup()` |
| `frida_module_load` | Load a module with `Module.load()` |
| `frida_module_ensure_initialized` | Force module initialization |
| `frida_module_find_global_export_by_name` | Resolve a global export by name |
| `frida_process_attach_thread_observer` | Observe thread add/remove events |
| `frida_process_attach_module_observer` | Observe module load/unload events |
| `frida_gum_script_evaluate` | Evaluate code with GumJS `Script.evaluate()` |
| `frida_gum_script_load` | Load code with GumJS `Script.load()` |
| `frida_gum_script_register_source_map` | Register a GumJS source map |
| `frida_interceptor_flush` | Flush Interceptor changes |
| `frida_interceptor_revert` | Revert an Interceptor replacement |
| `frida_system_function_call` | Call a native function with SystemFunction |
| `frida_thread_hardware_breakpoint` | Set/unset a hardware breakpoint |
| `frida_thread_hardware_watchpoint` | Set/unset a hardware watchpoint |
| `frida_code_writer_template` | Generate CodeWriter/Relocator templates |
| `frida_kernel_enumerate_ranges` | Enumerate kernel ranges |
| `frida_kernel_enumerate_module_ranges` | Enumerate kernel module ranges |
| `frida_kernel_alloc` | Allocate kernel memory |
| `frida_kernel_protect` | Change kernel memory protection |
| `frida_stalker_add_call_probe` | Install a temporary Stalker call probe |
| `frida_stalker_invalidate` | Invalidate Stalker translations |
| `frida_rust_module_compile` | Compile a GumJS RustModule |
| `frida_checksum_memory` | Compute a GumJS Checksum over memory |
| `frida_worker_template` | Generate a GumJS Worker template |
| `frida_sampler_template` | Generate a GumJS Sampler template |
| `frida_java_enumerate_class_loaders` | Enumerate Java class loaders |
| `frida_java_choose` | Find live Java instances |
| `frida_java_backtrace` | Capture Java backtrace frames |
| `frida_java_deoptimize` | Trigger Java deoptimization |
| `frida_objc_implement_template` | Generate an ObjC.implement template |
| `frida_objc_bind_data` | Bind host data to an ObjC object |

### Device management

| Tool | Description |
|---|---|
| `frida_list_devices` | List all available Frida devices (USB, remote, local) |
| `frida_get_device_info` | Get info about a specific Frida device or the default local device |
| `frida_remote_device_add` | Add a remote Frida server with official DeviceManager options |
| `frida_list_apps` | List all installed applications on a device (not just running) |
| `frida_get_frontmost_app` | Get the frontmost (foreground) application on a device |
| `frida_launch_app` | Spawn and resume an application by bundle/package identifier |
| `frida_kill_app` | Kill a process by PID or name on a device |
| `frida_resume_process` | Resume a suspended process by PID |

### Session lifecycle

| Tool | Description |
|---|---|
| `frida_connect` | Connect/attach/spawn/await a target and create a persistent Frida session |
| `frida_await_spawn` | Wait for a gated spawn matching a pattern, optionally attach and resume |
| `frida_disconnect` | Disconnect from the current or a specified Frida session |
| `frida_list_sessions` | List all active Frida sessions |
| `frida_switch_session` | Switch the active Frida session |
| `frida_is_connected` | Check if the current Frida session is alive |
| `frida_session_get_events` | Read lifecycle events such as detach/crash/disconnect |
| `frida_session_clear_events` | Clear lifecycle events for a persistent session |
| `frida_session_recover` | Recover a broken/crashed Frida session by re-attaching |
| `frida_interactive_eval` | Execute arbitrary JS in an existing persistent Frida session (REPL) |

### Long-running scripts and RPC

| Tool | Description |
|---|---|
| `frida_script_load` | Load a long-running Frida script with runtime, parameters, debugger, and error policy options |
| `frida_script_load_file` | Load a local JavaScript file as a long-running Frida script with the same script options |
| `frida_script_list` | List scripts loaded in a persistent session |
| `frida_script_unload` | Unload a long-running script by script id |
| `frida_script_reload` | Reload a long-running script while preserving name and kind |
| `frida_script_call_rpc` | Call a function exposed through `rpc.exports` |
| `frida_script_post_message` | Post a JSON-serialisable message to a long-running script |
| `frida_script_get_events` | Read queued events emitted by long-running scripts |
| `frida_script_clear_events` | Clear queued events for one script or a whole session |
| `frida_script_export_events` | Export queued script events to JSON or JSONL |

### Hooks

| Tool | Description |
|---|---|
| `frida_install_hook` | Install a persistent hook and return its script id |
| `frida_get_hook_messages` | Get queued events from persistent hook scripts |
| `frida_clear_hook_messages` | Clear hook event queues for the active session |
| `frida_uninstall_hooks` | Unload all persistent hook scripts in the current session |
| `frida_list_hooks` | List all installed persistent hooks in the current session |
| `frida_hook_native_by_offset` | Hook a native function by module name + hex offset |
| `frida_hook_native_function` | Hook a native function by address using Interceptor.attach |

### Memory

| Tool | Description |
|---|---|
| `frida_read_memory` | Read raw memory from a target process |
| `frida_write_memory` | Write raw bytes to process memory |
| `frida_memory_scan` | Scan process memory for a hex pattern |
| `frida_memory_protect` | Change memory protection on a region |
| `frida_enumerate_ranges` | Enumerate memory ranges matching a protection filter |
| `frida_get_module_base` | Get base address of a module by name (partial match) |
| `frida_memory_dump_regions` | Dump all readable memory regions from a target process to disk |
| `frida_dump_module` | Dump a live in-memory module image to disk |
| `frida_memory_alloc` | Allocate memory inside a target process via Memory.alloc |
| `frida_memory_patch_code` | Patch executable code at an address using Memory.patchCode |
| `frida_memory_query_protection` | Query memory protection at a specific address |
| `frida_memory_alloc_string` | Allocate a string inside a target process |
| `frida_memory_access_monitor` | Monitor memory accesses (read/write/execute) on specified ranges |
| `frida_read_typed` | Read a typed value from process memory |
| `frida_write_typed` | Write a typed value to process memory |
| `frida_hexdump` | Formatted hex dump of memory at an address |
| `frida_memory_dup` | Duplicate memory with GumJS `Memory.dup()` |

### Process introspection

| Tool | Description |
|---|---|
| `frida_check` | Verify frida + frida-tools install state and version |
| `frida_list_processes` | Enumerate running processes via Frida's local device |
| `frida_process_info` | Get detailed process metadata (pid, arch, platform, etc.) |
| `frida_enumerate_threads` | List all threads with state and registers |
| `frida_enumerate_modules` | List all loaded modules in a target process |
| `frida_enumerate_exports` | List exported symbols from a specific module |
| `frida_enumerate_imports` | Enumerate imports of a module |
| `frida_enumerate_symbols` | List all symbols (not just exports) from a module |
| `frida_enumerate_sections` | Enumerate sections (name, base, size, protection) of a module |
| `frida_enumerate_dependencies` | Enumerate dependencies of a module |
| `frida_enumerate_malloc_ranges` | Enumerate malloc heap ranges filtered by memory protection |
| `frida_find_export_by_name` | Find a single export by name, optionally scoped to a module |
| `frida_find_symbol_by_name` | Find a symbol by name within a module |
| `frida_resolve_debug_symbol` | Resolve a debug symbol from an address |
| `frida_find_functions_named` | Find all functions with an exact name |
| `frida_find_functions_matching` | Find functions matching a glob pattern |
| `frida_load_debug_symbols` | Load debug symbols from a file (e.g. dSYM) |

### Interceptor

| Tool | Description |
|---|---|
| `frida_intercept_objc_method` | Hook a specific ObjC method via Interceptor and log invocations |
| `frida_interceptor_replace` | Replace a native function entirely using Interceptor.replace |
| `frida_spoof_return` | Spoof the return value of a function |
| `frida_callstack_tracer` | Trace call stacks for a specific function, symbolicated |

### Stalker

| Tool | Description |
|---|---|
| `frida_stalker_coverage` | Collect basic-block coverage using Frida Stalker |
| `frida_stalker_configure` | Configure and start Stalker with advanced options on a specific thread |
| `frida_spawn_gating` | Enable spawn gating to intercept all new process spawns |
| `frida_child_process_trap` | Monitor child process creation by hooking spawn/fork/exec APIs |
| `frida_discover` | Run official `frida-discover` for internal function discovery |
| `frida_gum_graft` | Run official `gum-graft` when available |

### Script injection

| Tool | Description |
|---|---|
| `frida_script_run_file` | Run a local Frida JS script against a process with runtime/parameters options |
| `frida_eval` | Evaluate inline JavaScript against a target |
| `frida_cli_compile_bundle` | Compile a Frida JS script with `frida-compile` |
| `frida_cli_options_file_parse` | Parse a Frida CLI `--options-file` into tokens for agent planning |
| `frida_codeshare_run` | Run an official frida-tools CodeShare script via `frida -c` |
| `frida_script_eternalize` | Inject a script and eternalize it so it survives session detach |
| `frida_cmodule_compile` | Compile inline C code and load it via CModule, with optional toolchain selection |
| `frida_native_function_call` | Call a native function by address inside a target process |
| `frida_inject_library` | Inject a shared library (.dylib / .so) into a target process |
| `frida_trace` | frida-trace function-tracing capture for N seconds |

### Objective-C

| Tool | Description |
|---|---|
| `frida_objc_classes` | Enumerate ObjC class names matching a pattern |
| `frida_objc_choose` | Find live ObjC instances of a class on the heap |
| `frida_objc_register_class` | Register a new ObjC class at runtime |
| `frida_objc_create_block` | Create an ObjC block at runtime |
| `frida_objc_schedule` | Schedule JavaScript on the ObjC main thread dispatch queue |
| `frida_objc_inspect_object` | Inspect an ObjC object at a given address |
| `frida_objc_call_method` | Call an ObjC method on an object at a given address |
| `frida_objc_list_protocols` | List all registered ObjC protocols |
| `frida_dump_class` | Dump full ObjC class structure: methods, protocols, ivars |
| `frida_xpc_intercept` | xpcspy-style XPC message capture |

### Swift

| Tool | Description |
|---|---|
| `frida_swift_demangle` | Demangle a Swift symbol using the in-process Swift runtime |
| `frida_api_resolver` | Resolve API symbols using Frida's ApiResolver |

### Java / Android Runtime

| Tool | Description |
|---|---|
| `frida_java_list_classes` | Enumerate loaded Java/ART classes |
| `frida_java_list_methods` | List declared methods of a Java class |
| `frida_java_hook_method` | Hook all overloads of a Java method |
| `frida_java_call` | Execute arbitrary JS inside a Java.perform() block |
| `frida_java_load_dex` | Dynamically load a DEX file into an Android process |

### Security bypass

| Tool | Description |
|---|---|
| `frida_ssl_pinning_disable` | Universal SSL pinning bypass (Android + iOS/macOS) |
| `frida_ssl_keylog` | Extract TLS session keys for Wireshark decryption |
| `frida_crypto_hook` | Hook crypto APIs to capture encryption/decryption operations |
| `frida_string_sniffer` | Sniff strings as they are created at runtime |
| `frida_time_warp` | Warp time perception for a target process |
| `frida_anti_root_bypass` | Bypass root/jailbreak detection |
| `frida_anti_debug_bypass` | Bypass debugger detection mechanisms |

### File system

| Tool | Description |
|---|---|
| `frida_file_list` | List files in a directory on the target's filesystem |
| `frida_file_read` | Read a file from the target's filesystem view |
| `frida_file_download` | Download a file from the target to the local host |
| `frida_file_write` | Write data to a file on the target's filesystem |
| `frida_file_seek_read` | Read bytes from a file at a specific offset |

### Database

| Tool | Description |
|---|---|
| `frida_sqlite_open` | Open a SQLite database and list tables |
| `frida_sqlite_exec` | Execute SQL against a SQLite database inside the target |
| `frida_sqlite_dump` | Full schema + data dump of a SQLite database |

### Network

| Tool | Description |
|---|---|
| `frida_socket_connect` | Open a TCP/UDP connection from within the target process |
| `frida_socket_listen` | Open a listening socket inside the target process |

### Cloak

| Tool | Description |
|---|---|
| `frida_cloak_thread` | Hide a thread from in-process detection |
| `frida_cloak_range` | Hide a memory range from detection |
| `frida_cloak_fd` | Hide a file descriptor from detection |

### Profiler

| Tool | Description |
|---|---|
| `frida_profiler_start` | Start profiling specific addresses |
| `frida_profiler_report` | Retrieve the profiler report |
| `frida_instruction_parse` | Disassemble a single instruction at an address |

### Kernel

| Tool | Description |
|---|---|
| `frida_kernel_read` | Read kernel memory at an address |
| `frida_kernel_write` | Write raw bytes to kernel memory |
| `frida_kernel_scan` | Scan kernel memory for a hex pattern |
| `frida_kernel_enumerate_modules` | Enumerate kernel modules (kexts) |

### Windows platform

| Tool | Description |
|---|---|
| `frida_win_api_monitor` | Hook Win32 APIs and log call arguments |
| `frida_win_dotnet_list_assemblies` | Enumerate .NET assemblies loaded in a target process |
| `frida_win_dotnet_hook_method` | Hook a .NET method and log invocations |
| `frida_win_registry_monitor` | Monitor Registry operations |
| `frida_win_com_intercept` | Intercept a COM vtable method call |
| `frida_win_etw_bypass` | Patch EtwEventWrite to neutralise ETW event logging |
| `frida_win_crypto_hook` | Hook CryptoAPI and BCrypt encryption/decryption |
| `frida_win_amsi_bypass` | Patch AmsiScanBuffer to bypass AMSI scanning |
| `frida_win_hollowing_detect` | Detect process hollowing via PE section comparison |

### Android platform

| Tool | Description |
|---|---|
| `frida_android_content_provider_hook` | Hook ContentResolver operations for a specific authority |
| `frida_android_intent_intercept` | Intercept Intent dispatching |
| `frida_android_shared_prefs_dump` | Dump SharedPreferences key-value pairs |
| `frida_android_webview_hook` | Hook WebView methods to capture JS bridge interactions |
| `frida_android_jni_hook` | Hook JNI functions in libart.so |

### iOS / macOS platform

| Tool | Description |
|---|---|
| `frida_ios_keychain_dump` | Dump accessible Keychain items from a target process |
| `frida_ios_ats_bypass` | Disable App Transport Security for a target process |
| `frida_ios_url_scheme_hook` | Hook URL scheme and Universal Link handling |

### Linux platform

| Tool | Description |
|---|---|
| `frida_linux_syscall_hook` | Hook libc syscall wrappers and log arguments |
| `frida_linux_preload_detect` | Detect LD_PRELOAD and suspicious library injections |
| `frida_linux_dbus_intercept` | Intercept D-Bus method calls and messages |
| `frida_linux_got_hook` | Overwrite a GOT/PLT entry for a function in a target module |
| `frida_linux_seccomp_detect` | Detect seccomp sandbox status in a target process |

### Misc

| Tool | Description |
|---|---|
| `frida_set_exception_handler` | Install an in-process exception handler to catch crashes |
| `frida_run_on_thread` | Execute JavaScript on a specific thread |
| `frida_heap_search` | Search the heap for live ObjC instances of a class |

## Platform support

| Platform | Capabilities |
|---|---|
| **Cross-platform** | Script/session lifecycle, RPC, event queues, process, memory, hooks, stalker, interceptor, ObjC, Swift, Java, files, DB, network, cloak, profiler, kernel, agent workflows |
| **macOS / iOS** | ObjC runtime, XPC interception, Keychain, ATS bypass, URL schemes, SSL pinning, code signing |
| **Android** | Java/ART bridge, JNI hooks, Intent interception, ContentProvider, WebView, SharedPrefs, root bypass |
| **Windows** | Win32 API monitoring, .NET/CLR, COM interception, Registry, ETW bypass, AMSI bypass, CryptoAPI, hollowing detection |
| **Linux** | Syscall hooks, LD_PRELOAD detection, D-Bus interception, GOT/PLT hooks, seccomp detection |
| **Kernel** | Kernel memory read/write/scan, kext enumeration |

## Capability summary

| Feature | Support |
|---|---|
| Tool catalogue | Registered MCP tools for Frida workflows |
| Persistent sessions and scripts | Yes |
| RPC exports | Long-running scripts can expose callable functions through `rpc.exports` |
| Event queues | Script and hook events are stored per `script_id` |
| Platform-focused workflows | macOS/iOS, Android, Windows, Linux, kernel |
| Process and module introspection | Yes |
| Memory operations | Read, write, scan, protect, dump, typed access |
| Native instrumentation | Interceptor, Stalker, CModule, NativeFunction |
| Official Frida APIs | DeviceManager, Device, Bus, Session, Script, Compiler, PackageManager, PortalService, peer connection, ModuleMap, SystemFunction, Thread hardware break/watchpoints, Worker, RustModule, Checksum, Sampler |
| Runtime helpers | ObjC, Java/ART, Swift, .NET-oriented workflows |
| Files and databases | Target-side file access and SQLite helpers |
| Agent workflow entrypoint | Target snapshot with recommended next tools |
| Bidirectional messaging | `script.post()` plus target-side `recv()` |

## macOS attach permissions

Frida attaches through task ports, and macOS can deny that for several independent reasons. SIP is only one of them. Even with SIP fully disabled, attach may still fail if the terminal/Python host lacks Developer Tools/debugging permission, the target is a protected platform binary, the process is sandboxed, architectures do not match, or the host environment hides the process list.

For normal development, prefer self-built test apps or explicitly authorized apps first. Avoid using Apple system binaries such as `/bin/sleep` as the first attach probe; they are platform-signed and can be denied even when launched by your own user. If a self-built target fails, fix local debugging permission before changing SIP. System daemons and Apple platform binaries may require reduced SIP debug restrictions, but that still does not guarantee attach on every target.

Useful checks:

- Run `frida_check` to confirm Python Frida and frida-tools are installed.
- Run `frida_host_diagnostics` from the same shell or MCP client that will run Frida. On macOS it reports Developer Tools status, task-port AuthorizationDB checks, the active Python executable, and whether that Python shows debugger-related code-signing entitlements.
- Run `frida_list_devices` and `frida_list_processes`; an empty process list usually points to host permission or sandboxing.
- Try a self-built process with `frida_connect(..., spawn=True)` before targeting system services.
- On macOS, grant the terminal or Python runner Developer Tools/debugging permission in System Settings when prompted.

If self-built spawn/attach fails with `unable to access process ... from the current user account`, treat it as a local macOS debug-permission issue first. Check `DevToolsSecurity -status`, the `_developer` group, and the code-signing entitlements of the Python interpreter used by `fuzzmind-frida-mcp` or `frida`. The official Frida troubleshooting notes cover macOS task-port authorization: https://frida.re/docs/troubleshooting/

Common lab-only recovery steps:

```bash
sudo DevToolsSecurity -enable
sudo dseditgroup -o edit -a "$USER" -t user _developer
```

Restart the terminal or MCP client after changing Developer Tools permissions. If AuthorizationDB task-port checks still fail on a dedicated research host, follow the Frida troubleshooting guidance for `system.privilege.taskport`. If the Python host remains the blocker, use a disposable pyenv/venv Python for Frida work and sign that interpreter with debugger entitlements rather than changing the system Python.

For release validation, use official Frida packages in a clean project venv and run the real smoke tests with `FUZZMIND_FRIDA_REAL_ATTACH=1`. These tests require native Frida spawn/attach for a self-built target.

## Repository layout

| Path | Purpose |
|---|---|
| `src/fuzzmind_frida_mcp/server.py` | CLI entrypoint and FastMCP startup only |
| `src/fuzzmind_frida_mcp/toolsets/` | MCP-facing tool functions grouped by exposed surface: lifecycle, instrumentation, runtimes, platform, data, recipes |
| `src/fuzzmind_frida_mcp/tools/` | Implementation modules used by MCP-facing tools |
| `src/fuzzmind_frida_mcp/tools/official/` | Thin wrappers around official Frida Python/GumJS APIs, grouped by upstream object |
| `src/fuzzmind_frida_mcp/tools/lifecycle/` | Device, process, session, and script lifecycle workflows |
| `src/fuzzmind_frida_mcp/tools/instrumentation/` | Memory, hook, Interceptor, Stalker, Kernel, Cloak, and profiler helpers |
| `src/fuzzmind_frida_mcp/tools/runtimes/` | Java, ObjC, and Swift runtime workflows |
| `src/fuzzmind_frida_mcp/tools/platform/` | Android, iOS/macOS, Linux, and Windows focused workflows |
| `src/fuzzmind_frida_mcp/tools/data/` | File, database, and socket helpers |
| `src/fuzzmind_frida_mcp/tools/recipes/` | Higher-level security and environment workflows |

The `official/` package is intentionally separate from high-level workflow modules. For example, `tools/official/device.py` follows official `DeviceManager`/`Device` APIs, while `tools/lifecycle/device.py` exposes Agent-friendly workflows built on top of Frida.

## Contributing

PRs welcome. Please read the [CONTRIBUTING](CONTRIBUTING) document first:
- Keep one MCP-facing function per tool and register grouped surfaces through `src/fuzzmind_frida_mcp/toolsets/`
- Put official API thin wrappers under `src/fuzzmind_frida_mcp/tools/official/`
- Add platform-specific tools to the appropriate `src/fuzzmind_frida_mcp/tools/platform/` module
- Cross-platform implementation tools go in the matching grouped package (`instrumentation/`, `lifecycle/`, `runtimes/`, `data/`, or `recipes/`)

## License

[MIT](LICENSE) — Copyright (c) 2026 FuzzMind Security Lab
