"""Android, iOS/macOS, Linux, and Windows MCP tools."""
from __future__ import annotations

from fuzzmind_frida_mcp import tools as _f
from fuzzmind_frida_mcp.toolsets._helpers import register_module_tools


def frida_win_api_monitor(
    target: str,
    apis: list[str],
    duration_seconds: int = 10,
) -> dict:
    """[Windows] Hook Win32 APIs and log call arguments.

    Attaches Interceptor to the specified Win32 API exports across
    kernel32, advapi32, ws2_32, ntdll, user32. Logs up to 6 arguments
    per call.

    `target`: process name or pid (string).
    `apis`: list of API names, e.g. ["CreateFileW", "RegOpenKeyExW", "socket"].
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.win_api_monitor(target, apis=apis, duration_seconds=duration_seconds)


def frida_win_dotnet_list_assemblies(target: str) -> dict:
    """[Windows] Enumerate .NET assemblies loaded in a target process.

    Tries CLR.enumerateAssemblies() first, falls back to module
    enumeration with .NET metadata detection.
    """
    return _f.win_dotnet_list_assemblies(target)


def frida_win_dotnet_hook_method(
    target: str,
    assembly: str,
    namespace: str,
    class_name: str,
    method_name: str,
    duration_seconds: int = 10,
) -> dict:
    """[Windows] Hook a .NET method and log invocations.

    Tries CLR bridge, falls back to JIT-compiled export scanning.

    `target`: process name or pid (string).
    `assembly`: assembly name (e.g. 'mscorlib').
    `namespace`: .NET namespace (e.g. 'System.IO').
    `class_name`: class name (e.g. 'File').
    `method_name`: method to hook (e.g. 'ReadAllText').
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.win_dotnet_hook_method(
        target,
        assembly=assembly,
        namespace=namespace,
        class_name=class_name,
        method_name=method_name,
        duration_seconds=duration_seconds,
    )


def frida_win_registry_monitor(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """[Windows] Monitor Registry operations in a target process.

    Hooks RegOpenKeyExW, RegSetValueExW, RegQueryValueExW, RegDeleteKeyW
    in advapi32.dll. Logs key paths, value names, and data sizes.

    `target`: process name or pid (string).
    `duration_seconds`: how long to monitor (default 10).
    """
    return _f.win_registry_monitor(target, duration_seconds=duration_seconds)


def frida_win_com_intercept(
    target: str,
    clsid_or_progid: str,
    method_index: int,
    duration_seconds: int = 10,
) -> dict:
    """[Windows] Intercept a COM vtable method call.

    Hooks CoCreateInstance to capture COM object creation for the CLSID,
    then patches the vtable at method_index to log invocations.

    `target`: process name or pid (string).
    `clsid_or_progid`: CLSID string or '*' for all.
    `method_index`: 0-based vtable index (0=QI, 1=AddRef, 2=Release, 3+=interface).
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.win_com_intercept(
        target,
        clsid_or_progid=clsid_or_progid,
        method_index=method_index,
        duration_seconds=duration_seconds,
    )


def frida_win_etw_bypass(target: str) -> dict:
    """[Windows] Patch EtwEventWrite to neutralise ETW event logging.

    Overwrites ntdll!EtwEventWrite with `xor eax,eax; ret` so it
    returns SUCCESS (0) without emitting events. Standard anti-logging
    bypass.

    `target`: process name or pid (string).
    """
    return _f.win_etw_bypass(target)


def frida_win_crypto_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """[Windows] Hook CryptoAPI and BCrypt encryption/decryption.

    Hooks CryptEncrypt, CryptDecrypt (advapi32), BCryptEncrypt,
    BCryptDecrypt (bcrypt.dll). Logs key handle, data sizes, and
    operation type.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.win_crypto_hook(target, duration_seconds=duration_seconds)


def frida_win_amsi_bypass(target: str) -> dict:
    """[Windows] Patch AmsiScanBuffer to bypass AMSI scanning.

    Overwrites amsi!AmsiScanBuffer to always return E_INVALIDARG,
    causing callers to treat content as clean. Standard AMSI bypass.

    `target`: process name or pid (string).
    """
    return _f.win_amsi_bypass(target)


def frida_win_hollowing_detect(target: str) -> dict:
    """[Windows] Detect process hollowing via PE section comparison.

    Parses the in-memory PE header, compares each section's expected
    size/characteristics vs actual memory content. Flags discrepancies
    like RWX .text, unmapped sections, or size mismatches.

    `target`: process name or pid (string).
    """
    return _f.win_hollowing_detect(target)


def frida_android_content_provider_hook(
    target: str,
    authority: str,
    duration_seconds: int = 10,
) -> dict:
    """[Android] Hook ContentResolver operations for a specific authority.

    Hooks ContentResolver.query, insert, update, delete. Filters by
    the specified authority URI prefix. Logs URI, result counts, and
    affected rows.

    `target`: process name or pid (string).
    `authority`: content provider authority (e.g. 'com.example.provider').
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.android_content_provider_hook(
        target, authority=authority, duration_seconds=duration_seconds,
    )


def frida_android_intent_intercept(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """[Android] Intercept Intent dispatching: startActivity, sendBroadcast, startService.

    Logs Intent action, extras keys, component name, categories, and
    data URI for each dispatched Intent.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.android_intent_intercept(target, duration_seconds=duration_seconds)


def frida_android_shared_prefs_dump(
    target: str,
    pref_name: str | None = None,
) -> dict:
    """[Android] Dump SharedPreferences key-value pairs.

    Reads via Context.getSharedPreferences(). If pref_name is given,
    reads that specific file. Otherwise discovers and reads common
    preference files.

    `target`: process name or pid (string).
    `pref_name`: optional SharedPreferences file name (without .xml).
    """
    return _f.android_shared_prefs_dump(target, pref_name=pref_name)


def frida_android_webview_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """[Android] Hook WebView methods to capture JS bridge interactions.

    Hooks addJavascriptInterface, evaluateJavascript, loadUrl. Captures
    JS interface registrations, evaluated code, and loaded URLs.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.android_webview_hook(target, duration_seconds=duration_seconds)


def frida_android_jni_hook(
    target: str,
    function_name: str,
    duration_seconds: int = 10,
) -> dict:
    """[Android] Hook JNI functions in libart.so.

    Hooks RegisterNatives, FindClass, GetMethodID, CallObjectMethod,
    NewStringUTF, GetStringUTFChars, etc. Captures arguments and
    return values.

    `target`: process name or pid (string).
    `function_name`: JNI function to hook (e.g. 'RegisterNatives', 'FindClass').
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.android_jni_hook(
        target, function_name=function_name, duration_seconds=duration_seconds,
    )


def frida_ios_keychain_dump(target: str) -> dict:
    """[iOS/macOS] Dump accessible Keychain items from a target process.

    Hooks SecItemCopyMatching and queries for generic and internet
    passwords accessible to the process. Returns service, account,
    access group, and data (UTF-8 or hex) for each item.

    `target`: process name or pid (string).
    """
    return _f.ios_keychain_dump(target)


def frida_ios_ats_bypass(target: str) -> dict:
    """[iOS/macOS] Disable App Transport Security for a target process.

    Patches NSURLSessionConfiguration and hooks SecTrustEvaluate /
    SecTrustEvaluateWithError to allow arbitrary HTTP loads and
    self-signed certificates.

    `target`: process name or pid (string).
    """
    return _f.ios_ats_bypass(target)


def frida_ios_url_scheme_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """[iOS/macOS] Hook URL scheme and Universal Link handling.

    Hooks UIApplication openURL:, application:openURL:options:, and
    application:continueUserActivity:restorationHandler:. Also hooks
    NSWorkspace openURL: on macOS. Captures incoming URL schemes and
    Universal Links.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.ios_url_scheme_hook(target, duration_seconds=duration_seconds)


def frida_linux_syscall_hook(
    target: str,
    syscall_names: list[str],
    duration_seconds: int = 10,
) -> dict:
    """[Linux] Hook libc syscall wrappers and log arguments.

    Hooks the specified libc wrappers (open, read, write, connect,
    execve, mmap, socket, etc.) with smart argument extraction for
    common syscalls.

    `target`: process name or pid (string).
    `syscall_names`: list of function names, e.g. ["open", "connect", "execve"].
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.linux_syscall_hook(
        target, syscall_names=syscall_names, duration_seconds=duration_seconds,
    )


def frida_linux_preload_detect(target: str) -> dict:
    """[Linux] Detect LD_PRELOAD and suspicious library injections.

    Checks LD_PRELOAD env var, /etc/ld.so.preload, and enumerates
    loaded libraries flagging non-standard paths, /tmp, /dev/shm,
    and memfd-backed modules.

    `target`: process name or pid (string).
    """
    return _f.linux_preload_detect(target)


def frida_linux_dbus_intercept(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """[Linux] Intercept D-Bus method calls and messages.

    Hooks dbus_message_new_method_call, dbus_connection_send
    (libdbus-1), and g_dbus_connection_call (GIO). Captures
    destination, interface, method, and object path.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.linux_dbus_intercept(target, duration_seconds=duration_seconds)


def frida_linux_got_hook(
    target: str,
    module_name: str,
    function_name: str,
    replacement_addr: str | None = None,
) -> dict:
    """[Linux] Overwrite a GOT/PLT entry for a function in a target module.

    Finds the GOT entry for function_name in module_name. If
    replacement_addr is given, overwrites the slot directly. Otherwise
    installs a logging trampoline that logs calls and passes through.

    `target`: process name or pid (string).
    `module_name`: ELF module name (e.g. 'myapp', 'libssl.so').
    `function_name`: function name whose GOT entry to patch.
    `replacement_addr`: optional hex address (e.g. '0x7f001234').
    """
    return _f.linux_got_hook(
        target,
        module_name=module_name,
        function_name=function_name,
        replacement_addr=replacement_addr,
    )


def frida_linux_seccomp_detect(target: str) -> dict:
    """[Linux] Detect seccomp sandbox status in a target process.

    Reads /proc/self/status and calls prctl(PR_GET_SECCOMP) to
    determine seccomp mode (disabled/strict/filter), filter count,
    and NoNewPrivs flag.

    `target`: process name or pid (string).
    """
    return _f.linux_seccomp_detect(target)


def frida_android_frida_server_status(
    adb_serial: str | None = None,
    server_path: str = "/data/local/tmp/frida-server",
) -> dict:
    """Check Android adb/frida-server readiness without modifying the device."""
    return _f.android_frida_server_status(adb_serial=adb_serial, server_path=server_path)


def frida_android_frida_server_install(
    server_binary_path: str,
    adb_serial: str | None = None,
    remote_path: str = "/data/local/tmp/frida-server",
) -> dict:
    """Push a user-supplied frida-server binary to an Android device."""
    return _f.android_frida_server_install(
        server_binary_path,
        adb_serial=adb_serial,
        remote_path=remote_path,
    )


def frida_android_frida_server_start(
    adb_serial: str | None = None,
    remote_path: str = "/data/local/tmp/frida-server",
    as_root: bool = True,
    listen_address: str | None = None,
) -> dict:
    """Start frida-server on an Android device."""
    return _f.android_frida_server_start(
        adb_serial=adb_serial,
        remote_path=remote_path,
        as_root=as_root,
        listen_address=listen_address,
    )


def frida_android_frida_server_stop(
    adb_serial: str | None = None,
    as_root: bool = True,
) -> dict:
    """Stop frida-server on an Android device."""
    return _f.android_frida_server_stop(adb_serial=adb_serial, as_root=as_root)


def frida_android_port_forward(
    adb_serial: str | None = None,
    local_port: int = 27042,
    remote_port: int = 27042,
) -> dict:
    """Forward a local TCP port to an Android device TCP port with adb."""
    return _f.android_port_forward(
        adb_serial=adb_serial,
        local_port=local_port,
        remote_port=remote_port,
    )


def frida_android_port_forward_list(adb_serial: str | None = None) -> dict:
    """List adb port forwards."""
    return _f.android_port_forward_list(adb_serial=adb_serial)


def frida_android_port_forward_remove(
    adb_serial: str | None = None,
    local_port: int = 27042,
) -> dict:
    """Remove an adb TCP port forward."""
    return _f.android_port_forward_remove(adb_serial=adb_serial, local_port=local_port)


def frida_android_frida_server_setup(
    server_binary_path: str,
    adb_serial: str | None = None,
    remote_path: str = "/data/local/tmp/frida-server",
    as_root: bool = True,
    forward: bool = True,
    local_port: int = 27042,
    remote_port: int = 27042,
) -> dict:
    """Install, start, and optionally forward to a user-supplied frida-server binary."""
    return _f.android_frida_server_setup(
        server_binary_path,
        adb_serial=adb_serial,
        remote_path=remote_path,
        as_root=as_root,
        forward=forward,
        local_port=local_port,
        remote_port=remote_port,
    )


def frida_android_device_prepare(
    package: str | None = None,
    device_id: str | None = None,
    adb_serial: str | None = None,
) -> dict:
    """Summarize Android readiness for Frida-based app analysis."""
    return _f.android_device_prepare(package=package, device_id=device_id, adb_serial=adb_serial)


def frida_ios_device_prepare(
    bundle_id: str | None = None,
    device_id: str | None = None,
) -> dict:
    """Summarize iOS/macOS USB-device readiness for Frida app analysis."""
    return _f.ios_device_prepare(bundle_id=bundle_id, device_id=device_id)


def register_platform_tools(mcp) -> None:
    """Register platform tools with FastMCP."""
    register_module_tools(mcp, globals())
