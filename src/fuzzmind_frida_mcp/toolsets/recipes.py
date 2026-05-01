"""Higher-level security, bridge, Gadget, and environment MCP tools."""
from __future__ import annotations

from fuzzmind_frida_mcp import tools as _f
from fuzzmind_frida_mcp.toolsets._helpers import register_module_tools


def frida_ssl_pinning_disable(target: str) -> dict:
    """Inject a universal SSL pinning bypass script.

    `target`: process name or pid (string).
    Works on both Android (TrustManager, OkHttp3 CertificatePinner,
    Conscrypt) and iOS/macOS (SecTrustEvaluateWithError,
    SecTrustEvaluate, NSURLSession challenge delegates).
    Returns list of successfully bypassed mechanisms.
    """
    return _f.ssl_pinning_disable(target)


def frida_crypto_hook(
    target: str,
    duration_seconds: int = 10,
) -> dict:
    """Hook crypto APIs to capture encryption/decryption operations live.

    Platform hooks:
    - macOS/iOS: CCCrypt (CommonCrypto), SecKeyCreateEncryptedData,
      SecKeyCreateDecryptedData
    - Android: javax.crypto.Cipher.doFinal (all overloads)

    Each captured operation includes: API name, operation type
    (encrypt/decrypt), algorithm, key bytes (hex), and I/O sizes.

    `target`: process name or pid (string).
    `duration_seconds`: how long to capture (default 10).
    """
    return _f.crypto_hook(target, duration_seconds=duration_seconds)


def frida_string_sniffer(
    target: str,
    min_length: int = 4,
    duration_seconds: int = 10,
) -> dict:
    """Sniff strings as they are created at runtime in a target process.

    Hooks string-producing functions to capture decoded, decrypted, or
    dynamically constructed strings:
    - ObjC: NSString -initWithBytes:length:encoding:,
      +stringWithUTF8String:
    - Native: strlen (with min_length filter)

    `target`: process name or pid (string).
    `min_length`: minimum string length to capture (default 4).
    `duration_seconds`: how long to sniff (default 10).

    Returns unique strings observed during the capture window. Useful
    for finding decrypted config, URLs, tokens, keys in obfuscated apps.
    """
    return _f.string_sniffer(target, min_length=min_length, duration_seconds=duration_seconds)


def frida_ssl_keylog(
    target: str,
    output_file: str,
    duration_seconds: int = 30,
) -> dict:
    """Extract TLS session keys for Wireshark decryption (SSLKEYLOGFILE).

    Hooks SSL/TLS internals to capture pre-master secrets:
    - BoringSSL: SSL_CTX_set_keylog_callback + SSL_new interception
    - macOS SecureTransport: SSLHandshake fallback

    Writes keys in standard NSS SSLKEYLOGFILE format to `output_file`.
    Point Wireshark's (Pre)-Master-Secret log to this file to decrypt
    captured TLS traffic.

    `target`: process name or pid (string).
    `output_file`: local path for the keylog output file.
    `duration_seconds`: how long to capture keys (default 30).
    """
    return _f.ssl_keylog(target, output_file=output_file, duration_seconds=duration_seconds)


def frida_time_warp(
    target: str,
    speed_factor: float = 0.0,
    fixed_time: int | None = None,
) -> dict:
    """Warp time perception for a target process. Anti-sandbox evasion.

    Hooks time APIs: gettimeofday, clock_gettime, mach_absolute_time,
    time(). Manipulates the return values to alter the process's
    perception of elapsed time.

    `target`: process name or pid (string).
    `speed_factor`: time speed multiplier. 0.0 = freeze time,
      1.0 = normal, 2.0 = double speed, 0.5 = half speed.
    `fixed_time`: if set, all time functions return this specific
      Unix timestamp (seconds since epoch). Overrides speed_factor.

    Common uses: bypass time-based anti-analysis checks, accelerate
    timers, freeze expiry checks. Stays active for 30 seconds.
    """
    return _f.time_warp(target, speed_factor=speed_factor, fixed_time=fixed_time)


def frida_anti_root_bypass(target: str) -> dict:
    """Bypass root/jailbreak detection in a target process.

    iOS: hooks NSFileManager for jailbreak paths, sysctl for P_TRACED,
    getenv for DYLD_INSERT_LIBRARIES.
    Android: hooks File.exists for su paths, Runtime.exec for su,
    spoofs Build.TAGS/FINGERPRINT.

    `target`: process name or pid (string).
    Returns a list of successfully installed bypasses.
    """
    return _f.anti_root_bypass(target)


def frida_anti_debug_bypass(target: str) -> dict:
    """Bypass debugger detection mechanisms in a target process.

    Hooks: ptrace(PT_DENY_ATTACH) -> return 0, sysctl P_TRACED -> clear,
    ObjC isDebuggerAttached -> false, getppid -> 1 (launchd),
    Android Debug.isDebuggerConnected -> false.

    `target`: process name or pid (string).
    Returns a list of successfully installed bypasses.
    """
    return _f.anti_debug_bypass(target)


def frida_host_diagnostics() -> dict:
    """Collect local host diagnostics relevant to Frida MCP operation."""
    return _f.host_diagnostics()


def frida_bridge_status(bridge_root: str | None = None) -> dict:
    """Check whether Frida 17 ObjC/Java/Swift bridge packages can be bundled."""
    return _f.bridge_status(bridge_root=bridge_root)


def frida_bridge_install(
    bridges: list[str] | None = None,
    bridge_root: str | None = None,
    save_optional: bool = True,
    registry: str | None = None,
) -> dict:
    """Install Frida 17 runtime bridge packages using official frida-pm."""
    return _f.bridge_install(
        bridges=bridges,
        bridge_root=bridge_root,
        save_optional=save_optional,
        registry=registry,
    )


def frida_gadget_config(
    interaction: str = "listen",
    output_path: str | None = None,
    address: str | None = None,
    port: int | None = None,
    path: str | None = None,
    parameters: dict | None = None,
    on_load: str = "wait",
    on_port_conflict: str = "fail",
    on_change: str | None = None,
    teardown: str = "minimal",
    runtime: str = "default",
    code_signing: str = "optional",
    token: str | None = None,
    certificate: str | None = None,
    origin: str | None = None,
    asset_root: str | None = None,
    acl: list[str] | None = None,
) -> dict:
    """Generate a Frida Gadget configuration."""
    return _f.gadget_config(
        interaction=interaction,
        output_path=output_path,
        address=address,
        port=port,
        path=path,
        parameters=parameters,
        on_load=on_load,
        on_port_conflict=on_port_conflict,
        on_change=on_change,
        teardown=teardown,
        runtime=runtime,
        code_signing=code_signing,
        token=token,
        certificate=certificate,
        origin=origin,
        asset_root=asset_root,
        acl=acl,
    )


def frida_gadget_script_template(kind: str = "minimal") -> dict:
    """Return a Frida Gadget-compatible script template."""
    return _f.gadget_script_template(kind=kind)


def frida_gadget_bundle_assets(
    gadget_library_path: str,
    output_dir: str,
    config_json: str | None = None,
    config_path: str | None = None,
    script_path: str | None = None,
    library_name: str | None = None,
) -> dict:
    """Copy Gadget library, config, and optional script into a staging directory."""
    return _f.gadget_bundle_assets(
        gadget_library_path,
        output_dir,
        config_json=config_json,
        config_path=config_path,
        script_path=script_path,
        library_name=library_name,
    )


def frida_gumjs_template(kind: str, symbol: str | None = None) -> dict:
    """Return an advanced GumJS template for direct use with script_load."""
    return _f.gumjs_template(kind=kind, symbol=symbol)


def register_recipe_tools(mcp) -> None:
    """Register recipes tools with FastMCP."""
    register_module_tools(mcp, globals())
