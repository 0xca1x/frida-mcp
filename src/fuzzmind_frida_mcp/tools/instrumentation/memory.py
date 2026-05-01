"""fuzzmind-frida-mcp -- memory tools."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import time

from .._core import INSTALL_HINT, _create_script, _load_frida, _run_script


def read_memory(
    target: str,
    address: str,
    size: int,
) -> dict[str, Any]:
    """Attach to process, read memory at address, return hex dump."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    # Cap size to prevent huge reads
    capped = min(size, 0x10000)  # 64KB max
    address_js = json.dumps(address)

    js = f"""
    'use strict';
    try {{
        const address = {address_js};
        const buf = ptr(address).readByteArray({capped});
        const arr = new Uint8Array(buf);
        const hex = Array.from(arr).map(b => ('0' + b.toString(16)).slice(-2)).join('');
        send({{type: 'memory', address: address, size: {capped}, hex: hex}});
    }} catch(e) {{
        send({{type: 'error', message: 'read failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def write_memory(
    target: str,
    address: str,
    hex_bytes: str,
) -> dict[str, Any]:
    """Write raw bytes to process memory at address.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100004000').
    `hex_bytes`: hex-encoded bytes to write (e.g. 'deadbeef').
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    # Validate hex_bytes
    cleaned = hex_bytes.replace(" ", "")
    if len(cleaned) % 2 != 0:
        return {"error": "hex_bytes must have even length"}

    address_js = json.dumps(address)
    cleaned_js = json.dumps(cleaned)
    js = f"""
    'use strict';
    try {{
        const address = {address_js};
        const hex = {cleaned_js};
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {{
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }}
        ptr(address).writeByteArray(bytes.buffer);
        // Verify by reading back
        const verify = ptr(address).readByteArray(bytes.length);
        const arr = new Uint8Array(verify);
        const readback = Array.from(arr).map(b => ('0' + b.toString(16)).slice(-2)).join('');
        send({{type: 'write_memory', address: address, size: bytes.length, readback: readback, ok: true}});
    }} catch(e) {{
        send({{type: 'error', message: 'write_memory failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def memory_scan(
    target: str,
    address: str,
    size: int,
    pattern: str,
) -> dict[str, Any]:
    """Attach to process, run Memory.scan() with hex pattern, return matches."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    pattern_js = json.dumps(pattern)
    js = f"""
    'use strict';
    const matches = [];
    Memory.scan(ptr({address_js}), {size}, {pattern_js}, {{
        onMatch: function(address, size) {{
            matches.push({{address: address.toString(), size: size}});
        }},
        onComplete: function() {{
            send({{type: 'scan_results', matches: matches.slice(0, 1000), count: matches.length, truncated: matches.length > 1000}});
        }},
        onError: function(reason) {{
            send({{type: 'error', message: 'scan error: ' + reason}});
        }}
    }});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def memory_protect(
    target: str,
    address: str,
    size: int,
    protection: str,
) -> dict[str, Any]:
    """Change memory protection on a region.

    `target`: process name or pid (string).
    `address`: hex address (e.g. '0x100000000').
    `size`: number of bytes in the region.
    `protection`: protection string like 'rwx', 'r-x', 'rw-', '---'.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    protection_js = json.dumps(protection)
    js = f"""
    'use strict';
    try {{
        const address = {address_js};
        const protection = {protection_js};
        Memory.protect(ptr(address), {size}, protection);
        send({{type: 'memory_protect', address: address, size: {size}, protection: protection, ok: true}});
    }} catch(e) {{
        send({{type: 'error', message: 'memory_protect failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def enumerate_ranges(
    target: str,
    protection: str = "r--",
) -> dict[str, Any]:
    """Enumerate memory ranges matching a protection filter.

    `target`: process name or pid (string).
    `protection`: filter string (e.g. 'r--', 'rwx', 'r-x'). Frida matches
    ranges whose protection is a superset of this value.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    protection_js = json.dumps(protection)
    js = f"""
    'use strict';
    const ranges = Process.enumerateRanges({protection_js});
    send({{
        type: 'ranges',
        items: ranges.slice(0, 5000).map(r => ({{
            base: r.base.toString(),
            size: r.size,
            protection: r.protection,
            file: r.file ? r.file.path : null
        }})),
        count: ranges.length,
        truncated: ranges.length > 5000
    }});
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def get_module_base(target: str, module_name: str) -> dict[str, Any]:
    """Get base address of a module by name (partial match supported).

    `target`: process name or pid (string).
    `module_name`: full or partial module name (case-insensitive).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped = json.dumps(module_name.lower())
    js = f"""
    'use strict';
    var result = null;
    var pattern = {escaped};
    Process.enumerateModules().forEach(function(m) {{
        if (m.name.toLowerCase().indexOf(pattern) !== -1) {{
            result = {{name: m.name, base: m.base.toString(), size: m.size, path: m.path}};
        }}
    }});
    if (result) {{
        send({{type: 'module_base', module: result}});
    }} else {{
        send({{type: 'error', message: 'module not found: ' + pattern}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def memory_dump_regions(
    target: str,
    output_dir: str,
    *,
    filter_protection: str = "r--",
) -> dict[str, Any]:
    """Dump readable memory regions from a target process to disk.

    Enumerates all memory ranges matching `filter_protection`, reads each
    region via Memory.readByteArray(), and saves to individual binary files
    in `output_dir` named `<base_address>_<size>.bin`.

    `target`: process name or pid (string).
    `output_dir`: local directory to write dump files to.
    `filter_protection`: Frida protection filter (default 'r--').

    Warning: this can produce a lot of data for processes with many
    readable regions. Regions larger than 64MB are skipped.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    # Ensure output dir exists
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    escaped_prot = json.dumps(filter_protection)

    js = f"""
    'use strict';
    var maxRegionSize = 64 * 1024 * 1024;  // 64MB cap per region
    var ranges = Process.enumerateRanges({escaped_prot});
    var dumped = 0;
    var skipped = 0;
    var totalBytes = 0;

    for (var i = 0; i < ranges.length; i++) {{
        var r = ranges[i];
        if (r.size > maxRegionSize) {{
            skipped++;
            send({{type: 'region_skip', base: r.base.toString(), size: r.size, reason: 'too_large'}});
            continue;
        }}
        try {{
            var buf = r.base.readByteArray(r.size);
            send({{
                type: 'region_dump',
                base: r.base.toString(),
                size: r.size,
                protection: r.protection,
                file: r.file ? r.file.path : null,
                index: dumped
            }}, buf);
            dumped++;
            totalBytes += r.size;
        }} catch(e) {{
            skipped++;
            send({{type: 'region_skip', base: r.base.toString(), size: r.size, reason: e.message}});
        }}
    }}
    send({{
        type: 'dump_complete',
        total_ranges: ranges.length,
        dumped: dumped,
        skipped: skipped,
        total_bytes: totalBytes
    }});
    """

    events: list[dict[str, Any]] = []
    region_files: list[dict[str, Any]] = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict):
                if payload.get("type") == "region_dump" and data is not None:
                    base_addr = payload["base"].replace("0x", "")
                    size = payload["size"]
                    fname = f"{base_addr}_{size}.bin"
                    fpath = out_dir / fname
                    try:
                        fpath.write_bytes(data)
                        region_files.append({
                            "base": payload["base"],
                            "size": size,
                            "protection": payload.get("protection"),
                            "backing_file": payload.get("file"),
                            "local_path": str(fpath),
                        })
                    except Exception:
                        pass
                else:
                    events.append(payload)
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        device = frida.get_local_device()
        if target.isdigit():
            session = frida.attach(int(target))
        else:
            session = frida.attach(target)

        script = _create_script(session, js)
        script.on("message", on_message)
        script.load()

        # Wait for dump_complete
        deadline = time.time() + 300  # 5 minute max
        while time.time() < deadline:
            time.sleep(0.2)
            if any(isinstance(e, dict) and e.get("type") in ("dump_complete", "error") for e in events):
                break

        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"memory_dump_regions failed: {e}", "regions_saved": len(region_files)}

    summary = [e for e in events if isinstance(e, dict) and e.get("type") == "dump_complete"]
    total_bytes = summary[0].get("total_bytes", 0) if summary else sum(r["size"] for r in region_files)

    return {
        "target": target,
        "output_dir": str(out_dir),
        "filter_protection": filter_protection,
        "regions_dumped": len(region_files),
        "total_bytes": total_bytes,
        "regions": region_files[:200],
        "regions_truncated": len(region_files) > 200,
        "events": [e for e in events if isinstance(e, dict) and e.get("type") != "dump_complete"][:50],
    }

def dump_module(
    target: str,
    module_name: str,
    output_path: str,
) -> dict[str, Any]:
    """Dump a live in-memory module image to disk.

    Reads the full module image from process memory and writes the raw
    bytes to `output_path`. Critical for unpacking or analysing modules
    that differ from their on-disk representation.

    `target`: process name or pid (string).
    `module_name`: exact or partial module name (e.g. 'libsystem_kernel.dylib').
    `output_path`: local path to write the dumped binary.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_name = json.dumps(module_name)

    js = f"""
    'use strict';
    var mod = Process.findModuleByName({escaped_name});
    if (!mod) {{
        // Try partial match
        var mods = Process.enumerateModules();
        var pattern = {escaped_name}.toLowerCase();
        for (var i = 0; i < mods.length; i++) {{
            if (mods[i].name.toLowerCase().indexOf(pattern) !== -1) {{
                mod = mods[i];
                break;
            }}
        }}
    }}
    if (!mod) {{
        send({{type: 'error', message: 'module not found: ' + {escaped_name}}});
    }} else {{
        try {{
            var buf = mod.base.readByteArray(mod.size);
            send({{
                type: 'module_dump',
                name: mod.name,
                base: mod.base.toString(),
                size: mod.size,
                path: mod.path
            }}, buf);
        }} catch(e) {{
            send({{type: 'error', message: 'dump_module read failed: ' + e.message}});
        }}
    }}
    """

    result_data: bytes | None = None
    events: list[dict[str, Any]] = []
    module_info: dict[str, Any] = {}

    def on_message(msg, data):
        nonlocal result_data, module_info
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict):
                if payload.get("type") == "module_dump" and data is not None:
                    result_data = data
                    module_info = payload
                else:
                    events.append(payload)
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        device = frida.get_local_device()
        if target.isdigit():
            session = frida.attach(int(target))
        else:
            session = frida.attach(target)

        script = _create_script(session, js)
        script.on("message", on_message)
        script.load()

        deadline = time.time() + 60
        while time.time() < deadline:
            time.sleep(0.1)
            if result_data is not None or any(
                isinstance(e, dict) and e.get("type") == "error" for e in events
            ):
                break

        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"dump_module attach failed: {e}"}

    errors = [e for e in events if isinstance(e, dict) and e.get("type") == "error"]
    if errors:
        return {"error": errors[0].get("message", str(errors[0]))}

    if result_data is None:
        return {"error": "no data received from target"}

    try:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(result_data)
        return {
            "status": "dumped",
            "module": module_info.get("name"),
            "base": module_info.get("base"),
            "size": module_info.get("size"),
            "original_path": module_info.get("path"),
            "output_path": str(out),
            "bytes_written": len(result_data),
        }
    except Exception as e:
        return {"error": f"dump_module write failed: {e}"}

def memory_alloc(target: str, size: int) -> dict[str, Any]:
    """Allocate memory inside a target process.

    `target`: process name or pid (string).
    `size`: number of bytes to allocate.
    Returns the address of the allocated region.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    if size > 10 * 1024 * 1024:
        return {"error": "size too large; capped at 10MB"}

    js = f"""
    'use strict';
    try {{
        var buf = Memory.alloc({size});
        send({{
            type: 'memory_alloc',
            address: buf.toString(),
            size: {size}
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'Memory.alloc failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def memory_patch_code(target: str, address: str, hex_bytes: str) -> dict[str, Any]:
    """Patch executable code at an address using Memory.patchCode.

    Uses Memory.patchCode which handles cache flushing on architectures
    that need it (ARM). Safer than raw write_memory for code pages.

    `target`: process name or pid (string).
    `address`: hex address to patch (e.g. '0x100004000').
    `hex_bytes`: hex-encoded bytes to write (e.g. 'c3', '90909090').
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    clean = hex_bytes.replace(" ", "")
    byte_len = len(clean) // 2
    address_js = json.dumps(address)

    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        var addr = ptr(address);
        var bytes = [{', '.join(f'0x{clean[i:i+2]}' for i in range(0, len(clean), 2))}];
        Memory.patchCode(addr, {byte_len}, function(code) {{
            for (var i = 0; i < bytes.length; i++) {{
                code.add(i).writeU8(bytes[i]);
            }}
        }});
        // Read back to verify
        var readBack = [];
        for (var i = 0; i < {byte_len}; i++) {{
            readBack.push(('0' + addr.add(i).readU8().toString(16)).slice(-2));
        }}
        send({{
            type: 'memory_patch_code',
            address: address,
            size: {byte_len},
            written_hex: readBack.join(''),
            ok: true
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'Memory.patchCode failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def memory_query_protection(target: str, address: str) -> dict[str, Any]:
    """Query memory protection at a specific address.

    `target`: process name or pid (string).
    `address`: hex address to query (e.g. '0x100004000').
    Returns the protection string (e.g. 'rwx', 'r-x', 'rw-').
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        var prot = Memory.queryProtection(ptr(address));
        send({{
            type: 'memory_protection',
            address: address,
            protection: prot
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'Memory.queryProtection failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def memory_alloc_string(
    target: str,
    string: str,
    encoding: str = "utf8",
) -> dict[str, Any]:
    """Allocate a string inside a target process.

    `target`: process name or pid (string).
    `string`: the string value to allocate.
    `encoding`: 'utf8' (default), 'utf16', or 'ansi'.
    Returns the address of the allocated string.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped = json.dumps(string)  # proper JS string escape

    alloc_fn = {
        "utf8": "allocUtf8String",
        "utf16": "allocUtf16String",
        "ansi": "allocAnsiString",
    }.get(encoding, "allocUtf8String")

    js = f"""
    'use strict';
    try {{
        var str = {escaped};
        var buf = Memory.{alloc_fn}(str);
        send({{
            type: 'memory_alloc_string',
            address: buf.toString(),
            encoding: {json.dumps(encoding)},
            length: str.length
        }});
    }} catch(e) {{
        send({{type: 'error', message: 'Memory.{alloc_fn} failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def memory_access_monitor(
    target: str,
    ranges: list[dict[str, str]],
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Monitor memory accesses (read/write/execute) on specified ranges.

    Uses MemoryAccessMonitor to capture access events on memory regions.

    `target`: process name or pid (string).
    `ranges`: list of dicts with 'base' (hex addr) and 'size' (int) keys.
      Example: [{"base": "0x100004000", "size": 4096}].
    `duration_seconds`: how long to monitor (default 10).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    if not ranges:
        return {"error": "ranges list must not be empty"}

    try:
        ranges_spec = [
            {"base": str(r["base"]), "size": int(r["size"])}
            for r in ranges
        ]
    except (KeyError, TypeError, ValueError) as e:
        return {"error": f"invalid range entry: {e}"}
    ranges_js = json.dumps(ranges_spec)

    js = f"""
    'use strict';
    try {{
        var accesses = [];
        var ranges = {ranges_js}.map(function(r) {{ return {{base: ptr(r.base), size: r.size}}; }});
        MemoryAccessMonitor.enable(ranges, {{
            onAccess: function(details) {{
                accesses.push({{
                    operation: details.operation,
                    from: details.from.toString(),
                    address: details.address.toString(),
                    rangeIndex: details.rangeIndex,
                    pageIndex: details.pageIndex
                }});
                if (accesses.length >= 500) {{
                    send({{
                        type: 'memory_access_batch',
                        items: accesses,
                        count: accesses.length
                    }});
                    accesses = [];
                }}
            }}
        }});
        setTimeout(function() {{
            MemoryAccessMonitor.disable();
            send({{
                type: 'memory_access_monitor',
                items: accesses,
                count: accesses.length,
                ok: true
            }});
        }}, {duration_seconds * 1000});
    }} catch(e) {{
        send({{type: 'error', message: 'MemoryAccessMonitor failed: ' + e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=duration_seconds + 2, mode="attach")

def read_typed(target: str, address: str, type: str) -> dict[str, Any]:
    """Read a typed value from process memory.

    *type*: one of pointer, s8, u8, s16, u16, s32, u32, s64, u64,
    float, double, utf8, utf16, cstring, ansi.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    type_map = {
        "pointer": "readPointer()",
        "s8": "readS8()",
        "u8": "readU8()",
        "s16": "readS16()",
        "u16": "readU16()",
        "s32": "readS32()",
        "u32": "readU32()",
        "s64": "readS64()",
        "u64": "readU64()",
        "float": "readFloat()",
        "double": "readDouble()",
        "utf8": "readUtf8String()",
        "utf16": "readUtf16String()",
        "cstring": "readCString()",
        "ansi": "readAnsiString()",
    }
    read_call = type_map.get(type)
    if read_call is None:
        return {"error": f"unsupported type: {type}", "valid_types": list(type_map.keys())}

    address_js = json.dumps(address)
    type_js = json.dumps(type)
    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        var p = ptr(address);
        var val = p.{read_call};
        var result = val;
        if (val !== null && typeof val === 'object' && val.toString) {{
            result = val.toString();
        }}
        send({{type: 'read_typed', address: address, data_type: {type_js}, value: result}});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def write_typed(target: str, address: str, type: str, value: str) -> dict[str, Any]:
    """Write a typed value to process memory.

    *type*: one of pointer, s8, u8, s16, u16, s32, u32, s64, u64,
    float, double, utf8, utf16, cstring, ansi.
    *value*: string representation of the value to write.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    int_types = {
        "s8": "writeS8",
        "u8": "writeU8",
        "s16": "writeS16",
        "u16": "writeU16",
        "s32": "writeS32",
        "u32": "writeU32",
    }
    float_types = {"float": "writeFloat", "double": "writeDouble"}
    string_types = {
        "utf8": "writeUtf8String",
        "utf16": "writeUtf16String",
        "cstring": "writeCString",
        "ansi": "writeAnsiString",
    }
    valid_types = ["pointer", *int_types.keys(), "s64", "u64", *float_types.keys(), *string_types.keys()]
    value_js = json.dumps(value)
    if type == "pointer":
        write_call = f"writePointer(ptr({value_js}))"
    elif type in int_types:
        try:
            parsed_int = int(value, 0)
        except ValueError:
            return {"error": f"invalid integer value for {type}: {value!r}"}
        write_call = f"{int_types[type]}({parsed_int})"
    elif type == "s64":
        write_call = f"writeS64(int64({value_js}))"
    elif type == "u64":
        write_call = f"writeU64(uint64({value_js}))"
    elif type in float_types:
        try:
            parsed_float = float(value)
        except ValueError:
            return {"error": f"invalid float value for {type}: {value!r}"}
        write_call = f"{float_types[type]}({parsed_float!r})"
    elif type in string_types:
        write_call = f"{string_types[type]}({value_js})"
    else:
        return {"error": f"unsupported type: {type}", "valid_types": valid_types}

    address_js = json.dumps(address)
    type_js = json.dumps(type)
    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        var p = ptr(address);
        p.{write_call};
        send({{type: 'write_typed', address: address, data_type: {type_js}, value: {value_js}, ok: true}});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def hexdump_memory(target: str, address: str, length: int = 256) -> dict[str, Any]:
    """Produce a formatted hex dump of memory at *address*.

    *length*: number of bytes (default 256, capped at 4096).
    Returns the formatted hexdump string from Frida's built-in hexdump().
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    capped = min(length, 4096)
    address_js = json.dumps(address)

    js = f"""
    'use strict';
    try {{
        var address = {address_js};
        var dump = hexdump(ptr(address), {{length: {capped}}});
        send({{type: 'hexdump', address: address, length: {capped}, dump: dump}});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")
