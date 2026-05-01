"""fuzzmind-frida-mcp -- files tools."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import time

from .._core import INSTALL_HINT, _create_script, _load_frida, _run_script


def file_list(target: str, path: str = "/") -> dict[str, Any]:
    """List files in a directory visible to the target process.

    `target`: process name or pid (string).
    `path`: directory path to list (default '/').

    Uses ObjC NSFileManager inside the target process so the listing
    reflects the target's sandbox and file-system view.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_path = json.dumps(path)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        var fm = ObjC.classes.NSFileManager.defaultManager();
        var error = Memory.alloc(Process.pointerSize);
        error.writePointer(ptr(0));
        var items = fm.contentsOfDirectoryAtPath_error_(
            ObjC.classes.NSString.stringWithString_({escaped_path}),
            error
        );
        if (items === null) {{
            var errObj = new ObjC.Object(error.readPointer());
            send({{type: 'error', message: 'listing failed: ' + errObj.localizedDescription().toString()}});
        }} else {{
            var count = items.count().valueOf();
            var files = [];
            var limit = Math.min(count, 1000);
            for (var i = 0; i < limit; i++) {{
                var name = items.objectAtIndex_(i).toString();
                var fullPath = {escaped_path} + (({escaped_path}).endsWith('/') ? '' : '/') + name;
                var isDir = Memory.alloc(1);
                isDir.writeU8(0);
                var exists = fm.fileExistsAtPath_isDirectory_(
                    ObjC.classes.NSString.stringWithString_(fullPath),
                    isDir
                );
                files.push({{
                    name: name,
                    is_directory: isDir.readU8() === 1,
                }});
            }}
            send({{
                type: 'file_list',
                path: {escaped_path},
                items: files,
                count: count,
                truncated: count > 1000
            }});
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def file_read(target: str, path: str) -> dict[str, Any]:
    """Read a file from the target process's filesystem view.

    `target`: process name or pid (string).
    `path`: file path to read.

    Uses NSData inside the target so it respects the target's sandbox.
    Returns the file content as a UTF-8 string (truncated at 64KB).
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_path = json.dumps(path)
    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        var data = ObjC.classes.NSData.dataWithContentsOfFile_(
            ObjC.classes.NSString.stringWithString_({escaped_path})
        );
        if (data === null) {{
            send({{type: 'error', message: 'could not read file: ' + {escaped_path}}});
        }} else {{
            var len = data.length().valueOf();
            var cap = Math.min(len, 65536);
            var str = ObjC.classes.NSString.alloc().initWithData_encoding_(
                data.subdataWithRange_([0, cap]),
                4  /* NSUTF8StringEncoding */
            );
            if (str === null) {{
                /* Binary data — return hex instead */
                var bytes = new Uint8Array(data.subdataWithRange_([0, cap]).bytes().readByteArray(cap));
                var hex = Array.from(bytes).map(function(b) {{ return ('0' + b.toString(16)).slice(-2); }}).join('');
                send({{
                    type: 'file_read',
                    path: {escaped_path},
                    encoding: 'hex',
                    content: hex,
                    size: len,
                    truncated: len > cap
                }});
            }} else {{
                send({{
                    type: 'file_read',
                    path: {escaped_path},
                    encoding: 'utf8',
                    content: str.toString(),
                    size: len,
                    truncated: len > cap
                }});
            }}
        }}
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def file_download(
    target: str,
    remote_path: str,
    local_path: str,
) -> dict[str, Any]:
    """Download a file from the target process's filesystem to a local path.

    Attaches to the target, reads the file in 1MB chunks using ObjC NSData
    inside the target process, sends each chunk as binary data back to the
    host, and writes the reassembled file to `local_path`.

    `target`: process name or pid (string).
    `remote_path`: absolute path on the target's filesystem.
    `local_path`: local path where the downloaded file will be written.

    Supports large files through chunked transfer.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    escaped_remote = json.dumps(remote_path)
    chunk_size = 1024 * 1024  # 1MB chunks

    js = f"""
    'use strict';
    if (!ObjC.available) {{
        send({{type: 'error', message: 'ObjC runtime not available'}});
    }} else {{
        var path = ObjC.classes.NSString.stringWithString_({escaped_remote});
        var fm = ObjC.classes.NSFileManager.defaultManager();
        if (!fm.fileExistsAtPath_(path)) {{
            send({{type: 'error', message: 'file not found: ' + {escaped_remote}}});
        }} else {{
            var data = ObjC.classes.NSData.dataWithContentsOfFile_(path);
            if (data === null) {{
                send({{type: 'error', message: 'could not read file: ' + {escaped_remote}}});
            }} else {{
                var totalLen = data.length().valueOf();
                var chunkSize = {chunk_size};
                var offset = 0;
                var chunkIndex = 0;
                while (offset < totalLen) {{
                    var len = Math.min(chunkSize, totalLen - offset);
                    var sub = data.subdataWithRange_([offset, len]);
                    var buf = sub.bytes().readByteArray(len);
                    send({{type: 'chunk', index: chunkIndex, offset: offset, length: len, total: totalLen}}, buf);
                    offset += len;
                    chunkIndex++;
                }}
                send({{type: 'download_complete', path: {escaped_remote}, size: totalLen, chunks: chunkIndex}});
            }}
        }}
    }}
    """

    chunks: dict[int, bytes] = {}
    events: list[dict[str, Any]] = []
    total_size = 0

    def on_message(msg, data):
        nonlocal total_size
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict):
                if payload.get("type") == "chunk" and data is not None:
                    chunks[payload["index"]] = data
                    total_size = payload.get("total", total_size)
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

        # Wait for completion — poll for the download_complete event
        deadline = time.time() + 120  # 2 minute max for large files
        while time.time() < deadline:
            time.sleep(0.1)
            if any(isinstance(e, dict) and e.get("type") in ("download_complete", "error") for e in events):
                break

        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"file_download attach failed: {e}"}

    # Check for errors
    errors = [e for e in events if isinstance(e, dict) and e.get("type") == "error"]
    if errors:
        return {"error": errors[0].get("message", str(errors[0]))}

    # Reassemble chunks and write
    if not chunks:
        return {"error": "no data received from target"}

    try:
        out = Path(local_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            for i in sorted(chunks.keys()):
                f.write(chunks[i])

        return {
            "status": "downloaded",
            "remote_path": remote_path,
            "local_path": str(out),
            "size": total_size,
            "chunks": len(chunks),
        }
    except Exception as e:
        return {"error": f"file_download write failed: {e}"}

def file_write(target: str, path: str, data_hex_or_text: str, mode: str = "w") -> dict[str, Any]:
    """Write data to a file on the target process's filesystem.

    *path*: file path to write.
    *data_hex_or_text*: text data (when mode='w') or hex-encoded bytes
    (when mode='wb').
    *mode*: 'w' for text, 'wb' for binary.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    path_js = json.dumps(path)
    if mode == "wb":
        clean = data_hex_or_text.replace(" ", "")
        byte_array = ",".join(str(b) for b in bytes.fromhex(clean))
        js = f"""
        'use strict';
        try {{
            var f = new File({path_js}, 'wb');
            f.write(new Uint8Array([{byte_array}]).buffer);
            f.close();
            send({{type: 'file_write', path: {path_js}, mode: 'wb', bytes_written: {len(clean) // 2}, ok: true}});
        }} catch (e) {{
            send({{type: 'error', message: e.message}});
        }}
        """
    else:
        data_js = json.dumps(data_hex_or_text)
        js = f"""
        'use strict';
        try {{
            var f = new File({path_js}, 'w');
            f.write({data_js});
            f.close();
            send({{type: 'file_write', path: {path_js}, mode: 'w', ok: true}});
        }} catch (e) {{
            send({{type: 'error', message: e.message}});
        }}
        """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def file_seek_read(target: str, path: str, offset: int, length: int) -> dict[str, Any]:
    """Read *length* bytes from a file at *offset* on the target filesystem.

    Opens in binary mode, seeks to offset, reads length bytes, returns
    as hex. Useful for reading specific regions of large files.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    capped = min(length, 65536)
    path_js = json.dumps(path)

    js = f"""
    'use strict';
    try {{
        var f = new File({path_js}, 'rb');
        f.seek({offset});
        var data = f.readBytes({capped});
        f.close();
        send({{type: 'file_seek_read', path: {path_js}, offset: {offset}, length: {capped}}}, data);
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    events: list[dict[str, Any]] = []
    binary_chunks: list[bytes] = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            events.append(msg.get("payload"))
            if data is not None:
                binary_chunks.append(data)
        elif msg.get("type") == "error":
            events.append({"type": "error", "stack": msg.get("stack")})

    try:
        if target.isdigit():
            session = frida.attach(int(target))
        else:
            session = frida.attach(target)
        script = _create_script(session, js)
        script.on("message", on_message)
        script.load()
        time.sleep(2)
        script.unload()
        session.detach()
    except Exception as e:
        return {"error": f"file_seek_read failed: {e}"}

    result: dict[str, Any] = {"path": path, "offset": offset, "length": capped, "events": events}
    if binary_chunks:
        result["hex"] = binary_chunks[0].hex()
        result["bytes_read"] = len(binary_chunks[0])
    return result
