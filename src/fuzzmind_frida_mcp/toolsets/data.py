"""File, database, and socket MCP tools."""
from __future__ import annotations

from fuzzmind_frida_mcp import tools as _f
from fuzzmind_frida_mcp.toolsets._helpers import register_module_tools


def frida_file_list(target: str, path: str = "/") -> dict:
    """List files in a directory on the target process's filesystem.

    `target`: process name or pid (string).
    `path`: directory to list (default '/').
    Uses NSFileManager inside the target so it reflects that process's
    sandbox view. Returns file names and directory flags.
    """
    return _f.file_list(target, path=path)


def frida_file_read(target: str, path: str) -> dict:
    """Read a file from the target process's filesystem view.

    `target`: process name or pid (string).
    `path`: file path to read.
    Uses NSData inside the target (respects sandbox). Returns content
    as UTF-8 text or hex for binary data. Capped at 64KB.
    """
    return _f.file_read(target, path=path)


def frida_file_download(
    target: str,
    remote_path: str,
    local_path: str,
) -> dict:
    """Download a file from the target process's filesystem to the local host.

    Attaches to the target process, reads the remote file in 1MB chunks
    using ObjC NSData inside the process (respecting its sandbox view),
    transfers each chunk back via Frida's binary data channel, and
    reassembles the file locally at `local_path`.

    `target`: process name or pid (string).
    `remote_path`: absolute file path on the target's filesystem.
    `local_path`: local path to write the downloaded file.

    Supports large files through chunked transfer. 2-minute timeout.
    """
    return _f.file_download(target, remote_path=remote_path, local_path=local_path)


def frida_socket_connect(target: str, host: str, port: int, type: str = "tcp") -> dict:
    """Open a TCP/UDP connection from within the target process.

    `target`: process name or pid (string).
    `host`: remote hostname or IP.
    `port`: remote port number.
    `type`: 'tcp' (default) or 'udp'.
    """
    return _f.socket_connect(target, host=host, port=port, type=type)


def frida_socket_listen(target: str, port: int, type: str = "tcp") -> dict:
    """Open a listening socket inside the target process.

    `target`: process name or pid (string).
    `port`: local port to bind.
    `type`: 'tcp' (default) or 'udp'.
    """
    return _f.socket_listen(target, port=port, type=type)


def frida_file_write(target: str, path: str, data_hex_or_text: str, mode: str = "w") -> dict:
    """Write data to a file on the target process's filesystem.

    `target`: process name or pid (string).
    `path`: file path to write.
    `data_hex_or_text`: text data (mode='w') or hex bytes (mode='wb').
    `mode`: 'w' for text (default), 'wb' for binary.
    """
    return _f.file_write(target, path=path, data_hex_or_text=data_hex_or_text, mode=mode)


def frida_file_seek_read(target: str, path: str, offset: int, length: int) -> dict:
    """Read bytes from a file at a specific offset on the target filesystem.

    `target`: process name or pid (string).
    `path`: file path to read.
    `offset`: byte offset to seek to.
    `length`: number of bytes to read (capped at 64KB).
    Returns hex-encoded bytes.
    """
    return _f.file_seek_read(target, path=path, offset=offset, length=length)


def frida_sqlite_open(target: str, db_path: str) -> dict:
    """Open a SQLite database in the target process and list tables.

    Uses Frida's SqliteDatabase API within the process's sandbox view.

    `target`: process name or pid (string).
    `db_path`: path to the .db file.
    """
    return _f.sqlite_open(target, db_path=db_path)


def frida_sqlite_exec(target: str, db_path: str, sql: str) -> dict:
    """Execute SQL against a SQLite database inside the target process.

    `target`: process name or pid (string).
    `db_path`: path to the .db file.
    `sql`: SQL statement to execute.
    """
    return _f.sqlite_exec(target, db_path=db_path, sql=sql)


def frida_sqlite_dump(target: str, db_path: str) -> dict:
    """Full schema + data dump of a SQLite database in the target process.

    `target`: process name or pid (string).
    `db_path`: path to the .db file.
    """
    return _f.sqlite_dump(target, db_path=db_path)


def register_data_tools(mcp) -> None:
    """Register data tools with FastMCP."""
    register_module_tools(mcp, globals())
