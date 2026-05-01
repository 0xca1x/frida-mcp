"""fuzzmind-frida-mcp -- database tools."""
from __future__ import annotations

from typing import Any

from .._core import INSTALL_HINT, _js_literal, _load_frida, _run_script


def sqlite_open(target: str, db_path: str) -> dict[str, Any]:
    """Open a SQLite database inside the target process and list tables.

    Uses Frida's SqliteDatabase API to open the db file within the
    process's sandbox view.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    db_path_js = _js_literal(db_path)
    sqlite_master_query = "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
    sqlite_master_query_js = _js_literal(sqlite_master_query)
    js = f"""
    'use strict';
    try {{
        var db = SqliteDatabase.open({db_path_js});
        var smt = db.prepare({sqlite_master_query_js});
        var tables = [];
        var row;
        while ((row = smt.step()) !== null) {{
            tables.push({{name: row[0], type: row[1]}});
        }}
        smt.reset();
        send({{
            type: 'sqlite_open',
            path: {db_path_js},
            tables: tables,
            ok: true
        }});
        db.close();
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")

def sqlite_exec(target: str, db_path: str, sql: str) -> dict[str, Any]:
    """Execute SQL against a SQLite database inside the target process.

    *db_path*: path to the .db file (resolved in process's sandbox).
    *sql*: SQL statement to execute.
    Returns query results or affected row count.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    db_path_js = _js_literal(db_path)
    sql_js = _js_literal(sql)
    query_prefix = sql.strip().split(None, 1)[0].lower() if sql.strip() else ""
    is_query = query_prefix in {"select", "pragma", "with", "explain"}

    js = f"""
    'use strict';
    try {{
        var db = SqliteDatabase.open({db_path_js});
        if ({str(is_query).lower()}) {{
            var smt = db.prepare({sql_js});
            var rows = [];
            var totalRows = 0;
            var row;
            while ((row = smt.step()) !== null) {{
                totalRows++;
                if (rows.length < 1000) rows.push(row);
            }}
            smt.reset();
            send({{
                type: 'sqlite_exec',
                path: {db_path_js},
                sql: {sql_js},
                rows: rows,
                row_count: totalRows,
                rows_truncated: totalRows > rows.length,
                ok: true
            }});
        }} else {{
            db.exec({sql_js});
            send({{
                type: 'sqlite_exec',
                path: {db_path_js},
                sql: {sql_js},
                ok: true
            }});
        }}
        db.close();
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def sqlite_dump(target: str, db_path: str) -> dict[str, Any]:
    """Dump all tables from a SQLite database inside the target process.

    Returns a full schema + data dump.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    db_path_js = _js_literal(db_path)
    js = f"""
    'use strict';
    try {{
        var db = SqliteDatabase.open({db_path_js});
        var dump = db.dump();
        send({{
            type: 'sqlite_dump',
            path: {db_path_js},
            dump: dump,
            ok: true
        }});
        db.close();
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=10, mode="attach")
