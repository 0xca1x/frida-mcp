"""fuzzmind-frida-mcp -- network tools."""
from __future__ import annotations

from typing import Any

from .._core import INSTALL_HINT, _js_literal, _load_frida, _run_script


def socket_connect(target: str, host: str, port: int, type: str = "tcp") -> dict[str, Any]:
    """Open a socket connection from within the target process.

    *host*: remote hostname or IP.
    *port*: remote port number.
    *type*: 'tcp' (default) or 'udp'.
    Returns connection info from within the target.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    family = "ipv4"
    sock_type = "tcp" if type == "tcp" else "udp"
    host_js = _js_literal(host)
    family_js = _js_literal(family)
    sock_type_js = _js_literal(sock_type)

    js = f"""
    'use strict';
    Socket.connect({{
        family: {family_js},
        host: {host_js},
        port: {port},
        type: {sock_type_js}
    }}).then(function(connection) {{
        send({{
            type: 'socket_connect',
            local_address: connection.localAddress,
            remote_address: connection.peerAddress,
            ok: true
        }});
        connection.close().catch(function() {{}});
    }}).catch(function(err) {{
        send({{type: 'error', message: err.message}});
    }});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")

def socket_listen(target: str, port: int, type: str = "tcp") -> dict[str, Any]:
    """Open a listening socket inside the target process.

    *port*: local port to bind.
    *type*: 'tcp' (default) or 'udp'.
    Returns listener info.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    sock_type = "tcp" if type == "tcp" else "udp"
    sock_type_js = _js_literal(sock_type)

    js = f"""
    'use strict';
    Socket.listen({{
        family: 'ipv4',
        host: '0.0.0.0',
        port: {port},
        type: {sock_type_js},
        backlog: 1
    }}).then(function(listener) {{
        send({{
            type: 'socket_listen',
            port: {port},
            ok: true
        }});
        setTimeout(function() {{
            listener.close().catch(function() {{}});
        }}, 2000);
    }}).catch(function(err) {{
        send({{type: 'error', message: err.message}});
    }});
    """
    return _run_script(frida, target, js, duration_seconds=5, mode="attach")
