"""Official Frida API wrapper group."""
from __future__ import annotations

import base64
import time
import uuid
from typing import Any

from .._core import (
    INSTALL_HINT,
    _create_script,
    _get_device,
    _json_safe,
    _load_frida,
    _registry,
    _require_session,
    _run_script,
)
from .common import (
    _BusRecord,
    _PortalRecord,
    _application_summary,
    _bus_records,
    _child_summary,
    _decode_base64,
    _device_summary,
    _official_lock,
    _portal_records,
    _process_summary,
    _service_request_params,
    _spawn_summary,
    _target_value,
)



def session_enable_child_gating(session_id: str | None = None) -> dict[str, Any]:
    """Call Session.enable_child_gating()."""
    try:
        fs = _require_session(session_id)
        fs.session.enable_child_gating()
        return {"status": "enabled", "session_id": fs.id}
    except Exception as e:
        return {"error": f"enable_child_gating failed: {e}"}


def session_disable_child_gating(session_id: str | None = None) -> dict[str, Any]:
    """Call Session.disable_child_gating()."""
    try:
        fs = _require_session(session_id)
        fs.session.disable_child_gating()
        return {"status": "disabled", "session_id": fs.id}
    except Exception as e:
        return {"error": f"disable_child_gating failed: {e}"}


def session_resume(session_id: str | None = None) -> dict[str, Any]:
    """Call Session.resume()."""
    try:
        fs = _require_session(session_id)
        fs.session.resume()
        return {"status": "resumed", "session_id": fs.id}
    except Exception as e:
        return {"error": f"session.resume failed: {e}"}


def session_is_detached(session_id: str | None = None) -> dict[str, Any]:
    """Call Session.is_detached()."""
    try:
        fs = _require_session(session_id)
        return {"session_id": fs.id, "is_detached": bool(fs.session.is_detached())}
    except Exception as e:
        return {"error": f"session.is_detached failed: {e}"}


def session_setup_peer_connection(
    session_id: str | None = None,
    stun_server: str | None = None,
    relays: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Call Session.setup_peer_connection() with optional STUN/relays."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        fs = _require_session(session_id)
        relay_objects = None
        if relays:
            relay_objects = [
                frida.Relay(
                    item["address"],
                    item.get("username"),
                    item.get("password"),
                    item.get("kind", "turn-udp"),
                )
                for item in relays
            ]
        fs.session.setup_peer_connection(stun_server=stun_server, relays=relay_objects)
        return {"status": "configured", "session_id": fs.id, "stun_server": stun_server, "relay_count": len(relays or [])}
    except Exception as e:
        return {"error": f"setup_peer_connection failed: {e}"}


def session_join_portal(
    address: str,
    session_id: str | None = None,
    certificate: str | None = None,
    token: str | None = None,
    acl: list[str] | None = None,
) -> dict[str, Any]:
    """Call Session.join_portal()."""
    try:
        fs = _require_session(session_id)
        membership = fs.session.join_portal(address, certificate=certificate, token=token, acl=acl)
        membership_id = "membership_" + str(uuid.uuid4())[:8]
        if not hasattr(fs, "_portal_memberships"):
            setattr(fs, "_portal_memberships", {})
        getattr(fs, "_portal_memberships")[membership_id] = membership
        return {"status": "joined", "session_id": fs.id, "membership_id": membership_id, "address": address}
    except Exception as e:
        return {"error": f"join_portal failed: {e}"}


def session_leave_portal(membership_id: str, session_id: str | None = None) -> dict[str, Any]:
    """Terminate a portal membership created by session_join_portal()."""
    try:
        fs = _require_session(session_id)
        memberships = getattr(fs, "_portal_memberships", {})
        membership = memberships.pop(membership_id, None)
        if membership is None:
            return {"error": f"portal membership not found: {membership_id}"}
        membership.terminate()
        return {"status": "terminated", "session_id": fs.id, "membership_id": membership_id}
    except Exception as e:
        return {"error": f"leave_portal failed: {e}", "membership_id": membership_id}
