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



def portal_start(
    cluster_address: str | None = None,
    cluster_port: int | None = None,
    control_address: str | None = None,
    control_port: int | None = None,
    certificate: str | None = None,
    origin: str | None = None,
    token: str | None = None,
    asset_root: str | None = None,
) -> dict[str, Any]:
    """Create and start a PortalService using EndpointParameters."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        authentication = ("token", token) if token is not None else None
        cluster_params = frida.EndpointParameters(
            address=cluster_address,
            port=cluster_port,
            certificate=certificate,
            origin=origin,
            authentication=authentication,
            asset_root=asset_root,
        )
        control_params = None
        if control_address is not None or control_port is not None:
            control_params = frida.EndpointParameters(
                address=control_address,
                port=control_port,
                certificate=certificate,
                origin=origin,
                authentication=authentication,
                asset_root=asset_root,
            )
        service = frida.PortalService(cluster_params=cluster_params, control_params=control_params)
        portal_id = "portal_" + str(uuid.uuid4())[:8]
        record = _PortalRecord(id=portal_id, service=service)

        for signal in ("node-connected", "node-joined", "node-left", "node-disconnected", "controller-connected", "controller-disconnected"):
            try:
                service.on(signal, lambda *args, _signal=signal: record.add_event(_signal, *args))
            except Exception:
                pass

        service.start()
        with _official_lock:
            _portal_records[portal_id] = record
        return {
            "status": "started",
            "portal_id": portal_id,
            "cluster": {"address": cluster_address, "port": cluster_port},
            "control": {"address": control_address, "port": control_port},
        }
    except Exception as e:
        return {"error": f"portal_start failed: {e}"}


def portal_stop(portal_id: str) -> dict[str, Any]:
    """Stop a PortalService."""
    with _official_lock:
        record = _portal_records.pop(portal_id, None)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    try:
        record.service.stop()
        return {"status": "stopped", "portal_id": portal_id}
    except Exception as e:
        return {"error": f"portal_stop failed: {e}", "portal_id": portal_id}


def portal_broadcast(portal_id: str, message: Any, data_base64: str | None = None) -> dict[str, Any]:
    """Call PortalService.broadcast()."""
    with _official_lock:
        record = _portal_records.get(portal_id)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    try:
        record.service.broadcast(message, data=_decode_base64(data_base64))
        return {"status": "broadcast", "portal_id": portal_id}
    except Exception as e:
        return {"error": f"portal_broadcast failed: {e}", "portal_id": portal_id}


def portal_narrowcast(portal_id: str, tag: str, message: Any, data_base64: str | None = None) -> dict[str, Any]:
    """Call PortalService.narrowcast()."""
    with _official_lock:
        record = _portal_records.get(portal_id)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    try:
        record.service.narrowcast(tag, message, data=_decode_base64(data_base64))
        return {"status": "narrowcast", "portal_id": portal_id, "tag": tag}
    except Exception as e:
        return {"error": f"portal_narrowcast failed: {e}", "portal_id": portal_id}


def portal_post(portal_id: str, connection_id: int, message: Any, data_base64: str | None = None) -> dict[str, Any]:
    """Call PortalService.post()."""
    with _official_lock:
        record = _portal_records.get(portal_id)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    try:
        record.service.post(connection_id, message, data=_decode_base64(data_base64))
        return {"status": "posted", "portal_id": portal_id, "connection_id": connection_id}
    except Exception as e:
        return {"error": f"portal_post failed: {e}", "portal_id": portal_id}


def portal_tag(portal_id: str, connection_id: int, tag: str) -> dict[str, Any]:
    """Call PortalService.tag()."""
    with _official_lock:
        record = _portal_records.get(portal_id)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    try:
        record.service.tag(connection_id, tag)
        return {"status": "tagged", "portal_id": portal_id, "connection_id": connection_id, "tag": tag}
    except Exception as e:
        return {"error": f"portal_tag failed: {e}", "portal_id": portal_id}


def portal_untag(portal_id: str, connection_id: int, tag: str) -> dict[str, Any]:
    """Call PortalService.untag()."""
    with _official_lock:
        record = _portal_records.get(portal_id)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    try:
        record.service.untag(connection_id, tag)
        return {"status": "untagged", "portal_id": portal_id, "connection_id": connection_id, "tag": tag}
    except Exception as e:
        return {"error": f"portal_untag failed: {e}", "portal_id": portal_id}


def portal_enumerate_tags(portal_id: str, connection_id: int) -> dict[str, Any]:
    """Call PortalService.enumerate_tags()."""
    with _official_lock:
        record = _portal_records.get(portal_id)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    try:
        tags = record.service.enumerate_tags(connection_id)
        return {"portal_id": portal_id, "connection_id": connection_id, "tags": list(tags), "count": len(tags)}
    except Exception as e:
        return {"error": f"portal_enumerate_tags failed: {e}", "portal_id": portal_id}


def portal_get_events(portal_id: str, clear: bool = False, limit: int = 100) -> dict[str, Any]:
    """Read queued PortalService lifecycle events."""
    with _official_lock:
        record = _portal_records.get(portal_id)
    if record is None:
        return {"error": f"portal not found: {portal_id}"}
    events = record.get_events(clear=clear, limit=limit)
    return {"portal_id": portal_id, "count": len(events), "events": events, "cleared": clear}
