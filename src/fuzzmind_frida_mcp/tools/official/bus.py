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



def bus_attach(device_id: str | None = None) -> dict[str, Any]:
    """Attach to a device bus and keep an event queue."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        bus = device.get_bus()
        bus_id = "bus_" + str(uuid.uuid4())[:8]
        record = _BusRecord(id=bus_id, device_id=device_id, bus=bus)

        def on_message(message=None, data=None, *args):
            if args:
                message = {"message": _json_safe(message), "args": [_json_safe(arg) for arg in args]}
            record.add_event(message, data)

        bus.on("message", on_message)
        bus.attach()
        with _official_lock:
            _bus_records[bus_id] = record
        return {"status": "attached", "bus_id": bus_id, "device": _device_summary(device)}
    except Exception as e:
        return {"error": f"bus_attach failed: {e}"}


def bus_post(bus_id: str, message: Any, data_base64: str | None = None) -> dict[str, Any]:
    """Post a message on an attached Frida bus."""
    with _official_lock:
        record = _bus_records.get(bus_id)
    if record is None:
        return {"error": f"bus not found: {bus_id}"}
    try:
        data = _decode_base64(data_base64)
        record.bus.post(message, data=data)
        return {"status": "posted", "bus_id": bus_id, "has_data": data is not None}
    except Exception as e:
        return {"error": f"bus_post failed: {e}", "bus_id": bus_id}


def bus_get_events(bus_id: str, clear: bool = False, limit: int = 100) -> dict[str, Any]:
    """Read queued bus events."""
    with _official_lock:
        record = _bus_records.get(bus_id)
    if record is None:
        return {"error": f"bus not found: {bus_id}"}
    events = record.get_events(clear=clear, limit=limit)
    return {"bus_id": bus_id, "count": len(events), "events": events, "cleared": clear}


def bus_detach(bus_id: str) -> dict[str, Any]:
    """Forget a bus record. Frida's Bus does not expose an explicit detach."""
    with _official_lock:
        record = _bus_records.pop(bus_id, None)
    if record is None:
        return {"error": f"bus not found: {bus_id}"}
    return {"status": "detached", "bus_id": bus_id}
