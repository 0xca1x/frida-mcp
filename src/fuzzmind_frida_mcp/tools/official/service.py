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
    _ChannelRecord,
    _PortalRecord,
    _ServiceRecord,
    _application_summary,
    _bus_records,
    _channel_records,
    _child_summary,
    _decode_base64,
    _device_summary,
    _official_lock,
    _portal_records,
    _process_summary,
    _service_records,
    _service_request_params,
    _spawn_summary,
    _target_value,
)



def service_request(
    address: str,
    params_json: str | None = None,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Open a device service and send one request."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        service = device.open_service(address)
        result = service.request(_service_request_params(params_json))
        try:
            service.cancel()
        except Exception:
            pass
        return {"address": address, "result": _json_safe(result), "device": _device_summary(device)}
    except Exception as e:
        return {"error": f"service_request failed: {e}", "address": address}


def open_channel(address: str, device_id: str | None = None) -> dict[str, Any]:
    """Open and immediately close a raw device channel as a readiness probe."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        stream = device.open_channel(address)
        try:
            stream.close()
        except Exception:
            pass
        return {"status": "opened", "address": address, "device": _device_summary(device)}
    except Exception as e:
        return {"error": f"open_channel failed: {e}", "address": address}


def channel_open(address: str, device_id: str | None = None) -> dict[str, Any]:
    """Open a raw device channel and keep it for stream operations."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        stream = device.open_channel(address)
        channel_id = "chan_" + str(uuid.uuid4())[:8]
        record = _ChannelRecord(id=channel_id, device_id=device_id, address=address, stream=stream)
        with _official_lock:
            _channel_records[channel_id] = record
        return {"status": "opened", "channel_id": channel_id, "address": address, "device": _device_summary(device)}
    except Exception as e:
        return {"error": f"channel_open failed: {e}", "address": address}


def channel_read(channel_id: str, size: int = 4096) -> dict[str, Any]:
    """Read bytes from an open IOStream channel."""
    record = _channel_records.get(channel_id)
    if record is None:
        return {"error": f"channel not found: {channel_id}"}
    try:
        data = record.stream.read(max(1, min(size, 1024 * 1024)))
        raw = bytes(data or b"")
        return {"channel_id": channel_id, "byte_length": len(raw), "data_base64": base64.b64encode(raw).decode("ascii")}
    except Exception as e:
        return {"error": f"channel_read failed: {e}", "channel_id": channel_id}


def channel_write(channel_id: str, data_base64: str, write_all: bool = True) -> dict[str, Any]:
    """Write bytes to an open IOStream channel."""
    record = _channel_records.get(channel_id)
    if record is None:
        return {"error": f"channel not found: {channel_id}"}
    try:
        raw = base64.b64decode(data_base64)
        if write_all and hasattr(record.stream, "write_all"):
            record.stream.write_all(raw)
            written = len(raw)
        else:
            written = record.stream.write(raw)
        return {"status": "written", "channel_id": channel_id, "bytes_written": written}
    except Exception as e:
        return {"error": f"channel_write failed: {e}", "channel_id": channel_id}


def channel_close(channel_id: str) -> dict[str, Any]:
    """Close and forget an open IOStream channel."""
    with _official_lock:
        record = _channel_records.pop(channel_id, None)
    if record is None:
        return {"error": f"channel not found: {channel_id}"}
    try:
        record.stream.close()
    except Exception:
        pass
    return {"status": "closed", "channel_id": channel_id, "address": record.address}


def service_open(address: str, device_id: str | None = None, activate: bool = True) -> dict[str, Any]:
    """Open a device service and keep it for repeated requests/events."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        service = device.open_service(address)
        service_id = "svc_" + str(uuid.uuid4())[:8]
        record = _ServiceRecord(id=service_id, device_id=device_id, address=address, service=service)

        def on_message(*args):
            record.add_event("message", *args)

        try:
            service.on("message", on_message)
            record.callbacks["message"] = on_message
        except Exception:
            pass
        if activate and hasattr(service, "activate"):
            service.activate()
        with _official_lock:
            _service_records[service_id] = record
        return {"status": "opened", "service_id": service_id, "address": address, "device": _device_summary(device)}
    except Exception as e:
        return {"error": f"service_open failed: {e}", "address": address}


def service_request_by_id(service_id: str, params_json: str | None = None) -> dict[str, Any]:
    """Send a request through an open device service."""
    record = _service_records.get(service_id)
    if record is None:
        return {"error": f"service not found: {service_id}"}
    try:
        result = record.service.request(_service_request_params(params_json))
        return {"service_id": service_id, "address": record.address, "result": _json_safe(result)}
    except Exception as e:
        return {"error": f"service_request_by_id failed: {e}", "service_id": service_id}


def service_get_events(service_id: str, clear: bool = False, limit: int = 100) -> dict[str, Any]:
    """Read queued events from an open device service."""
    record = _service_records.get(service_id)
    if record is None:
        return {"error": f"service not found: {service_id}"}
    events = record.get_events(clear=clear, limit=limit)
    return {"service_id": service_id, "address": record.address, "count": len(events), "events": events, "cleared": clear}


def service_close(service_id: str) -> dict[str, Any]:
    """Cancel and forget an open device service."""
    with _official_lock:
        record = _service_records.pop(service_id, None)
    if record is None:
        return {"error": f"service not found: {service_id}"}
    for event_name, callback in record.callbacks.items():
        try:
            record.service.off(event_name, callback)
        except Exception:
            pass
    try:
        record.service.cancel()
    except Exception:
        pass
    return {"status": "closed", "service_id": service_id, "address": record.address}
