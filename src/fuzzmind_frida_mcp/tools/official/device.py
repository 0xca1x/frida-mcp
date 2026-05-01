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
    _EventSubscriptionRecord,
    _PortalRecord,
    _application_summary,
    _bus_records,
    _child_summary,
    _decode_base64,
    _device_summary,
    _event_subscription_records,
    _official_lock,
    _portal_records,
    _process_summary,
    _service_request_params,
    _spawn_summary,
    _target_value,
)



def device_get_usb(timeout: int = 0) -> dict[str, Any]:
    """Get the first USB Frida device."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        return {"device": _device_summary(frida.get_usb_device(timeout=timeout))}
    except Exception as e:
        return {"error": f"get_usb_device failed: {e}"}


def device_get_remote() -> dict[str, Any]:
    """Get Frida's default remote device."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        return {"device": _device_summary(frida.get_remote_device())}
    except Exception as e:
        return {"error": f"get_remote_device failed: {e}"}


def device_get_matching(type: str | None = None, name_contains: str | None = None, timeout: int = 0) -> dict[str, Any]:
    """Find a device by official DeviceManager predicate inputs."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        needle = name_contains.lower() if name_contains else None

        def predicate(device: Any) -> bool:
            if type is not None and getattr(device, "type", None) != type:
                return False
            if needle is not None and needle not in getattr(device, "name", "").lower():
                return False
            return True

        device = frida.get_device_manager().get_device_matching(predicate, timeout=timeout)
        return {"device": _device_summary(device)}
    except Exception as e:
        return {"error": f"get_device_matching failed: {e}"}


def remote_device_add(
    address: str,
    certificate: str | None = None,
    origin: str | None = None,
    token: str | None = None,
    keepalive_interval: int | None = None,
) -> dict[str, Any]:
    """Add a remote Frida device with official authentication options."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        mgr = frida.get_device_manager()
        device = mgr.add_remote_device(
            address,
            certificate=certificate,
            origin=origin,
            token=token,
            keepalive_interval=keepalive_interval,
        )
        return {"status": "added", "address": address, "device": _device_summary(device)}
    except Exception as e:
        return {"error": f"add_remote_device failed: {e}"}


def remote_device_remove(address: str) -> dict[str, Any]:
    """Remove a remote Frida device from DeviceManager."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        frida.get_device_manager().remove_remote_device(address)
        return {"status": "removed", "address": address}
    except Exception as e:
        return {"error": f"remove_remote_device failed: {e}"}


def device_query_system_parameters(device_id: str | None = None) -> dict[str, Any]:
    """Call Device.query_system_parameters()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        return {"device": _device_summary(device), "parameters": _json_safe(device.query_system_parameters())}
    except Exception as e:
        return {"error": f"query_system_parameters failed: {e}"}


def device_override_option(name: str, value: Any, device_id: str | None = None) -> dict[str, Any]:
    """Call Device.override_option()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        device.override_option(name, value)
        return {"status": "overridden", "device": _device_summary(device), "name": name, "value": _json_safe(value)}
    except Exception as e:
        return {"error": f"override_option failed: {e}"}


def device_unpair(device_id: str | None = None) -> dict[str, Any]:
    """Call Device.unpair()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        summary = _device_summary(device)
        device.unpair()
        return {"status": "unpaired", "device": summary}
    except Exception as e:
        return {"error": f"unpair failed: {e}"}


def device_input(target: str, data_base64: str, device_id: str | None = None) -> dict[str, Any]:
    """Send raw input bytes to a target spawned with stdio pipes."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        raw = base64.b64decode(data_base64)
        device = _get_device(frida, device_id)
        device.input(_target_value(target), raw)
        return {"status": "sent", "target": target, "bytes_sent": len(raw), "device": _device_summary(device)}
    except Exception as e:
        return {"error": f"device.input failed: {e}"}


def device_get_process(target: str, device_id: str | None = None) -> dict[str, Any]:
    """Call Device.get_process()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        process = device.get_process(_target_value(target))
        return {"device": _device_summary(device), "process": _process_summary(process)}
    except Exception as e:
        return {"error": f"get_process failed: {e}", "target": target}


def device_is_lost(device_id: str | None = None) -> dict[str, Any]:
    """Call Device.is_lost()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        return {"device": _device_summary(device), "is_lost": bool(device.is_lost())}
    except Exception as e:
        return {"error": f"is_lost failed: {e}"}


def inject_library_blob(
    target: str,
    library_base64: str,
    entrypoint: str = "",
    data: str = "",
    device_id: str | None = None,
) -> dict[str, Any]:
    """Call Device.inject_library_blob()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        raw = base64.b64decode(library_base64)
        device = _get_device(frida, device_id)
        library_id = device.inject_library_blob(_target_value(target), raw, entrypoint, data)
        return {
            "status": "injected",
            "target": target,
            "entrypoint": entrypoint,
            "library_id": library_id,
            "byte_length": len(raw),
            "device": _device_summary(device),
        }
    except Exception as e:
        return {"error": f"inject_library_blob failed: {e}", "target": target}


def pending_spawn_list(device_id: str | None = None) -> dict[str, Any]:
    """List pending spawns captured by device spawn gating."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        items = [_spawn_summary(item) for item in device.enumerate_pending_spawn()]
        return {"device": _device_summary(device), "items": items, "count": len(items)}
    except Exception as e:
        return {"error": f"enumerate_pending_spawn failed: {e}"}


def pending_children_list(device_id: str | None = None) -> dict[str, Any]:
    """List pending children captured by child gating."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        items = [_child_summary(item) for item in device.enumerate_pending_children()]
        return {"device": _device_summary(device), "items": items, "count": len(items)}
    except Exception as e:
        return {"error": f"enumerate_pending_children failed: {e}"}


def spawn_with_options(
    program: str,
    argv: list[str] | None = None,
    env: dict[str, str] | None = None,
    envp: dict[str, str] | None = None,
    cwd: str | None = None,
    stdio: str | None = None,
    aux: dict[str, Any] | None = None,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Spawn a process using official Device.spawn options without attaching."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        device = _get_device(frida, device_id)
        kwargs: dict[str, Any] = {}
        if argv is not None:
            kwargs["argv"] = argv
        if envp is not None:
            kwargs["envp"] = envp
        if env is not None:
            kwargs["env"] = env
        if cwd is not None:
            kwargs["cwd"] = cwd
        if stdio is not None:
            kwargs["stdio"] = stdio
        if aux is not None:
            kwargs["aux"] = aux
        pid = device.spawn(program, **kwargs)
        return {"status": "spawned", "pid": pid, "program": program, "device": _device_summary(device), "options": kwargs}
    except Exception as e:
        return {"error": f"spawn failed: {e}"}


def event_subscribe(
    source: str = "device",
    events: list[str] | None = None,
    device_id: str | None = None,
    session_id: str | None = None,
    enable_spawn_gating: bool = False,
    enable_child_gating: bool = False,
) -> dict[str, Any]:
    """Subscribe to official DeviceManager/Device/Session events and queue them."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    default_events = {
        "device_manager": ["added", "removed", "changed"],
        "device": ["lost", "output", "spawn-added", "spawn-removed", "child-added", "child-removed", "process-crashed"],
        "session": ["detached"],
    }
    if source not in default_events:
        return {"error": "source must be one of: device_manager, device, session"}
    event_names = events or default_events[source]

    try:
        if source == "device_manager":
            target = frida.get_device_manager()
            target_id = None
        elif source == "device":
            target = _get_device(frida, device_id)
            target_id = getattr(target, "id", device_id)
            if enable_spawn_gating:
                target.enable_spawn_gating()
        else:
            fs = _require_session(session_id)
            target = fs.session
            target_id = fs.id
            if enable_child_gating:
                target.enable_child_gating()

        sub_id = "evt_" + str(uuid.uuid4())[:8]
        callbacks: dict[str, Any] = {}
        record = _EventSubscriptionRecord(id=sub_id, source=source, target_id=target_id, target=target, callbacks=callbacks)

        for event_name in event_names:
            def callback(*args, _event_name=event_name):
                record.add_event(_event_name, *args)

            target.on(event_name, callback)
            callbacks[event_name] = callback

        with _official_lock:
            _event_subscription_records[sub_id] = record
        return {
            "status": "subscribed",
            "subscription_id": sub_id,
            "source": source,
            "target_id": target_id,
            "events": event_names,
            "spawn_gating_enabled": bool(source == "device" and enable_spawn_gating),
            "child_gating_enabled": bool(source == "session" and enable_child_gating),
        }
    except Exception as e:
        return {"error": f"event_subscribe failed: {e}", "source": source}


def event_get_events(subscription_id: str, clear: bool = False, limit: int = 100) -> dict[str, Any]:
    """Read queued official event subscription events."""
    record = _event_subscription_records.get(subscription_id)
    if record is None:
        return {"error": f"subscription not found: {subscription_id}"}
    events = record.get_events(clear=clear, limit=limit)
    return {
        "subscription_id": record.id,
        "source": record.source,
        "target_id": record.target_id,
        "count": len(events),
        "events": events,
        "cleared": clear,
    }


def event_unsubscribe(subscription_id: str) -> dict[str, Any]:
    """Unsubscribe and remove an official event queue."""
    with _official_lock:
        record = _event_subscription_records.pop(subscription_id, None)
    if record is None:
        return {"error": f"subscription not found: {subscription_id}"}
    for event_name, callback in record.callbacks.items():
        try:
            record.target.off(event_name, callback)
        except Exception:
            pass
    return {"status": "unsubscribed", "subscription_id": subscription_id, "source": record.source}
