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
    _CompilerWatchRecord,
    _PortalRecord,
    _application_summary,
    _bus_records,
    _child_summary,
    _compiler_watch_records,
    _decode_base64,
    _device_summary,
    _official_lock,
    _portal_records,
    _process_summary,
    _service_request_params,
    _spawn_summary,
    _target_value,
)



def compiler_build(
    entrypoint: str,
    project_root: str | None = None,
    output_format: str | None = None,
    bundle_format: str | None = None,
    type_check: str | None = None,
    source_maps: str | None = None,
    compression: str | None = None,
    platform: str | None = "gum",
    externals: list[str] | None = None,
) -> dict[str, Any]:
    """Call frida.Compiler.build()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        compiler = frida.Compiler()
        output = compiler.build(
            entrypoint,
            project_root=project_root,
            output_format=output_format,
            bundle_format=bundle_format,
            type_check=type_check,
            source_maps=source_maps,
            compression=compression,
            platform=platform,
            externals=externals,
        )
        return {"status": "built", "entrypoint": entrypoint, "output": output}
    except Exception as e:
        return {"error": f"compiler_build failed: {e}"}


def compiler_watch(
    entrypoint: str,
    project_root: str | None = None,
    output_format: str | None = None,
    bundle_format: str | None = None,
    type_check: str | None = None,
    source_maps: str | None = None,
    compression: str | None = None,
    platform: str | None = "gum",
    externals: list[str] | None = None,
) -> dict[str, Any]:
    """Call frida.Compiler.watch() and queue compiler events."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        compiler = frida.Compiler()
        watch_id = "cw_" + str(uuid.uuid4())[:8]
        record = _CompilerWatchRecord(id=watch_id, compiler=compiler, entrypoint=entrypoint)

        def on_output(*args):
            record.add_event("output", *args)

        def on_diagnostics(*args):
            record.add_event("diagnostics", *args)

        callbacks = {"output": on_output, "diagnostics": on_diagnostics}
        for event_name, callback in callbacks.items():
            try:
                compiler.on(event_name, callback)
            except Exception:
                pass
        record.callbacks.update(callbacks)
        compiler.watch(
            entrypoint,
            project_root=project_root,
            output_format=output_format,
            bundle_format=bundle_format,
            type_check=type_check,
            source_maps=source_maps,
            compression=compression,
            platform=platform,
            externals=externals,
        )
        with _official_lock:
            _compiler_watch_records[watch_id] = record
        return {"status": "watching", "watch_id": watch_id, "entrypoint": entrypoint, "project_root": project_root}
    except Exception as e:
        return {"error": f"compiler_watch failed: {e}", "entrypoint": entrypoint}


def compiler_watch_get_events(watch_id: str, clear: bool = False, limit: int = 100) -> dict[str, Any]:
    """Read events from a compiler watch."""
    record = _compiler_watch_records.get(watch_id)
    if record is None:
        return {"error": f"compiler watch not found: {watch_id}"}
    events = record.get_events(clear=clear, limit=limit)
    return {"watch_id": watch_id, "entrypoint": record.entrypoint, "count": len(events), "events": events, "cleared": clear}


def compiler_watch_stop(watch_id: str) -> dict[str, Any]:
    """Stop tracking a compiler watch and detach event handlers."""
    with _official_lock:
        record = _compiler_watch_records.pop(watch_id, None)
    if record is None:
        return {"error": f"compiler watch not found: {watch_id}"}
    for event_name, callback in record.callbacks.items():
        try:
            record.compiler.off(event_name, callback)
        except Exception:
            pass
    return {"status": "stopped", "watch_id": watch_id, "entrypoint": record.entrypoint}


def package_search(query: str, offset: int | None = None, limit: int | None = None) -> dict[str, Any]:
    """Call frida.PackageManager.search()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        result = frida.PackageManager().search(query, offset=offset, limit=limit)
        return {"query": query, "result": _json_safe(result)}
    except Exception as e:
        return {"error": f"package_search failed: {e}"}


def package_install(
    project_root: str | None = None,
    role: str | None = None,
    specs: list[str] | None = None,
    omits: list[str] | None = None,
) -> dict[str, Any]:
    """Call frida.PackageManager.install()."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        result = frida.PackageManager().install(project_root=project_root, role=role, specs=specs, omits=omits)
        return {"status": "installed", "result": _json_safe(result)}
    except Exception as e:
        return {"error": f"package_install failed: {e}"}


def package_registry() -> dict[str, Any]:
    """Read PackageManager.registry."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}
    try:
        registry = frida.PackageManager().registry
        return {"registry": _json_safe(registry)}
    except Exception as e:
        return {"error": f"package_registry failed: {e}"}
