"""Shared helpers for official Frida API wrappers.

This module is intentionally private to the official API wrapper package.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from threading import RLock
from typing import Any

from .._core import (
    INSTALL_HINT,
    _create_script,
    _get_device,
    _json_safe,
    _load_frida,
    _require_session,
    _run_script,
)


def _target_value(target: str) -> int | str:
    return int(target) if isinstance(target, str) and target.isdigit() else target


def _decode_base64(data_base64: str | None) -> bytes | None:
    if data_base64 is None:
        return None
    return base64.b64decode(data_base64)


def _object_attrs(obj: Any, names: list[str]) -> dict[str, Any]:
    return {name: _json_safe(getattr(obj, name, None)) for name in names}


def _device_summary(device: Any) -> dict[str, Any]:
    return _object_attrs(device, ["id", "name", "type", "is_lost"])


def _spawn_summary(spawn: Any) -> dict[str, Any]:
    return _object_attrs(spawn, ["pid", "identifier"])


def _child_summary(child: Any) -> dict[str, Any]:
    return _object_attrs(child, ["pid", "parent_pid", "identifier", "origin"])


def _application_summary(app: Any) -> dict[str, Any]:
    return _object_attrs(app, ["identifier", "name", "pid", "parameters"])


def _process_summary(proc: Any) -> dict[str, Any]:
    return _object_attrs(proc, ["pid", "name", "parameters"])


def _service_request_params(params_json: str | None) -> Any:
    if params_json is None or not params_json.strip():
        return {}
    return json.loads(params_json)


@dataclass
class _BusRecord:
    id: str
    device_id: str | None
    bus: Any
    created_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)
    _lock: RLock = field(default_factory=RLock)

    def add_event(self, message: Any, data: bytes | None = None) -> None:
        with self._lock:
            event: dict[str, Any] = {
                "ts": time.time(),
                "bus_id": self.id,
                "message": _json_safe(message),
            }
            if data is not None:
                raw = bytes(data)
                event["data_size"] = len(raw)
                event["data_base64"] = base64.b64encode(raw).decode("ascii")
            self.events.append(event)
            self.events = self.events[-1000:]

    def get_events(self, *, clear: bool, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self.events[-max(1, min(limit, 1000)):])
            if clear:
                self.events = []
            return events


@dataclass
class _PortalRecord:
    id: str
    service: Any
    created_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)
    _lock: RLock = field(default_factory=RLock)

    def add_event(self, event_type: str, *args: Any) -> None:
        with self._lock:
            self.events.append({
                "ts": time.time(),
                "portal_id": self.id,
                "type": event_type,
                "args": [_json_safe(arg) for arg in args],
            })
            self.events = self.events[-1000:]

    def get_events(self, *, clear: bool, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self.events[-max(1, min(limit, 1000)):])
            if clear:
                self.events = []
            return events


@dataclass
class _EventSubscriptionRecord:
    id: str
    source: str
    target_id: str | None
    target: Any
    callbacks: dict[str, Any]
    created_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)
    _lock: RLock = field(default_factory=RLock)

    def add_event(self, event_type: str, *args: Any) -> None:
        with self._lock:
            self.events.append({
                "ts": time.time(),
                "subscription_id": self.id,
                "source": self.source,
                "type": event_type,
                "args": [_json_safe(arg) for arg in args],
            })
            self.events = self.events[-1000:]

    def get_events(self, *, clear: bool, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self.events[-max(1, min(limit, 1000)):])
            if clear:
                self.events = []
            return events


@dataclass
class _CompilerWatchRecord:
    id: str
    compiler: Any
    entrypoint: str
    created_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)
    callbacks: dict[str, Any] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock)

    def add_event(self, event_type: str, *args: Any) -> None:
        with self._lock:
            self.events.append({
                "ts": time.time(),
                "watch_id": self.id,
                "type": event_type,
                "args": [_json_safe(arg) for arg in args],
            })
            self.events = self.events[-1000:]

    def get_events(self, *, clear: bool, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self.events[-max(1, min(limit, 1000)):])
            if clear:
                self.events = []
            return events


@dataclass
class _ChannelRecord:
    id: str
    device_id: str | None
    address: str
    stream: Any
    created_at: float = field(default_factory=time.time)


@dataclass
class _ServiceRecord:
    id: str
    device_id: str | None
    address: str
    service: Any
    created_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)
    callbacks: dict[str, Any] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock)

    def add_event(self, event_type: str, *args: Any) -> None:
        with self._lock:
            self.events.append({
                "ts": time.time(),
                "service_id": self.id,
                "type": event_type,
                "args": [_json_safe(arg) for arg in args],
            })
            self.events = self.events[-1000:]

    def get_events(self, *, clear: bool, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self.events[-max(1, min(limit, 1000)):])
            if clear:
                self.events = []
            return events


_bus_records: dict[str, _BusRecord] = {}
_portal_records: dict[str, _PortalRecord] = {}
_event_subscription_records: dict[str, _EventSubscriptionRecord] = {}
_compiler_watch_records: dict[str, _CompilerWatchRecord] = {}
_channel_records: dict[str, _ChannelRecord] = {}
_service_records: dict[str, _ServiceRecord] = {}
_official_lock = RLock()
