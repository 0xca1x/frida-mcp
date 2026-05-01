from __future__ import annotations

import pytest


@pytest.fixture
def fresh_registry(monkeypatch):
    from fuzzmind_frida_mcp.tools import _core
    from fuzzmind_frida_mcp.tools.lifecycle import script as script_tools
    from fuzzmind_frida_mcp.tools.lifecycle import session as session_tools

    registry = _core._SessionRegistry()
    monkeypatch.setattr(_core, "_registry", registry)
    monkeypatch.setattr(script_tools, "_registry", registry)
    monkeypatch.setattr(session_tools, "_registry", registry)
    return registry


@pytest.fixture(autouse=True)
def clear_official_records():
    from fuzzmind_frida_mcp.tools.official import common

    records = [
        common._bus_records,
        common._portal_records,
        common._event_subscription_records,
        common._compiler_watch_records,
        common._channel_records,
        common._service_records,
    ]
    for record in records:
        record.clear()
    yield
    for record in records:
        record.clear()
