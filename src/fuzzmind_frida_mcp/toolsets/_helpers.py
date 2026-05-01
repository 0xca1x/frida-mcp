"""Shared MCP toolset registration helpers."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


def register_module_tools(mcp: Any, namespace: dict[str, Any]) -> None:
    """Register all public MCP tool functions from a module namespace."""
    functions: list[Callable[..., Any]] = [
        fn
        for name, fn in namespace.items()
        if name.startswith("frida_") and callable(fn)
    ]
    for fn in functions:
        mcp.tool()(fn)
