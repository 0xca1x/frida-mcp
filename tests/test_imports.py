from __future__ import annotations

import importlib
import pkgutil

import fuzzmind_frida_mcp


def test_all_package_modules_import_cleanly():
    failures = []
    for module_info in pkgutil.walk_packages(
        fuzzmind_frida_mcp.__path__,
        prefix=f"{fuzzmind_frida_mcp.__name__}.",
    ):
        try:
            importlib.import_module(module_info.name)
        except Exception as exc:  # pragma: no cover - assertion reports details
            failures.append(f"{module_info.name}: {type(exc).__name__}: {exc}")

    assert failures == []
