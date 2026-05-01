from __future__ import annotations

import ast
import inspect
import textwrap
from types import ModuleType
from typing import Any, get_args, get_origin

import pytest

from fuzzmind_frida_mcp.toolsets import data, instrumentation, lifecycle, platform, recipes, runtimes


TOOLSET_MODULES = [data, instrumentation, lifecycle, platform, recipes, runtimes]
EXPECTED_TOOL_COUNT = 275
REGISTER_FUNCTIONS = {
    data: data.register_data_tools,
    instrumentation: instrumentation.register_instrumentation_tools,
    lifecycle: lifecycle.register_lifecycle_tools,
    platform: platform.register_platform_tools,
    recipes: recipes.register_recipe_tools,
    runtimes: runtimes.register_runtime_tools,
}


def _tool_functions() -> list[tuple[ModuleType, str, Any]]:
    functions = []
    for module in TOOLSET_MODULES:
        for name, value in vars(module).items():
            if name.startswith("frida_") and callable(value):
                functions.append((module, name, value))
    return functions


def _delegate_name(fn: Any) -> str:
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    delegates = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "_f"
    }
    assert len(delegates) == 1, f"{fn.__name__} should delegate to exactly one _f function"
    return delegates.pop()


def _dummy_value(name: str, annotation: Any) -> Any:
    if name.endswith("base64") or name in {"data_base64", "library_base64"}:
        return "AQID"
    if name.endswith("json") or name in {"params_json", "options_json", "source_map_json", "args_json"}:
        return "{}"
    if name in {"output_path", "output_file", "local_path", "script_path", "input_path", "server_binary_path"}:
        return "/tmp/fuzzmind-test-value"
    if name in {"js_code", "source", "worker_source", "replacement_js", "on_enter_js", "on_leave_js"}:
        return "send('ok');"
    if name in {"hex_bytes", "pattern"}:
        return "00"
    if name in {"address", "function_addr", "replacement_addr", "pc", "src", "dst", "object_address"}:
        return "0x1000"
    if name in {"return_type", "type", "runtime", "kind", "mode", "encoding", "protection", "conditions"}:
        return "test"

    origin = get_origin(annotation)
    args = get_args(annotation)
    if annotation is int:
        return 1
    if annotation is float:
        return 1.0
    if annotation is bool:
        return False
    if annotation is str:
        return f"{name}-value"
    if origin is list:
        inner = args[0] if args else str
        return [_dummy_value(name, inner)]
    if origin is dict:
        return {"key": "value"}

    annotation_text = str(annotation)
    if "int" in annotation_text and "str" not in annotation_text:
        return 1
    if "float" in annotation_text:
        return 1.0
    if "bool" in annotation_text:
        return False
    if "list" in annotation_text:
        return ["value"]
    if "dict" in annotation_text or "Any" in annotation_text:
        return {"key": "value"}
    return f"{name}-value"


def _required_kwargs(fn: Any) -> dict[str, Any]:
    signature = inspect.signature(fn)
    kwargs = {}
    for name, parameter in signature.parameters.items():
        if parameter.default is inspect.Signature.empty:
            kwargs[name] = _dummy_value(name, parameter.annotation)
    return kwargs


def test_repository_exposes_expected_275_mcp_tool_functions():
    names = [name for _module, name, _fn in _tool_functions()]
    assert len(names) == EXPECTED_TOOL_COUNT
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    ("module", "tool_name", "fn"),
    _tool_functions(),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_all_275_toolset_functions_delegate_to_src_tools(monkeypatch, module, tool_name, fn):
    delegate = _delegate_name(fn)
    calls = []

    def fake_delegate(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return {"delegate": delegate, "tool": tool_name}

    monkeypatch.setattr(module._f, delegate, fake_delegate)

    result = fn(**_required_kwargs(fn))

    assert result == {"delegate": delegate, "tool": tool_name}
    assert len(calls) == 1


def test_register_functions_register_all_275_tools_once():
    registered = []

    class FakeMcp:
        def tool(self):
            def decorator(fn):
                registered.append(fn.__name__)
                return fn

            return decorator

    for module in TOOLSET_MODULES:
        register = REGISTER_FUNCTIONS[module]
        register(FakeMcp())

    expected_names = [name for _module, name, _fn in _tool_functions()]
    assert len(registered) == EXPECTED_TOOL_COUNT
    assert registered == expected_names
