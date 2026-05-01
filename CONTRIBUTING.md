# Contributing to fuzzmind-frida-mcp

Thanks for your interest in contributing! This project is maintained by **FuzzMind Security Lab**.

## Getting started

```bash
git clone https://github.com/fuzzmind/frida-mcp.git
cd frida-mcp
uv sync --extra dev
uv run pytest tests/
```

## Development workflow

1. **Fork & branch** — create a feature branch from `main`
2. **Write code** — follow the existing patterns in `src/fuzzmind_frida_mcp/tools/`
3. **Add tests** — put them in `tests/`
4. **Run checks** — `uv run --extra dev pytest -rx && uv run --extra dev bandit -r src --severity-level medium`
5. **Submit PR** — describe what you added and why

## Adding a new tool

1. Add the implementation function to the appropriate module under `src/fuzzmind_frida_mcp/tools/`
2. Add the MCP wrapper function (prefixed `frida_`) to the matching `src/fuzzmind_frida_mcp/toolsets/` file
3. The wrapper is auto-registered via `register_module_tools()`
4. Add a test in `tests/`

## Code style

- Python 3.11+ type hints
- All user-controlled strings passed to Frida JS must use `_js_literal()` from `_core.py` — never f-string interpolation
- Every tool function returns a `dict[str, Any]` with structured output
- Errors return `{"error": "message"}`, never raise exceptions to the MCP layer

## JS injection safety

This is a security tool. All values embedded into Frida JavaScript must go through `_js_literal()` or `json.dumps()`. The `test_static_release_audit.py` test enforces this — PRs that bypass it will be rejected.

## Reporting issues

Open an issue at [github.com/fuzzmind/frida-mcp/issues](https://github.com/fuzzmind/frida-mcp/issues).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
