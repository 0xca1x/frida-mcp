"""fuzzmind-frida-mcp — Frida MCP tools for dynamic analysis."""
from __future__ import annotations

import argparse
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

from fuzzmind_frida_mcp import __version__
from fuzzmind_frida_mcp import tools as _f
from fuzzmind_frida_mcp.toolsets.data import register_data_tools
from fuzzmind_frida_mcp.toolsets.instrumentation import register_instrumentation_tools
from fuzzmind_frida_mcp.toolsets.lifecycle import register_lifecycle_tools
from fuzzmind_frida_mcp.toolsets.platform import register_platform_tools
from fuzzmind_frida_mcp.toolsets.recipes import register_recipe_tools
from fuzzmind_frida_mcp.toolsets.runtimes import register_runtime_tools

mcp = FastMCP("fuzzmind-frida")


register_lifecycle_tools(mcp)
register_instrumentation_tools(mcp)
register_runtime_tools(mcp)
register_platform_tools(mcp)
register_data_tools(mcp)
register_recipe_tools(mcp)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzmind-frida-mcp",
        description="Frida MCP server for authorized dynamic analysis.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print package version and exit.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check local Frida availability and exit.",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Print local host diagnostics for Frida attach/debugging readiness and exit.",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run the MCP stdio server even when started from an interactive terminal.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"fuzzmind-frida-mcp {__version__}")
        return

    if args.check:
        print(json.dumps(_f.check(), indent=2, sort_keys=True))
        return

    if args.diagnose:
        print(json.dumps(_f.host_diagnostics(), indent=2, sort_keys=True))
        return

    if sys.stdin.isatty() and not args.stdio:
        print(
            "fuzzmind-frida-mcp is an MCP stdio server.\n"
            "Use `fuzzmind-frida-mcp` in Claude/Codex MCP config, where stdin/stdout are managed "
            "by the client.\n"
            "For a local sanity check, run `fuzzmind-frida-mcp --check`.\n"
            "For attach/debugging diagnostics, run `fuzzmind-frida-mcp --diagnose`.\n"
            "To force stdio server mode from this terminal, run `fuzzmind-frida-mcp --stdio`.",
            file=sys.stderr,
            flush=True,
        )
        return

    try:
        mcp.run()
    except KeyboardInterrupt:
        print("fuzzmind-frida-mcp stopped.", file=sys.stderr, flush=True)
        if sys.stdin.isatty():
            os._exit(130)
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
