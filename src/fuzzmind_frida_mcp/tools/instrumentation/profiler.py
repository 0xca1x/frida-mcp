"""fuzzmind-frida-mcp -- profiler tools."""
from __future__ import annotations

from typing import Any
import json

from .._core import INSTALL_HINT, _load_frida, _run_script


def profiler_start(
    target: str,
    addresses: list[str],
    sampler_type: str = "wall_clock",
    duration_seconds: int = 10,
) -> dict[str, Any]:
    """Start profiling specific addresses in the target process.

    *addresses*: list of hex addresses to instrument.
    *sampler_type*: 'wall_clock' (default) or 'cycle_count'.
    *duration_seconds*: how long to profile (default 10).
    Returns a profiling report after completion.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    if not addresses:
        return {"error": "addresses must not be empty"}

    sampler_map = {
        "wall_clock": "WallClockSampler",
        "cycle_count": "CycleSampler",
        "busy_cycle": "BusyCycleSampler",
        "user_time": "UserTimeSampler",
        "malloc_count": "MallocCountSampler",
    }
    sampler_ctor = sampler_map.get(sampler_type)
    if sampler_ctor is None:
        return {"error": f"unsupported sampler_type: {sampler_type}", "valid_types": list(sampler_map.keys())}

    addrs_js = json.dumps(addresses)
    delay_ms = max(0, int(duration_seconds * 1000) - 250)

    js = f"""
    'use strict';
    try {{
        var addrs = {addrs_js}.map(function(a) {{ return ptr(a); }});
        var profiler = new Profiler();
        var sampler = new {sampler_ctor}();
        for (var i = 0; i < addrs.length; i++) {{
            profiler.instrument(addrs[i], sampler);
        }}
        send({{
            type: 'profiler_start',
            addresses: addrs.map(function(a) {{ return a.toString(); }}),
            sampler: {json.dumps(sampler_type)},
            ok: true
        }});
        setTimeout(function() {{
            try {{
                var report = profiler.generateReport();
                send({{type: 'profiler_report', report: report, ok: true}});
            }} catch (reportError) {{
                send({{type: 'error', message: 'Profiler.generateReport failed: ' + reportError.message}});
            }}
        }}, {delay_ms});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=duration_seconds + 1, mode="attach")

def profiler_report(target: str) -> dict[str, Any]:
    """Explain how to retrieve profiler output with the current one-shot API."""
    return {
        "error": "profiler state is script-local and cannot be retrieved after detach",
        "target": target,
        "hint": "use frida_profiler_start; it now returns profiler_report events after duration_seconds",
    }

def instruction_parse(target: str, address: str) -> dict[str, Any]:
    """Disassemble a single instruction at *address*.

    Uses Frida's Instruction.parse() for architecture-aware disassembly.
    Returns mnemonic, operands, size, and other instruction metadata.
    """
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    address_js = json.dumps(address)
    js = f"""
    'use strict';
    try {{
        var insn = Instruction.parse(ptr({address_js}));
        send({{
            type: 'instruction_parse',
            address: insn.address.toString(),
            next: insn.next.toString(),
            size: insn.size,
            mnemonic: insn.mnemonic,
            opStr: insn.opStr,
            toString: insn.toString()
        }});
    }} catch (e) {{
        send({{type: 'error', message: e.message}});
    }}
    """
    return _run_script(frida, target, js, duration_seconds=3, mode="attach")
