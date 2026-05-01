"""fuzzmind-frida-mcp -- agent workflow and environment tools."""
from __future__ import annotations

from importlib import metadata
from pathlib import Path
from typing import Any
import json
import os
import platform
import shutil
import sys
import tempfile

from .._core import INSTALL_HINT, _have_tool, _load_frida, _resolve_tool, _run_cmd


_BRIDGES = {
    "objc": ("frida-objc-bridge", "ObjC"),
    "java": ("frida-java-bridge", "Java"),
    "swift": ("frida-swift-bridge", "Swift"),
}


def default_bridge_root() -> Path:
    """Return a writable bridge package root suitable for PyPI/uv installs."""
    base = os.environ.get("FUZZMIND_FRIDA_BRIDGE_ROOT")
    if base:
        return Path(base).expanduser()
    return Path.home() / ".fuzzmind" / "frida-mcp" / "frida-bridges"


def bridge_status(bridge_root: str | None = None) -> dict[str, Any]:
    """Check whether Frida 17 runtime bridge packages can be bundled."""
    frida = _load_frida()
    if frida is None:
        return {"error": "frida not installed", **INSTALL_HINT}

    root = Path(bridge_root).expanduser() if bridge_root else default_bridge_root()
    result: dict[str, Any] = {
        "frida_version": getattr(frida, "__version__", None),
        "bridge_root": str(root),
        "compiler_available": hasattr(frida, "Compiler"),
        "bridges": {},
    }
    if not hasattr(frida, "Compiler"):
        result["hint"] = "frida.Compiler is unavailable; install a Frida version with Compiler support."
        return result

    for key, (package, global_name) in _BRIDGES.items():
        result["bridges"][key] = _probe_bridge(frida, root, package, global_name)

    missing = [
        item["package"]
        for item in result["bridges"].values()
        if not item.get("available")
    ]
    result["all_available"] = not missing
    if missing:
        result["hint"] = (
            "Install the missing bridge package(s) in the bridge cache used by the MCP server: "
            + " ".join(missing)
        )
    return result


def bridge_install(
    bridges: list[str] | None = None,
    bridge_root: str | None = None,
    save_optional: bool = True,
    registry: str | None = None,
) -> dict[str, Any]:
    """Install Frida 17 runtime bridge packages with frida-pm."""
    if not _have_tool("frida-pm"):
        return {
            "error": "frida-pm not found",
            "hint": "install frida-tools>=14.8.1,<15, then rerun frida_bridge_install",
        }

    specs = _bridge_specs(bridges)
    if isinstance(specs, dict) and "error" in specs:
        return specs
    root = Path(bridge_root).expanduser() if bridge_root else default_bridge_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return {
            "error": f"could not create bridge cache directory: {e}",
            "bridge_root": str(root),
        }

    cmd = ["frida-pm"]
    if registry:
        cmd.extend(["--registry", registry])
    cmd.extend(["install", "--project-root", str(root)])
    if save_optional:
        cmd.append("--save-optional")
    cmd.extend(specs)

    res = _run_cmd(cmd, check=False, timeout=180.0)
    status = bridge_status(bridge_root=str(root))
    return {
        "command": cmd,
        "returncode": res.returncode,
        "stdout": res.stdout[-4000:],
        "stderr": res.stderr[-4000:],
        "installed": res.returncode == 0,
        "bridge_root": str(root),
        "requested": specs,
        "status": status,
    }


def _bridge_specs(bridges: list[str] | None) -> list[str] | dict[str, Any]:
    if bridges is None:
        return [package for package, _global_name in _BRIDGES.values()]

    specs: list[str] = []
    allowed = {**{k: v[0] for k, v in _BRIDGES.items()}, **{v[0]: v[0] for v in _BRIDGES.values()}}
    for bridge in bridges:
        package = allowed.get(bridge)
        if package is None:
            return {
                "error": "unknown bridge: " + bridge,
                "allowed": sorted(allowed),
            }
        specs.append(package)
    return specs


def _probe_bridge(frida, root: Path, package: str, global_name: str) -> dict[str, Any]:
    if not root.is_dir():
        return {
            "package": package,
            "global": global_name,
            "available": False,
            "error": f"bridge root does not exist: {root}",
        }

    source = (
        f"import {global_name} from {json.dumps(package)};\n"
        f"globalThis.{global_name} = {global_name};\n"
        f"send({{{json.dumps('bridge')}: {json.dumps(global_name)}}});\n"
    )
    fd, path = tempfile.mkstemp(prefix="fuzzmind-bridge-probe-", suffix=".js", dir=root)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(source)
        compiler = frida.Compiler()
        compiler.build(
            path,
            project_root=str(root),
            bundle_format="iife",
            platform="gum",
            type_check="none",
            source_maps="omitted",
        )
        return {"package": package, "global": global_name, "available": True}
    except Exception as e:
        return {
            "package": package,
            "global": global_name,
            "available": False,
            "error": str(e),
        }
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def gadget_config(
    interaction: str = "listen",
    output_path: str | None = None,
    address: str | None = None,
    port: int | None = None,
    path: str | None = None,
    parameters: dict[str, Any] | None = None,
    on_load: str = "wait",
    on_port_conflict: str = "fail",
    on_change: str | None = None,
    teardown: str = "minimal",
    runtime: str = "default",
    code_signing: str = "optional",
    token: str | None = None,
    certificate: str | None = None,
    origin: str | None = None,
    asset_root: str | None = None,
    acl: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a Frida Gadget configuration file."""
    if interaction not in {"listen", "connect", "script", "script-directory"}:
        return {"error": "interaction must be one of: listen, connect, script, script-directory"}
    if teardown not in {"minimal", "full"}:
        return {"error": "teardown must be 'minimal' or 'full'"}
    if runtime not in {"default", "qjs", "v8"}:
        return {"error": "runtime must be one of: default, qjs, v8"}
    if code_signing not in {"optional", "required"}:
        return {"error": "code_signing must be 'optional' or 'required'"}

    interaction_config: dict[str, Any] = {"type": interaction}
    if interaction == "listen":
        interaction_config.update(
            {
                "address": address or "127.0.0.1",
                "port": port or 27042,
                "on_port_conflict": on_port_conflict,
                "on_load": on_load,
            }
        )
        if on_load not in {"wait", "resume"}:
            return {"error": "on_load must be 'wait' or 'resume' for listen interaction"}
        if on_port_conflict not in {"fail", "pick-next"}:
            return {"error": "on_port_conflict must be 'fail' or 'pick-next'"}
        _set_optional(interaction_config, "origin", origin)
        _set_optional(interaction_config, "asset_root", asset_root)
    elif interaction == "connect":
        interaction_config.update({"address": address or "127.0.0.1", "port": port or 27052})
        if acl is not None:
            interaction_config["acl"] = acl
    else:
        if not path:
            return {"error": f"path is required for {interaction} interaction"}
        interaction_config["path"] = path
        if interaction == "script":
            interaction_config["parameters"] = parameters or {}
            if on_change is not None:
                if on_change not in {"ignore", "reload"}:
                    return {"error": "on_change must be 'ignore' or 'reload' for script interaction"}
                interaction_config["on_change"] = on_change
        else:
            if on_change is not None:
                if on_change not in {"ignore", "rescan"}:
                    return {"error": "on_change must be 'ignore' or 'rescan' for script-directory interaction"}
                interaction_config["on_change"] = on_change

    _set_optional(interaction_config, "token", token)
    _set_optional(interaction_config, "certificate", certificate)

    config: dict[str, Any] = {"interaction": interaction_config}
    if teardown != "minimal":
        config["teardown"] = teardown
    if runtime != "default":
        config["runtime"] = runtime
    if code_signing != "optional":
        config["code_signing"] = code_signing

    rendered = json.dumps(config, indent=2, sort_keys=True)
    result: dict[str, Any] = {
        "config": config,
        "json": rendered,
        "suggested_filename": "FridaGadget.config",
    }
    if output_path:
        out = Path(output_path)
        out.write_text(rendered + "\n")
        result["output_path"] = str(out)
    return result


def _set_optional(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target[key] = value


def gadget_script_template(kind: str = "minimal") -> dict[str, Any]:
    """Return a Frida Gadget-compatible script template."""
    templates = {
        "minimal": """
rpc.exports = {
  init(stage, parameters) {
    console.log('[init]', stage, JSON.stringify(parameters));
  },
  dispose() {
    console.log('[dispose]');
  }
};
""".strip(),
        "native-open": """
rpc.exports = {
  init(stage, parameters) {
    const openPtr = Module.getGlobalExportByName('open');
    Interceptor.attach(openPtr, {
      onEnter(args) {
        const path = args[0].readUtf8String();
        console.log('open(\"' + path + '\")');
      }
    });
  },
  dispose() {}
};
""".strip(),
        "java-ready": """
rpc.exports = {
  init(stage, parameters) {
    Java.perform(function () {
      console.log('[java-ready]', Java.available);
    });
  },
  dispose() {}
};
""".strip(),
        "objc-ready": """
rpc.exports = {
  init(stage, parameters) {
    if (ObjC.available) {
      ObjC.schedule(ObjC.mainQueue, function () {
        console.log('[objc-ready]', Process.id);
      });
    }
  },
  dispose() {}
};
""".strip(),
    }
    if kind not in templates:
        return {"error": "kind must be one of: " + ", ".join(sorted(templates))}
    return {"kind": kind, "js_code": templates[kind]}


def android_frida_server_status(
    adb_serial: str | None = None,
    server_path: str = "/data/local/tmp/frida-server",
) -> dict[str, Any]:
    """Check Android adb/frida-server readiness without modifying the device."""
    result: dict[str, Any] = {
        "adb_available": _have_tool("adb"),
        "client": _frida_client_versions(),
        "server_path": server_path,
    }
    if not result["adb_available"]:
        result["hint"] = "adb not found in PATH; install Android platform-tools."
        return result

    adb = _adb_prefix(adb_serial)
    devices = _run_cmd(["adb", "devices"], check=False, timeout=10.0)
    result["adb_devices_output"] = devices.stdout.strip()
    if devices.returncode != 0:
        result["error"] = devices.stderr.strip() or "adb devices failed"
        return result

    result["device"] = {
        "abi": _adb_shell(adb, "getprop ro.product.cpu.abi"),
        "sdk": _adb_shell(adb, "getprop ro.build.version.sdk"),
        "release": _adb_shell(adb, "getprop ro.build.version.release"),
        "arch": _adb_shell(adb, "uname -m"),
    }
    result["frida_server"] = {
        "pid": _adb_shell(adb, "pidof frida-server"),
        "version": _adb_shell(adb, f"{server_path} --version"),
    }
    result["recommended_next_actions"] = _android_recommendations(result)
    return result


def android_frida_server_install(
    server_binary_path: str,
    adb_serial: str | None = None,
    remote_path: str = "/data/local/tmp/frida-server",
) -> dict[str, Any]:
    """Push a user-supplied frida-server binary to an Android device."""
    if not _have_tool("adb"):
        return {"error": "adb not found in PATH; install Android platform-tools."}

    source = Path(server_binary_path)
    if not source.is_file():
        return {"error": f"frida-server binary not found: {server_binary_path}"}

    adb = _adb_prefix(adb_serial)
    push = _run_cmd([*adb, "push", str(source), remote_path], check=False, timeout=120.0)
    chmod = _adb_shell(adb, f"chmod 755 {remote_path}") if push.returncode == 0 else None
    version = _adb_shell(adb, f"{remote_path} --version") if push.returncode == 0 else None
    return {
        "installed": push.returncode == 0 and (chmod is None or chmod["returncode"] == 0),
        "remote_path": remote_path,
        "source_path": str(source),
        "push": _proc_to_dict(push),
        "chmod": chmod,
        "version": version,
        "hint": "Start the server with frida_android_frida_server_start, then verify with frida_android_frida_server_status.",
    }


def android_frida_server_start(
    adb_serial: str | None = None,
    remote_path: str = "/data/local/tmp/frida-server",
    as_root: bool = True,
    listen_address: str | None = None,
) -> dict[str, Any]:
    """Start frida-server on an Android device."""
    if not _have_tool("adb"):
        return {"error": "adb not found in PATH; install Android platform-tools."}

    adb = _adb_prefix(adb_serial)
    args = [remote_path]
    if listen_address:
        args.extend(["-l", listen_address])
    command = " ".join(args) + " >/dev/null 2>&1 &"
    if as_root:
        command = "su -c " + _shell_quote(command)

    start = _run_cmd([*adb, "shell", command], check=False, timeout=10.0)
    status = android_frida_server_status(adb_serial=adb_serial, server_path=remote_path)
    return {
        "started": start.returncode == 0,
        "command": [*adb, "shell", command],
        "start": _proc_to_dict(start),
        "status": status,
    }


def android_frida_server_stop(adb_serial: str | None = None, as_root: bool = True) -> dict[str, Any]:
    """Stop frida-server on an Android device."""
    if not _have_tool("adb"):
        return {"error": "adb not found in PATH; install Android platform-tools."}

    adb = _adb_prefix(adb_serial)
    command = "pkill frida-server"
    if as_root:
        command = "su -c " + _shell_quote(command)
    stop = _run_cmd([*adb, "shell", command], check=False, timeout=10.0)
    return {
        "stopped": stop.returncode == 0,
        "command": [*adb, "shell", command],
        "stop": _proc_to_dict(stop),
    }


def android_port_forward(
    adb_serial: str | None = None,
    local_port: int = 27042,
    remote_port: int = 27042,
) -> dict[str, Any]:
    """Forward a local TCP port to a device TCP port with adb."""
    if not _have_tool("adb"):
        return {"error": "adb not found in PATH; install Android platform-tools."}

    adb = _adb_prefix(adb_serial)
    res = _run_cmd(
        [*adb, "forward", f"tcp:{local_port}", f"tcp:{remote_port}"],
        check=False,
        timeout=10.0,
    )
    return {
        "forwarded": res.returncode == 0,
        "local": f"tcp:{local_port}",
        "remote": f"tcp:{remote_port}",
        "command": [*adb, "forward", f"tcp:{local_port}", f"tcp:{remote_port}"],
        "result": _proc_to_dict(res),
    }


def android_port_forward_list(adb_serial: str | None = None) -> dict[str, Any]:
    """List adb port forwards."""
    if not _have_tool("adb"):
        return {"error": "adb not found in PATH; install Android platform-tools."}

    adb = _adb_prefix(adb_serial)
    res = _run_cmd([*adb, "forward", "--list"], check=False, timeout=10.0)
    return {"items": _parse_adb_forward_list(res.stdout), "raw": _proc_to_dict(res)}


def android_port_forward_remove(
    adb_serial: str | None = None,
    local_port: int = 27042,
) -> dict[str, Any]:
    """Remove an adb TCP port forward."""
    if not _have_tool("adb"):
        return {"error": "adb not found in PATH; install Android platform-tools."}

    adb = _adb_prefix(adb_serial)
    res = _run_cmd([*adb, "forward", "--remove", f"tcp:{local_port}"], check=False, timeout=10.0)
    return {"removed": res.returncode == 0, "local": f"tcp:{local_port}", "result": _proc_to_dict(res)}


def android_frida_server_setup(
    server_binary_path: str,
    adb_serial: str | None = None,
    remote_path: str = "/data/local/tmp/frida-server",
    as_root: bool = True,
    forward: bool = True,
    local_port: int = 27042,
    remote_port: int = 27042,
) -> dict[str, Any]:
    """Install, start, and optionally forward to a user-supplied frida-server binary."""
    install = android_frida_server_install(server_binary_path, adb_serial=adb_serial, remote_path=remote_path)
    if not install.get("installed"):
        return {"installed": install, "started": None, "forward": None, "status": None}

    start = android_frida_server_start(adb_serial=adb_serial, remote_path=remote_path, as_root=as_root)
    forward_result = (
        android_port_forward(adb_serial=adb_serial, local_port=local_port, remote_port=remote_port)
        if forward
        else None
    )
    status = android_frida_server_status(adb_serial=adb_serial, server_path=remote_path)
    return {
        "installed": install,
        "started": start,
        "forward": forward_result,
        "status": status,
    }


def android_device_prepare(
    package: str | None = None,
    device_id: str | None = None,
    adb_serial: str | None = None,
) -> dict[str, Any]:
    """Summarize Android readiness for Frida-based app analysis."""
    frida = _load_frida()
    result: dict[str, Any] = {
        "host": _host_info(),
        "client": _frida_client_versions(),
        "adb": android_frida_server_status(adb_serial=adb_serial),
        "frida_available": frida is not None,
    }
    if frida is None:
        result.update({"error": "frida not installed", **INSTALL_HINT})
        return result

    try:
        device = frida.get_device(device_id) if device_id else None
        if device is None:
            usb_devices = [d for d in frida.enumerate_devices() if d.type == "usb"]
            device = usb_devices[0] if usb_devices else frida.get_local_device()
        result["frida_device"] = {"id": device.id, "name": device.name, "type": device.type}
        if package:
            apps = device.enumerate_applications()
            matches = [a for a in apps if a.identifier == package or a.name == package]
            result["package"] = package
            result["application"] = (
                {"identifier": matches[0].identifier, "name": matches[0].name, "pid": matches[0].pid}
                if matches
                else None
            )
    except Exception as e:
        result["frida_device_error"] = str(e)

    actions = [
        "Confirm adb sees the device and frida-server is running with a version matching the Python frida client.",
        "Use frida_list_devices to choose the USB device id, then frida_list_apps to confirm package visibility.",
        "Use frida_target_snapshot with the chosen package/process before installing hooks.",
    ]
    if package:
        actions.append("If the app is not attachable, use Gadget with a listen or script configuration.")
    result["recommended_next_actions"] = actions
    return result


def gadget_bundle_assets(
    gadget_library_path: str,
    output_dir: str,
    config_json: str | None = None,
    config_path: str | None = None,
    script_path: str | None = None,
    library_name: str | None = None,
) -> dict[str, Any]:
    """Copy Gadget dylib/so, config, and optional script into a staging directory."""
    gadget = Path(gadget_library_path)
    if not gadget.is_file():
        return {"error": f"gadget library not found: {gadget_library_path}"}
    if config_json is None and config_path is None:
        return {"error": "provide config_json or config_path"}
    if config_json is not None and config_path is not None:
        return {"error": "provide only one of config_json or config_path"}

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    lib_out = out / (library_name or gadget.name)
    shutil.copy2(gadget, lib_out)

    if config_json is not None:
        try:
            parsed = json.loads(config_json)
        except json.JSONDecodeError as e:
            return {"error": f"config_json is not valid JSON: {e}"}
        config_out = out / "FridaGadget.config"
        config_out.write_text(json.dumps(parsed, indent=2, sort_keys=True) + "\n")
    else:
        source_config = Path(config_path or "")
        if not source_config.is_file():
            return {"error": f"config file not found: {config_path}"}
        config_out = out / source_config.name
        shutil.copy2(source_config, config_out)

    script_out = None
    if script_path:
        source_script = Path(script_path)
        if not source_script.is_file():
            return {"error": f"script file not found: {script_path}"}
        script_out = out / source_script.name
        shutil.copy2(source_script, script_out)

    return {
        "status": "staged",
        "output_dir": str(out),
        "library_path": str(lib_out),
        "config_path": str(config_out),
        "script_path": str(script_out) if script_out else None,
        "next_steps": [
            "Embed these files into the authorized app bundle/package.",
            "Apply platform-specific signing or packaging outside the MCP if required.",
            "Launch the app and connect using the interaction mode in FridaGadget.config.",
        ],
    }


def ios_device_prepare(
    bundle_id: str | None = None,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Summarize iOS/macOS USB-device readiness for Frida app analysis."""
    frida = _load_frida()
    result: dict[str, Any] = {
        "host": _host_info(),
        "client": _frida_client_versions(),
        "frida_available": frida is not None,
    }
    if frida is None:
        result.update({"error": "frida not installed", **INSTALL_HINT})
        return result

    try:
        devices = frida.enumerate_devices()
        result["devices"] = [{"id": d.id, "name": d.name, "type": d.type} for d in devices]
        if device_id:
            device = frida.get_device(device_id)
        else:
            usb_devices = [d for d in devices if d.type == "usb"]
            device = usb_devices[0] if usb_devices else frida.get_local_device()
        result["selected_device"] = {"id": device.id, "name": device.name, "type": device.type}
        if bundle_id:
            apps = device.enumerate_applications()
            matches = [a for a in apps if a.identifier == bundle_id or a.name == bundle_id]
            result["bundle_id"] = bundle_id
            result["application"] = (
                {"identifier": matches[0].identifier, "name": matches[0].name, "pid": matches[0].pid}
                if matches
                else None
            )
    except Exception as e:
        result["frida_device_error"] = str(e)

    result["recommended_next_actions"] = [
        "Confirm frida_list_devices shows the iOS USB device.",
        "Use frida_list_apps with the selected device id to confirm bundle visibility.",
        "For jailed/non-attachable apps, embed Gadget and generate a matching FridaGadget.config.",
        "For macOS/iOS protected targets, confirm debugging permission and platform-binary restrictions separately.",
    ]
    return result


def host_diagnostics() -> dict[str, Any]:
    """Collect local host diagnostics relevant to Frida MCP operation."""
    frida = _load_frida()
    result: dict[str, Any] = {
        "host": _host_info(),
        "client": _frida_client_versions(),
        "tools": {
            "frida": _have_tool("frida"),
            "frida-ps": _have_tool("frida-ps"),
            "frida-trace": _have_tool("frida-trace"),
            "frida-compile": _have_tool("frida-compile"),
            "frida-pm": _have_tool("frida-pm"),
            "adb": _have_tool("adb"),
        },
        "frida_available": frida is not None,
    }
    if platform.system() == "Darwin":
        result["macos_debug"] = _macos_debug_status()
    if frida is not None:
        try:
            devices = frida.enumerate_devices()
            result["devices"] = [{"id": d.id, "name": d.name, "type": d.type} for d in devices]
        except Exception as e:
            result["device_error"] = str(e)
        try:
            procs = frida.get_local_device().enumerate_processes()
            result["local_process_count"] = len(procs)
            if not procs:
                result["warning"] = "Frida returned no local processes; host permissions or sandboxing may be hiding them."
        except Exception as e:
            result["process_error"] = str(e)
    return result


def _macos_debug_status() -> dict[str, Any]:
    """Collect macOS task-port/debugging state for local attach triage."""
    status: dict[str, Any] = {
        "python_executable": sys.executable,
        "frida_cli": _resolve_tool("frida"),
        "developer_tools_security": _proc_summary(
            _run_cmd(["DevToolsSecurity", "-status"], check=False, timeout=5.0)
        ),
        "authorizationdb_taskport_debug": _proc_summary(
            _run_cmd(
                ["security", "authorizationdb", "read", "system.privilege.taskport.debug"],
                check=False,
                timeout=5.0,
            ),
            max_chars=800,
        ),
        "authorizationdb_taskport": _proc_summary(
            _run_cmd(
                ["security", "authorizationdb", "read", "system.privilege.taskport"],
                check=False,
                timeout=5.0,
            ),
            max_chars=800,
        ),
        "groups": _proc_summary(_run_cmd(["id", "-Gn"], check=False, timeout=5.0), max_chars=800),
        "python_codesign": _codesign_summary(sys.executable),
    }

    frida_cli = status.get("frida_cli")
    if frida_cli:
        shebang = _read_shebang(Path(frida_cli))
        status["frida_cli_shebang"] = shebang
        if shebang and shebang.startswith("#!"):
            interpreter = shebang[2:].split()[0]
            status["frida_cli_interpreter"] = interpreter
            status["frida_cli_interpreter_codesign"] = _codesign_summary(interpreter)

    actions = [
        "Run frida_host_diagnostics from the same shell or MCP client that will run Frida.",
        "Run sudo DevToolsSecurity -enable, then restart the shell or MCP client before retrying attach.",
        "If AuthorizationDB task-port reads still fail on a dedicated lab machine, follow Frida troubleshooting for system.privilege.taskport.",
        "Use a self-built target or frida_connect(..., spawn=True) as the baseline; Apple platform binaries are not a reliable first probe.",
    ]
    if not _has_debugger_entitlement(status.get("python_codesign")):
        actions.append(
            "The Python interpreter running the MCP does not show com.apple.security.cs.debugger; "
            "macOS may deny task_for_pid even for same-user targets. Use a properly signed Python host "
            "or sign the lab interpreter with debugger entitlements."
        )
    status["diagnostic_commands"] = [
        "DevToolsSecurity -status",
        "security authorizationdb read system.privilege.taskport",
        "python3 -c 'import os,sys; print(os.path.realpath(sys.executable))'",
        "codesign -dv --entitlements :- \"$(python3 -c 'import os,sys; print(os.path.realpath(sys.executable))')\"",
    ]
    status["lab_repair_notes"] = [
        "Prefer sudo DevToolsSecurity -enable first.",
        "Frida troubleshooting documents sudo security authorizationdb write system.privilege.taskport allow for task-port authorization failures; use it only on a dedicated research host.",
        "If the Python host is the remaining blocker, codesign that interpreter with com.apple.security.cs.debugger in a disposable pyenv/venv used for Frida work.",
    ]
    status["recommended_next_actions"] = actions
    return status


def _proc_summary(result: Any, *, max_chars: int = 1200) -> dict[str, Any]:
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    return {
        "returncode": result.returncode,
        "ok": result.returncode == 0,
        "stdout": stdout[:max_chars],
        "stderr": stderr[:max_chars],
    }


def _codesign_summary(path: str) -> dict[str, Any]:
    if not path:
        return {"available": False, "error": "no path"}
    if not Path(path).exists():
        return {"available": False, "error": "path does not exist", "path": path}
    result = _run_cmd(["codesign", "-dv", "--entitlements", ":-", path], check=False, timeout=10.0)
    combined = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    return {
        "path": path,
        "returncode": result.returncode,
        "ok": result.returncode == 0,
        "has_cs_debugger": "com.apple.security.cs.debugger" in combined,
        "has_get_task_allow": "com.apple.security.get-task-allow" in combined,
        "summary": combined[:2000],
    }


def _read_shebang(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            first = f.readline().strip()
        return first or None
    except Exception:
        return None


def _has_debugger_entitlement(summary: Any) -> bool:
    return isinstance(summary, dict) and bool(summary.get("has_cs_debugger"))


def gumjs_template(kind: str, symbol: str | None = None) -> dict[str, Any]:
    """Return an advanced GumJS template for direct use with script_load."""
    templates = {
        "module-map": """
const moduleMap = new ModuleMap();
send({ type: 'module_map', count: moduleMap.values().length });
""".strip(),
        "worker": """
const worker = new Worker('/absolute/path/to/worker.js');
worker.post({ type: 'start' });
worker.recv('event', function (message) {
  send({ type: 'worker-event', message });
});
""".strip(),
        "system-function": """
const fn = new SystemFunction(ptr('0xADDRESS'), 'int', ['pointer']);
const result = fn(Memory.allocUtf8String('input'));
send({ type: 'system_function', value: result.value, errno: result.errno });
""".strip(),
        "rust-module": """
const cm = new RustModule(`
#[no_mangle]
pub extern "C" fn add(a: i32, b: i32) -> i32 { a + b }
`);
const add = new NativeFunction(cm.add, 'int', ['int', 'int']);
send({ type: 'rust_module', result: add(2, 3) });
""".strip(),
        "stalker-transform": """
const targetThread = Process.getCurrentThreadId();
Stalker.follow(targetThread, {
  transform(iterator) {
    let instruction = iterator.next();
    while (instruction !== null) {
      iterator.keep();
      instruction = iterator.next();
    }
  }
});
""".strip(),
        "hardware-breakpoint": """
const threadId = Process.getCurrentThreadId();
Process.runOnThread(threadId, function () {
  Thread.setHardwareBreakpoint(0, ptr('0xADDRESS'));
});
""".strip(),
    }
    if kind not in templates:
        return {"error": "kind must be one of: " + ", ".join(sorted(templates))}
    js_code = templates[kind]
    if symbol:
        js_code = js_code.replace("0xADDRESS", symbol)
    return {"kind": kind, "js_code": js_code}


def _adb_prefix(serial: str | None) -> list[str]:
    return ["adb", "-s", serial] if serial else ["adb"]


def _adb_shell(adb: list[str], command: str) -> dict[str, Any]:
    res = _run_cmd([*adb, "shell", command], check=False, timeout=8.0)
    return {"stdout": res.stdout.strip(), "stderr": res.stderr.strip(), "returncode": res.returncode}


def _proc_to_dict(res) -> dict[str, Any]:
    return {
        "stdout": res.stdout[-4000:],
        "stderr": res.stderr[-4000:],
        "returncode": res.returncode,
    }


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _parse_adb_forward_list(output: str) -> list[dict[str, str]]:
    items = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            items.append({"serial": parts[0], "local": parts[1], "remote": parts[2]})
    return items


def _frida_client_versions() -> dict[str, Any]:
    frida = _load_frida()
    return {
        "frida": getattr(frida, "__version__", None) if frida is not None else None,
        "frida_available": frida is not None,
        "frida_tools": _distribution_version("frida-tools"),
        "frida_cli": _tool_version("frida"),
        "frida_ps": _tool_version("frida-ps"),
    }


def _distribution_version(package: str) -> str | None:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def _tool_version(tool: str) -> str | None:
    if not _have_tool(tool):
        return None
    res = _run_cmd([tool, "--version"], check=False, timeout=5.0)
    return (res.stdout or res.stderr).strip() or None


def _host_info() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def _android_recommendations(status: dict[str, Any]) -> list[str]:
    actions = []
    server = status.get("frida_server", {})
    version = (server.get("version") or {}).get("stdout") if isinstance(server, dict) else None
    pid = (server.get("pid") or {}).get("stdout") if isinstance(server, dict) else None
    if not pid:
        actions.append("Start frida-server on the Android device, usually from /data/local/tmp with executable permission.")
    if not version:
        actions.append("Check that the frida-server binary runs on the device and matches the device ABI.")
    client_version = (status.get("client") or {}).get("frida")
    if client_version and version and version != client_version:
        actions.append(f"Use a frida-server build matching the Python frida client version: {client_version}.")
    actions.append("After server readiness, verify with frida_list_devices and frida_list_apps.")
    return actions
