from __future__ import annotations

import json
from types import SimpleNamespace

from fuzzmind_frida_mcp.toolsets import _helpers
from fuzzmind_frida_mcp.tools.official import bus as bus_tools
from fuzzmind_frida_mcp.tools.official import runtime as official_runtime
from fuzzmind_frida_mcp.tools.recipes import workflow


class FakeBus:
    def __init__(self):
        self.callbacks = {}
        self.attached = False
        self.posts = []

    def on(self, event, callback):
        self.callbacks[event] = callback

    def attach(self):
        self.attached = True

    def post(self, message, data=None):
        self.posts.append((message, data))


class FakeDevice:
    id = "local"
    name = "Local Device"
    type = "local"

    def __init__(self):
        self.bus = FakeBus()

    def get_bus(self):
        return self.bus


class FakeFrida:
    def __init__(self, device):
        self.device = device

    def get_local_device(self):
        return self.device


def test_bus_attach_post_get_events_and_detach(monkeypatch):
    device = FakeDevice()
    monkeypatch.setattr(bus_tools, "_load_frida", lambda: FakeFrida(device))

    attached = bus_tools.bus_attach()
    bus_id = attached["bus_id"]

    assert attached["status"] == "attached"
    assert device.bus.attached is True

    device.bus.callbacks["message"]({"hello": "world"}, b"\x00\xff")
    events = bus_tools.bus_get_events(bus_id)
    assert events["count"] == 1
    assert events["events"][0]["message"] == {"hello": "world"}
    assert events["events"][0]["data_base64"] == "AP8="

    posted = bus_tools.bus_post(bus_id, {"cmd": "run"}, data_base64="AQID")
    assert posted == {"status": "posted", "bus_id": bus_id, "has_data": True}
    assert device.bus.posts == [({"cmd": "run"}, b"\x01\x02\x03")]

    cleared = bus_tools.bus_get_events(bus_id, clear=True)
    assert cleared["count"] == 1
    assert bus_tools.bus_get_events(bus_id)["events"] == []
    assert bus_tools.bus_detach(bus_id) == {"status": "detached", "bus_id": bus_id}


def test_gadget_config_generates_valid_script_interaction_and_writes_file(tmp_path):
    output = tmp_path / "FridaGadget.config"

    result = workflow.gadget_config(
        interaction="script",
        path="agent.js",
        parameters={"answer": 42},
        on_change="reload",
        runtime="qjs",
        code_signing="required",
        output_path=str(output),
    )

    assert result["config"] == {
        "interaction": {
            "type": "script",
            "path": "agent.js",
            "parameters": {"answer": 42},
            "on_change": "reload",
        },
        "runtime": "qjs",
        "code_signing": "required",
    }
    assert json.loads(output.read_text()) == result["config"]


def test_gadget_config_rejects_invalid_interaction_options():
    assert "error" in workflow.gadget_config(interaction="script")
    assert workflow.gadget_config(interaction="listen", on_load="bad") == {
        "error": "on_load must be 'wait' or 'resume' for listen interaction"
    }


def test_gadget_bundle_assets_copies_library_config_and_script(tmp_path):
    library = tmp_path / "libFridaGadget.dylib"
    script = tmp_path / "agent.js"
    output_dir = tmp_path / "bundle"
    library.write_bytes(b"library")
    script.write_text("send('ready');")

    result = workflow.gadget_bundle_assets(
        gadget_library_path=str(library),
        output_dir=str(output_dir),
        config_json=json.dumps({"interaction": {"type": "listen"}}),
        script_path=str(script),
        library_name="FridaGadget.dylib",
    )

    assert result["status"] == "staged"
    assert (output_dir / "FridaGadget.dylib").read_bytes() == b"library"
    assert json.loads((output_dir / "FridaGadget.config").read_text()) == {"interaction": {"type": "listen"}}
    assert (output_dir / "agent.js").read_text() == "send('ready');"


def test_parse_adb_forward_list_uses_adb_columns():
    output = "emulator-5554 tcp:27042 tcp:27042\nserial tcp:123 tcp:456 extra\nignored-line\n"
    assert workflow._parse_adb_forward_list(output) == [
        {"serial": "emulator-5554", "local": "tcp:27042", "remote": "tcp:27042"},
        {"serial": "serial", "local": "tcp:123", "remote": "tcp:456"},
    ]


def test_register_module_tools_only_registers_public_frida_functions():
    calls = []

    class FakeMcp:
        def tool(self):
            def decorator(fn):
                calls.append(fn.__name__)
                return fn

            return decorator

    def frida_alpha():
        return "alpha"

    def helper():
        return "helper"

    _helpers.register_module_tools(
        FakeMcp(),
        {
            "frida_alpha": frida_alpha,
            "helper": helper,
            "frida_not_callable": "value",
        },
    )

    assert calls == ["frida_alpha"]


def test_official_runtime_objc_template_uses_json_quoted_inputs():
    result = official_runtime.objc_implement_template('Class"Name', "- doThing:", return_type="int", arg_types=["pointer"])

    assert result["class_name"] == 'Class"Name'
    assert 'ObjC.classes["Class\\"Name"]' in result["js_code"]
    assert '"- doThing:"' in result["js_code"]
    assert '"int"' in result["js_code"]
