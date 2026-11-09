"""Mocked launcher boundaries: no real capture, hardware, subprocess or API calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from detection import launcher as module
from detection.launcher import Adapter, API, LauncherError, LocalMonitor

GUID = "11111111-2222-3333-4444-555555555555"
ADAPTER = Adapter(GUID, "Wired lab fixture", ("10.50.2.3",), True)
CURRENT_HEALTH = {"mode": "monitor", "public_demo": False,
                  "capabilities": {"incident_write": True, "simulation_control": False}}


class FakeProcess:
    def __init__(self):
        self.ended, self.terminated, self.killed = False, False, False

    def poll(self):
        return 0 if self.ended else None

    def terminate(self):
        self.terminated = True
        self.ended = True

    def kill(self):
        self.killed = True
        self.ended = True

    def wait(self, timeout):
        return 0


@pytest.fixture
def local(tmp_path, monkeypatch):
    app = LocalMonitor(tmp_path)
    app.python.parent.mkdir(parents=True)
    app.python.write_text("unit fixture; never executed")
    app.vite.parent.mkdir(parents=True)
    app.vite.write_text("unit fixture; never executed")
    node = tmp_path/"node.exe"
    node.write_text("unit fixture; never executed")
    monkeypatch.setattr(module, "adapters", lambda: [ADAPTER])
    monkeypatch.setattr(app, "_node", lambda: node)
    monkeypatch.setattr(app, "_wireshark", lambda: ("trusted-tshark.exe", "trusted-dumpcap.exe"))
    monkeypatch.setattr(module, "_port_in_use", lambda port: False)
    monkeypatch.setattr(module, "_json_get", lambda port, path: dict(CURRENT_HEALTH))
    monkeypatch.setattr(app, "_wait_healthy", lambda *args: None)
    return app


def test_default_script_is_check_only_no_service_capture_or_key_prompt(monkeypatch, capsys):
    path = Path(__file__).parents[1]/"scripts"/"local_monitor.py"
    spec = importlib.util.spec_from_file_location("local_monitor_cli_unit", path)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    calls = []
    class FakeLauncher:
        def __init__(self, root):
            pass
        def check(self):
            calls.append("check")
            return {"capture_enabled": False, "services_started": False, "key_prompted": False}
        def interactive(self):
            pytest.fail("Default script opened an interactive/action session")
    monkeypatch.setattr(cli, "LocalMonitor", FakeLauncher)
    assert cli.main([]) == 0 and calls == ["check"]
    assert '"capture_enabled": false' in capsys.readouterr().out


def test_check_inventory_does_not_prompt_start_or_capture(local, monkeypatch):
    monkeypatch.setattr(local, "_spawn", lambda *a: pytest.fail("Check started a service"))
    monkeypatch.setattr(module, "_monitor_module", lambda: pytest.fail("Check loaded capture"))
    result = local.check()
    assert result["capture_enabled"] is False and result["key_prompted"] is False
    assert result["wired_candidates"][0]["assigned_address_count"] == 1
    assert "10.50.2.3" not in json.dumps(result)
    assert not local.private.exists()


def test_fixed_inventory_excludes_known_virtual_and_normalizes_assigned_addresses(monkeypatch):
    def powershell(script):
        if script == module.INVENTORY_SCRIPT:
            return [{"guid": GUID, "label": "Wired", "description": "Generic physical Ethernet model", "addresses": ["10.50.2.3", "fe80::1%7", "127.0.0.1"]},
                    {"guid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "label": "Virtual", "addresses": ["10.1.1.1"]}]
        assert script == module.PHYSICAL_SCRIPT
        return [{"guid": GUID}]
    monkeypatch.setattr(module, "_powershell_json", powershell)
    result = module.adapters()
    assert len(result) == 1 and result[0].physical_verified
    assert result[0].addresses == ("10.50.2.3", "fe80::1")
    assert result[0].description == "Generic physical Ethernet model"


@pytest.mark.skipif(os.name != "nt", reason="Exact Windows PowerShell process contract; other launcher boundary tests are platform independent")
def test_powershell_inventory_uses_fixed_readonly_script_and_sanitized_environment(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "private-fixture")
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout="[]")
    monkeypatch.setattr(module.subprocess, "run", run)
    assert module._powershell_json(module.INVENTORY_SCRIPT) == []
    argv, kwargs = calls[0]
    assert argv[-1].endswith(module.INVENTORY_SCRIPT)
    assert "-NoProfile" in argv and "-NonInteractive" in argv
    assert "SENTINEL_API_KEY" not in kwargs["env"]
    assert kwargs["timeout"] == 10 and kwargs["creationflags"] == module._flags()


def test_unavailable_physical_check_never_silently_verifies_a_candidate(monkeypatch):
    def powershell(script):
        if script == module.INVENTORY_SCRIPT:
            return [{"guid": GUID, "label": "Wired", "addresses": ["10.50.2.3"]}]
        raise LauncherError("Optional physical verification unavailable")
    monkeypatch.setattr(module, "_powershell_json", powershell)
    assert module.adapters()[0].physical_verified is False


def test_unverified_wired_selection_requires_explicit_manual_confirmation(local, monkeypatch):
    candidate = Adapter(GUID, "Unverified wired", ADAPTER.addresses, False)
    monkeypatch.setattr(module, "adapters", lambda: [candidate])
    with pytest.raises(LauncherError, match="explicitly confirm"):
        local.select(GUID)
    local.select(GUID, confirm_unverified=True)
    assert local.selected_manual is True


def test_saved_selection_only_guid_label_and_not_automatic_authorization(local):
    local.select(GUID)
    value = json.loads(local.config_path.read_text())
    assert set(value) == {"selected_guid", "label"}
    assert "10.50.2.3" not in local.config_path.read_text()
    other = LocalMonitor(local.project)
    assert other.load_selection()["selected_guid"] == GUID
    assert other.selected is None
    with pytest.raises(LauncherError, match="Explicitly select"):
        other._fresh_adapter()


@pytest.mark.parametrize("payload", [
    {"selected_guid": GUID, "label": "Wired", "api_key": "must-never-load"},
    {"selected_guid": GUID, "label": "Wired", "addresses": ["10.50.2.3"]},
    {"selected_guid": "bad", "label": "Wired"},
    {"selected_guid": GUID, "label": "bad\nlabel"},
])
def test_configuration_rejects_keys_commands_stale_addresses_and_invalid_values(local, payload):
    local.private.mkdir(parents=True)
    local.config_path.write_text(json.dumps(payload))
    with pytest.raises(LauncherError):
        local.load_selection()


def test_wrong_backend_mode_is_not_adopted_started_or_stopped(local, monkeypatch):
    monkeypatch.setattr(module, "_port_in_use", lambda port: True)
    monkeypatch.setattr(module, "_json_get", lambda *args: {"mode": "demo"})
    monkeypatch.setattr(local, "_spawn", lambda *a: pytest.fail("Wrong-profile port started replacement"))
    with pytest.raises(LauncherError, match="not adopted or stopped"):
        local.start_backend()
    assert local._backend is None


@pytest.mark.parametrize("profile", [
    {"mode": "monitor"},  # Genuine pre-v1 backend contract: explicitly reject stale code.
    {"mode": "monitor", "public_demo": False, "capabilities": {"incident_write": True}},
    {"mode": "monitor", "public_demo": True, "capabilities": CURRENT_HEALTH["capabilities"]},
    {"mode": "monitor", "public_demo": False, "capabilities": {"incident_write": True, "simulation_control": True}},
])
def test_stale_or_incompatible_backend_never_adopted_killed_or_used_for_capture(local, monkeypatch, profile):
    local.select(GUID)
    monkeypatch.setattr(module, "_port_in_use", lambda port: True)
    monkeypatch.setattr(module, "_json_get", lambda *args: profile)
    monkeypatch.setattr(local, "_spawn", lambda *a: pytest.fail("Stale backend was replaced"))
    monkeypatch.setattr(module, "_monitor_module", lambda: pytest.fail("Stale backend invoked capture"))
    with pytest.raises(LauncherError, match="own terminal, retaining its API key and monitoring database"):
        local.start_backend()
    with pytest.raises(LauncherError, match="not adopted or stopped"):
        local.capture_once(confirmation="START", prompt=lambda *a: pytest.fail("Stale backend prompted key"))
    assert local._backend is None and local._owned_key == ""


@pytest.mark.parametrize("description", ["bad\nmodel", "x"*161, None])
def test_invalid_adapter_description_cannot_inject_menu_output(monkeypatch, description):
    def powershell(script):
        if script == module.INVENTORY_SCRIPT:
            return [{"guid": GUID, "label": "Wired", "description": description, "addresses": ["10.50.2.3"]}]
        return [{"guid": GUID}]
    monkeypatch.setattr(module, "_powershell_json", powershell)
    assert module.adapters() == []


def test_own_backend_key_is_only_child_env_and_frontend_gets_no_inherited_secrets(local, monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "inherited-private-key")
    monkeypatch.setenv("VITE_API_KEY", "browser-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-secret")
    monkeypatch.setenv("NODE_OPTIONS", "--untrusted-option")
    launched = []
    monkeypatch.setattr(local, "_spawn", lambda args, cwd, env: launched.append((args, env)) or FakeProcess())
    assert local.start_backend() == "started_owned"
    assert local.start_frontend() == "started_owned"
    backend_args, backend_env = launched[0]
    front_args, front_env = launched[1]
    key = backend_env["SENTINEL_API_KEY"]
    assert len(key) >= 32 and key != "inherited-private-key"
    assert key not in " ".join(backend_args+front_args)
    assert backend_env["SENTINEL_DB_PATH"] == str(local.database)
    assert backend_env["SENTINEL_MONITOR_MODE"] == "true" and "--no-access-log" in backend_args
    assert "--host" in backend_args and "127.0.0.1" in backend_args
    assert front_env["VITE_API_BASE"] == "" and front_env["VITE_API_PROXY_TARGET"] == API
    assert all(name not in front_env for name in ("SENTINEL_API_KEY", "VITE_API_KEY", "AWS_SECRET_ACCESS_KEY", "NODE_OPTIONS"))
    assert os.environ["SENTINEL_API_KEY"] == "inherited-private-key"
    local.stop_owned()


def test_frontend_env_file_cannot_reintroduce_browser_secrets(local, monkeypatch):
    (local.project/"frontend"/".env.local").write_text("VITE_API_KEY=private\n")
    monkeypatch.setattr(local, "_spawn", lambda *a: pytest.fail("Unsafe dotenv file started frontend"))
    with pytest.raises(LauncherError, match="Review frontend"):
        local.start_frontend()


@pytest.mark.parametrize("content", [
    "VITE_=fixture-only\n",  # Node parseEnv accepts these broader key names.
    "VITE_AUDIT-KEY=fixture-only\n",
    "VITE_AUDIT.KEY=fixture-only\n",
    "VITE_é=fixture-only\n",
    "VITE_API_BASE=\"\nVITE_AUDIT_KEY=fixture-only\n\"\n",
    "VITE_API_PROXY_TARGET=${OTHER}\n",
    "BROWSER=unreviewed-launch-option\n",
])
def test_frontend_env_file_rejects_parser_edges_expansion_and_launch_options(local, monkeypatch, content):
    (local.project/"frontend"/".env.local").write_text(content, encoding="utf-8")
    monkeypatch.setattr(local, "_spawn", lambda *a: pytest.fail("Unreviewed dotenv syntax started frontend"))
    with pytest.raises(LauncherError, match="simple literal assignments"):
        local.start_frontend()


def test_frontend_env_file_allows_only_documented_literal_monitor_settings(local):
    (local.project/"frontend"/".env.local").write_text(
        "# Local monitor only\n\nexport VITE_API_BASE=\"\"\nVITE_API_PROXY_TARGET='"+API+"'\n", encoding="utf-8")
    local._safe_frontend_files()


def test_capture_cancel_does_not_prompt_or_call_api_or_collector(local, monkeypatch):
    monkeypatch.setattr(module, "_monitor_module", lambda: pytest.fail("Cancelled capture loaded collector"))
    result = local.capture_once(confirmation="", prompt=lambda *a: pytest.fail("Cancel prompted key"))
    assert result["started"] is False


def test_reused_monitor_uses_private_prompt_not_inherited_or_new_key_and_restores_env(local, monkeypatch, capsys):
    local.select(GUID)
    monkeypatch.setattr(module, "_port_in_use", lambda port: True)
    assert local.start_backend() == "reused_external"
    assert local._backend is None and local._owned_key == ""
    old, supplied = "original-env-value", "private-typed-key-"+"x"*40
    monkeypatch.setenv("SENTINEL_API_KEY", old)
    calls = []
    def main(argv):
        assert supplied not in " ".join(argv)
        assert os.environ["SENTINEL_API_KEY"] == supplied
        assert argv[argv.index("--duration")+1] == "15"
        assert argv[argv.index("--max-packets")+1] == "5000"
        assert argv[argv.index("--max-flows")+1] == "1000"
        assert "--enable-capture" in argv and "--ingest" in argv
        calls.append(argv)
        return 0
    monitor = SimpleNamespace(main=main, preflight=lambda base, key: calls.append((base, key)))
    monkeypatch.setattr(module, "_monitor_module", lambda: monitor)
    result = local.capture_once(confirmation="START", prompt=lambda prompt: supplied)
    assert result["exit_code"] == 0 and len(calls) == 2
    assert os.environ["SENTINEL_API_KEY"] == old
    assert supplied not in capsys.readouterr().out
    local.stop_owned()  # No handle is adopted for the external service.


def test_disconnected_or_addressless_adapter_fails_before_capture_without_fallback(local, monkeypatch):
    local.select(GUID)
    monkeypatch.setattr(module, "adapters", lambda: [])
    monkeypatch.setattr(module, "_monitor_module", lambda: pytest.fail("Disconnected adapter loaded collector"))
    with pytest.raises(LauncherError, match="no fallback"):
        local.capture_once(confirmation="START", prompt=lambda *a: pytest.fail("Disconnected adapter prompted key"))
    monkeypatch.setattr(module, "adapters", lambda: [Adapter(GUID, "Wired", (), True)])
    with pytest.raises(ValueError):
        local.capture_once(confirmation="START")


def test_key_preflight_or_disconnect_after_prompt_never_opens_adapter(local, monkeypatch):
    local.select(GUID)
    monitor = SimpleNamespace(main=lambda *a: pytest.fail("Failed preflight opened capture"),
        preflight=lambda *a: (_ for _ in ()).throw(LauncherError("Wrong key")))
    monkeypatch.setattr(module, "_monitor_module", lambda: monitor)
    with pytest.raises(LauncherError, match="Wrong key"):
        local.capture_once(confirmation="START", prompt=lambda *a: "x"*48)
    monitor.preflight = lambda *a: monkeypatch.setattr(module, "adapters", lambda: [])
    with pytest.raises(LauncherError, match="disconnected"):
        local.capture_once(confirmation="START", prompt=lambda *a: "x"*48)


def test_changed_assigned_addresses_are_refreshed_after_prompt_not_loaded_from_disk(local, monkeypatch):
    local.select(GUID)
    replacement = Adapter(GUID, ADAPTER.label, ("10.50.2.99",), True)
    monitor = SimpleNamespace(preflight=lambda *a: monkeypatch.setattr(module, "adapters", lambda: [replacement]))
    def main(argv):
        assert "10.50.2.99" in argv and "10.50.2.3" not in argv
        return 0
    monitor.main = main
    monkeypatch.setattr(module, "_monitor_module", lambda: monitor)
    assert local.capture_once(confirmation="START", prompt=lambda *a: "x"*48)["exit_code"] == 0
    assert "10.50.2.99" not in local.config_path.read_text()


def test_cancelled_collector_restores_environment_and_stops_only_owned_on_exit(local, monkeypatch):
    local.select(GUID)
    backend, frontend = FakeProcess(), FakeProcess()
    local._backend, local._frontend, local._owned_key = backend, frontend, "o"*48
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    def interrupted(argv):
        assert os.environ["SENTINEL_API_KEY"] == "o"*48
        raise KeyboardInterrupt
    monkeypatch.setattr(module, "_monitor_module", lambda: SimpleNamespace(main=interrupted, preflight=lambda *a: None))
    assert local.capture_once(confirmation="START")["exit_code"] == 130
    assert "SENTINEL_API_KEY" not in os.environ
    assert backend.terminated is False and frontend.terminated is False
    assert local.interactive(input_fn=lambda *a: "0", output=lambda *a: None) == 0
    assert backend.terminated and frontend.terminated and local._owned_key == ""


def test_startup_failure_and_stop_timeout_clean_only_explicit_handles(local, monkeypatch):
    process = FakeProcess()
    monkeypatch.setattr(local, "_spawn", lambda *a: process)
    monkeypatch.setattr(local, "_wait_healthy", lambda *a: (_ for _ in ()).throw(LauncherError("startup failed")))
    with pytest.raises(LauncherError):
        local.start_backend()
    assert process.terminated and local._backend is None and local._owned_key == ""
    waiting = FakeProcess()
    counter = [0]
    def wait(timeout):
        counter[0] += 1
        if counter[0] == 1:
            raise subprocess.TimeoutExpired("owned fixture", timeout)
        return 0
    waiting.wait = wait
    local._stop_one(waiting)
    assert waiting.terminated and waiting.killed and counter[0] == 2
