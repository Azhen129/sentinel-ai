"""Explicit local Windows monitoring menu. Import/check never starts capture.

Only fixed localhost services and a freshly selected wired adapter are supported.
The collector remains the sole capture implementation. This is an interactive
bounded helper, not a daemon, browser command endpoint or elevation mechanism.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import getpass
import http.client
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time
from uuid import UUID
import webbrowser

from detection.collector import CaptureConfig, CollectorError

API_PORT, FRONTEND_PORT = 8004, 5176
API = f"http://127.0.0.1:{API_PORT}"
DASHBOARD = f"http://127.0.0.1:{FRONTEND_PORT}"
INVENTORY_SCRIPT = r"""$ErrorActionPreference='Stop'; $items=@([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {$_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -eq 'Ethernet'} | ForEach-Object {[pscustomobject]@{guid=$_.Id;label=$_.Name;description=$_.Description;addresses=@($_.GetIPProperties().UnicastAddresses | ForEach-Object {$_.Address.ToString()})}}); ConvertTo-Json -InputObject $items -Depth 4 -Compress"""
PHYSICAL_SCRIPT = r"""$ErrorActionPreference='Stop'; $items=@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {[pscustomobject]@{guid=$_.InterfaceGuid.ToString()}}); ConvertTo-Json -InputObject $items -Depth 3 -Compress"""
SAFE_ENV = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "PROGRAMFILES", "PROGRAMFILES(X86)", "COMSPEC", "SYSTEMDRIVE"}


class LauncherError(ValueError):
    pass


def child_environment():
    """Allow only ordinary OS locations; no inherited API/cloud/browser secrets."""
    return {key: value for key, value in os.environ.items() if key.upper() in SAFE_ENV}


def frontend_environment():
    return dict(child_environment(), VITE_API_BASE="", VITE_API_PROXY_TARGET=API)


def _flags():
    return subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def _powershell_json(script):
    if os.name != "nt":
        raise LauncherError("Adapter checks require Windows; no capture was started")
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows"))/"System32"/"WindowsPowerShell"/"v1.0"/"powershell.exe"
    try:
        encoded_script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "+script
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", encoded_script],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
            check=True, env=child_environment(), creationflags=_flags())
        if len(result.stdout) > 65536:
            raise LauncherError("Adapter inventory exceeded its bounded response size")
        rows = json.loads(result.stdout.lstrip("\ufeff"))
        rows = rows if isinstance(rows, list) else [rows]
        if len(rows) > 64 or not all(isinstance(row, dict) for row in rows):
            raise LauncherError("Unexpected adapter inventory shape")
        return rows
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        raise LauncherError("Windows adapter inventory failed; verify it in a normal local PowerShell terminal") from None


@dataclass(frozen=True)
class Adapter:
    guid: str
    label: str
    addresses: tuple[str, ...]
    physical_verified: bool
    description: str = ""

    @property
    def interface(self):
        return "\\Device\\NPF_{"+self.guid+"}"


def adapters():
    rows = _powershell_json(INVENTORY_SCRIPT)
    try:
        physical = {str(UUID(row["guid"])).upper() for row in _powershell_json(PHYSICAL_SCRIPT)}
    except (LauncherError, ValueError, KeyError, TypeError):
        physical = None  # Explicit manual wired-device confirmation is then required.
    result = []
    for row in rows:
        try:
            guid, label = str(UUID(row["guid"])).upper(), row["label"]
            description = row.get("description", "")
            if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c)<32 for c in label):
                continue
            if not isinstance(description, str) or len(description) > 160 or any(ord(c)<32 for c in description):
                continue
            if physical is not None and guid not in physical:
                continue  # Known nonphysical/virtual Ethernet is not a selectable candidate.
            values = row.get("addresses", [])
            if not isinstance(values, list) or len(values) > 32:
                continue
            assigned = []
            for raw in values:
                address = ip_address(str(raw).split("%", 1)[0])
                if not (address.is_loopback or address.is_multicast or address.is_unspecified) and str(address) not in assigned:
                    assigned.append(str(address))
            result.append(Adapter(guid, label, tuple(assigned), physical is not None, description))
        except (ValueError, KeyError, TypeError):
            continue
    if len({item.guid for item in result}) != len(result):
        raise LauncherError("Duplicate adapter identities returned; no automatic selection is permitted")
    return result


def _json_get(port, path):
    if port not in {API_PORT, FRONTEND_PORT} or path not in {"/api/health", "/api/system"}:
        raise LauncherError("Only fixed localhost status requests are permitted")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read(65537)
        if response.status != 200 or len(body) > 65536:
            raise LauncherError("The local service did not return a bounded successful status response")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise LauncherError("Unexpected local status response")
        return value  # http.client never follows redirects or environment proxies.
    except (OSError, http.client.HTTPException, json.JSONDecodeError):
        raise LauncherError("Local service status is unavailable; verify the fixed port/profile") from None
    finally:
        connection.close()


def _port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(.4)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _require_current_monitor(profile, label="Local service"):
    """Detect stale running code before reusing it; this is not authentication."""
    capabilities = profile.get("capabilities")
    if (profile.get("mode") != "monitor" or profile.get("public_demo") is not False
        or not isinstance(capabilities, dict) or capabilities.get("incident_write") is not True
        or capabilities.get("simulation_control") is not False):
        raise LauncherError(label+" has a non-Monitor or stale service. Restart the existing backend in its own terminal, retaining its API key and monitoring database; it was not adopted or stopped")


@contextmanager
def _temporary_key(key):
    existed, previous = "SENTINEL_API_KEY" in os.environ, os.environ.get("SENTINEL_API_KEY")
    os.environ["SENTINEL_API_KEY"] = key
    try:
        yield
    finally:
        if existed:
            os.environ["SENTINEL_API_KEY"] = previous
        else:
            os.environ.pop("SENTINEL_API_KEY", None)


def _monitor_module():
    from scripts import monitor_windows
    return monitor_windows


class LocalMonitor:
    def __init__(self, project):
        self.project = Path(project).resolve()
        self.private = self.project/"data"/"monitoring"
        self.config_path = self.private/"launcher.json"
        self.database = self.private/"windows-monitor.db"
        self.python = self.project/".venv"/"Scripts"/"python.exe"
        self.vite = self.project/"frontend"/"node_modules"/"vite"/"bin"/"vite.js"
        self.selected = None  # A saved preference never authorizes automatic capture.
        self.selected_manual = False
        self._backend, self._frontend, self._owned_key = None, None, ""

    def _private_paths(self):
        if not self.private.resolve().is_relative_to(self.project) or self.config_path.is_symlink() or self.database.is_symlink():
            raise LauncherError("Monitoring paths must remain private paths inside this project; linked paths are refused")

    def _node(self):
        candidates = [Path(os.environ.get("ProgramFiles", r"C:\Program Files"))/"nodejs"/"node.exe"]
        if os.environ.get("LOCALAPPDATA"):
            candidates.append(Path(os.environ["LOCALAPPDATA"])/"Programs"/"nodejs"/"node.exe")
        return next((path for path in candidates if path.is_file()), None)

    def _wireshark(self):
        folder = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))/"Wireshark"
        tshark, dumpcap = folder/"tshark.exe", folder/"dumpcap.exe"
        if not tshark.is_file() or not dumpcap.is_file():
            raise LauncherError("Existing Wireshark TShark/dumpcap were not found in Program Files; no install was attempted")
        return str(tshark), str(dumpcap)

    def check(self):
        self._private_paths()
        candidates = adapters()
        try:
            self._wireshark()
            tools = True
        except LauncherError:
            tools = False
        return dict(capture_enabled=False, services_started=False, key_prompted=False,
            python_environment=self.python.is_file(), node=self._node() is not None,
            frontend_dependencies=self.vite.is_file(), wireshark_tools=tools,
            wired_candidates=[dict(guid=a.guid, label=a.label, description=a.description, assigned_address_count=len(a.addresses),
                physical_verification="verified" if a.physical_verified else "manual_confirmation_required") for a in candidates],
            note="File/inventory checks do not establish Npcap permission or a healthy sensor. No adapter was opened.",
            saved_selection=self.load_selection())

    def load_selection(self):
        self._private_paths()
        if not self.config_path.exists():
            return None
        if self.config_path.stat().st_size > 4096:
            raise LauncherError("Private launcher configuration exceeds its bound")
        try:
            value = json.loads(self.config_path.read_text(encoding="utf-8"))
            if set(value) != {"selected_guid", "label"}:
                raise ValueError
            guid, label = str(UUID(value["selected_guid"])).upper(), value["label"]
            if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c)<32 for c in label):
                raise ValueError
            return dict(selected_guid=guid, label=label)
        except (ValueError, TypeError, KeyError):
            raise LauncherError("Launcher configuration is invalid; it may contain only selected GUID and label") from None

    def select(self, guid, *, confirm_unverified=False):
        self._private_paths()
        match = next((a for a in adapters() if a.guid == str(UUID(guid)).upper()), None)
        if match is None:
            raise LauncherError("The selected Up Ethernet adapter is no longer present")
        if not match.physical_verified and not confirm_unverified:
            raise LauncherError("Physical verification unavailable: explicitly confirm this is your wired hardware adapter")
        self.private.mkdir(parents=True, exist_ok=True)
        temporary = self.private/("launcher-"+secrets.token_hex(8)+".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(dict(selected_guid=match.guid, label=match.label), stream)
            os.replace(temporary, self.config_path)
        finally:
            if temporary.exists():
                temporary.unlink()  # Only this invocation's exact temporary config path.
        self.selected, self.selected_manual = match.guid, confirm_unverified
        return match

    def _fresh_adapter(self):
        if self.selected is None:
            raise LauncherError("Explicitly select a wired adapter in this session first")
        candidate = next((a for a in adapters() if a.guid == self.selected), None)
        if candidate is None:
            raise LauncherError("Selected adapter is disconnected/changed; collection stopped with no fallback")
        if not candidate.physical_verified and not self.selected_manual:
            raise LauncherError("Physical verification changed; explicitly reselect and confirm the wired adapter")
        # The existing collector validates assigned addresses and hard bounds too.
        CaptureConfig(candidate.interface, candidate.addresses, candidate.label, 15, 5000, 1000)
        return candidate

    def _spawn(self, argv, cwd, env):
        return subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=_flags())

    def _wait_healthy(self, process, port):
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise LauncherError("Owned local service exited during startup; check dependencies/database profile")
            try:
                profile = _json_get(port, "/api/health")
            except LauncherError:
                time.sleep(.2)
                continue
            _require_current_monitor(profile, f"Port {port}")
            return
        raise LauncherError("Owned local service did not become healthy within 10 seconds")

    def start_backend(self):
        self._private_paths()
        if _port_in_use(API_PORT):
            _require_current_monitor(_json_get(API_PORT, "/api/health"), "Port 8004")
            return "owned" if self._backend is not None and self._backend.poll() is None else "reused_external"
        if not self.python.is_file():
            raise LauncherError("Project .venv Python is missing; install documented dependencies separately")
        key = secrets.token_urlsafe(48)
        env = dict(child_environment(), SENTINEL_MONITOR_MODE="true", SENTINEL_LAB_MODE="false",
            SENTINEL_PCAP_ENABLED="false", SENTINEL_PUBLIC_DEMO="false", SENTINEL_DB_PATH=str(self.database),
            SENTINEL_API_KEY=key, SENTINEL_CORS_ORIGINS=DASHBOARD, PYTHONDONTWRITEBYTECODE="1")
        self._backend = self._spawn([str(self.python), "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1",
            "--port", str(API_PORT), "--no-access-log", "--no-proxy-headers"], self.project, env)
        self._owned_key = key
        try:
            self._wait_healthy(self._backend, API_PORT)
        except BaseException:
            self._stop_one(self._backend)
            self._backend, self._owned_key = None, ""
            raise
        return "started_owned"

    def _safe_frontend_files(self):
        # Vite can load .env files after process env sanitization. Fail closed on
        # all but two simple literal assignments. Its Node parser accepts keys
        # beyond Python's usual identifier alphabet, and expansion/multiline
        # syntax must not create an unreviewed browser variable or launch option.
        for path in (self.project/"frontend").glob(".env*"):
            if path.name.endswith(".example") or not path.is_file():
                continue
            if path.stat().st_size > 65536:
                raise LauncherError("Frontend environment file exceeds the review bound")
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                assignment = re.fullmatch(r"(?:export[ \t]+)?(VITE_API_BASE|VITE_API_PROXY_TARGET)[ \t]*=[ \t]*(.*)", line)
                if assignment:
                    name, value = assignment.groups()
                    allowed = {"", '\"\"', "''"} if name == "VITE_API_BASE" else {API, '\"'+API+'\"', "'"+API+"'"}
                    if value.strip() in allowed:
                        continue
                raise LauncherError("Review frontend .env files: this launcher permits only comments and simple literal assignments for blank VITE_API_BASE and the fixed monitor proxy")

    def start_frontend(self):
        _require_current_monitor(_json_get(API_PORT, "/api/health"), "Port 8004")
        if _port_in_use(FRONTEND_PORT):
            _require_current_monitor(_json_get(FRONTEND_PORT, "/api/health"), "Port 5176")
            return "owned" if self._frontend is not None and self._frontend.poll() is None else "reused_external"
        node = self._node()
        if not node or not self.vite.is_file():
            raise LauncherError("Existing trusted Node/Vite dependencies are missing; no install was attempted")
        self._safe_frontend_files()
        self._frontend = self._spawn([str(node), str(self.vite), "--host", "127.0.0.1", "--port", str(FRONTEND_PORT), "--strictPort"],
            self.project/"frontend", frontend_environment())
        try:
            self._wait_healthy(self._frontend, FRONTEND_PORT)
        except BaseException:
            self._stop_one(self._frontend)
            self._frontend = None
            raise
        return "started_owned"

    @staticmethod
    def _stop_one(process):
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def stop_owned(self):
        # Never enumerate/kill by port, PID or name; external services are not ours.
        self._stop_one(self._frontend)
        self._stop_one(self._backend)
        self._frontend, self._backend, self._owned_key = None, None, ""

    def status(self):
        _require_current_monitor(_json_get(API_PORT, "/api/health"), "Port 8004")
        system = _json_get(API_PORT, "/api/system")
        if system.get("mode") != "monitor":
            raise LauncherError("The API is not in Monitor mode")
        state = system.get("monitoring", {})
        return dict(mode="monitor", receipt_status=state.get("status"), last_ingest_at=state.get("last_ingest_at"),
            retained_records=state.get("retained_records"), max_rows=state.get("max_rows"), capacity_reached=state.get("capacity_reached"),
            note="Receiving/stale describe metadata receipt, not whether a capture process is running. Collection occurs only during the explicit 15-second action.")

    def capture_once(self, *, confirmation, prompt=getpass.getpass):
        if confirmation != "START":
            return dict(started=False, reason="Explicit START was not supplied")
        candidate = self._fresh_adapter()  # Resolve addresses at action time, never from config.
        tshark, dumpcap = self._wireshark()
        _require_current_monitor(_json_get(API_PORT, "/api/health"), "Port 8004")
        key = self._owned_key if self._backend is not None and self._backend.poll() is None else prompt("Existing monitor API key (not saved): ")
        if not isinstance(key, str) or len(key) < 32:
            raise LauncherError("A monitor key of at least 32 characters is required; capture did not start")
        monitor = _monitor_module()
        invoked = False
        try:
            monitor.preflight(API, key)  # Wrong key/profile/capacity fails before interface access.
            # Refresh a second time after a possibly slow private key prompt/preflight.
            candidate = self._fresh_adapter()
            argv = ["--interface", candidate.interface, "--interface-label", candidate.label,
                "--duration", "15", "--max-packets", "5000", "--max-flows", "1000",
                "--tshark", tshark, "--dumpcap", dumpcap, "--api", API, "--enable-capture", "--ingest"]
            for address in candidate.addresses:
                argv.extend(("--local-address", address))
            with _temporary_key(key):
                invoked = True
                result = monitor.main(argv)
            return dict(collector_invoked=True, capture_success=result == 0, exit_code=result, continuous_capture=False)
        except KeyboardInterrupt:
            return dict(collector_invoked=invoked, capture_success=False, exit_code=130, continuous_capture=False)
        finally:
            key = ""

    def open_dashboard(self):
        _require_current_monitor(_json_get(FRONTEND_PORT, "/api/health"), "Port 5176")
        webbrowser.open(DASHBOARD)  # Only this explicit menu action opens a browser.

    def interactive(self, input_fn=input, output=print):
        output("Sentinel local monitoring: disabled until explicit START; Ctrl+C stops an active bounded collection. No elevation/settings changes.")
        try:
            while True:
                choice = input_fn("\n1 Check  2 Select wired adapter  3 Start/reuse local services  4 Status  5 Open dashboard  6 Capture 15s  7 Stop owned services  0 Exit\n> ").strip()
                try:
                    if choice == "0":
                        return 0
                    if choice == "1":
                        output(json.dumps(self.check(), indent=2))
                    elif choice == "2":
                        items = adapters()
                        for index, item in enumerate(items, 1):
                            output(f"{index}: {item.label} - {item.description or 'hardware description unavailable'} ({item.guid}); {'physical verified' if item.physical_verified else 'UNVERIFIED: confirm wired hardware'}; {len(item.addresses)} assigned addresses")
                        raw = input_fn("Select candidate number (blank cancels): ").strip()
                        if not raw:
                            continue
                        if not raw.isdigit() or not 1 <= int(raw) <= len(items):
                            raise LauncherError("Select an available listed candidate")
                        item = items[int(raw)-1]
                        manual = not item.physical_verified and input_fn("Confirm this is your physical wired Ethernet adapter: type WIRED: ") == "WIRED"
                        self.select(item.guid, confirm_unverified=manual)
                        output("Selection saved privately; addresses will be refreshed before every collection.")
                    elif choice == "3":
                        output("Backend: "+self.start_backend())
                        output("Frontend: "+self.start_frontend())
                    elif choice == "4":
                        output(json.dumps(self.status(), indent=2))
                    elif choice == "5":
                        self.open_dashboard()
                    elif choice == "6":
                        item = self._fresh_adapter()
                        output(f"Preview: {item.label} - {item.description or 'hardware description unavailable'} ({item.guid}); 15 seconds; 5000 packets; 1000 flows maximum. Passive 128-byte RAM pipe; no packet file. Metadata goes only to the isolated local Monitor API. Ctrl+C stops capture; no continuous loop.")
                        output(json.dumps(self.capture_once(confirmation=input_fn("Type START to authorize this one window, or Enter to cancel: "))))
                    elif choice == "7":
                        self.stop_owned()
                        output("Stopped only services created by this launcher; reused external services remain running.")
                    else:
                        output("Choose a listed action.")
                except (LauncherError, CollectorError, OSError) as exc:
                    output("Action stopped: "+str(exc))
        except (KeyboardInterrupt, EOFError):
            output("Launcher exiting; stopping only its owned services.")
            return 130
        finally:
            self.stop_owned()
