# Optional Windows Ethernet metadata monitoring

This is a separate, off-by-default profile for **one manually selected local laptop interface**. The API and dashboard do not start capture. A local launcher or command-line collector can observe one explicitly authorized bounded Ethernet window and then submit metadata to an isolated loopback backend. The default synthetic demo, controlled localhost experiments, authorized file imports and read-only public snapshot remain separate.

**Bounded hardware collection was subsequently verified in normal Windows execution.** An initial process-context restriction was resolved; 164 genuine packets produced 18 stored live flow records and two historical benchmark ML incidents, and the owner verified their dashboard display. The 1 November detection-intelligence upgrade was then activated and visually reviewed by the owner. This is bounded workflow/display evidence, not continuous monitoring, gap-free visibility, attack ground truth or proven protection. The 7 November launcher/UI changes have separate dated verification; no new hardware collection is implied by those source changes.

To inspect existing records, use [Update and view existing stored observations](#update-and-view-existing-stored-observations). It requires only the existing backend/frontend; skip interface queries, dry runs and collector commands when no new collection is needed.

## Local launcher

The launcher is an optional convenience for the existing native Windows profile, not a browser capture service. From a normal PowerShell at the repository root, with the existing `.venv` and frontend dependencies installed:

```powershell
# Safe default/read-only entry point:
.\.venv\Scripts\python.exe scripts/local_monitor.py --check
# Open the explicit local action menu:
.\sentinel-monitor.cmd
# Equivalent menu entry point:
.\.venv\Scripts\python.exe scripts/local_monitor.py --interactive
```

`--check` (also the Python command's default) inspects prerequisite files and current wired-adapter inventory. It does not open an adapter, start services, prompt for a key, or prove Npcap access. The menu does not start capture on opening. Its actions are:

| Menu action | Behavior |
|---|---|
| 1 — Check | Show prerequisite/inventory results. Treat local identifiers in the output as private. |
| 2 — Select wired adapter | Select one currently Up wired candidate in this session. Physical verification uses a fixed Windows inventory query; if unavailable, an explicit `WIRED` confirmation is required. No saved preference starts capture. |
| 3 — Start/reuse local services | Use fixed backend `127.0.0.1:8004` and frontend `127.0.0.1:5176`. A conflicting non-monitor service is refused and left running. |
| 4 — Status | Report retained records, last ingestion and capacity. Receipt recency is not a running-sensor heartbeat. |
| 5 — Open dashboard | Open only the fixed local monitor URL after checking that its proxy reaches Monitor Mode. Viewing saved records needs no collection. |
| 6 — Capture 15s | Preview the selected adapter/bounds and require typing `START` for one 15-second window, at most 5,000 packets and 1,000 flow aggregates. Enter cancels. |
| 7 — Stop owned services | Stop only backend/frontend child handles created by this launcher. Reused external services and stored evidence are left intact. |
| 0 — Exit | Stop the launcher's owned services and exit. |

The launcher uses `data/monitoring/windows-monitor.db` when it starts a backend. If an existing monitor already runs on 8004, it can be explicitly reused without changing its key or database after its current release profile is verified. A backend still running the 1 November code is refused as stale and left running. Restart it in its own existing terminal using [the workflow below](#update-and-view-existing-stored-observations), retaining the original private key and dedicated database, before reusing it with this launcher. **If your original dedicated database is elsewhere, retain the existing backend configuration/restart workflow below; do not move or replace its database merely to use the launcher.** The launcher never discovers another process's secret or changes its credentials.

A newly owned backend receives a random key only in memory and its private child environment. For a reused external backend, the capture action asks for its current key using a hidden prompt; viewing/status does not. A wrong key/profile or full capacity fails before interface access. Keys are not stored in the browser, preferences or command arguments. Only an adapter preference (GUID and label) is saved to ignored `data/monitoring/launcher.json`; fresh assigned addresses are resolved before capture and again after preflight. Disconnection/change stops collection with no fallback interface.

Frontend children receive a sanitized environment with blank `VITE_API_BASE` and the fixed monitor proxy. In actual frontend `.env*` files, this launcher accepts only blank lines, comments, and simple literal assignments `VITE_API_BASE=` and `VITE_API_PROXY_TARGET=http://127.0.0.1:8004`; every other active line stops launcher startup for review. Example files are ignored. This deliberately narrow check avoids differences between environment-file parsers. Do not put secrets in frontend files or overwrite an existing private configuration to bypass that error. The manual setup remains available for a reviewed configuration that is intentionally different.

Ctrl+C during collection requests the existing collector's bounded cleanup. The launcher creates no repeating capture loop, installs no driver, changes no permissions/settings, and never elevates. If Windows denies adapter access, stop; any separately approved manual elevated run remains a distinct action. The manual CLI below retains its 20-second default and configurable bounds; the launcher deliberately chooses a fixed 15-second action.

See [verification](verification.md) for what launcher checks and interactions were actually executed. Implementation does not establish that a newly started capture succeeded.

## Update and view existing stored observations

In the **existing monitor backend terminal**, press Ctrl+C to stop uvicorn while leaving the terminal open. Retain its current `SENTINEL_MONITOR_MODE`, private `SENTINEL_API_KEY`, dedicated `SENTINEL_DB_PATH` and other environment values. Do not print the key, generate a replacement, reload an example environment over the current settings, or choose a new empty database. From the repository root, restart one worker:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8004
```

In the existing frontend terminal, stop/restart only that dev server if needed. The public proxy settings remain:

```powershell
# From the repository root in the frontend terminal:
cd frontend
$env:VITE_API_BASE = ''
$env:VITE_API_PROXY_TARGET = 'http://127.0.0.1:8004'
npm run dev -- --host 127.0.0.1 --port 5176 --strictPort
```

If that terminal is already in `frontend/`, omit `cd frontend`. Do not put the private monitor key in frontend variables. Open the [existing local dashboard](http://127.0.0.1:5176); the same database retains its stored flow records and historical incidents. `stale` after a completed collection means no recent ingest, not lost data or a failed UI. If the original backend terminal/environment is unavailable, recover that private configuration through the owner's local process instead of replacing it blindly.

The previous two ML incidents remain saved with their priorities, notes and history. Current compatibility/context is derived read-only without re-scoring old records; a threshold not stored historically is shown as a current baseline reference. Comparison uses the reported six-decimal score and cannot recover the original full-precision decision near a rounding boundary. New live baseline scores are informational only and do not generate new ML incidents. See [live detection](live-detection.md) for the three review rules, port-context limitations and constructed evaluation. No collector is necessary to inspect existing observations or their updated explanations.

The remaining setup/capability/collector sections are optional instructions for a **new explicitly authorized observation** or first-time profile setup. They are not upgrade steps.

## What is observed and retained

- IPv4/IPv6 TCP/UDP address/port metadata, observation timestamps, transport flags, stream/window identifiers, and header-derived transport payload-length counters.
- Byte counters include observed retransmissions. They are **not wire-byte totals or verified payload contents**; a header can describe payload bytes beyond the captured prefix.
- Flow records use the laptop's perspective: source is the selected local address, including when the laptop is a responder. A record covers a bounded observation window, not necessarily a complete session. Duration is a lower bound; the same connection may appear in another explicitly started window.
- Scope is the selected interface and supplied assigned local addresses. It does not reveal every device behind a router, attribute traffic to a process, decrypt TLS, or establish HTTP/SSH/password authentication outcomes.

dumpcap writes a bounded binary stream to stdout; TShark reads it from stdin and emits only fixed metadata fields. The application requests no raw packet filename or temporary capture file. **A 128-byte prefix can contain application fragments in RAM and process pipes.** Payload text/password fields are not exported or stored by the application. The prefix can also truncate IPv6/transport headers; unavailable, ambiguous, malformed, nonlocal, or over-limit metadata is skipped and counted. No promiscuous mode, name resolution, active scan, firewall action, router change, or external metadata service is requested.

## Prerequisites

Use the existing Python venv/dependencies from [the README](../README.md#run-locally), Node 22.12+, and trusted, already installed Windows `tshark.exe` and `dumpcap.exe` with an appropriate Npcap installation. This guide does not install drivers or change capture permissions. If prerequisites are missing, stop and arrange any installation separately with the machine owner's approval.

Examples below use the usual Wireshark installation directory; adjust the executable paths to the trusted local installation. Never copy a real interface GUID, local/router address, key, or private screenshot into this guide.

## 1. Inspect the selected interface without collecting packets

From a **normal, non-elevated PowerShell** at the repository root:

```powershell
$tshark = 'C:\Program Files\Wireshark\tshark.exe'
$dumpcap = 'C:\Program Files\Wireshark\dumpcap.exe'
& $tshark --version
& $dumpcap --version
& $tshark -D
$nic = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
  Where-Object { $_.Name -eq 'Ethernet' -and $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -eq 'Ethernet' })
if ($nic.Count -ne 1) { throw 'Select one exact, currently Up wired Ethernet adapter; do not fall back to another interface.' }
$nic = $nic[0]
$nic | Select-Object Name, Description, OperationalStatus, NetworkInterfaceType, Speed, Id
$interfaceId = '\Device\NPF_' + $nic.Id
$assignedAddresses = @($nic.GetIPProperties().UnicastAddresses |
  ForEach-Object { $_.Address.ToString().Split('%')[0] } | Sort-Object -Unique)
$assignedAddresses
$localAddress = Read-Host 'One numeric address currently assigned to that exact Ethernet adapter'
if ($localAddress -notin $assignedAddresses) { throw 'Choose an address assigned to the selected adapter.' }
& $dumpcap -i $interfaceId -L
```

The .NET inventory is the main selection path because a physical interface GUID may be absent from `-D` output when capture access is denied. It identifies the Windows adapter; it does not prove that Npcap can open it. Change only the exact selected adapter name in the filter if the wired interface has another local name, keeping the unique/currently-Up/Ethernet-type guards. Optional normal checks are `Get-NetAdapter -Name 'Ethernet'` and `Get-NetIPAddress -InterfaceAlias 'Ethernet'`; neither replaces the assigned-address check.

The `-L` query lists link-layer capabilities; it does not request a packet collection. It opens the driver/interface and a helper may prompt for elevation. **Cancel any unexpected UAC prompt** pending separate owner approval. Do not select an index, an automatically chosen adapter, loopback, another person's device, or an address not assigned to the selected adapter.

If the query reports an access/permission error, stop. Do not weaken ACLs, alter Npcap permissions, disable security controls, or change router settings. If the machine owner **separately approves a one-time elevated observation**, manually open one Administrator PowerShell, repeat the capability query, and only then consider the explicitly bounded collector command below. Nothing here automatically elevates or approves that step. A repeated error means capture remains unavailable; do not report success.

Interface listings and dry-run previews can reveal actual local identifiers/addresses. Keep their output private.

## 2. Review a dry-run plan

```powershell
.\.venv\Scripts\python.exe scripts/monitor_windows.py --help
.\.venv\Scripts\python.exe scripts/monitor_windows.py `
  --interface $interfaceId --interface-label Ethernet `
  --local-address $localAddress --duration 20 --max-packets 5000 --max-flows 1000 `
  --tshark $tshark --dumpcap $dumpcap --api http://127.0.0.1:8004
```

There is deliberately no `--enable-capture` or `--ingest` in this preview. It launches no executable, opens no interface, asks for no key, and sends no API request. Review the exact selected interface and host filter locally. Repeat `--local-address` for each additional assigned IPv4/IPv6 address to include, up to eight; unsupported or omitted traffic is outside the observation scope.

The implemented bounds are 1–120 seconds (default 20), 1–5,000 packets, and 1–1,000 finalized flow aggregates held in memory. The supplied command uses the maximum packet/flow bounds and a 20-second window. No automatic loop or background capture service is created.

## 3. First-time setup: start a new isolated monitor backend

Keep any existing demo or file-import lab running on its own ports/database. The monitor examples use **backend 127.0.0.1:8004** and **frontend 127.0.0.1:5176**, leaving an existing lab UI on 5174 alone.

For first-time setup only, in a normal backend PowerShell at the repository root, enter a separate long random monitoring key privately. Existing installations should use the restart section above and keep their current key/database. Retain the same key privately so it can be entered at the collector's prompt; do not put its value in a script, shell argument, screenshot, or Git file.

```powershell
$env:SENTINEL_MONITOR_MODE = 'true'
$env:SENTINEL_LAB_MODE = 'false'
$env:SENTINEL_PCAP_ENABLED = 'false'
$env:SENTINEL_DB_PATH = 'data/monitoring/windows-monitor.db'
$env:SENTINEL_CORS_ORIGINS = 'http://127.0.0.1:5176'
$monitorSecret = Read-Host 'Private random monitor key, at least 32 characters' -AsSecureString
$env:SENTINEL_API_KEY = [System.Net.NetworkCredential]::new('', $monitorSecret).Password
Remove-Variable monitorSecret
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8004
```

Use one worker. The path must be new or already marked as a monitor database. Default demo, lab, and unmarked existing databases are refused rather than cleared. The server creates no synthetic seed in monitor mode. The default 5,000-row cap is an application factory setting, **not an environment variable**; reaching it stops new ingestion and preserves existing evidence.

Environment examples are documentation, not automatic configuration. The commands above set the backend process environment explicitly. This monitor profile is local-only; do not publish it, reverse-proxy it onto a network, or put its database behind a public demo.

## 4. Open the separate local dashboard

From a different normal PowerShell, starting at the repository root:

```powershell
cd frontend
$env:VITE_API_BASE = ''
$env:VITE_API_PROXY_TARGET = 'http://127.0.0.1:8004'
npm run dev -- --host 127.0.0.1 --port 5176 --strictPort
```

Open [the local monitoring console](http://127.0.0.1:5176). The development proxy target accepts only a literal loopback HTTP(S) origin and defaults to 8000 when unset, preserving the demo workflow. `VITE_API_BASE` stays blank so browser requests use this same-origin proxy. Do not place the monitoring key in either `VITE_` setting: frontend environment values are public to the browser.

A new empty monitor database correctly shows **Waiting for metadata**, with zero flow records. An existing dedicated monitor database retains its saved records even when no collector is running. There are no replay/capture start/reset buttons in monitor mode. The System page reports provenance and limitations; it cannot inspect a capture process's lifetime.

## 5. Optional: run one explicitly authorized bounded collection

Only after the selected interface, assigned addresses, dry run, isolated profile, and any required one-time elevation have been approved, run this from a separate collector PowerShell at the repository root. Re-establish the trusted executable paths and manually selected variables from step 1 in that terminal. Use the normal terminal when it has access; an elevated collector is a separate, manual owner-approved action.

```powershell
.\.venv\Scripts\python.exe scripts/monitor_windows.py `
  --interface $interfaceId --interface-label Ethernet `
  --local-address $localAddress --duration 20 --max-packets 5000 --max-flows 1000 `
  --tshark $tshark --dumpcap $dumpcap `
  --enable-capture --ingest --api http://127.0.0.1:8004 --ask-key
```

The private prompt requires the same key as the backend. Alternatively, the collector reads `SENTINEL_API_KEY` from its own process environment; omit `--ask-key` in that case. There is no key argument. The collector verifies the keyed loopback profile/capacity before opening the adapter, refuses redirects and proxy routing for metadata requests, and removes the key from dumpcap/TShark child environments.

Collection stops at the time/packet bounds or an error; Ctrl+C also requests cleanup of the owned processes. Finalized metadata is submitted in batches of at most 50 **after the collection window stops**, not as a continuous live stream. A failed process window is rejected rather than presented as successful partial capture. Omit `--ingest` to collect without API submission; `--ingest` cannot be used without `--enable-capture`.

No metadata file is saved unless explicitly requested. If an export is actually needed, `--output` accepts only a new `.json` under ignored `data/monitoring/`; it contains sensitive metadata, not raw packets, and must remain private. The default summary omits connection rows and addresses, but dry-run plans, optional files, databases, exports, and dashboard views can contain private identifiers.

## Interpret the result honestly

- **Live Ethernet** describes record origin. It does not mean collection is still running or that this laptop/network is protected.
- `receiving` means metadata reached the API within its recency window; `stale` means no recent ingest. Neither is a capture-process heartbeat.
- Counts are observed flow-window records. Durations are lower bounds, header-derived byte lengths include retransmissions, and dropped/truncated/unsupported data can undercount observations. They are not complete connection/session or verified payload statistics.
- New live findings are context-aware rule conditions for review, not confirmed attacks. The unchanged KDD baseline score is informational only; its historical precision/recall do not measure this laptop's traffic. Old ML incidents remain historical saved findings with a read-only compatibility explanation. Local/responder orientation, `unknown` service and observed transport states differ from benchmark semantics. Authentication/password outcomes and process attribution are unsupported.
- Port/address context such as possible SSDP, DNS, DHCP, mDNS or HTTPS does not verify the application, identify a router from a private address, or whitelist a peer. Review rules still apply to unusual behavior involving familiar protocols.
- Flow fanout/burst evidence requires observed local TCP initiation within one collection; low-volume/slow/cross-window or UDP/midstream scans can be missed. A large observed outbound counter warrants review but does not establish exfiltration.
- The row cap blocks new rows; it does not erase a database or its SQLite sidecars. Keep all monitor evidence private and use an explicit retention decision for old data.

Stop the frontend/backend with Ctrl+C when finished. Clear the process-local key from terminals where it was set (`Remove-Item Env:SENTINEL_API_KEY`) or close those terminals. Starting or stopping the backend does not start a collector. To return to the demo, use a fresh terminal with monitor/lab flags off and the separate demo database/ports from the README; never repoint a public demo to the private monitor file.

See [security and data handling](../SECURITY.md), [architecture](architecture.md), and [verification](verification.md) for scope and measured checks. No real private monitor screenshots, packet dumps, local GUIDs/addresses, or keys belong in public documentation.

For upstream access and command semantics, consult the [Npcap user guide](https://npcap.com/guide/npcap-users-guide.html), [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html), and [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html). These references do not authorize permission changes or elevation.
