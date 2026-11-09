# Security scope and data handling

Sentinel AI is an educational network-telemetry and investigation application. Its default dashboard replays explicitly synthetic traffic without interface capture. It does not provide proven live network protection, scan hosts, block traffic, or change firewall rules. A separate, off-by-default Windows monitor profile accepts metadata from an explicitly started, bounded local collector; see [Windows monitoring](docs/windows-monitoring.md).

## Local lab boundaries

Lab ingestion is disabled by default. Enabling it requires an import key; that key authorizes ingestion only. Reading telemetry and editing incidents are not protected by a multi-user authentication system. Private lab/monitor requests require loopback clients and a literal loopback Host; browser writes additionally require a trusted origin. Keep these profiles local rather than putting private telemetry behind a public proxy. CORS is not authentication.

Keep lab state separate from demo state. Never publish an incident database, its WAL/SHM/journal files, investigation notes, real connection logs, or private captures. Demo startup refuses a database containing lab records. That safeguard does not sanitize exported files or screenshots.

## Optional local Windows monitoring

Monitor mode is separate from both demo and file-import lab mode. It requires an explicitly selected new/dedicated database and rejects incompatible database roles. The monitor API accepts only loopback clients and literal loopback Host headers; its keyed metadata/profile endpoints do not start capture. Browser write-origin checks reduce cross-site request risk but do not provide per-user authentication. Other authorized processes/users on the machine may be able to read telemetry or edit local incidents.

The collector requires the exact manually selected Ethernet interface and assigned local addresses. Without `--enable-capture` it previews a plan and does not launch an executable, open an interface, prompt for a key, or call the API. `--ingest` is a separate opt-in for keyed loopback requests, after a profile/key/capacity preflight. Keys belong in a process environment or the private `--ask-key` prompt, never command-line arguments or `VITE_` variables.

An enabled run pipes dumpcap's binary stdout directly into TShark's stdin. It requests no raw capture filename or temporary capture file. **The 128-byte packet prefixes can include payload fragments in process/pipe memory.** The decoder exports only a fixed metadata-field allowlist, not HTTP/DNS/authentication fields, payload text, or passwords. This is not a guarantee that the OS, swap, crash dumps, or other software never retain memory. Optional `--output` stores sensitive metadata JSON only under ignored `data/monitoring/`; omit it when no metadata export is needed.

Runs stop at their explicit time/packet bounds, keep bounded aggregates, and deliver metadata after the collection window stops. The dashboard cannot start capture or determine that a capture process is running: `receiving` means API metadata arrived recently. The database row cap stops new ingestion without silently deleting existing evidence; it is not secure erasure.

The original process-context restriction was later resolved in normal Windows execution: the owner verified a bounded 164-packet collection, 18 stored live flow records, two historical ML incidents and their dashboard display. No new capture was performed for the detection-intelligence update. That bounded check does not establish continuous collection, gap-free visibility or detection accuracy. Query interface link capabilities from a normal PowerShell first if another collection is explicitly authorized. If access fails, stop; any one-time elevated collector must be separately approved by the machine owner and run manually. The application does not elevate, change Npcap/Windows permissions, weaken ACLs, change router settings, or configure security software.

The 1 November detection-intelligence upgrade was activated and visually reviewed by the owner. The 7 November release preparation preserves that completed work; its launcher, controlled experiments and UI polish have their own dated checks in [verification](docs/verification.md).

### Local launcher boundaries

`sentinel-monitor.cmd` opens an explicit local menu. The Python entry point defaults to a read-only prerequisite/inventory check; neither action starts capture automatically. Capture requires a fresh wired-adapter selection and typing `START` for one 15-second window, with the existing packet/flow bounds. Adapter disconnect/change, wrong profile/key, or full storage stops the action rather than selecting a fallback interface. No browser endpoint can invoke this menu or choose an arbitrary capture command.

The launcher can start fixed loopback services or explicitly reuse an existing monitor service. A newly owned backend gets a random process-local key; it is not written to configuration, browser code or command arguments. A reused service keeps its original credentials and database; capture requires the owner to enter its existing key privately. The launcher does not retrieve or replace that key. It refuses a stale backend contract, including an unrestarted 1 November service, without adopting or stopping it. Restart that backend in its own existing terminal while retaining its original key and database before reuse. The saved launcher file contains only adapter preference, not addresses or credentials, and remains private under `data/monitoring/`.

Only child processes created by that launcher are stopped. There is no kill-by-port, PID enumeration, automatic elevation, driver installation or permission change. Exiting stops its owned services and clears its in-memory key reference; external reused services remain running. Frontend children receive only allowlisted environment settings. For actual frontend `.env*` files, the launcher permits only blank lines, comments, and simple literal assignments `VITE_API_BASE=` and `VITE_API_PROXY_TARGET=http://127.0.0.1:8004`; any other active line stops startup for review. Example files are ignored. This avoids parser differences reintroducing browser variables after environment sanitization. A separately reviewed manual setup remains available. This is a local-process boundary, not protection against a privileged user inspecting another process's memory.

### Controlled localhost experiments

The explicit lab runner creates only its own retained loopback listeners, accepts no external destination, and writes into a new exclusive run directory/database. It does not open an Ethernet interface, contact a home router, use a packet decoder, or change rules to manufacture alerts. Stored evidence says `origin=lab`, `collector=localhost-lab`, and `measurement_semantics=application_bytes`. Router-role and discovery-format simulations are labeled as such; application exchanges do not establish capture-pipeline coverage or real-world detection accuracy.

## Isolated read-only public profile

`SENTINEL_PUBLIC_DEMO=true` requires a dedicated new or already public-demo database containing only synthetic records. Private, unmarked and incompatible profile databases are refused. The profile seeds a fixed 360-record synthetic snapshot and forbids monitor/lab/PCAP modes. All API mutation requests are rejected with HTTP 403, including incident changes, replay and ingestion; the UI also hides replay controls and disables note/status edits. Ordinary local Demo Mode retains its existing mutable workflow.

The separate `docker-compose.public-demo.yml` mounts only its own named volume and binds the frontend to `127.0.0.1:8082`; the backend has no host-port mapping. Do not add private mounts, keys, telemetry or capture privileges. This is a local preview configuration and does not authorize publication. Public hosting still needs the deployment review, HTTPS/access/resource controls appropriate to that service, and separate owner approval. No public capture service is provided.

Treat the selected interface ID, assigned addresses, monitor database, metadata exports, console transcripts, and dashboard screenshots as private. Do not add actual local/router details or keys to public documentation, issues, screenshots, or the reviewed publication manifest.

## Detection and historical-record boundaries

The historical KDD99 Isolation Forest, its threshold, evaluation artifact and model card remain unchanged. In Live Ethernet mode its score is informational only: incompatible packet-observation states, unknown service, lower-bound durations and local-host/header-derived byte semantics have not been validated against representative monitoring data. Category absence/range indicators are explanatory heuristics, not causal attribution or evidence of malicious intent.

New live findings come from bounded review rules for initiated TCP port fanout, initiated TCP flow bursts and observed outbound volume. Rules are not attack verdicts, and a volume threshold does not prove exfiltration. Port/address hints for discovery, DNS, DHCP, HTTPS or private peers do not create destination whitelists or establish device trust. The pipeline has no genuine authentication-event ingestion path, so it cannot claim failed-login detection from TCP metadata.

Historical incidents retain their saved title/priority, status, indicators, notes and history. Read-only current assessments do not re-score or rewrite them. If an original threshold was not persisted, any displayed comparison threshold is labeled as a current baseline reference. The reported six-decimal score does not recover an original full-precision decision; rounding can affect threshold comparisons near the boundary. No automatic resolving, blocking or response follows from this assessment. See [live detection](docs/live-detection.md) and [the existing-monitor restart instructions](docs/windows-monitoring.md#update-and-view-existing-stored-observations).

An upgrade should retain the existing private key/environment and dedicated monitor database. Do not change credentials or point the service at a new empty file merely to view existing records. Results on 27 constructed regression scenarios are not operational security assurance.

## Secrets and model files

Commit only blank/example environment files. `VITE_` configuration is embedded in browser JavaScript and must never contain credentials. The frontend import key remains in page memory and should not be entered into a public demo backed by private data.

Only load model files from a trusted source. Joblib/pickle deserialization can execute code. The included model's SHA-256, version and feature checks detect an accidental mismatch; they are not a signature and do not establish trust in an unknown artifact. No API accepts model uploads.

## Publication review

The repository's ignore rules are a guardrail, not a content-aware data-loss prevention system. Keep imports under ignored data/capture locations and review the exact staged file list and diff before any future commit. Newly added examples, screenshots or model artifacts need a separate provenance and privacy review. Refer to [the publication audit](docs/publication-audit.md) and [reviewed file manifest](docs/publication-files.txt).

If a credential is ever committed, ignoring or deleting the current file does not remove it from Git history. Revoke or rotate it first and review all affected history before publication.

## Reporting a problem

Do not post credentials, private telemetry, captures or database contents in a public issue. When a public repository is created, its owner should enable GitHub private vulnerability reporting and use that channel for sensitive reports. No public repository or reporting endpoint is configured by this local preparation stage.
