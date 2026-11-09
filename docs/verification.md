# Implementation and verification report

**Current release verification: [7 November 2026](#final-v1-verification--7-november-2026).** The earlier sections below are retained as dated history, including restrictions that were subsequently resolved.

Verified on **29 October 2026** on Windows, using Python 3.11, Node.js 22, SQLite, the actual saved Isolation Forest and the local React application. This is a new application; no previous AI-NDR source was used.

The sections through “Run and publication” below retain that dated original baseline. The later [optional Windows monitoring update](#optional-windows-monitoring-update) records the separate new checks and their limits; it does not turn the earlier synthetic screenshots/browser tests into evidence of real interface capture.

## Working functionality

- Five connected SOC views: Overview, Traffic explorer, Incidents, AI model and System health.
- Synthetic replay with 360 connection records, startup seed, start/pause/resume/reset and selectable speeds. A full accelerated replay completed through the actual API/model pipeline, producing 360 records and 56 correlated incidents (39 ML, 17 rule). These counts describe this synthetic demonstration, not evaluation performance.
- Validated connection records, directional byte counts, durations, states, addresses/ports, protocol breakdown, time buckets, top talkers, rule/ML incident totals, search and filters, paginated traffic, and CSV export.
- Windowed rule detections and separate ML anomalies with supporting indicators. Correlation, SQLite persistence, incident severity/status, investigation notes and history.
- Zeek JSON and TSV import, API-key gate, body limits, malformed-record rejection and background-thread batch inference. A live HTTP smoke check successfully imported the three sanitized JSON fixture records using the supplied CLI, rejected a missing key with HTTP 401, verified lab-origin labels, and verified that demo reset retained lab records.
- Safe rule-only fallback on missing, incompatible or mismatched model artifacts. Demo startup refuses a database containing lab evidence.

## Checks actually run

| Check | Result |
|---|---|
| `python -m pytest -q` | **53 passed**: 34 backend + 19 ML tests |
| TypeScript `tsc -b` | Passed |
| Vite production build | Passed, 2,146 modules; approximately 606 KB JS / 168 KB gzip |
| Python installed-environment dependency audit | 63 packages checked; no known vulnerabilities reported |
| npm dependency audit | 142 packages audited; no known vulnerabilities reported |
| Docker Compose configuration validation | Passed |
| Live demo health and model loading | HTTP 200, model loaded |
| Live authenticated lab import CLI | Passed on sanitized fixture; no private network accessed |
| Independent repeat training | Same metrics and byte-identical model artifact |

The tests cover rule thresholds and timestamp rewinds, JSON/TSV normalization, invalid batches, API validation, incident persistence/history, replay/reset isolation, authorization, pre-parse body limits, health responsiveness during imports, lab-database privacy protection, preprocessing, group disjointness, inference, artifact integrity and safe fallback.

Browser checks exercised start/pause/resume, a complete replay, combined UDP/address filtering, incident opening, notes/status saves, reset to zero records, actual model metrics/matrix, navigation and mobile layouts at 390 px and 320 px. The checked views had no browser console warnings or errors. Screenshots are actual rendered pages in [screenshots/](screenshots/). The frontend received a final CSV formula-neutralization check with malicious prefixes, ordinary strings, numbers, quotes and null values.

One upstream test-client deprecation warning remains: Starlette recommends its future httpx2 test client. All 53 tests pass using the pinned HTTPX version. The production build reports a bundle-size advisory; chart code currently ships in the main bundle.

## Actual model results

Dataset: checksum-verified **UCI KDD Cup 1999 10%**, 494,021 raw rows. Exact deduplication leaves 145,586 rows and 57,163 canonical feature groups. Group-based train/validation/test partitioning prevents identical inference feature vectors crossing splits. The 60/20/20 targets apply to groups, not row counts. Preprocessing and Isolation Forest fit 53,953 benign training rows. A separate set of 16,790 benign validation rows sets the 98th-percentile threshold before test evaluation.

Held-out test: **19,887 rows**, including 17,089 benign and 2,798 attacks.

| Metric | Actual value |
|---|---:|
| Precision | 51.04% |
| Recall | 20.12% |
| F1 | 28.86% |
| False-positive rate | 3.16% |
| ROC AUC | 85.40% |

Confusion matrix, rows actual / columns predicted, ordered benign then attack:

```text
                 Predicted benign   Predicted attack
Actual benign         16,549                540
Actual attack          2,235                563
```

Most false positives involve the benchmark's `private` (397) and `urp_i` (123) services. The threshold misses most test attacks: **2,235 false negatives**. This is a limited educational baseline, not a production detection claim. The old lab-generated dataset, simplified shared features, service/state approximations and lack of timestamps/hosts prevent a modern temporal or deployment validation. Synthetic replay metrics are not benchmark metrics. Full provenance, source links, hashes and limitations are in [the model card](../models/model_card.md) and [metrics.json](../models/metrics.json).

## Environment limits and unfinished validation

- Docker Compose is configured and its schema validates, but **the Docker engine was stopped**, so images, nginx proxy and Compose startup were not run. No container-image vulnerability scan was performed.
- At the original baseline, Ubuntu, Zeek and tshark were unavailable for an actual end-to-end capture conversion. Zeek parsers and PCAP flow aggregation were tested. The optional adapter groups TCP/UDP by five-tuple and may merge reused sessions; it uses frame bytes and inferred state. The later separate bounded Windows collector is described below; successful real-interface capture remains unverified.
- Windows process restrictions blocked Node child-process spawning. The successful Vite build/dev launch skipped only Vite's optional `net use` mapped-drive lookup through an ephemeral in-memory wrapper. Dependency and application sources were not patched. TypeScript and all Vite transforms/bundling ran. Standard `npm ci`/`npm run dev`/`npm run build` are documented for an ordinary terminal.
- The bundled Python 3.12 runtime had a temporary-directory permission problem, so validation used the installed Python 3.11 environment. The included workflow selects Python 3.11 on Linux; its remote CI run and Python 3.12 compatibility were not executed here.
- State is shared per backend, with no multi-user login. Lab ingestion is keyed; reading/editing lab evidence requires loopback deployment or an authenticated reverse proxy. Replay uses one worker. This is not a replacement for a production NDR platform.

## Run and publication

Follow [README.md](../README.md#run-locally) for exact Windows/Ubuntu commands and [deployment.md](deployment.md) for Compose and hosting preparation. The model is included; training downloads are unnecessary to run the demo. Start the backend on port 8000 and frontend on 5173; Compose uses 8080 once the engine is running.

The clean source and screenshots are prepared for GitHub, with a lockfile, license, workflow, Dockerfiles and a portfolio-showcase draft. **No GitHub push, public deployment or existing portfolio modification was performed.** No private telemetry, runtime databases, dependency folders or raw benchmark archive belongs in the deliverable ZIP.

## Optional Windows monitoring update

**30 October 2026.** A separate, off-by-default monitor profile and explicitly opted-in bounded Windows collector were implemented while preserving the original demo and file-import lab. The new origin is `live`; records represent local flow-window observations, not synthetic replay or complete session telemetry. See [the Windows guide](windows-monitoring.md).

| Check | Measured result and scope |
|---|---|
| Full Python suite | **116 passed**, 8.71 seconds in the final target run, including existing behavior plus collector/monitor profile isolation, bounds, provenance, key/loopback/preflight behavior, and controlled error/cleanup paths |
| Focused frontend presentation tests | **4 passed**: origin integrity, unknown-source handling, ingest-recency wording, and replay-action gating |
| TypeScript `tsc -b` | Passed for the monitor UI update |
| Vite 8.3.5 monitor UI production build | Passed: 2,147 modules; 613.46 kB JavaScript / 170.40 kB gzip, 49.37 kB CSS / 11.36 kB gzip; chunk-size advisory only |
| Configurable local frontend proxy | **6 checks passed using Vite's actual `loadConfigFromFile`**, without a server/network: default 8000, override 8004 and IPv6 loopback accepted; remote IP, credential-bearing URL and path URL rejected |
| Actual TShark decoder with synthetic in-memory packets | Five constructed packets produced two flow observations; **12 checks passed**. No real interface or network traffic was used for this decode |
| Real HTTP empty-monitor smoke check | Isolated loopback profile, actual saved model/key behavior and replay rejection with HTTP 403 passed; no capture was started |
| Actual Windows Ethernet capture | **Blocked/unverified** in the available process/interface access context; no successful real-interface collection is claimed |
| New monitor GUI/browser check | Not performed in this update; existing screenshots/browser claims above remain the earlier synthetic baseline |

The production build used the same ephemeral workaround for Vite's optional Windows `net use` lookup as the original environment check. It did not patch application/dependency sources; TypeScript and build transforms/bundling ran. The local proxy configuration was validated separately without launching a server or capture.

The focused frontend checks run from `frontend/` with `node --experimental-strip-types --test tests/presentation.test.mjs`. The flag is needed for compatibility with the project's Node 22.12 minimum; the recorded run used Node 22.19. These tests validate presentation helpers and replay gating, not a new browser interaction or hardware capture.

The collector's process/API tests use controlled substitutes and constructed metadata. The TShark decoder check used actual TShark on synthetic bytes in memory. Neither demonstrates that dumpcap/Npcap can open the selected physical Ethernet interface, that a capture is gap-free, or that the application detects real attacks. Normal capability queries did not establish successful hardware capture. No permissions were weakened, router/security settings changed, or automatic elevation implemented. A real one-time elevated observation would require separate explicit owner approval and successful execution; it is not part of these test results.

The implementation requests a bounded 128-byte-prefix stream from dumpcap stdout to TShark stdin without a raw packet filename. Prefixes can contain application fragments in RAM, even though only fixed metadata fields are exported. Header-derived transport payload-length counters include retransmissions and can describe bytes not present in the prefix; they are not wire-byte totals or verified payload contents. Durations are lower bounds and local-host/responder orientation, `unknown` service and partial transport states introduce model domain shift. Authentication/password outcomes, process attribution, continuous protection, and whole-router visibility are unsupported.

Monitor `receiving` means recent API metadata, not capture-process status. The default row cap stops new ingestion without deleting old evidence. No private monitor databases, raw captures, metadata exports, local GUIDs/addresses, real keys, or actual monitor screenshots were added to the public screenshot set or file manifest. No public deployment, GitHub push, or portfolio modification was performed in this update.

## Live detection intelligence update — 1 November 2026

The earlier process-context capture restriction was subsequently resolved in normal Windows execution. The owner verified a bounded physical Ethernet run: 164 accepted packets, 18 stored flow observations, dashboard display and two historical ML incidents. This later evidence supersedes the earlier hardware-access blocker for that normal terminal; it is not an attack-detection evaluation. This intelligence update performs no fresh capture and preserves the original evidence.

| Executed check | Result and boundary |
|---|---|
| Full Python suite, actual existing project | **165 passed**, including all original 116 tests; one existing Starlette/HTTPX deprecation warning; 7.34 seconds in the final run |
| Frontend presentation tests | **8 passed**, including historical-threshold provenance, unavailable-score handling and finding-versus-verdict wording |
| TypeScript project check | `tsc -b` passed |
| Standard production build | `npm run build` passed without an environment workaround or dependency patch; 2,147 modules, 621.68 kB JS / 172.33 kB gzip and 51.93 kB CSS / 11.85 kB gzip; existing chunk-size advisory remains |
| Offline constructed comparison | **27 scenarios**; exact fixture-only confusion counts and failures are in [live-detection.md](live-detection.md). No training, threshold tuning or private-network accuracy estimate |
| Owned localhost network exercise | Eight successful connections to disposable loopback listeners triggered probing review; a hash-verified 6,000,000-byte dummy transfer triggered outbound-volume review. Application endpoint instrumentation, not packet capture or Ethernet-header validation |
| Actual HTTP with preserved private observations | Separate loopback backend against a database copy returned all 18 enriched live records and both historical incidents. All three history entries remained; API reads succeeded with re-scoring explicitly disabled |
| Read-only original model investigation | Original saved scores reproduce; changing the unsupported state alone does not remove either threshold exceedance. Model, preprocessing and threshold were preserved |
| New policy browser/layout check | **Not completed:** browser automation stalled and temporary preview services expired. No successful new-policy GUI visual check is claimed. Prior owner-verified display and the passing HTTP/type/build/tests are separate evidence |

The real observations have no independently established attack/benign labels. Re-evaluation retains two baseline threshold exceedances as diagnostics, with zero new rule conditions on those 18 rows; the original two incidents remain stored. This is not a measured false-positive-rate improvement. The 27 constructed cases expose remaining nuisance findings, missed UDP/slow/midstream probing and indistinguishable low-volume intent; their precision/recall do not transfer to real traffic.

No private database schema migration or backfill is required. New live assessment fields are stored inside new connection JSON; old payloads/scores, incidents, severities/statuses, notes and history receive read-only view enrichment. All three original model files, original tests, dependency manifests/lockfile and original screenshots remain unchanged. The original Demo/Lab rule engine and threshold-generated ML behavior are preserved. See [the current policy and run commands](live-detection.md) and [Windows upgrade/viewing steps](windows-monitoring.md).

The user-owned backend process on port 8004 still reported the previous in-memory policy at the last read-only check. Restart it in its existing terminal to load the new source while retaining the current private key and dedicated database. No new capture or credential is needed to inspect the stored flows. Temporary review services were stopped; no GitHub push, deployment, active blocking, Windows-security change or router change occurred.

## Final v1 verification — 7 November 2026

This subsequent verification preserves the completed November baseline. No model retraining, threshold tuning, new physical capture, home-network probing or original database reset was performed.

| Executed check | Result and practical boundary |
|---|---|
| Full suite, actual existing Windows project and venv | **328 passed**, 26.80 seconds; one existing upstream Starlette/HTTPX TestClient deprecation warning |
| Frontend helper/request/CSV tests | **18 passed** using `npm test`; controlled fetch tests are separate from actual HTTP and browser results |
| Standard TypeScript and production build | Passed; Vite processed 2,148 modules; JS 629.63 kB / 174.42 kB gzip, CSS 52.40 kB / 11.93 kB gzip. Existing 500 kB chunk advisory remains |
| Genuine owned localhost activity | All seven scenarios passed: **49 endpoint observations, three rule incidents**, matching client/server byte counts, hash-verified 6 MiB transfer, TLS verification, idempotent replay, cleanup and database integrity |
| Actual HTTP, isolated profiles | Public: 360 synthetic records/read-only; lab copy: 49/three rules/no ML score; monitor copy: 18 live/two historical ML incidents; Demo copy: 120 startup records and working replay/pause/reset. Search, protocol, pagination, notes/status/history on copies and Host/Origin/key boundaries passed |
| Public isolation | Incompatible database roles refused before writes; public POST/PATCH checks returned 403; public profile cannot enable monitor/lab/PCAP. Separate Compose profile/volume prepared |
| Launcher default on this Windows machine | Python/Node/frontend/TShark files found; four Up wired-type candidates found, with optional physical verification unavailable in this process context. No adapter opened, key prompted or service/capture started. Manual wired confirmation remains available |
| Actual launcher service lifecycle | Owned backend 8004 and frontend 5176 started and proxied 18 observations from a disposable monitoring copy; repeated starts reused owned handles; shutdown released both ports within a bounded three-second socket teardown check. No collector invocation |
| Desktop/browser | Actual in-app browser verified all five public views, 74 UDP+DNS traffic matches, 12 high/rule incident matches, read-only investigation edits and an actual 50-row synthetic UDP page export |
| Controlled investigation GUI | Actual 6 MiB rule evidence, note save, status change and history verified on a disposable lab copy. The original controlled-run evidence was not edited |
| Existing Live Ethernet GUI | All 18 rows rendered with Live Ethernet origin and informational scores. Two historical baseline incidents and an anchor/explanation were visible on a private database copy. No private screenshot or export was made |
| Responsive/keyboard sample | Desktop 1440 × 900 and mobile 390 × 844; mobile model view had no document-wide horizontal overflow; navigation Shift+Tab wrapping, Escape, focus return and body-overflow restoration passed |
| Screenshots | Six genuine new v1 JPEGs, using only synthetic or owned loopback data; five older genuine October JPEGs retained unchanged. See [testing](testing.md) |
| Original evidence preservation | Stable byte copies of each original main database and WAL were read in the workspace. SQLite integrity checks and complete ordered table-content fingerprints match the before snapshots for both original databases: monitor **18 connections/two incidents/three history entries**, Demo **360 connections/56 incidents/57 history entries**. Metadata/batch tables also match |
| Protected files | All three original model artifacts, feature preparation/inference/training code, both rule engines, requirement pins, npm lockfile, MIT license and five original screenshots retained their original hashes |
| Dependency/notice checks | `pip check` passed; production frontend notices and owned-license copy match. Following pip/setuptools-only tool upgrades, OSV returned zero affected pairs among 204 installed-Python/npm name-version pairs at this date |
| Compose schema | Both local profiles validate. Docker engine was unavailable, so image builds, nginx/container execution and image advisories were not verified |

The earlier browser-provider absence, approval timeout and unsupported native Windows browser URL-policy route were investigated. A later supported in-app browser became available and enabled the successful visual checks above. No security-policy bypass or alternative headless browser was used. Temporary viewport/tab and all owned review services were closed/stopped.

These are scoped checks, not a full screen-reader/contrast/multi-browser/device matrix or a new hardware capture test. Linux/macOS runtime, Python 3.12, fresh-machine dependency installation and the new remote Linux/Windows CI workflow have not run here. A Windows-only process-contract test explicitly skips outside Windows; other mocked launcher checks remain portable. See [known issues](known-issues.md) and [deployment](deployment.md) for remaining release/deployment gates. No public URL, Git commit/push or deployment is claimed.

The three lab findings reflect authorized probing, burst and large-upload review conditions. The four routine scenarios were unflagged. Slow/cross-collection probes, UDP/midstream scans and low-volume malicious intent remain blind spots; no real-network precision, recall, F1, benignness guarantee or whole-home protection follows from this run. The unchanged historical Isolation Forest is an informational live reference.
