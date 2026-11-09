# Testing and release verification

This guide distinguishes the checks executed during the **7 November 2026 v1 preparation** from the remaining manual work. The [dated verification report](verification.md) and final release report are authoritative for the final rerun totals. A passing API test or production build does not establish that a page rendered correctly in a browser.

The completed 1 November baseline had 165 passing Python tests, eight frontend tests and a production build. Its detection-intelligence upgrade was activated and visually reviewed by the owner. The later work preserves that completed baseline rather than treating an earlier hardware restriction as an ongoing failure.

## Final recorded v1 checks

| Check | Executed result and scope |
|---|---|
| Python suite | **328 passed** in the final actual-project run, in **26.8 seconds**, with one existing Starlette/HTTPX deprecation warning. Coverage includes persistence, detection, profile isolation, ingestion, security boundaries, model compatibility and new functionality. |
| Frontend tests | **18 passed** through `npm test`: provenance/unknown-mode labels, read-only capability gating, historical score wording, CSV formula neutralization/lineage, and mocked request timeout/cancellation/error behavior. |
| TypeScript and production build | Standard type/build checks passed; the Vite build processed **2,148 modules**. This is compilation/bundling evidence, not browser execution. |
| Genuine controlled activity | All **seven scenarios passed**, producing **49 endpoint records and three rule incidents** in a new exclusive lab database. No Ethernet/Npcap capture was used. |
| Private-record preservation check | HTTP against a disposable private-monitor database copy returned **18 saved live observations, two historical ML incidents and three original history entries**. The original monitoring database was not the test target. |
| Separate profile HTTP checks | Public synthetic, authorized lab, private monitor copy and mutable demo copy were served on distinct loopback ports. API profile/capability, stored data and mutation boundaries were checked separately from browser rendering. |
| Local launcher | Default prerequisite/inventory check performed without capture. Owned backend/frontend startup, proxying 18 saved observations from a disposable copy, and owned-process stop passed on ports 8004/5176. Socket-release verification allowed the documented three-second shutdown grace. No physical capture occurred. |
| Fresh v1 browser/layout/screenshots | **Executed after the browser provider became available.** Actual dashboard views, filters, CSV download, read-only controls, investigation edits on a lab copy, saved Live Ethernet data on a monitor copy, and selected mobile/keyboard checks passed. Six new genuine public/lab screenshots are linked below. |
| Docker and public hosting | Configuration is preparation, not an executed container or hosted-service result. See [deployment](deployment.md) and the final verification report for the exact remaining checks. No public deployment is claimed. |

Frontend request tests replace `fetch` with controlled substitutes; they do not contact a server. Launcher unit tests use controlled/mocked process and adapter behavior; the separate actual service smoke test covers startup/proxy/shutdown, not Npcap permission or a new hardware collection. The earlier owner-verified 164-packet Ethernet observation remains separate evidence. The browser checks below supplement these tests; they are not a formal accessibility or multi-browser audit.

## Reproduce automated checks

Install the documented dependencies first; see [setup](../README.md#run-locally). Use Python 3.11/3.12 and Node 22.12 or later. Run from the repository root:

**Windows PowerShell:**

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -q
cd frontend
npm test
npm run typecheck
npm run build
cd ..
.\.venv\Scripts\python.exe scripts/generate_notices.py --check
```

**Linux/macOS:**

```sh
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
cd frontend
npm test
npm run typecheck
npm run build
cd ..
.venv/bin/python scripts/generate_notices.py --check
```

`npm test` uses Node's built-in runner with `--experimental-strip-types`, including compatibility with the Node 22.12 minimum. These are helper/request tests, not a browser automation suite. Python tests use temporary test state; do not point a test fixture or test server at an original evidence database. The included [GitHub Actions workflow](../.github/workflows/check.yml) must receive its own actual CI run before a CI success is claimed.

The notice check reads the lockfile and installed production dependency licenses without network access. After an intentional dependency/lockfile change and `npm ci`, regenerate and review the static notice:

```powershell
.\.venv\Scripts\python.exe scripts/generate_notices.py
.\.venv\Scripts\python.exe scripts/generate_notices.py --check
```

On Linux/macOS use `.venv/bin/python` in those two commands. Generated output is [frontend/public/third-party-notices.txt](../frontend/public/third-party-notices.txt); its scope is documented inside the file. Regeneration is not a substitute for reviewing a dependency's license or origin.

## Genuine controlled localhost scenarios

Previewing the plan opens no services and creates no run evidence. Actual exchanges require explicit execution:

```powershell
.\.venv\Scripts\python.exe scripts/verify_controlled_lab.py
.\.venv\Scripts\python.exe scripts/verify_controlled_lab.py --execute
```

The second command is optional and authorizes a new bounded experiment. On Linux/macOS use `.venv/bin/python`. An existing output directory/database is refused. Reports, evidence and the new `controlled_lab` database remain under ignored `data/lab-runs/`; review them privately. No actual home router, household device, public destination or third-party service is probed.

| Scenario | Actual owned activity | Observed rule outcome |
|---|---|---|
| TCP port probing | Eight completed banner exchanges with retained owned TCP listeners | `port_scan`, high priority |
| Connection burst | 25 distinct TCP exchanges with one owned service | `connection_frequency`, medium priority |
| Outbound volume | Three small uploads and one verified 6 MiB upload | `traffic_spike`, medium priority |
| Routine HTTPS | Three small requests to an owned TLS server | No rule incident in this scenario |
| Routine DNS | Three valid DNS question/NXDOMAIN exchanges over owned loopback UDP | No rule incident in this scenario |
| Local discovery format | Three SSDP-format unicast request/responses | No rule incident in this scenario |
| Router-role communication | Three small HTTP status exchanges with an owned router-role simulator | No rule incident in this scenario |

The HTTPS case uses a disposable local certificate, an explicit test trust anchor and normal certificate/address verification. It does not disable TLS verification or install a system trust certificate. If certificate setup is unavailable, the scenario must report that failure rather than substitute plain HTTP and claim HTTPS coverage.

These records come from **owned application/socket instrumentation**, labeled `origin=lab` and `collector=localhost-lab`. Application-byte measurements exclude transport/TLS/HTTP overhead and retransmissions; they are not Ethernet capture counters. The runner does not load or score the historical Isolation Forest and does not change its thresholds. Its DNS/discovery/router-role exchanges verify those controlled application scenarios, not conventional port labels, physical multicast or a household router. Each scenario uses a separate collection identity.

The three alerts demonstrate unchanged review-rule conditions. The authorized activity is not malicious; legitimate probing, bursts and uploads can meet the same thresholds. Absence of a finding on the four routine scenarios is not proof that all similar traffic is safe. Slow/cross-window probing, UDP/midstream scans and low-volume malicious intent remain limitations. These experiments provide no real-world accuracy, precision, recall or F1 estimate.

## HTTP checks and browser checks are separate

The temporary v1 validation profiles used these distinct loopback frontend ports, each proxying its matching isolated backend:

| Profile | Temporary frontend port | Data boundary |
|---|---:|---|
| Read-only public demonstration | 15180 | Fully synthetic 360-record snapshot; no private database |
| Controlled lab copy | 15181 | Copy of the 49-record/three-rule-incident owned-loopback run |
| Private monitor copy | 15182 | Disposable copy of the 18-record/two-historical-incident evidence |
| Mutable demo copy | 15183 | Disposable synthetic replay state |

These ports are a dated validation allocation, not permanent endpoints or a public deployment. Private validation services are stopped after the checks. Any remaining bounded local public preview is available only while its owner-managed process remains running. For a repeatable local synthetic-only preview, use [the separate Compose profile](../README.md#separate-read-only-public-demonstration) after Docker validation.

Public-demo mutations are rejected by the API with HTTP 403, independently of hidden/disabled UI controls. The public profile cannot enable lab, monitor or PCAP modes and refuses private/unmarked databases. Normal local Demo Mode remains mutable. Private lab/monitor APIs retain loopback/Host/Origin checks; ingestion keys do not provide per-user authorization for local reads or incident edits.

HTTP responses and automated tests verify API/data behavior. They do not themselves establish CSS layout, chart readability, keyboard focus, downloads or successful browser interaction. The later actual browser checks supplied separate evidence for the specific interactions listed below. The private copy was used to examine stored compatibility/context; its real addresses, identifiers, notes and screenshots are not public fixtures.

## Browser blocker and screenshot provenance

The initial v1 visual attempt encountered these concrete tool limits:

1. The initial native app-access approval timed out.
2. The in-app browser inventory exposed no browser provider; selecting it returned `Browser is not available: iab`.
3. A later native Firefox window binding succeeded, but the first state read ended Computer Use: **“browser URL policy enforcement is not yet supported for the current Windows browser.”**

That attempt did not navigate or take screenshots; the queued local preview alone was not a visual pass. **The blocker was subsequently resolved when the supported in-app browser provider became available.** Actual page observations and interactions then succeeded through that provider. The unsupported native Firefox policy boundary was not bypassed with a different automation driver.

| Actual browser check | Observed result on a disposable profile |
|---|---|
| Public overview and navigation | Rendered the 360-record synthetic read-only snapshot; inspected overview, Traffic Explorer, Incidents, AI Model and System Health. Public labeling, model provenance/limitations and health content were visible. |
| Traffic search/filter/export | UDP plus `dns` produced **74 matching synthetic records**. The actual CSV download contained the **50 currently loaded rows**, with UDP/demo values, consistent with page-scoped export. |
| Incident filters and public editing boundary | High severity plus rule source produced **12 matches**. Opening a public investigation showed status and note controls disabled. API mutation denial is independently tested. |
| Controlled investigation on a copy | The lab copy rendered **49 genuine owned-endpoint records and three rule findings**. The large-transfer finding displayed the actual **6 MiB** evidence. A verification note and status change persisted with history on the disposable copy, not the original run evidence. |
| Stored private-monitor compatibility | Traffic Explorer visibly rendered all **18 saved Live Ethernet observations** with informational scores; the **two historical incidents** remained distinguishable. The historical investigation showed its anchor, informational qualification and wording that the score is not proof of an attack. This used a private database copy and did not start capture. No private screenshot or export is included in public docs. |
| Mobile and keyboard sample | At **390 × 844**, the model page rendered without document-wide horizontal overflow. Mobile navigation supported Shift+Tab focus wrapping, Escape, focus return and restoration of body overflow after closing. |

Six genuine screenshots from these 7 November checks are included, using only synthetic public or controlled-loopback data:

- [Public synthetic overview](screenshots/v1-public-overview.jpg)
- [Public synthetic Traffic Explorer](screenshots/v1-public-traffic.jpg)
- [Read-only public investigation](screenshots/v1-public-investigation.jpg)
- [Controlled localhost lab](screenshots/v1-controlled-lab.jpg)
- [Controlled localhost overview with 49 records and three rule findings](screenshots/v1-controlled-lab-overview.jpg)
- [Mobile model page](screenshots/v1-mobile-model.jpg)

The five existing genuine 29 October JPEGs remain unchanged as earlier synthetic-demo evidence. The owner-confirmed 1 November visual review remains separate historical evidence. No generated, reconstructed, pixel-edited or ImageGen screenshot substitutes were created. A private-monitor screenshot was not added to the publication set.

The browser pass is limited to the actions and viewport above. A 320 px review, all pages at all breakpoints, full keyboard/screen-reader/contrast audit, multi-browser matrix, all failure/retry states and browser-console review are not established by this sample. Mutable-demo replay/pause/reset passed through actual HTTP on a disposable copy; these controls were not clicked in this GUI run. Native permission behavior and a new physical capture were not tested. Docker, Linux runtime and remote CI also remain separate unverified checks. Owned validation services were stopped, and the owned browser tab and temporary viewport settings were cleaned up after the checks.

## Repeatable manual visual acceptance steps

Run these only against a prepared **synthetic snapshot or disposable database copy**. Before an edit, confirm the profile and expected counts. Do not use the original private monitor or original controlled-run evidence database. A backend/API success is recorded separately from a visible browser result.

1. **Desktop overview:** open the synthetic snapshot and inspect totals, the percent value, chart axes/legend, protocol shares, top addresses and source-specific incident counts. Compare them with that same profile's API. Confirm public synthetic/read-only wording and absence of replay/reset controls.
2. **Five views:** navigate Overview, Traffic explorer, Incidents, AI model and System health. Confirm source/destination ports, directional bytes, dates, saved priorities, benchmark limitations and receipt timestamps are readable. A private monitor must say Live Ethernet; a controlled record must identify endpoint instrumentation rather than TShark/Zeek capture.
3. **Search/filter/export:** search for a displayed value, change protocol, and exercise incident severity/status/source filters and Clear filters. While matching results load, confirm previous-query rows are not presented/exported as current. Export the loaded page and inspect its row count, origin, lineage, byte semantics and score qualifications. Keep any private export private.
4. **Investigation on a copy:** open a real stored incident, inspect its anchor and multi-flow caveat, scroll the full evidence/history, and distinguish rule conditions from historical ML heuristics. On a disposable mutable copy only, add a clearly labeled verification note and change status; reload and confirm the note, status and history persisted. The public snapshot must disable both edits.
5. **Keyboard:** use Tab/Shift+Tab without a mouse. Verify visible focus, sidebar navigation, search/filter controls, incident opening, dialog focus containment, Escape and focus return. Disabled public edits must not be actionable. Verify history/evidence can be reached by scrolling without losing the investigation.
6. **Mobile:** repeat at 390 px and 320 px widths. Open/close the mobile menu, verify focus containment/Escape, heading/banner wrapping, in-panel table scrolling and long identifiers. Check for document-wide horizontal overflow and clipped controls. Recheck the desktop layout after resizing.
7. **Loading and recovery:** in a disposable setup, stop/restart only its owned API to inspect neutral unknown-mode labels, interruption/error wording and Retry. A failed incident request must stop its loading indicator and offer Retry. Do not claim a receiving sensor from recent metadata alone.
8. **Mutable demo:** on its disposable synthetic backend only, test speed, start, pause, resume and reset. Confirm reset affects only synthetic state; do not run reset against original evidence or a public read-only profile.
9. **Genuine screenshots:** after each page visibly passes, capture only the actual rendered synthetic or controlled-loopback UI. Exclude unrelated browser tabs and all private monitor identifiers/keys. Record date, profile, viewport and check outcome with each image. Do not fabricate events or replace missing screenshots with generated images.

Record pass/fail and the observed result for each step, including an actual reproduction for any bug. The recorded browser pass above covers a defined subset of this broader checklist. Browser console checks are not claimed when console access was not performed. The remaining extended accessibility/browser matrix and container/hosting checks keep this a **v1 release candidate**, not a publicly deployed or comprehensively certified release.
