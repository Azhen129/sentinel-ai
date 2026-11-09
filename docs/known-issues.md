# Known issues, evidence limits and future work

This document describes the **7 November 2026 v1 release candidate**. Refer to [verification](verification.md) for dated results and [testing](testing.md) for reproducible checks. Implemented code, automated/API evidence, historical owner verification and incomplete manual work are separate evidence categories.

## Release verification still incomplete

- **Extended browser/accessibility coverage:** actual v1 browser checks passed after the supported in-app browser provider became available. They covered five public views, filters, an actual CSV download, public read-only controls, lab investigation edits on a copy, saved Live Ethernet display on a private copy, and a 390 × 844 mobile/keyboard sample. A full screen-reader/contrast audit, all keyboard paths, 320 px/all-page breakpoint coverage, multi-browser matrix, all failure/retry states and browser-console review remain unverified. See [the exact observed scope](testing.md#browser-blocker-and-screenshot-provenance).
- **Screenshot provenance:** six new genuine 7 November public-synthetic/controlled-loopback JPEGs accompany those checks. The five original 29 October synthetic-demo screenshots remain unchanged, and the owner's 1 November visual review remains distinct historical evidence. No private-monitor screenshot/export or generated/reconstructed substitute is included. The initial missing-provider/native URL-policy blockers were resolved through the supported in-app browser; they are not current blockers.
- **Docker/hosting:** Compose parsed successfully, but the Docker Linux engine was unavailable. Image build, container startup, container-specific vulnerabilities, restart/persistence and final public routing remain unverified. No remote GitHub Actions run or cloud deployment is claimed.
- **Frontend bundle:** the production build passes but reports its existing large-chunk advisory. Bundle splitting can be assessed after visual acceptance; an advisory is not a measured browser performance result.

Container/hosting verification and the broader browser/accessibility scope remain release gates. The completed browser sample establishes specific working interactions without labeling the application comprehensively audited or publicly deployed.

## Real Ethernet coverage and safe local use

The owner previously verified a physical Windows Ethernet collection with **164 accepted packets and 18 ingested flow observations**, followed by their dashboard display. The 18 records, two saved historical ML incidents and investigation history are preserved. The v1 work did not repeat a physical capture, change Npcap permissions or demonstrate continuous monitoring.

The local launcher reduces setup steps. Its default check was exercised without capture, and actual owned backend/frontend startup, proxying 18 saved records from a copy, and shutdown passed on ports 8004/5176 with a three-second socket-release grace. This service test and mocked adapter/process tests do not prove that a later hardware capture will succeed. Current driver availability, interface state, permissions, storage capacity and the selected service profile still matter. Capture requires fresh selection of a physical wired adapter and explicit opt-in for one bounded window. It stops rather than switching adapters after a disconnect. If access fails, the launcher does not elevate or change security settings; resolve the specific failure with the owner's approval.

Observations are bounded flow aggregates delivered **after** capture stops. A dashboard `receiving` status means recent metadata ingestion, not that a capture process is active. Packet/time/flow caps, packet loss, midstream starts, truncation and interface visibility can leave incomplete evidence. Header-derived Ethernet byte counters are not application payload sizes. Captured packet prefixes may contain payload fragments in local process/pipe memory even though only allowlisted metadata fields are exported. See [Windows monitoring](windows-monitoring.md) and [security](../SECURITY.md).

Monitoring storage has a default 5,000-row capacity cap. Reaching the cap stops new ingestion; it does not automatically delete evidence. There is no automated retention policy or secure-erasure guarantee. Private backups, planned rotation and an explicit owner-approved deletion policy are future operational work. Do not reset or replace an evidence database to make ingestion resume.

## Detection is evidence for review, not proven protection

Unchanged live rules review initiated TCP port fanout, connection frequency and observed outbound volume. The genuine controlled localhost experiments generated three corresponding incidents. Their authorized activity is benign: routine testing, software updates, backups or large uploads can meet review thresholds. A volume finding does not establish exfiltration, and a score/priority is not a probability of attack.

Slow or cross-window probing, UDP/midstream scans, low-volume malicious traffic, application intent, authentication failures and encrypted content are outside the demonstrated coverage. The pipeline has no genuine authentication-event source. No failed-login or payload-inspection claim follows from connection metadata.

The seven controlled scenarios used owned loopback application sockets with application-byte instrumentation. Their DNS-format, unicast discovery-format and router-role exchanges did not contact a household router, exercise physical multicast or measure Ethernet capture counters. The normal HTTPS case used a real local TLS exchange with a disposable trust anchor. These tests demonstrate those scenario conditions; they are not real-network false-positive rates, comprehensive missed-detection evaluation or packet-collector coverage. See [controlled test details](testing.md#genuine-controlled-localhost-scenarios).

## Historical ML remains informational

The preserved Isolation Forest is a KDD99 research baseline. Its original held-out benchmark results concern that historical dataset, not current Windows Ethernet performance. Packet-derived features, categorical states, byte semantics and collection windows differ from that training domain. There is no representative labeled live dataset or reliable operational ground truth here from which to report accuracy, precision, recall or F1.

No model was retrained on the 18 observations, no threshold was changed to manufacture alerts, and historical incidents were not rewritten. The live UI qualifies the historical score as informational and distinguishes saved findings from current rule evidence. When an old incident lacks a persisted threshold, the displayed comparison is a preserved-baseline reference rather than a recovered historical decision. Six-decimal scores cannot recover lost full precision. A dedicated live model needs representative collection, consent/privacy handling, independent labels, separate evaluation and drift/false-positive analysis before deployment is scientifically justified. See the [model card](../models/model_card.md) and [live policy](live-detection.md).

## Local security and public-demo scope

Private monitor/lab profiles require loopback peers and literal loopback Host headers; unsafe browser requests also require an allowed local Origin. Keys protect monitoring ingestion/status and authorized import paths. **Private telemetry reads and local incident notes/status changes do not have per-user login or API-key authorization.** Another authorized local process/user may be able to read or edit them. CORS and loopback checks are not a multi-user security system. Do not put a private profile behind a public reverse proxy.

The isolated public profile contains only a frozen 360-record synthetic snapshot in its dedicated `public_demo` database. It rejects mutation requests and forbids monitoring/lab/PCAP modes. It has no public hardware-capture workflow. Ordinary local Demo Mode remains interactive with shared notes/replay state. An external authenticated multi-user SOC, remote sensors, centralized authorization and production operations are future features, not existing capabilities.

Dependency checks reflect the exact reviewed versions and advisory data at the time of the audit; they do not prove absence of unknown vulnerabilities or validate unbuilt operating-system container packages. Joblib deserialization requires trusted artifacts; the included hash checks are not signatures for arbitrary downloaded models. Keep third-party/dataset notices alongside source and distribution artifacts.

## Laptop visibility and whole-home monitoring

A normal switched Ethernet connection observes traffic visible to this laptop's interface. It does not give the application visibility into all other devices' unicast traffic. The examined GPON ONU router exposed basic device/current-speed controls; detailed security-event or traffic export was not verified. Its current UI is not an implemented Sentinel data source.

Whole-home monitoring would need an **authorized** observation point such as a supported switch mirror port, a network TAP, a gateway/router with suitable flow/log export, or a dedicated routed sensor. Hardware compatibility, throughput, packet loss, encrypted-traffic limits, placement, representative baselines, household consent and retention must be assessed. Each source also needs a bounded collector/normalization path, trustworthy timestamps/provenance and secure access controls. Passive monitoring still does not block threats. No router change, household scan or new whole-home protection claim was made during this release preparation.

## Future improvements after acceptance

Complete the remaining accessibility/browser matrix and validate the synthetic-only container profile plus a chosen host's storage/restart behavior. Later work may add clearer retention/rotation tooling, representative labeled live datasets, source-specific sensor adapters, measured frontend performance improvements and authenticated multi-user access. Each needs its own design and verification; none is implied by this release candidate.
