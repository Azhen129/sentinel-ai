# Live metadata detection: policy and evaluation

Updated 1 November 2026. Sentinel AI preserves its existing KDD99 Isolation Forest as a reproducible historical baseline. **Its live scores are informational and do not create new live ML incidents.** New live findings come from the explicitly documented rules below. Demo and file-import Lab retain their original model/rule behavior. No model was retrained, threshold adjusted, destination whitelisted, or historical incident removed.

This policy makes the evidence boundary clearer; it does not establish effective protection or improved operational accuracy. See [verification](verification.md), [Windows setup](windows-monitoring.md) and [security](../SECURITY.md).

## Why the historical model needs a separate live policy

The saved model uses three log-transformed numeric values (duration, sent bytes and received bytes) and one-hot protocol, service and state categories. Addresses, ports, local gateway identity, process identity, packet count and initiator role do not enter that model. It cannot recognize router or discovery activity from those omitted fields.

The live collector measures partial flow windows from the laptop's perspective. Its observed transport flags do not establish KDD connection outcomes, its durations are lower bounds, and its header-derived lengths include retransmissions. Unknown service is mapped by the unchanged legacy preprocessing to the trained `other` category. The existing HTTPS-to-HTTP approximation also cannot validate modern encrypted applications. These differences are structural, not fixed by silently substituting a successful state or a convenient service name.

With `OneHotEncoder(handle_unknown='ignore')`, an unseen state becomes an all-zero state block; that is not a trained unknown-state category or a fixed numerical anomaly penalty. A record can cross the forest threshold while each numeric input is inside its individual benign percentile range. Category-absence and percentile messages describe compatibility/ranges; they are **not computed causal feature attributions**. The actual historical numerical decision compares the forest score to its saved threshold. See the [encoder documentation](https://scikit-learn.org/1.6/modules/generated/sklearn.preprocessing.OneHotEncoder.html) and [Isolation Forest documentation](https://scikit-learn.org/1.6/modules/generated/sklearn.ensemble.IsolationForest.html).

Changing one input while holding the others fixed measures model sensitivity to that reference substitution. Such contrasts are not unique additive contributions, explanations of malicious intent, or permission to alter captured records. The original benchmark describes full connection durations, source/destination byte measurements and outcome flags; see the [KDD task and feature definitions](https://kdd.ics.uci.edu/databases/kddcup99/task.html).

## Evidence and context

| Observation | Displayed interpretation | What remains unknown |
|---|---|---|
| UDP/1900, especially multicast | Possible SSDP-related discovery | Message type, application, intent and legitimacy |
| TCP or UDP/53 | Possible DNS | Query names, response outcome, resolver role and tunneling intent |
| Conventional DHCP ports | Possible DHCP | Actual DHCP message, lease and configuration outcome |
| UDP/5353 or UDP/5355 | Possible mDNS or LLMNR | Message validity, owning process and expected local behavior |
| TCP/443 or UDP/443 | Possible TLS/HTTPS or QUIC/HTTPS | Encryption, application identity, content and software-update purpose |
| Private peer | RFC1918/ULA address context | Ownership, trust and whether the peer is a router |
| Large outbound length counters | Volume reached a fixed review threshold | Whether this was a legitimate upload, retransmission-heavy activity or exfiltration |

These hints do not exempt a peer or protocol from detection. Normal-looking DNS, multicast and private-peer observations can still trigger volume review. Conversely, an uncommon port or private address alone does not establish a threat. The [IANA port registry](https://www.iana.org/assignments/service-names-port-numbers/) cautions that use of a registered port neither verifies the application nor establishes good traffic. Local name-resolution and address-configuration protocols are documented in [mDNS RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html) and [DHCP RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html).

No authentication-event ingestion path was added. Ordinary TCP records, resets or missing responses never become failed-login evidence in the live rules. Encrypted attacks, malicious software identity, DNS content abuse and transfer intent need independent evidence not collected by this metadata path.

## Implemented live rules

Rules operate on unique flow identifiers within **one collection, local source and peer**. The counters do not merge unrelated manual collections: their overlap/gaps and repeated session observations cannot be reconciled reliably. Fixed thresholds are engineering review policies, not learned or operationally calibrated threat boundaries.

| Rule | Required observed condition | Review priority |
|---|---|---|
| Port scan indicators | At least eight distinct destination ports on one peer within 60 seconds, with observed local TCP initiation | High |
| Burst of initiated TCP flows | At least 25 unique locally initiated TCP flow observations to one peer within 60 seconds | Medium |
| Large outbound observation | At least 5,000,000 outbound length-counter bytes in one bounded flow observation, or across whole flow intervals contained within 60 seconds to one peer | Medium |

The burst finding is omitted when the same evidence already forms a port sweep. A 60-second per-rule/source/peer/collection cooldown reduces duplicate findings. SQLite's existing five-minute incident correlation and persistent batch/flow deduplication remain in place. Saved evidence includes collection and contributing flow identifiers, with truncation disclosed when necessary. An incident's linked connection is an anchor; aggregate rule evidence can include other observations.

The volume rule never spreads a long flow's counters uniformly across a shorter interval. A single 90-second, above-threshold observation can be reviewed as a 90-second observation, without calling it a 60-second rate. Legitimate backups/uploads can trigger this rule. Severity is triage priority, not probability, verified maliciousness or authentication-failure confidence.

State is bounded to 5,000 event entries, with at most 1,024 per peer window. Capture and storage limits still apply. Slow or cross-collection scans, UDP probing and role-unknown/midstream probing can be missed. Large inbound downloads are not outbound-volume findings, but low-volume misuse may be indistinguishable from ordinary traffic. Behavioral novelty and unusual-destination claims are deferred until a representative local baseline and independent evaluation exist.

## Saved records and explanations

Existing scores, alert flags, incident severity/status, indicators, notes and history are retained. An old benchmark incident remains a saved historical incident; it is not automatically resolved or deleted because current policy changed. Therefore the initial private dataset can still show its two original findings and saved finding percentage.

API reads attach protocol context and a compatibility assessment without re-scoring or backfilling old rows. Old records did not store a per-record threshold, so their view explicitly labels the preserved model's current threshold as a **reference**, not an invented historical field. New live ingests store score, threshold and model-version provenance in the connection's JSON payload; no SQLite schema migration is needed.

The ordinary prediction API reports six-decimal scores. Assessment compares that reported number with the threshold and discloses rounding ambiguity near the boundary; it does not reconstruct an unknown original full-precision decision. Scores are not attack probabilities.

An incident detail view separates saved indicators from current assessment, distinguishes rule trigger conditions from model heuristics, shows its actual linked connection and observation limits, and suggests additional host/process or application evidence. It does not infer router ownership or software identity from a port/address.

## Executed comparison and its limits

The offline regression set contains **27 deliberately constructed metadata scenarios** with author-assigned scenario-intent labels: 15 intended-benign and 12 review-worthy scenarios. It includes routine service-port activity, uploads/downloads, local discovery, probing, bursts, volume aggregation and known blind spots. It is not an independent sample of network attacks. No new model is fitted, calibrated or tuned on these cases or on the private observations; no train/validation/test generalization claim is made.

| Constructed-scenario result | Original live policy | New live policy |
|---|---:|---:|
| True positives | 8 | 8 |
| False positives | 8 | 2 |
| True negatives | 7 | 13 |
| False negatives | 4 | 4 |
| Precision | 50.0% | 80.0% |
| Recall | 66.7% | 66.7% |
| F1 | 57.1% | 72.7% |
| False-positive rate | 53.3% | 13.3% |

These exact fixture-only numbers are engineering diagnostics, **not estimates of laptop accuracy**. The remaining nuisance cases are legitimate parallel HTTPS-like connections and a large intended-benign backup. One constructed UDP probing case that the old benchmark model happened to flag is missed by the new policy; a split outbound transfer previously missed is now caught. Equal aggregate recall hides that coverage change. Low-volume intent examples deliberately have identical observable metadata despite opposite scenario labels, exposing an unavoidable information gap.

In one local run, median per-record model-plus-policy computation was about 7.01 ms before and 7.07 ms after; p95 was about 7.82/8.20 ms. Timings exclude collection, API, storage and browser work. The collector delivers metadata after a bounded window, so this is not end-to-end detection latency.

An additional exercise used eight successful connections to owned disposable **127.0.0.1** listeners and a hash-verified 6,000,000-byte dummy loopback transfer. The corresponding probing and outbound-volume patterns were detected. That exercise used application endpoint instrumentation, not Npcap/header measurements or an Ethernet capture. Genuine authentication failures were not exercised because no suitable authentication-event path exists. No public targets, router or household device were involved.

## Run the upgraded application without another capture

In the **existing monitoring-backend terminal**, stop only that backend with Ctrl+C. Preserve its process environment and current private key. From the existing repository root, check the profile and restart:

```powershell
if ($env:SENTINEL_MONITOR_MODE -ne 'true') { throw 'Use the existing monitoring terminal/profile.' }
if ($env:SENTINEL_DB_PATH -ne 'data/monitoring/windows-monitor.db') { throw 'Confirm the existing dedicated monitor database path before proceeding.' }
if ([string]::IsNullOrWhiteSpace($env:SENTINEL_API_KEY)) { throw 'The current private monitoring key is missing; recover it locally rather than replace it blindly.' }
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8004
```

In the existing frontend terminal, Ctrl+C stops only Vite. From the repository root:

```powershell
cd frontend
$env:VITE_API_BASE = ''
$env:VITE_API_PROXY_TARGET = 'http://127.0.0.1:8004'
npm run dev -- --host 127.0.0.1 --port 5176 --strictPort
```

Open [Traffic Explorer](http://127.0.0.1:5176/#traffic). Its existing stored flows remain available. Open each historical incident to review the saved score and new assessment. No collector, new key, replay/reset or database replacement is needed. The API's `live_detection_policy.version` must be `live-metadata-v1` after restart. See [the Windows guide](windows-monitoring.md) for first-time setup and separately authorized optional future collection.

From a separate normal PowerShell, inspect only counts/policy without displaying rows or a key:

```powershell
$overview = Invoke-RestMethod 'http://127.0.0.1:8004/api/overview'
$overview | Select-Object mode, total_connections, data_sources, live_detection_policy | ConvertTo-Json -Depth 5
(Invoke-RestMethod 'http://127.0.0.1:5176/api/connections?limit=1').total
```

For offline verification from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/evaluate_detection.py --output data/evaluation/live-policy-v1.json
cd frontend
node --experimental-strip-types --test tests/presentation.test.mjs
npm run build
```

Choose a new evaluation output filename for repeat runs; the script refuses to overwrite an existing report. It constructs its own cases, does not open a private database, does not contact the API, performs no capture/network activity, and never trains a model. Reports under `data/evaluation/` are ignored by Git.

## Requirements before a dedicated live model

A defensible next model needs representative, explicitly authorized benign observations across independent days, application activity and collection sessions, including updates, discovery, DNS, uploads/downloads and local services. Record missingness, initiator evidence, collection boundaries and length-counter semantics explicitly. Do not derive benign labels from the existing model's decisions or from a router/multicast whitelist.

Define the intended observation unit before fitting. Keep overlapping windows and the same underlying sessions in one split, use time/host/session groups where available, fit preprocessing on training data only, set an alert-budget threshold once using separate validation data, and evaluate on untouched labeled test data. Document contamination, sampling gaps, class imbalance, confidence intervals and failures. A few local probing/transfer examples are not a representative attack test set. Until those prerequisites exist, live accuracy remains unverified and no dedicated live model is trained automatically.
