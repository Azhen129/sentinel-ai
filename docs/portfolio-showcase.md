# Sentinel AI — portfolio showcase draft

**Intelligent network threat detection and security analytics.** A full-stack security application that turns connection records into explainable rule and machine-learning alerts, with a synthetic traffic replay and an incident investigation workflow.

## Demonstrable features

- Start, pause and reset a synthetic traffic replay without network access or privileged capture.
- Inspect connection metadata, traffic trends, protocols and top communicating devices.
- Distinguish correlation rules from Isolation Forest anomaly alerts and inspect their contributing indicators.
- Filter incidents, update investigation status and maintain persistent notes and history in SQLite.
- Review the trained model's actual evaluation report and its limitations.
- Opt into authorized lab ingestion of existing Zeek logs; optional PCAP conversion requires tshark.

**Stack:** Python, FastAPI, SQLite, scikit-learn, pandas, NumPy, React, TypeScript, Vite, Tailwind CSS, Recharts, Docker Compose and pytest.

Use the actual dashboard screenshots in `docs/screenshots/` and the measured results in `models/metrics.json`. Avoid claims of production detection performance. This is an educational prototype evaluated on a historical benchmark.

**GitHub:** unpublished — add the real repository URL after approval and publication.

**Live demo:** not deployed — add the real deployed URL after approval and testing.

Suggested portfolio card:

> Sentinel AI combines network telemetry, explainable detection rules and unsupervised anomaly detection in an interactive SOC console. Its isolated replay demonstrates an end-to-end investigation, while a separate opt-in lab mode reads Zeek logs. Model quality is reported with reproducible, measured evaluation results.

The existing azhen-portfolio repository has not been modified. This file is prepared content for a later approved portfolio update.
