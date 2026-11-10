# Public synthetic demonstration

Live URL: **[sentinel-ai-azhen.vercel.app](https://sentinel-ai-azhen.vercel.app)**

Sentinel AI is an educational and research-oriented security monitoring project, not a validated production intrusion prevention system. This hosted application displays generated demonstration records; it does not monitor a visitor's network or provide live protection.

## Hosting and cost

The demonstration uses one Vercel project on the owner's existing **Hobby** plan, confirmed before resource creation. The existing React production build is served through Vercel's CDN, and the existing FastAPI application runs as a Python 3.12 Function in Frankfurt. The frontend uses relative `/api` URLs, so no external API origin, browser secret or CORS workaround is required. Node.js 22 builds the unchanged frontend.

No paid plan, persistent disk, database service, domain purchase or paid add-on was provisioned. The free `vercel.app` subdomain is assigned to this project. Hobby is intended for personal, noncommercial projects; included usage limits and availability restrictions apply. The console polls the API every two seconds and API responses use `Cache-Control: no-store`, so open tabs consume Function requests. This deployment is suitable for a modest personal demonstration, with no availability SLA.

See Vercel's current [Hobby plan](https://vercel.com/docs/plans/hobby), [FastAPI support](https://vercel.com/docs/frameworks/backend/fastapi), [Python runtime](https://vercel.com/docs/functions/runtimes/python), and [Function limits](https://vercel.com/docs/functions/limitations). Check the connected account's usage before increasing traffic or changing plans; any paid upgrade requires the owner's approval.

## SQLite and restart behavior

`deployment/build.py` builds the frontend and calls `generate_snapshot()` in a fresh source checkout. It uses the existing `Runtime`, synthetic generator, detection rules and approved Isolation Forest. It never accepts an existing runtime database as input. An existing output database or manifest causes the build to fail rather than overwrite or reuse it.

The generated `deployment/generated/public-demo.sqlite` contains **360 synthetic connections** and, with the current model, **56 synthetic incidents**: 17 rule incidents and 39 model anomalies. A manifest records its SHA-256, model hash, counts, role and synthetic generator provenance. Both files are build artifacts excluded from Git and source uploads. SQLite integrity, the `public_demo` role, complete record count, simulation completion, demo-only origins and absence of monitor tables are validated.

`deployment/public_app.py` verifies the bundled snapshot and matching loaded model, then copies the snapshot to a newly created private temporary directory. The original application initializes its normal SQLite/WAL metadata against this writable copy. Every instance starts from the same bundled snapshot, preserving connection records and incident IDs across cold instances within one deployment. The bundled copy remains unchanged.

Vercel temporary storage is ephemeral and is not a persistent or shared database. A cold instance restores the frozen build snapshot. A new deployment builds another complete synthetic snapshot; its timestamps, history creation times and incident IDs can change. There are no accepted user writes to preserve. The public demonstration does not use local monitoring, lab or interactive-demo storage.

## Safety boundaries

The deployment entrypoint explicitly passes:

```python
create_app(
    dedicated_temporary_database,
    public_demo=True,
    monitor_mode=False,
    lab_mode=False,
    pcap_enabled=False,
    api_key="",
    seed=False,
    detector=approved_matching_detector,
)
```

Environment variables cannot select a private database or enable another profile through this entrypoint. No monitoring or ingestion key is required or configured. No Npcap driver, capture device, router integration, elevated privilege, monitoring database or captured traffic is uploaded. The deployment API upload used an explicit source-file allowlist from the separate reviewed publication workspace.

The existing public-profile middleware rejects unsafe methods before routing, including import, replay, reset, notes and status changes. Monitor status is inaccessible. React hides replay/reset actions and disables investigation edits, while independent API checks enforce the same boundary. The API has no capture-start endpoint.

Only `frontend/dist` is registered with `app.frontend()`. Explicit CDN promotion applies to these public, credential-free static assets; application middleware still governs API requests. `fallback=None` preserves genuine API 404 responses, including requests accepting HTML. Database files, model artifacts, Python source and environment files are not served as static assets. MIT and third-party notices remain publicly available.

The original local application and its default entrypoint are unchanged. Local interactive Demo Mode, local lab workflows and explicitly opted-in local Windows monitoring retain their existing instructions and separate databases. They must never be substituted into this hosting entrypoint.

## Executed verification

Verification date: **10 November 2026**. These results describe the tested deployment and do not establish production detection performance.

| Check | Observed result |
|---|---|
| Hosted Linux build | Python 3.12, pinned model/dependencies, Node 22, TypeScript and Vite build succeeded. The unchanged frontend output retained its existing 629.63 kB JavaScript chunk advisory. |
| First HTTPS acceptance run | 33 checks passed against the initial production deployment; 360 connections and 56 incidents. First measured health request took 1.110 seconds. |
| Fresh production deployment | A second build and deployment completed. All 33 HTTPS checks passed on the final public URL, again with 360 connections and 56 incidents. First measured health request took 1.016 seconds. These samples are not a latency guarantee. |
| Actual API functionality | Health, overview, all 360 connection records, protocol filtering, empty search, incident list and linked detail/history, model report and system status returned actual FastAPI/SQLite responses. |
| Read-only enforcement | Eight POST/PATCH/PUT/DELETE attempts covering imports, replay/reset and incident edits returned 403; monitor status returned 403. Counts remained 360. |
| Private/static exposure | Explicit environment-file, database, model and Python-source URLs returned 404. Unknown API paths returned 404 for JSON and HTML requests. MIT and dependency notices were served successfully. |
| Desktop browser | All five pages loaded with API connected, populated charts/tables, model metrics and system status. Public investigation status, note entry and Add note were disabled. |
| CSV export | Actual browser download contained 50 displayed UDP records, all with `origin=demo`; export remains page-scoped. |
| Mobile browser | Overview and model views inspected at 390 × 844; model and traffic layouts also checked at 320 pixels. No document-wide overflow; wide traffic tables scroll inside their container. Navigation opened, changed pages and closed with Escape. |
| Fresh-instance unit checks | Two independent temporary databases retained identical connection rows and incident IDs. Private environment overrides, corrupted hashes, live/lab origins, missing roles, incomplete counts, monitor tables and unavailable/mismatched model states were rejected. |
| Local new tests | Ten public-deployment pytest checks passed. The remaining TestClient transport test could not run in this Windows sandbox because socketpair initialization timed out before application startup. It remains in CI, alongside the original tests and a Python 3.12 Linux job. Actual hosted HTTPS tests passed separately. |

The provider accepted and optimized the Python dependency bundle. Its build log reported 285.16 MB before dependency optimization; no paid build-machine or larger-memory option was enabled. This is not a container deployment: the older Docker-engine blocker and unexecuted container image checks remain documented in the local deployment guide.

A fresh deployment verifies restoration in a new runtime, and unit checks verify independent copies of the same bundled snapshot. No forced infrastructure crash, extended cold-idle soak, load test, independent penetration test, full accessibility audit or multi-browser matrix is claimed. Cold starts and free-plan quota exhaustion can affect availability.

## Reproduce safely

Use a clean checkout containing reviewed public source only. Do not deploy the owner's working directory, mount a private volume, upload a local database or pull private environment files into a source archive.

1. Run the repository's Python tests and frontend checks using the documented dependencies. The CI workflow additionally tests Python 3.12 on Ubuntu for the hosting runtime.
2. Select a free Hobby project, Python 3.12/FastAPI, Node.js 22 and the repository root. Leave private monitoring/ingestion environment variables unset. Use `pyproject.toml`, `vercel.json` and the existing lockfile; do not change the local default entrypoint to enable public exposure.
3. Build from fresh source. The build command generates its own synthetic snapshot and refuses pre-existing database artifacts. Keep `.vercelignore` and the Function exclusions in place.
4. Deploy with Vercel's authenticated CLI or connected API to the intended project. Do not enable a paid resource or upgrade without approval. This release was uploaded through the connected API; Git-triggered deployments were not configured.
5. Before updating links, verify actual HTTPS health flags, 360 demo-only records, model availability, filtered queries, read-only 403 responses, private-file 404s, all five pages, mobile navigation and a fresh deployment. Never test capture or private ingestion through a public host.

To take the public demonstration offline, use this project's Vercel deployment controls. There is no packet-capture session to stop. Existing private local services are independent of this hosted project.
