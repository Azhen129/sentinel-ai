# Local deployment and public demonstration

The project includes separate local Compose profiles for an interactive synthetic workspace and an isolated, read-only public-demo snapshot. Neither command below publishes a service on the internet. A separate Vercel synthetic-only deployment was verified on 10 November 2026: [open the demonstration](https://sentinel-ai-azhen.vercel.app) and read [the hosting, storage and verification report](public-demo-hosting.md). The local Compose instructions and their container-specific verification limits remain below.

## Local interactive demo

With an already installed and running Docker engine and Compose plugin, run from the repository root:

```sh
docker compose up --build -d
docker compose ps
```

Open [the local demo](http://127.0.0.1:8080). Nginx serves the frontend and proxies `/api` to the single backend worker; the backend has no host-port mapping. This profile explicitly disables monitor, lab, PCAP and public-demo flags. Its `sentinel-data` volume contains only this profile's state. Replay, reset, notes and status changes remain available and shared by users of this local workspace.

For local diagnostics and shutdown:

```sh
docker compose logs -f backend
docker compose down
```

`down` retains the named volume. Adding `-v` would delete it and is not part of these shutdown instructions. Keep diagnostic output private if a configuration has ever handled private data.

## Separate read-only public demonstration

Use the dedicated configuration rather than exposing the interactive workspace:

```sh
docker compose -f docker-compose.public-demo.yml config --quiet
docker compose -f docker-compose.public-demo.yml up --build -d
docker compose -f docker-compose.public-demo.yml ps
```

Open [the local read-only snapshot](http://127.0.0.1:8082). Its frontend is bound to `127.0.0.1:8082`; the backend has no host-port mapping. The configuration uses its own `public-demo-data` volume and `/app/data/public-demo.db`, with `SENTINEL_PUBLIC_DEMO=true` and monitor/lab/PCAP flags explicitly false. It mounts no host database or capture directory.

On first startup this profile creates the complete **360-record synthetic scenario** and marks its database role `public_demo`. It refuses private, unmarked and incompatible databases, including the normal demo database. It cannot enable imports or monitoring. The health/overview responses identify `public_demo=true` and both mutation capabilities as false. The UI hides replay/reset controls and disables notes/status edits; independently, the API rejects every unsafe HTTP method with **403**. The profile remains `mode=demo`, with the public-demo flag distinguishing this read-only snapshot from the interactive local workspace.

Verify `/api/health` and `/api/overview` through the frontend, confirm 360 synthetic records, and inspect the five dashboard views. Test a rejected mutation only against this isolated profile. Complete the [manual browser checks](testing.md#repeatable-manual-visual-acceptance-steps) before considering publication. To stop it while retaining its volume:

```sh
docker compose -f docker-compose.public-demo.yml down
```

Never mount private monitoring/lab databases, notes, captures, keys or metadata exports into this profile. Database-role checks are safeguards, not a sanitizer for copied files. Do not add host networking, capture devices, elevated privileges, ingestion keys or a browser capture endpoint.

## Executed verification and remaining gate

The Compose configuration passed parsing/validation. **Container builds and runtime checks were not executed:** Docker Desktop's Linux-engine named pipe was unavailable. No engine/service/security settings were changed to bypass that blocker. Python/Node tests, a production frontend build and actual loopback HTTP checks against separate disposable profile databases are recorded in [testing](testing.md) and [verification](verification.md). They do not establish that the container images start correctly.

Fresh v1 browser checks **subsequently passed after the supported in-app browser provider became available**. The 360-record public snapshot, filters, actual page-scoped CSV download, disabled public edits, model/health content, controlled-lab investigation on a copy and saved Live Ethernet display on a private copy were observed. A 390 × 844 mobile sample and navigation focus/Escape behavior were checked, and six genuine synthetic/lab screenshots were saved. The earlier tool blockers are history rather than an outstanding inability to inspect the page; see [the exact browser scope and provenance](testing.md#browser-blocker-and-screenshot-provenance). A full accessibility/multi-browser matrix is not claimed. Container smoke tests, the chosen host's actual deployment behavior and image/deployment-specific dependency review remain release gates.

## Separate services

The existing architecture is simplest to preserve with a static React build, one long-running FastAPI worker and a writable SQLite directory on persistent storage. The backend initializes and maintains database metadata even for the read-only public API; API read-only status does not make the application filesystem read-only. Keep the public database separate from every private environment.

Build the frontend inside `frontend/` using `npm ci && npm run build`; serve `frontend/dist/`. Prefer a same-origin reverse proxy for `/api`, as in the supplied Nginx configuration. If the API uses a different origin, set the frontend's `VITE_API_BASE` to its public HTTPS origin **at build time**, and set backend `SENTINEL_CORS_ORIGINS` to the exact frontend origin. No key belongs in `VITE_` configuration. Only the dedicated synthetic read-only backend is a candidate for public routing.

Run one backend worker using the host's required binding/port. The supplied container already starts Uvicorn at `0.0.0.0:8000` **inside the container**; the local Compose profile does not expose that port on the host. A future hosted service must explicitly set the public-demo flag, its dedicated writable database path, and all private ingestion/capture flags false. Do not publish a private monitoring service behind a reverse proxy: loopback/Host checks and CORS do not provide end-user authentication.

As an example of an architecture match, Render supports Python/FastAPI services and paid persistent disks. A disk is attached to one service instance, which fits this application's single-worker design but limits scaling. Free Render web services do not provide persistent disks and discard filesystem changes on restart/redeploy/spin-down; they do not provide durable SQLite state for this configuration. See the current primary [web-service](https://render.com/docs/web-services), [persistent-disk](https://render.com/docs/disks) and [free-service](https://render.com/docs/free) documentation. No account, service or paid resource was created or selected.

Vercel supports [native FastAPI deployments](https://vercel.com/docs/frameworks/backend/fastapi) and [multiple frontend/backend services](https://vercel.com/docs/services). The deployed read-only public profile now uses native FastAPI plus the unchanged React build on one origin. A build-generated synthetic SQLite snapshot is copied to isolated temporary storage per instance; it does not require persistent user-editable state. Its actual Linux build, model loading, HTTPS routes, restoration on a new deployment and browser checks are recorded in [the hosted-demo report](public-demo-hosting.md). This exception applies only to the frozen public snapshot: interactive/private workflows still require their documented local storage and single-worker behavior.

For any future hosting change, re-run HTTPS, resource, health, storage, restart, isolation and mutation-denial checks through the actual public route. Preserve the model/data licensing notices. The local launcher and hardware collection remain local-only and are never part of an internet capture service. No paid resource or portfolio update is included in the current deployment.

## Publication status

Reviewed source is published at [Azhen129/sentinel-ai](https://github.com/Azhen129/sentinel-ai), and the [separate synthetic public demo](https://sentinel-ai-azhen.vercel.app) is deployed. Deployment source came only from the separate reviewed publication workspace, with no private runtime data. Review staged files and Git history before every future publication; ignore rules alone do not prove clean contents. See [the current hosted scope](public-demo-hosting.md), [known issues](known-issues.md), [publication audit](publication-audit.md) and [security scope](../SECURITY.md).
