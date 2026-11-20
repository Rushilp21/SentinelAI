# SentinelAI

**SentinelAI is an agentic, safety-first Dynamic Application Security Testing (DAST) prototype for a B2B travel-booking platform.** It pairs a security operations dashboard with TravelCore, a deliberately vulnerable demo application, to demonstrate how bounded security tests can discover, verify, explain, and retest application flaws.

The project is designed for local demos and experimentation. It uses synthetic users and records, targets only the local TravelCore application, and does not contact a third-party LLM provider.

## Features

- **Security operations dashboard** for application health, scans, findings, events, API inventory, attack chains, authorization intelligence, and change impact.
- **Three repeatable security scenarios:** cross-agency insecure direct object reference (IDOR), client-controlled fare tampering, and duplicate refund processing.
- **Independent verification** that checks application responses or persisted demo ledger records before a finding is recorded.
- **Retesting workflow** that can resolve a finding after a secure behavior is independently verified.
- **TravelCore demo environment** with synthetic flights, bookings, payments, refunds, agencies, and role-based users.
- **Fix suggestions** with remediation guidance and regression assertions.
- **React and Vite frontend** with navigation across SentinelAI and TravelCore screens.
- **FastAPI backend** with SQLite for local runs and PostgreSQL support through Docker Compose.
- **Netlify-ready static frontend build** for previewing the UI without hosting the backend.

## USPs

- **Safety constraints are part of the test runner.** Scans accept named scenarios and fixed local routes, use synthetic principals, and apply request limits and short timeouts.
- **Findings are evidence-backed.** The prototype checks the response or demo ledger independently before it records a vulnerability.
- **Security results include business context.** Endpoint findings connect to roles, travel workflows, change impact, and suggested regression checks.
- **The demo runs locally.** SQLite avoids the need for Docker for the backend; Docker Compose is available when a PostgreSQL environment is preferred.
- **The agent stays constrained.** LangGraph is used for the planning node when installed, with a deterministic local fallback. The planner cannot bypass the target safety gate.

## Folder structure

```text
SentinelAI/
├── backend/
│   ├── app/
│   │   ├── agents/             # Constrained scan planning
│   │   ├── static/             # Bundled fallback interface
│   │   └── main.py             # FastAPI API, models, safety gate, and demo logic
│   ├── tests/                  # Workflow and HTTP smoke checks
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # React application and routes
│   │   ├── main.jsx            # React entry point
│   │   └── styles.css          # Application styles
│   ├── Dockerfile
│   ├── nginx.conf              # Compose frontend and API proxy
│   ├── package.json
│   └── vite.config.js          # Development server and API proxy
├── .env.example                # Local configuration template
├── docker-compose.yml          # PostgreSQL, backend, and frontend services
├── netlify.toml                # Netlify build and SPA routing settings
└── README.md
```

## Technology stack

| Layer | Technologies |
|---|---|
| Frontend | React, Vite, React Router, Recharts, Lucide, Tailwind CSS |
| Backend | Python, FastAPI, SQLAlchemy, Pydantic, HTTPX |
| Database | SQLite locally; PostgreSQL with Docker Compose |
| Agent planning | LangGraph when available; deterministic local fallback |
| Hosting | Netlify for the static frontend; backend hosting is separate |

## Run locally

### 1. Start the backend

From the project root, install the Python dependencies and start FastAPI:

```powershell
python -m pip install -r backend/requirements.txt
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

The local database is `backend/sentinelai.db`. The application creates the schema and seeds synthetic demo data on startup.

### 2. Start the React frontend

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open **http://127.0.0.1:5173/**. The Vite development server proxies `/api` to FastAPI on port `8000`. On localhost, the frontend automatically opens a demo session using the seeded admin account; this convenience is restricted to local preview hosts.

The API documentation is available at **http://127.0.0.1:8000/docs**.

### Demo accounts

All seeded accounts use the password **`Sentinel123!`**.

| Agency | Role | Email |
|---|---|---|
| Northstar Travel | Agency Admin | `admin@northstar.demo` |
| Northstar Travel | Booking Agent | `agent@northstar.demo` |
| Meridian Journeys | Agency Admin | `admin@meridian.demo` |
| Meridian Journeys | Booking Agent | `agent@meridian.demo` |

These credentials are for the synthetic local demo only. Do not reuse them for real services.

## Run with Docker Compose

With Docker Desktop installed and running:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open **http://localhost:8080/**. Compose starts PostgreSQL, FastAPI, and the React frontend behind Nginx. To stop the services, run:

```powershell
docker compose down
```

To also remove the disposable PostgreSQL demo database volume, run `docker compose down -v`.

## Demonstrate a vulnerability workflow

1. Open **Demo lab** in SentinelAI.
2. Switch one scenario to vulnerable.
3. Select **Deploy change** to record a demo application version and change-impact event.
4. Select **Run scan**. The runner exercises the selected fixed local route with a synthetic user.
5. Review the evidence-backed finding and the suggested remediation.
6. Switch the same scenario to secure and run the retest. An independently verified secure result resolves the finding.

The refund scenario creates a synthetic booking, cancels it, submits duplicate refunds, and checks ledger entries. The fare scenario compares a tampered fare against the server-defined fare. The IDOR scenario compares access to a user's own booking with a known booking from another demo agency.

**Reset** restores the scenarios to their secure baseline and removes scan-created findings and synthetic bookings. It retains the seeded accounts, bookings, endpoint catalogue, audit history, events, and deployment history.

## Safety and scope

- The proof runner accepts only the built-in `idor`, `fare`, and `refund` scenarios and fixed local routes.
- Requests use synthetic accounts and are bounded by a short timeout and a request-rate limit.
- Arbitrary external URLs, non-synthetic accounts, bulk extraction, and destructive operations are outside the scanner's allowed scope.
- The agent planner cannot override the host allowlist or request controls in `backend/app/main.py`.
- The application is a hackathon prototype, not a production DAST service.

## API and configuration

Key API routes include `/api/dashboard`, `/api/endpoints`, `/api/deployments`, `/api/scans`, `/api/findings`, `/api/authorization-intelligence`, `/api/change-impact`, `/api/retests`, `/api/audit-logs`, `/api/demo`, and `/api/travel`.

The API schema is available at **`/openapi.json`** and the interactive API explorer at **`/docs`**.

Backend configuration uses `DATABASE_URL`, `APP_SECRET`, `CORS_ORIGINS`, and the optional `LLM_API_KEY` signal. No LLM provider is called by this prototype. For a hosted API, set the frontend build variable `VITE_API_BASE_URL` to the API base URL and configure the backend's CORS origins for the frontend domain.

Netlify builds the frontend from `frontend` with `npm run build` and publishes `dist`. The frontend can be deployed on its own for a public UI preview; API-backed features need the separately hosted backend.

## Tests

Run the backend workflow smoke test from the project root:

```powershell
python backend/tests/smoke_workflows.py
```

It exercises authentication and role boundaries, vulnerable and secure proof pairs, retest resolution, audit events, the served interface, and report formats. An HTTP smoke check is also available at `backend/tests/http_smoke.py`.

Build the frontend production bundle with:

```powershell
cd frontend
npm ci
npm run build
```
