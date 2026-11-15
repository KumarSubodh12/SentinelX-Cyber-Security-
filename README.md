# SentinelX

AI-powered security monitoring (SIEM) for real, live log data.

A small agent on each server reads SSH logins, web server logs, firewall logs and Windows security events and sends them to SentinelX. The backend turns them into a common format, runs 16 detection rules and an anomaly model, scores each alert, groups related alerts into incidents, and pushes everything to the dashboard in real time.

```
 Linux / Windows servers                      SentinelX server
┌──────────────────────┐  HTTPS + API key   ┌───────────────────────────────────────────┐
│ sentinelx_agent      │ ─────────────────▶ │ FastAPI  /api/ingest                      │
│  auth.log / journald │                    │   normalise → de-duplicate → store        │
│  nginx / Apache logs │                    │   16 rules + Isolation Forest + intel     │
│  UFW / iptables      │                    │   risk score → alerts → incidents         │
│  Windows Security    │                    │ PostgreSQL        WebSocket /ws           │
└──────────────────────┘                    └──────────────┬────────────────────────────┘
                                                           │ live updates
                                                  ┌────────▼─────────┐
                                                  │ Next.js dashboard │
                                                  └───────────────────┘
```

## What is in this folder

| Folder / file | What it is |
|---|---|
| `backend/` | FastAPI API, detection engine, anomaly model, tests |
| `frontend/` | Next.js 14 dashboard (TypeScript, Tailwind, Recharts) |
| `agent/` | Log collection agent for Linux and Windows, installers, tests |
| `docker-compose.yml` | Everything on your computer with Docker (PostgreSQL + API + web) |
| `docker-compose.prod.yml` + `deploy/Caddyfile` | Production on one server, automatic HTTPS |
| `render.yaml` | One-click blueprint for Render |
| `.env.example` | Every setting, with comments |
| `.vscode/`, `sentinelx.code-workspace` | VS Code tasks, debug configurations, recommended extensions |

## Run it in VS Code (no Docker)

You need Python 3.11 or newer and Node.js 20 or newer.

1. Open `sentinelx.code-workspace` in VS Code. Accept the recommended extensions.
2. Copy the settings file: `cp .env.example .env` (on Windows: `copy .env.example .env`). The defaults work for local use with SQLite.
3. Terminal > Run Task > **backend: install**, then **frontend: install**. Do this once.
4. Terminal > Run Task > **dev: backend + frontend**.
5. Open <http://localhost:3000> and sign in with `FIRST_ADMIN_USERNAME` and `FIRST_ADMIN_PASSWORD` from `.env` (default `admin` / `ChangeMe-Now-123!`).

Press **F5** to debug instead: choose *Full stack (backend + frontend)*. API docs are at <http://localhost:8000/api/docs>.

Without VS Code tasks, the same steps from a terminal:

```bash
cp .env.example .env

cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload --port 8000      # leave running

cd ../frontend                                           # new terminal
npm install && npm run dev
```

## Run it with Docker

```bash
cp .env.example .env        # set POSTGRES_PASSWORD (letters and digits only)
docker compose up --build
```

Open <http://localhost:3000>. Data is kept in Docker volumes between restarts. Build once with an internet connection: the dashboard downloads its fonts during the build.

## Real data and simulated data

SentinelX keeps them apart on purpose. Every event, alert and incident carries an origin, and the switch at the top of the dashboard (All data, Real, Simulated) filters every page.

- **Real** data comes from agents (and from SentinelX's own sign-in events).
- **Simulated** data comes from the built-in attack simulator (Settings > Simulator, or "Run demo simulation" on an empty dashboard). It uses reserved documentation IP addresses, is labelled **SIM** everywhere, never feeds the real detection history, and can be removed with one click.

Set `ENABLE_SIMULATOR=false` when you only want real data.

## Connect real systems

1. In the dashboard open **Settings > Agents**, enter a name (for example `web-01`) and choose **Create agent**.
2. Copy the API key. It is shown once; only a hash is stored. Install commands with your key filled in appear next to it.
3. On the machine you want to monitor, copy the `agent/` folder and run the command shown.

**Linux** (needs Python 3 with `venv`, for example `apt install python3-venv`):

```bash
cd agent
sudo ./install/install-linux.sh https://your-sentinelx-address sx_your_agent_key
journalctl -u sentinelx-agent -f
```

**Windows** (Administrator PowerShell, Python 3.9+ on PATH):

```powershell
cd agent
.\install\install-windows.ps1 -Url https://your-sentinelx-address -ApiKey sx_your_agent_key
```

The agent starts at the end of each log, survives log rotation and restarts without sending duplicates, retries when the server is unreachable and keeps unsent events in a small on-disk queue. It refuses plain HTTP except to `localhost`.

What it collects by default: SSH and sudo activity and new accounts (`/var/log/auth.log`, `/var/log/secure` or the systemd journal) and the Windows Security log. Add web and firewall logs in `/etc/sentinelx-agent/agent.env` (Windows: `C:\ProgramData\SentinelXAgent\agent.env`):

```
WEB_ACCESS_LOGS=/var/log/nginx/access.log
FIREWALL_LOGS=/var/log/ufw.log
```

then `sudo systemctl restart sentinelx-agent`. Every option is documented in `agent/agent.env.example`. To check a connection without installing anything: `cd agent && pip install -r requirements.txt && SENTINELX_URL=... SENTINELX_API_KEY=... python -m sentinelx_agent --check`.

A new agent shows as **Online** on the Agents tab within about 30 seconds, and its events appear on **Live events**.

## What it detects

- **Accounts:** brute force, password spraying, distributed attacks on one account, a successful login after many failures, off-hours logins, account lockouts, new accounts, privileged group changes, cleared audit logs.
- **Web:** scanners and probing, SQL injection, path traversal, command injection, XSS, requests for sensitive files, abnormal request rates.
- **Network:** port scans, bursts of blocked connections, access violations.
- **Threat intelligence:** known-bad IP addresses from your blocklists and from AbuseIPDB (optional).
- **Anomaly model:** an Isolation Forest learns normal activity per IP and user in 5-minute windows and flags large departures. It trains on its own from your real data (after at least 200 samples) and retrains every 24 hours.

Each alert gets a 0 to 100 **risk score**: a base from the rule severity, plus up to 20 points for repeated activity, bad IP reputation and unusual behaviour. The alert screen shows exactly how the score was made. Thresholds can be changed under **Settings > Detection rules** without a restart.

## Deploy on a server (Docker + automatic HTTPS)

For a VPS from any provider (Ubuntu with Docker installed):

1. Point a domain name at the server. Open ports 80 and 443.
2. Copy the project to the server, then:

   ```bash
   cp .env.example .env
   ```

   Edit `.env`: set `DOMAIN`, a long random `SECRET_KEY`, a strong `FIRST_ADMIN_PASSWORD` (12+ characters), `FIRST_ADMIN_EMAIL`, and `POSTGRES_PASSWORD` (letters and digits only). Optionally set `ENABLE_SIMULATOR=false`.

3. Start it:

   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   ```

4. Open `https://your-domain`. Caddy gets and renews the certificate by itself.

In this setup only Caddy is exposed. The API, the web app and the database are on a private Docker network, and one address serves everything (`/` the dashboard, `/api` and `/ws` the API). Agents use `https://your-domain` as their server address. In production mode the backend refuses to start with a default secret, a default admin password or SQLite.

Update later with `git pull && docker compose -f docker-compose.prod.yml up -d --build`. Back up the `pgdata` volume (for example `docker compose -f docker-compose.prod.yml exec db pg_dump -U sentinelx sentinelx > backup.sql`).

To try this stack on your own computer first, leave `DOMAIN=localhost` and open `https://localhost` (the browser warns about the local certificate).

## Deploy on Render

1. Push this project to your own GitHub repository.
2. In Render choose **New > Blueprint** and select the repository. Render reads `render.yaml` and creates the database, the API (`sentinelx-api`) and the web app (`sentinelx-web`).
3. Render asks for the values marked in `render.yaml`. Enter `FIRST_ADMIN_EMAIL` and `FIRST_ADMIN_PASSWORD` (12+ characters); `SECRET_KEY` is generated for you. The two address fields need the services' public addresses, which normally are `https://sentinelx-api.onrender.com` and `https://sentinelx-web.onrender.com`. If Render added a suffix because a name was taken, the real address is shown on each service's page. If you are unsure, enter a placeholder now and correct it afterwards:
   - on `sentinelx-web`: `API_PUBLIC_URL` = the API's address (no trailing slash)
   - on `sentinelx-api`: `CORS_ORIGINS` = the web app's address

   After changing either value, redeploy that service.
4. Open the web app address and sign in. Agents use the API's address as their server address.

Use plans that stay awake: a service that sleeps cannot receive logs or push live updates. The blueprint leaves the plan at Render's default for that reason. The anomaly model is stored on the container disk and retrains automatically after a redeploy, so it needs no persistent disk.

## Settings you will want to know

All settings are in `.env.example` with comments. The ones that matter most:

| Setting | Purpose |
|---|---|
| `SECRET_KEY`, `FIRST_ADMIN_PASSWORD` | Must be changed for production |
| `CORS_ORIGINS` | Needed only when the dashboard and API are on different addresses |
| `TRUST_PROXY_HEADERS` | `true` only behind your own proxy (already set in the production files) |
| `BUSINESS_TZ_OFFSET_MINUTES` | Time zone for "unusual hour" detection. Default 330 (India) |
| `ABUSEIPDB_API_KEY`, `THREAT_FEED_URLS` | Optional IP reputation and blocklists |
| `ALERT_WEBHOOK_URL` | Send alerts to Slack, Discord or your own service |
| `RETENTION_DAYS` | Old events are deleted nightly. Default 90 |

Roles: **viewer** (read only), **analyst** (triage alerts, manage incidents, run simulations) and **admin** (agents, rules, users, settings, audit log).

## Tests and checks

```bash
cd backend && .venv/bin/python -m pytest -q            # 66 tests: parsing, detection rules, scoring, anomaly model, simulator
cd agent   && ../backend/.venv/bin/python -m pytest -q  # 28 tests: log parsers, log rotation, shipping, retries
cd frontend && npm run typecheck                         # TypeScript
```

The agent tests include a contract test that feeds agent output into the backend's normaliser, so a change on either side that breaks the format is caught.

## Security notes

- Passwords are hashed with bcrypt. Agent keys are stored only as hashes, can be rotated and disabled per machine, and are sent in a header over HTTPS.
- Sign-in is rate limited per IP address, and failed and successful sign-ins to SentinelX itself are analysed by the same detection rules.
- Exports neutralise spreadsheet formulas. Request paths are stored without query strings and sensitive query values are removed by the agent.
- Every change to rules, users, agents and alerts is written to the audit log.
- Put SentinelX behind HTTPS. The production files do this for you.

## Known limits

Read these before relying on SentinelX for something critical.

- **Not run end to end where it was written.** The detection engine, scoring, anomaly model, simulator, log parsers and agent are covered by automated tests that passed. The API layer (FastAPI and SQLAlchemy) and the dashboard (Next.js) could only be checked for syntax and types in that environment, because their packages could not be installed there. Expect that a first run may show a small issue to fix. Please run the commands in *Tests and checks* and tell me what you see.
- **One API process on purpose.** Live updates and the anomaly model are held in memory, so run a single worker. This handles a small to medium number of servers. Beyond that it needs a message broker and a separate worker.
- **No database migrations.** Tables are created automatically on first start. Changing the data model later needs migration tooling such as Alembic.
- **Sign-in token in the browser's local storage**, valid for 8 hours by default. Simple and works across domains, but a script injected into the page could read it. A strict content policy at your proxy reduces that risk.
- **Rate limiting is in memory** and resets when the API restarts.
- It detects and alerts. It does not block traffic or change firewalls.
- Reputation lookups use AbuseIPDB's free tier limits unless you have a paid key.

## Troubleshooting

| Problem | What to check |
|---|---|
| Dashboard says "Could not reach the server" | The API is not running, or the address is wrong. In development the dashboard expects the API at `http://localhost:8000`. Otherwise set `API_PUBLIC_URL` on the web app. |
| Browser console shows a CORS error | Add the dashboard's exact address to `CORS_ORIGINS` and restart the API. |
| Live indicator stays on "Offline, retrying" | WebSocket blocked by a proxy. Make sure `/ws` is forwarded (Caddy does this by default). |
| API exits with "Unsafe production configuration" | Change `SECRET_KEY` (32+ characters) and `FIRST_ADMIN_PASSWORD` (12+), and use PostgreSQL. |
| Agent shows "Waiting for first contact" | Run the agent with `--check`. Common causes: wrong URL, plain `http://` to a non-local address, firewall, or the key was rotated. |
| No alerts from a Linux agent | The agent user must be able to read the log (the installer adds the `adm` and `systemd-journal` groups). Confirm the log path with `--check`. |
| Anomaly model "Needs training data" | It needs 200 five-minute samples of normal activity. Collect a day or two of real logs, or use *Settings > Simulator > Create baseline traffic*. |
| Docker build cannot download fonts | The web app build needs internet access once. |
