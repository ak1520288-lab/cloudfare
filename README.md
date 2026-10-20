# AntiFlair — PBL Reverse-Proxy Security Project

AntiFlair is a learning project that places an Express reverse proxy in front
of an origin website. It demonstrates Redis-backed rate limiting and IP
blocks, a basic pattern-based WAF, admin authentication, viewer signup, and a
MongoDB-backed audit dashboard. It is **not** a production WAF, a Cloudflare replacement, or a
complete DDoS/bot-protection service.

## Request flow

```text
Browser / API client
        |
        +---- /api/* ----> Admin API
        |                  session auth -> CSRF checks -> dashboard/audit APIs
        |
        +---- other paths -> Reverse proxy (default :8080)
                             1. Existing IP-block check (Redis)
                             2. Fixed-window rate limit (Redis)
                             3. Basic URL/query/body WAF
                             4. Forward request to origin
                             5. Persist the response event to MongoDB
                                      |
                                      v
                              Test origin (default :4000)
```

The demo dashboard is a separate React/Vite app (default `:5173`). Its dev
server proxies `/api` to the backend, so browser cookies and CSRF protection
work without a permissive wildcard CORS policy.

## Quick start on Windows

Requirements: Node.js 20.19+ (22 recommended), MongoDB, and Redis.

### 1. Start MongoDB and Redis

Start the MongoDB Windows service if one is installed:

```powershell
Start-Service MongoDB
```

Run Redis locally, or use the Redis service in Docker Compose as described
below. Redis is mandatory for rate limits, temporary blocks, and login
sessions. MongoDB is mandatory for registered accounts and security-event history.

### 2. Configure the backend

```powershell
cd backend
npm install
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

If `backend/.env` already exists, keep it and add the settings from
`.env.example` without deleting your current Redis/origin configuration.
Older versions used `USERNAME` and plaintext `PASSWORD`; migrate those locally
without printing the password:

```powershell
npm run migrate-legacy-admin
```

Copy the printed `ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH` lines into
`.env`, then remove the old `USERNAME` and `PASSWORD` lines. The migration
requires the legacy password to have at least 12 characters. Otherwise set a
new one using:

```powershell
npm run create-admin-hash
```

This command securely prompts for a password (minimum 12 characters) and
prints an `ADMIN_PASSWORD_HASH=...` line. Paste it into `backend/.env`.
Generate a session secret:

```powershell
node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"
```

Copy the output into `SESSION_SECRET` in the same `.env` file. Review
`ORIGIN_SERVER`, `MONGODB_URI`, `REDIS_URL`, and `CORS_ORIGINS`, then start the
backend:

```powershell
npm start
```

The API and reverse proxy listen on `http://localhost:8080`. The backend
refuses to start unless its admin settings are valid and both Redis and
MongoDB are reachable. The configured admin has control privileges; anyone
can create a viewer account from the dashboard sign-in screen to access
read-only dashboard data.

### 3. Start the test origin

In a second terminal:

```powershell
cd test-origin-server
npm install
npm start
```

The origin listens on `http://localhost:4000`; use `http://localhost:8080`
to visit it through the protection middleware.

### 4. Start the dashboard

In a third terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal and sign in with the configured
`ADMIN_USERNAME` and the password used to generate its hash, or register a
read-only viewer account. Sign-in is validated by the backend; account
credentials and audit events are stored in MongoDB, while expiring sessions
are held in Redis and use an HttpOnly cookie. The dashboard loads actual event
and block data from the API and refreshes its summary every 15 seconds.

### Docker Compose

First create and configure `backend/.env` using steps 2 above (the compose
stack injects Redis, MongoDB, and origin service addresses). Then, from the
project root:

```powershell
docker compose up --build
```

This starts Redis, MongoDB, the test origin, and the backend. The React
dashboard can still be started locally with `npm run dev` in `frontend`.
Compose stores MongoDB data in the `mongo-data` named volume.

## Backend documentation

See [backend/README.md](./backend/README.md) for the API contract, environment
settings, security controls, audit-event model, and troubleshooting.

## Safe local verification

Use only the local test origin or systems you are authorized to test. The
configured limit is 30 requests per client IP in 60 seconds; exceeding it
creates a 5-minute Redis block. Check the proxy's `RateLimit-*` response
headers and the admin dashboard's event/block tables. The dashboard's URL
inspection endpoint checks only the submitted URL path against local WAF
rules; it does **not** fetch or scan the target.

## Current scope

- Implemented: reverse proxy, Redis session and block storage, IP block check,
  configurable rate limiting, basic SQLi/XSS/path-traversal pattern checks,
  admin login and viewer signup, role-protected controls, MongoDB user accounts
  and audit events, service health and dashboard APIs.
- Roadmap: trained bot-risk model, CAPTCHA/challenge service, predictive
  attacks, and production-grade WAF/rules.

Pattern matching is heuristic: it can miss attacks and produce false
positives. Do not expose the admin API or proxy to the public internet without
adding TLS, monitoring, hardened deployment, and an appropriate security
review.

$root='C:\Users\Asus\OneDrive\Desktop\anti-cloudflare'; $m=Get-Service MongoDB -ErrorAction SilentlyContinue; if($m -and $m.Status -ne 'Running'){Start-Service MongoDB}; if(-not(Test-NetConnection 127.0.0.1 -Port 6379 -InformationLevel Quiet)){throw 'Redis nahi chal raha. Pehle Redis start karo.'}; if(-not(Test-NetConnection 127.0.0.1 -Port 27017 -InformationLevel Quiet)){throw 'MongoDB port 27017 par reachable nahi hai.'}; Start-Process cmd.exe -ArgumentList '/k',"cd /d `"$root\test-origin-server`" && npm start"; Start-Process cmd.exe -ArgumentList '/k',"cd /d `"$root\backend`" && set PORT=8081 && npm start"; Start-Process cmd.exe -ArgumentList '/k',"cd /d `"$root\frontend`" && set ANTIFLAIR_API_URL=http://127.0.0.1:8081 && npm run dev -- --host 127.0.0.1 --port 5175 --strictPort"