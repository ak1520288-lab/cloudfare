# AntiFlair backend

The backend provides two surfaces on one Express process:

1. A protected reverse proxy on all non-`/api/*` paths.
2. An authenticated JSON API on `/api/*`; the configured admin can manage
   controls, while registered users have read-only viewer access.

Redis is used for request counters, temporary blocks, and opaque sessions.
MongoDB stores registered viewer accounts and persists proxy, WAF, rate-limit,
login, signup, logout, and admin-action events. Startup checks both services
and fails explicitly when either is unavailable.

## Local setup (Windows PowerShell)

Requires Node.js 20.19+ (22 recommended), MongoDB, and Redis.

```powershell
cd backend
npm install
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

If a `.env` already exists, retain it and add any missing settings from
`.env.example`. Previous versions used `USERNAME` and plaintext `PASSWORD`;
convert them without printing the password:

```powershell
npm run migrate-legacy-admin
```

Paste its `ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH` output into `.env`, then
remove the old `USERNAME` and `PASSWORD` entries. If the old password is
shorter than 12 characters, create a new password hash instead:

```powershell
npm run create-admin-hash
```

Paste the generated `ADMIN_PASSWORD_HASH=...` into `.env`, then generate
`SESSION_SECRET` in another command:

```powershell
node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"
```

Copy the output into `SESSION_SECRET`. Make sure the MongoDB and Redis
services are running and review the connection strings in `.env`.

Initialize the MongoDB account and audit collections and their indexes without starting the
proxy or API:

```powershell
npm run setup-db
```

See [database/README.md](./database/README.md) for the complete MongoDB
collection schema, Redis keyspaces, and request-to-storage flow.

The default database is `anti_cloudflare`, with `securityevents` and `users`
collections. `npm run setup-db` ensures their indexes and MongoDB JSON Schema
validators, promoting each collection to strict rejection once existing
documents pass validation. New signups are viewer-only and their passwords are
stored as scrypt hashes. The configured admin remains environment-based. The
`securityevents` collection stores authentication and security audit events;
they are automatically removed after `EVENT_RETENTION_DAYS` (30 days by
default). Existing audit history is retained. Redis continues to store
temporary IP blocks, rate-limit counters, and expiring login sessions; expired
Redis state is not recoverable from MongoDB.

Database models, validators, Redis-backed persistence services, setup code,
and database-focused tests are grouped under `backend/database/`.

```powershell
npm start
```

Development reload and tests:

```powershell
npm run dev
npm test
```

The password-hash generator reads the password without echoing it and
requires at least 12 characters. The app compares passwords with scrypt
(`N=32768`, `r=8`, `p=1`) and constant-time comparison; it never stores the
cleartext password.

## Configuration

Create `.env` from `backend/.env.example` only when one does not already exist;
for an existing configuration, merge in the required settings. Important
settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | API and reverse-proxy listen port |
| `ORIGIN_SERVER` | `http://localhost:4000` | HTTP(S) target for allowed proxy requests |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Rate counters, blocks, and sessions |
| `MONGODB_URI` | `mongodb://127.0.0.1:27017/anti_cloudflare` | Persistent account and event database |
| `ADMIN_USERNAME` | `admin` in the example | The single configured admin identity |
| `ADMIN_PASSWORD_HASH` | generated | scrypt hash from `npm run create-admin-hash` |
| `SESSION_SECRET` | generated | At least 32 bytes; HMAC key for Redis session keys |
| `SESSION_TTL_SECONDS` | `28800` | Absolute session lifetime (8 hours) |
| `COOKIE_SECURE` | `false` | Set `true` when served over HTTPS |
| `CORS_ORIGINS` | localhost Vite origins | Exact allowed browser origins; comma-separated |
| `OPENROUTER_API_KEY` | unset | Optional OpenRouter key; used only by the authenticated security Q&A endpoint and never sent to the browser |
| `OPENROUTER_MODEL` | `openrouter/free` | OpenRouter model/router identifier for security Q&A |
| `TRUST_PROXY_HOPS` | `0` | Exact trusted proxy hop count used to resolve the client IP from `X-Forwarded-For`; keep zero unless correctly deployed behind a trusted proxy |
| `AUTH_RATE_LIMIT` | `10` | Failed/successful login attempts counted per client in a window |
| `AUTH_RATE_WINDOW_SECONDS` | `900` | Login rate-limit window |
| `PROXY_RATE_LIMIT` | `30` | Requests allowed per client in one window |
| `PROXY_RATE_WINDOW_SECONDS` | `60` | Proxy fixed-window duration |
| `PROXY_BLOCK_SECONDS` | `300` | Temporary block duration after the limit is exceeded |
| `EVENT_RETENTION_DAYS` | `30` | MongoDB TTL retention for security-event records |

Client IPs are resolved for each request from Express's `req.ip` and normalized
before rate limiting, blocking, and audit logging. When running locally, the
recorded IP is normally `127.0.0.1` or `::1` because the backend sees a local
connection. Behind a reverse proxy, set `TRUST_PROXY_HOPS` to the exact number
of trusted proxy hops; do not trust arbitrary forwarded headers from clients.

The authenticated dashboard security assistant sends each submitted question
to OpenRouter from the backend. Set `OPENROUTER_API_KEY` in `backend/.env` and
restart the backend to enable it. Questions are limited to 1,000 characters,
rate-limited to 8 per minute per client IP, and are not stored in the audit log.

Do not commit `.env`, admin password hashes, or session secrets. The example
file contains blank secret fields intentionally. Regenerate the session secret
when rotating credentials or invalidating every existing session.

## API contract

All API responses use JSON except successful logout (`204 No Content`).
Browser state-changing requests need the `X-CSRF-Token` returned by login or
session lookup. Authentication uses an HttpOnly, `SameSite=Strict` cookie;
the cookie is `Secure` automatically in production or when
`COOKIE_SECURE=true`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/health` | No | Dependency health (`200` when Redis and MongoDB are connected, otherwise `503`) |
| `POST` | `/api/auth/signup` | No | Create a viewer account with a salted scrypt hash and start a session |
| `POST` | `/api/auth/login` | No | Verify configured admin or registered user credentials, create Redis session |
| `GET` | `/api/auth/session` | Session | Return signed-in user and current CSRF token |
| `DELETE` | `/api/auth/session` | Session + CSRF | Revoke Redis session and clear cookie |
| `GET` | `/api/dashboard/summary` | Session | 24-hour totals, active IP-block count, service states, module states |
| `GET` | `/api/dashboard/events?limit=20&offset=0&category=waf&outcome=blocked&ip=203.0.113.10&from=2026-10-01T00:00:00Z&to=2026-10-20T23:59:59Z` | Session | Paginated retained events; filters are optional; limit 1–100 |
| `GET` | `/api/dashboard/blocks` | Session | Current Redis IP blocks and remaining seconds |
| `POST` | `/api/dashboard/blocks` | Session + CSRF | Create a manual IPv4/IPv6 block; duration 60–86400 seconds |
| `DELETE` | `/api/dashboard/blocks/:ip` | Session + CSRF | Remove an active IP block |
| `POST` | `/api/dashboard/inspect` | Session + CSRF | Apply local WAF rules to a URL path without contacting its host |

Login request:

```json
{ "username": "admin", "password": "the configured password" }
```

Signup request:

```json
{ "username": "viewer01", "password": "a password of at least 12 characters" }
```

Signup always creates a viewer account. Only the configured admin can manage
IP blocks or use the security assistant. Event filters support category,
outcome, an exact client IP, and inclusive ISO date bounds.

Block request:

```json
{ "ip": "203.0.113.10", "durationSeconds": 300, "reason": "manual review" }
```

URL-inspection request:

```json
{ "url": "https://example.com/search?q=term" }
```

The inspection result includes `contactedTarget: false`; it is a local
pattern check, not an external scanner or safety verdict.

## Request processing

Requests to `/api/*` are routed to the admin API and do not pass through the
origin-proxy middleware. Other requests run through:

1. **Client IP resolution:** Express `req.ip`; forwarding headers are only
   trusted when `TRUST_PROXY_HOPS` is deliberately configured.
2. **Existing block check:** reject active `blocked:<ip>` Redis keys; persist
   the denial.
3. **Rate limit:** atomic Redis fixed-window counter; when over limit, create
   a temporary IP block and persist the decision. Redis errors fail closed
   with a service error rather than bypassing the control.
4. **Basic WAF:** inspect request path/query and parsed JSON or form body for
   common SQLi, XSS, and traversal patterns. A match returns `403`.
5. **Origin proxy:** fix parsed POST bodies, overwrite `X-Forwarded-For`
   using the resolved client IP, and forward to `ORIGIN_SERVER`.
6. **Audit event:** persist the response status and duration in MongoDB.

The WAF is deliberately basic pattern matching—not a complete parser, an
AI model, or a substitute for maintained rulesets. Bot scoring, CAPTCHA,
forecasting, and an adaptive policy engine are returned as `roadmap` in the
module status API.

## Audit record and privacy

Each event can include category, outcome, HTTP method, URL path without the
query string, requester IP, status code, reason, admin actor, request ID, and
duration. Events are protected by the admin session and are deleted by a
MongoDB TTL index after the configured retention. IP addresses and paths are
sensitive operational data: restrict database access, choose an appropriate
retention period, and use TLS/secure infrastructure when deployed.

## Docker Compose

Configure `backend/.env` first (valid admin hash and session secret are
required), then run from the repository root:

```powershell
docker compose up --build
```

Compose starts Redis, MongoDB, the test origin, and backend with health
checks. For the Vite dashboard, run `npm run dev` in `frontend` on the host;
its `/api` proxy targets `localhost:8080`.

## Troubleshooting

- **Startup says admin hash is invalid:** run `npm run create-admin-hash` in
  `backend` and paste the entire generated line into `.env`.
- **Startup says session secret is too short:** generate at least 32 random
  bytes with the command above; do not use a human password.
- **Redis connection refused:** start Redis and verify `REDIS_URL`.
- **MongoDB selection timeout:** start MongoDB and verify `MONGODB_URI`.
- **Dashboard cannot reach API:** start the backend on port 8080. In dev, use
  the Vite server so `/api` is proxied; for a separate frontend origin, add
  its exact origin to `CORS_ORIGINS`.
- **Origin returns `502`:** confirm the origin is reachable from the backend
  and check `ORIGIN_SERVER`.
- **Dashboard session returns `401`:** log in again; the session is stored
  in Redis and expires after `SESSION_TTL_SECONDS`.

Tests:

```powershell
npm test
```



https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
https://example.com/item?id=1%20UNION%20SELECT
https://example.com/files/..%2F..%2Fsecret
