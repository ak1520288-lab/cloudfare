# Database schema and flow

AntiFlair uses MongoDB for durable audit history and Redis for short-lived
security state. It does not use relational SQL tables: MongoDB stores
documents in collections, while Redis stores expiring key/value records.
Keeping counters, blocks, and sessions in Redis lets them expire automatically
and keeps request-time checks fast.

## Database code layout

Database and persistence code is grouped in this directory:

```text
database/
  models/       Mongoose user and security-event schemas
  services/     MongoDB event persistence and Redis state/session access
  test/         Database schema, index, and validator tests
  setupDatabase.js
  validators.js
  README.md
  db.md
```

The Express routes and middleware import persistence helpers from here.
`npm run setup-db` invokes `database/setupDatabase.js`.

## Storage architecture

```text
                              +------------------------------+
                              | MongoDB: anti_cloudflare     |
                              | securityevents + users       |
                              +---------------^--------------+
                                              |
                                 audit events | read dashboard
                                              |
Client --> Express backend ------------------+
             |
             +-- /api/* --> auth / dashboard
             |                |          |
             |                |          +--> event history and metrics (MongoDB)
             |                +--> login sessions, rate limits, IP blocks (Redis)
             |
             +-- other paths --> IP block check (Redis)
                                  --> proxy rate limit (Redis)
                                  --> WAF inspection
                                  --> origin server
                                  --> proxy audit event (MongoDB)
```

## MongoDB database and collection

Run `npm run setup-db` from `backend` to connect using `MONGODB_URI`, create
the database/collection if needed, and ensure the model indexes. MongoDB
creates the database and collection when the first collection is initialized.
The backend also ensures the model indexes during startup.

The setup command applies MongoDB `$jsonSchema` validators to both
collections. It starts with `moderate`/`warn`, checks existing documents, and
promotes a collection to `strict`/`error` only when all existing documents
match. Collections with legacy-invalid documents remain `moderate`/`warn` and
the command reports the count without deleting or rewriting data. Validators
enforce required fields, types, enums, field bounds, viewer-only public roles,
and password hash formats even for writes that bypass Mongoose. Setup requires
a MongoDB role that can manage collection validators in addition to creating
indexes.

### `securityevents`

One document per persisted security or proxy event. Event categories share
this collection so the dashboard can filter, count, and paginate one
chronological history.

| Field | Type | Rules / purpose |
| --- | --- | --- |
| `_id` | ObjectId | MongoDB document identifier |
| `category` | String | Required; `proxy`, `rate_limit`, `waf`, `ip_block`, `auth`, or `admin` |
| `outcome` | String | Required; `allowed`, `blocked`, or `warning` |
| `method` | String | Optional; up to 12 characters |
| `path` | String | Optional; query string removed; up to 512 characters |
| `ip` | String | Optional; up to 64 characters |
| `statusCode` | Number | Optional; HTTP status from 100 to 599 |
| `reason` | String | Optional; up to 240 characters |
| `actor` | String | Optional; admin username, up to 64 characters |
| `requestId` | String | Optional; request correlation ID, up to 64 characters |
| `durationMs` | Number | Optional; non-negative elapsed time |
| `createdAt` | Date | Automatically assigned; used for ordering, dashboard periods, and TTL |

Indexes: category, outcome, IP, descending creation time, and a TTL index on
`createdAt`. The TTL duration is `EVENT_RETENTION_DAYS` (30 days by default).
MongoDB removes expired audit records asynchronously.

Authenticated event-history queries support optional category, outcome, exact
IP, and inclusive `from`/`to` date filters, with a limit from 1 to 100 and an
offset from 0 to 10,000.

### `users`

Public signups are stored as user documents. New accounts are always assigned
the `viewer` role; only the configured environment admin has administrator
access. Usernames are unique and normalized to lowercase. Passwords are never
stored in plaintext: each account stores a random salt and a scrypt password
hash. The hash and salt are excluded from normal Mongoose query results.

| Field | Type | Rules / purpose |
| --- | --- | --- |
| `_id` | ObjectId | MongoDB document identifier |
| `username` | String | Required, unique, lowercase; 3-64 letters, numbers, dots, underscores, or hyphens |
| `passwordSalt` | String | Required; random per-account scrypt salt |
| `passwordHash` | String | Required; scrypt-derived password hash |
| `role` | String | Required; signup assigns `viewer` |
| `createdAt`, `updatedAt` | Date | Mongoose-managed account timestamps |

The configured admin identity remains in backend environment variables and is
not copied into this collection. Existing security-event documents are kept;
new login, logout, signup, and failed-authentication events use the existing
30-day audit retention policy.

## Redis keyspaces

Redis data is temporary and is not represented as MongoDB collections.

| Key | Value | Expiry / purpose |
| --- | --- | --- |
| `rate:<ip>` | Integer request count | Proxy fixed-window rate counter; `PROXY_RATE_WINDOW_SECONDS` |
| `rate:auth:<ip>` | Integer login-attempt count | Login rate counter; `AUTH_RATE_WINDOW_SECONDS` |
| `blocked:<ip>` | Block reason string | Temporary IP block; configured block duration |
| `session:<token-hmac>` | JSON with `username`, `role`, `csrfToken`, `createdAt` | Authenticated session; `SESSION_TTL_SECONDS` |
| `chat-rate:<ip>` | Integer question count | Security assistant limit; 60 seconds |

The browser receives the random session token in an HttpOnly cookie. Redis is
keyed with an HMAC of that token rather than the raw cookie value.

## Request and data flow

1. Express assigns a request ID and resolves the client IP.
2. `/api/*` requests use the authenticated API. Login/signup attempts are
   counted in Redis. The configured admin credentials remain environment-based;
   registered user credentials are verified against their MongoDB scrypt hashes.
   Successful signups receive viewer access, and login/signup/logout plus
   failed-authentication events are written to `securityevents`.
3. Authenticated dashboard reads aggregate or paginate `securityevents` and
   read the active Redis blocks. Block/unblock actions update Redis and write
   an admin audit event to MongoDB. Assistant questions are rate-limited in
   Redis and are not stored in the audit collection.
4. Other paths enter the proxy flow: check the Redis block key, increment the
   Redis rate counter, inspect the request with the WAF, and only then forward
   allowed requests to the configured origin.
5. Block, rate-limit, and WAF decisions are written to `securityevents`.
   Completed proxied requests are also recorded there with their response
   status and duration. Request bodies, passwords, session tokens, and
   assistant conversation content are not stored in audit events.

## Data intentionally kept outside MongoDB

- The configured admin identity and password hash come from backend environment
  configuration. Registered viewer accounts are stored in MongoDB.
- Sessions, request counters, active blocks, and assistant rate counters are
  expiring Redis records; MongoDB is not their source of truth.
- Origin and security settings are environment configuration, not database
  records.

The Mongoose source of truth for the audit document shape and indexes is
[`models/SecurityEvent.js`](./models/SecurityEvent.js). MongoDB
collection-level validators are defined in
[`validators.js`](./validators.js).
