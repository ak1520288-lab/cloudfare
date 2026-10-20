# PRODUCT REQUIREMENTS DOCUMENT (PRD)
## AntiFlair — Database Architecture, Storage Design and Data Flow

**Project Name:** AntiFlair  
**Document Type:** Product Requirements Document (PRD)  
**Module:** Database Architecture and Data Management  
**Backend Technology:** Node.js, Express.js, MongoDB, Redis  
**Database Layer:** Mongoose ODM  
**Version:** 1.0  
**Status:** Technical Specification  

---

# 1. Executive Summary

AntiFlair is a security-focused reverse proxy application designed to inspect incoming HTTP requests, enforce rate limits, detect potentially malicious traffic, manage temporary IP blocks, and maintain an auditable record of security decisions.

The database architecture is divided into two complementary storage systems:

1. **MongoDB:** Provides persistent storage for registered users and security audit events.
2. **Redis:** Provides fast, temporary storage for request counters, authentication rate limits, active IP blocks, authenticated sessions, and security assistant rate limits.

The system uses MongoDB for historical records and reporting, while Redis handles short-lived security state that must be checked quickly during request processing.

This separation reduces unnecessary database writes during request-time security checks and allows temporary records to expire automatically.

## 1.1 Product Objectives

The database architecture must:

- Maintain a chronological history of proxy and security events.
- Support secure user registration and authentication.
- Separate administrator privileges from regular viewer privileges.
- Enforce rate limits without querying MongoDB for every request.
- Maintain temporary IP blocks with automatic expiration.
- Support dashboard filtering, pagination, aggregation, and reporting.
- Avoid storing passwords, session tokens, or request bodies in audit records.
- Provide indexes and retention policies for efficient database operations.

## 1.2 Success Criteria

The architecture will be considered successful when:

- Security events are persisted and can be retrieved by the dashboard.
- Usernames remain unique and normalized.
- Passwords are stored only as salted scrypt hashes.
- Temporary security records expire according to their configured TTLs.
- Proxy requests are checked against IP blocks, rate limits, and WAF rules before forwarding.
- Administrative block and unblock operations produce audit records.
- Expired audit records are eventually removed according to the configured retention policy.

---

# 2. Scope and System Boundaries

## 2.1 In Scope

The PRD covers:

- MongoDB database and collection design.
- Redis keyspace design and expiration.
- User authentication data.
- Security event storage.
- Database indexes and retention.
- Request processing and data flow.
- Dashboard queries and administrative operations.
- Security, validation, and error-handling requirements.
- Testing and acceptance criteria.

## 2.2 Out of Scope

The following are outside the primary scope of this document:

- Frontend UI and visual design.
- Implementation of new WAF detection rules.
- Machine-learning-based threat detection.
- Persistent storage of assistant conversations.
- Storing complete request and response bodies.
- Replacing the existing backend or reverse proxy architecture.
- Introducing a relational database or SQL tables.

---

# 3. System Architecture Overview

AntiFlair uses a two-layer storage architecture coordinated by an Express.js backend.

## 3.1 High-Level Architecture

```text
                    CLIENT / BROWSER
                           |
                           v
                    EXPRESS BACKEND
                           |
              +------------+------------+
              |                         |
              v                         v
       AUTHENTICATED API          PROXY REQUESTS
              |                         |
       +------+-------+          +------+-------+
       |              |          |              |
       v              v          v              v
    MongoDB         Redis      Redis           WAF
       |              |          |              |
       |              |          |              v
       |              |          |        Origin Server
       |              |          |              |
       |              |          |              v
       |              |          +--------> Audit Event
       |              |                         |
       +--------------+-------------------------+
                           |
                           v
                     DASHBOARD
```

The diagram represents the logical architecture. MongoDB stores persistent application records, whereas Redis manages temporary security state. The Express backend coordinates communication between these components.

## 3.2 Core Components

### A. Express.js Backend

The backend acts as the central application layer. It:

- Receives incoming HTTP requests.
- Assigns request correlation IDs.
- Resolves the client IP address.
- Routes `/api/*` requests through authentication and dashboard handlers.
- Applies security middleware to proxied requests.
- Reads and updates Redis keys.
- Writes audit records to MongoDB.
- Returns responses to clients.

### B. MongoDB

MongoDB is the primary persistent document database.

Database name: `anti_cloudflare`

Collections:

- `securityevents`
- `users`

MongoDB stores historical events, user account records, timestamps, and the information needed by the dashboard.

### C. Redis

Redis is the temporary security-state store.

It manages:

- Proxy request counters.
- Login-attempt counters.
- Temporary IP blocks.
- Authenticated sessions.
- Security assistant request counters.

Redis records are created and updated during request processing and expire according to their configured expiration rules.

### D. Dashboard

The authenticated dashboard reads MongoDB event history and metrics, and retrieves active IP blocks from Redis.

Administrative operations can block or unblock IP addresses. These actions update Redis and generate an audit record in MongoDB.

---

# 4. Database Design

## 4.1 Database Technology Selection

MongoDB and Redis have different responsibilities.

| Requirement | MongoDB | Redis |
|---|---|---|
| Persistent user records | Yes | No |
| Historical security events | Yes | No |
| Dashboard event history | Yes | No |
| Temporary rate counters | No | Yes |
| Active IP blocks | No | Yes |
| Authenticated sessions | No | Yes |
| Automatic expiration | TTL index | Key expiration |
| Fast request-time checks | Supporting role | Primary role |

### Design rationale

MongoDB is appropriate for event records because events need to be filtered, sorted, aggregated, and retained for a defined period.

Redis is appropriate for rate limits, blocks, and sessions because these values change frequently and need low-latency access. Their expiration can be managed without requiring periodic application-level cleanup.

---

# 5. MongoDB Schema Specification

## 5.1 Database Configuration

**Database name:** `anti_cloudflare`

**Connection configuration:** `MONGODB_URI`

The database setup process is initiated from the backend directory:

```bash
npm run setup-db
```

The setup process should:

1. Read the MongoDB connection string from the environment.
2. Establish a database connection.
3. Initialize the required models and collections.
4. Ensure the indexes defined by the models.
5. Report connection or initialization errors.

MongoDB can create a database and collection when the first write or collection initialization requires them. A setup script should not assume that an empty database already contains the required collections.

The backend also ensures model indexes during startup.

The setup command applies MongoDB `$jsonSchema` validators to the
`securityevents` and `users` collections. It starts with `moderate`/`warn`,
checks existing documents, and promotes each collection to `strict`/`error`
only when all existing documents match. Invalid legacy documents are reported
and are never deleted or rewritten by setup. These database-level validators
enforce required fields, BSON types, enums, length and numeric bounds, and
viewer-only roles for writes that bypass Mongoose. The setup database user must
have permission to modify collection validators.

## 5.2 Collection: `securityevents`

### Purpose

The `securityevents` collection stores persisted security-related and proxy-related events.

Instead of creating a separate collection for every event category, AntiFlair uses one common collection. This makes it possible to display a unified chronological history and apply consistent filtering and pagination.

### Document structure

```javascript
{
  _id: ObjectId,
  category: "proxy",
  outcome: "allowed",
  method: "GET",
  path: "/api/products",
  ip: "203.0.113.10",
  statusCode: 200,
  reason: "Request passed security checks",
  actor: "admin",
  requestId: "req-12345",
  durationMs: 42,
  createdAt: ISODate("2026-10-20T10:00:00Z")
}
```

This is an illustrative document. Optional fields depend on the type of event, and the example values are not actual production records.

### Field definitions

| Field | Data type | Requirement | Purpose |
|---|---|---|---|
| `_id` | ObjectId | System-generated | Unique document identifier |
| `category` | String | Required | Classifies the event |
| `outcome` | String | Required | Describes the security decision |
| `method` | String | Optional | HTTP method |
| `path` | String | Optional | Request path without query string |
| `ip` | String | Optional | Client IP address |
| `statusCode` | Number | Optional | HTTP response status |
| `reason` | String | Optional | Explanation of the decision |
| `actor` | String | Optional | Administrator username |
| `requestId` | String | Optional | Correlation identifier |
| `durationMs` | Number | Optional | Elapsed request time |
| `createdAt` | Date | Automatically assigned | Event creation timestamp |

### Validation requirements

**Category:** Must be one of:

- `proxy`
- `rate_limit`
- `waf`
- `ip_block`
- `auth`
- `admin`

**Outcome:** Must be one of:

- `allowed`
- `blocked`
- `warning`

**Method:** Maximum 12 characters.

**Path:** Maximum 512 characters. Query strings must be removed before persistence.

**IP:** Maximum 64 characters.

**Status code:** Integer between 100 and 599.

**Reason:** Maximum 240 characters.

**Actor:** Maximum 64 characters.

**Request ID:** Maximum 64 characters.

**Duration:** Must be non-negative.

**Created timestamp:** Generated by the backend or Mongoose timestamp configuration.

The model should reject invalid category and outcome values and validate numeric fields. Field lengths and types should be enforced consistently at the application/model boundary.

## 5.3 Event Categories and Their Usage

| Category | Typical trigger | Example outcome |
|---|---|---|
| `proxy` | Request processing completed | `allowed` |
| `rate_limit` | Request limit exceeded | `blocked` |
| `waf` | Request inspected by security rules | `blocked` |
| `ip_block` | Request came from a blocked IP | `blocked` |
| `auth` | Login, signup, logout, or failed authentication | Varies |
| `admin` | Administrator changes security state | Varies |

These categories allow the dashboard to display multiple types of events in a unified timeline.

The precise event outcome must reflect the actual decision. For example, a blocked request should not be recorded as allowed.

## 5.4 Indexing Strategy

Indexes are required to support frequent dashboard queries and event lookups.

| Index | Purpose |
|---|---|
| `category` | Filter events by type |
| `outcome` | Filter allowed, blocked, and warning events |
| `ip` | Investigate activity associated with an IP |
| `createdAt` descending | Retrieve the latest events efficiently |
| `createdAt` TTL | Remove expired audit records |

The model source of truth is:

`backend/database/models/SecurityEvent.js`

Database-level validation rules are defined in:

`backend/database/validators.js`

The exact index definitions should be verified in the implementation.

### TTL retention

The event retention configuration is:

`EVENT_RETENTION_DAYS`

Default: **30 days**

The TTL index should use a retention duration equivalent to:

```javascript
expireAfterSeconds = EVENT_RETENTION_DAYS * 24 * 60 * 60
```

MongoDB's TTL monitor removes expired records asynchronously. Therefore, the 30-day value is a retention target, not a guarantee that every document disappears at the exact expiration second.

### Query efficiency

Dashboard event queries should use filters, sorting, and pagination rather than loading the complete collection into application memory.

For large event volumes, compound indexes may be introduced based on observed query patterns. Their use should be validated with query execution plans to avoid unnecessary index overhead.

---

# 6. User Collection Specification

## 6.1 Collection: `users`

### Purpose

The `users` collection stores registered application accounts and their authentication information.

New public signups receive the `viewer` role. Administrator access is determined by the configured environment-based admin identity rather than by allowing public signups to select an administrator role.

### Document structure

```javascript
{
  _id: ObjectId,
  username: "akhil01",
  passwordSalt: "<random-salt>",
  passwordHash: "<scrypt-derived-hash>",
  role: "viewer",
  createdAt: ISODate("2026-10-20T10:00:00Z"),
  updatedAt: ISODate("2026-10-20T10:00:00Z")
}
```

This is an illustrative schema. The password salt and hash shown are placeholders, not real credentials.

### Field definitions

| Field | Type | Requirement | Purpose |
|---|---|---|---|
| `_id` | ObjectId | System-generated | Unique user identifier |
| `username` | String | Required, unique | Account identity |
| `passwordSalt` | String | Required | Random salt for password hashing |
| `passwordHash` | String | Required | Scrypt-derived password hash |
| `role` | String | Required | Authorization role |
| `createdAt` | Date | Automatic | Account creation timestamp |
| `updatedAt` | Date | Automatic | Last account modification timestamp |

### Username rules

Usernames must:

- Be converted to lowercase before storage.
- Contain between 3 and 64 characters.
- Use only letters, numbers, dots, underscores, or hyphens.
- Be unique after normalization.

For example, `Akhil01` and `akhil01` should resolve to the same normalized username.

A unique MongoDB index must enforce uniqueness at the database level. Application-side duplicate checks alone are insufficient because simultaneous requests can race.

### Password storage

Passwords must never be stored in plaintext.

The system uses:

1. A randomly generated per-account salt.
2. The scrypt password derivation function.
3. A stored derived hash for future verification.
4. Exclusion of password hash and salt fields from normal Mongoose query results.

Authentication must verify the submitted password against the stored hash using the same parameters and salt.

The implementation should also ensure that explicitly selecting sensitive fields is limited to trusted authentication code.

### Role-based access

The supported account roles include:

- `viewer`
- `admin`, where explicitly supported by the authorization model

Public registration must always assign `viewer`.

The configured environment admin remains outside the `users` collection. Authorization must verify the authenticated identity and role before permitting administrative operations.

A public user must never be able to elevate their own privileges by submitting a modified role during signup or profile updates.

---

# 7. Redis Architecture and Keyspace Design

## 7.1 Redis Responsibilities

Redis stores temporary records used to make security decisions quickly.

These records are not MongoDB collections. They are Redis keys containing strings, integers, or serialized JSON values.

Each key has a specific naming convention and expiration policy.

## 7.2 Redis Keyspace Specification

| Key pattern | Value | Expiration configuration | Purpose |
|---|---|---|---|
| `rate:<ip>` | Integer request count | `PROXY_RATE_WINDOW_SECONDS` | Proxy rate limiting |
| `rate:auth:<ip>` | Integer login-attempt count | `AUTH_RATE_WINDOW_SECONDS` | Login rate limiting |
| `blocked:<ip>` | Block reason string | Configured block duration | Temporary IP blocking |
| `session:<token-hmac>` | JSON session data | `SESSION_TTL_SECONDS` | Authentication sessions |
| `chat-rate:<ip>` | Integer question count | 60 seconds | Assistant rate limiting |

The placeholders `<ip>` and `<token-hmac>` represent values inserted by the application at runtime.

## 7.3 Proxy Rate Limiting

**Key:** `rate:<ip>`

The backend maintains a counter for each client IP address.

Typical process:

1. Receive a proxied request.
2. Resolve the client IP.
3. Read or increment the corresponding counter.
4. Establish or respect the configured rate window.
5. Compare the counter with the configured request limit.
6. Continue processing or reject the request.
7. Record relevant security decisions in MongoDB.

The counter must expire after the configured rate window.

The implementation should ensure that counter updates and expiration behave correctly under concurrent requests. A fixed-window implementation should initialize expiration reliably without accidentally resetting the window on every request.

## 7.4 Authentication Rate Limiting

**Key:** `rate:auth:<ip>`

This key tracks login attempts associated with an IP address.

The objective is to reduce automated login abuse and repeated password-guessing attempts.

The system should:

- Increment the counter for relevant login attempts.
- Apply the configured authentication rate window.
- Reject attempts that exceed the configured threshold.
- Avoid recording submitted passwords in logs or audit events.

A distributed deployment should use atomic Redis operations or scripts when multiple application instances share the same rate-limit state.

## 7.5 Temporary IP Blocks

**Key:** `blocked:<ip>`

**Value:** A string describing the reason for the block.

When an administrator blocks an IP, the backend creates or updates the Redis key with an expiration time.

When an administrator unblocks an IP, the backend deletes the relevant key.

During proxy processing, the block check must occur before forwarding the request to the origin server.

The dashboard obtains the current active blocks from Redis rather than treating historical MongoDB audit events as the authoritative list of active blocks.

A block action should be authorized, validated, and audited. If a block update fails, the backend must not report success unless the Redis operation has actually succeeded.

## 7.6 Authenticated Sessions

**Key:** `session:<token-hmac>`

**Stored JSON fields:**

```json
{
  "username": "akhil01",
  "role": "viewer",
  "csrfToken": "<csrf-token>",
  "createdAt": "2026-10-20T10:00:00.000Z"
}
```

The values above are illustrative placeholders.

### Session lifecycle

1. A user submits login credentials.
2. The backend verifies the account credentials or configured admin credentials.
3. The backend generates a random session token.
4. The browser receives the token in an HttpOnly cookie.
5. The backend computes an HMAC of the token.
6. Redis stores the session under the HMAC-derived key.
7. Authenticated requests use the cookie to locate the session.
8. Logout invalidates the corresponding session.
9. Redis automatically expires the session according to `SESSION_TTL_SECONDS`.

The raw cookie token must not be used as the Redis key or stored in the audit collection.

The session implementation should use secure cookie settings appropriate to the deployment, including `Secure` when served over HTTPS, an appropriate `SameSite` policy, and a suitable path and expiration policy.

Cookie-based state-changing requests should receive CSRF protection. Session renewal and invalidation should also be handled consistently.

## 7.7 Security Assistant Rate Limiting

**Key:** `chat-rate:<ip>`

The assistant request counter expires after 60 seconds.

This limits the number of questions accepted from an IP during the relevant window.

Assistant conversation content is not stored in the MongoDB audit collection. The system records only the relevant rate-limit decision if required by its event-logging policy.

---

# 8. Application Configuration Requirements

The application must obtain database connections and security settings from environment configuration.

| Configuration | Responsibility |
|---|---|
| `MONGODB_URI` | MongoDB connection string |
| `EVENT_RETENTION_DAYS` | Security-event retention duration |
| `PROXY_RATE_WINDOW_SECONDS` | Proxy rate-counter window |
| `AUTH_RATE_WINDOW_SECONDS` | Authentication rate-counter window |
| `SESSION_TTL_SECONDS` | Redis session lifetime |
| Admin environment configuration | Configured administrator identity and authentication material |

The exact environment variable names for Redis connection settings, origin configuration, rate thresholds, and block duration should be verified against the backend implementation.

Configuration requirements:

- Secrets must not be committed to source control.
- Production secrets must be protected from unauthorized access.
- The application must validate required configuration during startup.
- Invalid database connections must be reported clearly.
- Redis connection failures must be handled according to an explicit security policy.
- Configuration changes must not silently disable authentication or security checks.

---

# 9. Detailed Request and Data Flow

## 9.1 Common Request Initialization

Every incoming request begins with backend request initialization.

1. Express receives the request.
2. The middleware assigns a request ID.
3. The backend resolves the client IP.
4. The request is routed to either the API flow or proxy flow.
5. The appropriate authentication and security middleware executes.

The request ID is used to correlate application activity and persisted events without storing sensitive request content.

Client IP resolution must be configured carefully when a reverse proxy or load balancer is present. The application should trust forwarding headers only from known, trusted proxies.

## 9.2 Authentication and Signup Flow

```text
Client
  |
  v
POST /api/auth/signup
  |
  v
Validate input
  |
  v
Normalize username
  |
  v
Check authentication rate limit (Redis)
  |
  v
Generate salt and scrypt hash
  |
  v
Insert user document (MongoDB)
  |
  v
Write signup audit event (MongoDB)
  |
  v
Return appropriate response
```

Signup requirements:

- Validate username and password inputs.
- Normalize the username before checking uniqueness.
- Always assign the `viewer` role.
- Generate a random salt and a password hash.
- Persist the user record.
- Record the relevant signup event.
- Avoid exposing password hashes, salts, or internal database errors to the client.

A duplicate username must be handled safely using the unique index.

Whether signup automatically creates a session is an implementation decision that must match the actual authentication handlers; it should not be assumed from the schema alone.

## 9.3 Login Flow

```text
Client
  |
  v
POST /api/auth/login
  |
  v
Check login rate limit (Redis)
  |
  v
Verify configured admin or registered user
  |
  +---- Invalid credentials
  |          |
  |          v
  |     Record auth event
  |     Return safe error
  |
  +---- Valid credentials
             |
             v
       Generate session token
             |
             v
       Store HMAC-keyed session
       in Redis with expiration
             |
             v
       Set HttpOnly cookie
             |
             v
       Record login event
             |
             v
       Return success
```

Authentication events should not contain submitted passwords, raw session tokens, or password hashes.

Failed attempts should produce safe, consistent error responses that do not disclose whether a particular username exists.

## 9.4 Authenticated Dashboard Flow

```text
Browser
  |
  v
GET /api/dashboard
  |
  v
Read session cookie
  |
  v
Compute token HMAC
  |
  v
Look up session in Redis
  |
  v
Validate identity and permissions
  |
  +--------------------+
  |                    |
  v                    v
MongoDB             Redis
Event history       Active IP blocks
and metrics
  |                    |
  +---------+----------+
            |
            v
      Dashboard response
```

The dashboard may:

- Retrieve recent events.
- Filter by category, outcome, IP, or date.
- Paginate event history.
- Aggregate counts and metrics over a time period.
- Display active IP blocks.
All protected dashboard operations must verify authentication and authorization before accessing protected information.

The event-history endpoint is `GET /api/dashboard/events`. It validates
optional category, outcome, exact IP, and inclusive `from`/`to` date filters,
along with bounded limit and offset pagination.

## 9.5 Administrative Block and Unblock Flow

### Block operation

1. Authenticate the administrator.
2. Verify administrative authorization.
3. Validate the target IP and block duration.
4. Create or update `blocked:<ip>` in Redis.
5. Apply the configured expiration.
6. Write an administrative audit event to MongoDB.
7. Return the result only after the relevant operation succeeds.

### Unblock operation

1. Authenticate the administrator.
2. Verify administrative authorization.
3. Validate the target IP.
4. Delete the corresponding Redis block key.
5. Write an administrative audit event to MongoDB.
6. Return an accurate result.

The implementation must define what happens if Redis succeeds but MongoDB audit persistence fails. A failed audit write should not be silently treated as a fully successful audited operation.

For security-critical administrative actions, the system should surface the partial failure and use an appropriate retry or reconciliation mechanism.

## 9.6 Proxy Request Flow

```text
Client
  |
  v
Express request initialization
  |
  v
Resolve client IP and request ID
  |
  v
Check blocked:<ip> in Redis
  |
  +---- Blocked
  |       |
  |       v
  |   Reject request
  |   Record ip_block event
  |
  v
Increment proxy rate counter in Redis
  |
  +---- Limit exceeded
  |       |
  |       v
  |   Reject request
  |   Record rate_limit event
  |
  v
Inspect request using WAF
  |
  +---- Rejected by WAF
  |       |
  |       v
  |   Reject request
  |   Record waf event
  |
  v
Forward request to configured origin
  |
  v
Receive origin response
  |
  v
Record proxy event in MongoDB
  |
  v
Return response to client
```

The block check, rate-limit check, and WAF inspection must occur before forwarding an allowed request to the origin server.

A denied request must not continue to the origin merely because a logging operation fails.

For completed proxied requests, the audit event should include available response status and elapsed duration.

For rejected requests, the event should accurately describe the rejection category and reason without exposing sensitive information.

## 9.7 Logout Flow

1. Receive the logout request.
2. Validate the session.
3. Derive the Redis key using the session token HMAC.
4. Delete or invalidate the session.
5. Clear the browser cookie.
6. Record the logout event.
7. Return the appropriate response.

The session must no longer authorize subsequent requests after successful invalidation.

---

# 10. Audit Logging Requirements

## 10.1 Events That Must Be Recorded

The audit system should record relevant occurrences such as:

- Successful and failed authentication.
- Signup and logout.
- Requests rejected by rate limiting.
- Requests rejected by WAF inspection.
- Requests rejected due to active IP blocks.
- Completed proxy requests.
- Administrative block and unblock operations.

The exact event coverage should be verified against the backend handlers and middleware.

## 10.2 Required Audit Properties

Each event should include the applicable combination of:

- Category.
- Outcome.
- Timestamp.
- Request ID.
- Client IP.
- Request method and path, when relevant.
- Response status.
- Decision reason.
- Actor, for applicable administrative actions.
- Duration, for completed proxied requests.

Optional fields may be absent when they are not applicable to an event.

## 10.3 Sensitive Data Exclusions

The audit collection must not store:

- Plaintext passwords.
- Password hashes or salts.
- Raw session tokens.
- Complete request bodies.
- Assistant conversation content.

The path must be stored without its query string. Any additional sensitive information in paths or decision reasons should be excluded or sanitized before persistence.

## 10.4 Audit Retention

Audit records follow the `EVENT_RETENTION_DAYS` policy, with a default of 30 days.

Retention is implemented using a MongoDB TTL index.

Expired records are removed asynchronously. If longer-term compliance or forensic retention becomes necessary, a separate archival policy must be designed rather than assuming that the current TTL mechanism provides permanent history.

---

# 11. Data Integrity and Security Requirements

## 11.1 Authentication and Authorization

- Passwords must be processed using the specified scrypt-based mechanism.
- Usernames must be normalized before uniqueness checks.
- The unique username index must be enforced.
- Public signups must not receive administrator privileges.
- Administrative endpoints must enforce authorization on the server.
- Session identifiers must be random and protected.
- Raw session tokens must not be persisted in MongoDB.
- CSRF protections must cover applicable cookie-authenticated state changes.

## 11.2 Input Validation

All user-controlled inputs must be validated before they are used in database queries or Redis keys.

Examples include:

- Username format.
- Password input constraints.
- IP address format.
- Block duration.
- Dashboard date ranges.
- Pagination parameters.
- Event category and outcome filters.
- Administrative action payloads.

MongoDB query filters must be constructed from validated values rather than accepting arbitrary client-supplied query objects.

## 11.3 Redis Security

- Redis must not be publicly exposed without appropriate protection.
- Connections should use authentication and transport protection where appropriate.
- Redis keys should use consistent naming conventions.
- Expiration must be configured for temporary counters, blocks, and sessions.
- Session keys must be derived from the HMAC of the session token.
- Atomic operations should be used where concurrency can affect rate-limit correctness.

## 11.4 Failure Handling

The backend must define its behavior when MongoDB or Redis becomes unavailable.

Recommended principles:

- If a block or rate-limit check cannot be completed, do not silently bypass that security control.
- If authentication state cannot be validated, do not grant access.
- If MongoDB is unavailable, report event persistence failures and apply an explicit audit failure policy.
- Return safe error responses without exposing credentials, database URIs, stack traces, or internal secrets.
- Emit operational logs and metrics sufficient to diagnose failures without recording sensitive payloads.

The exact fail-open or fail-closed policy must be documented for each security middleware. For high-risk controls, fail-closed behavior is generally safer, but it can reduce availability during infrastructure outages.

---

# 12. Non-Functional Requirements

## 12.1 Performance

- Redis must be used for frequent request-time state checks.
- Dashboard history must support pagination.
- MongoDB indexes must support common filtering and chronological sorting.
- Expensive aggregation queries must be bounded by suitable time ranges.
- Security middleware should avoid unnecessary database round trips.

## 12.2 Scalability

- MongoDB must support increasing volumes of audit documents.
- Redis must support the expected number of active keys and concurrent requests.
- The architecture should permit multiple backend instances to share the same Redis security state.
- Indexes and query patterns should be reviewed as event volume grows.

## 12.3 Reliability

- Database and cache connection failures must be observable.
- The backend should retry only operations that can be retried safely.
- Administrative actions should report partial failures accurately.
- Persistent audit events should remain available until retention removes them.
- Session invalidation and expiration must be enforced consistently.

## 12.4 Maintainability

- Mongoose models should define the document shape and indexes.
- Environment variables should control configurable durations.
- Redis keys should follow documented naming conventions.
- Schema changes should be reviewed and tested.
- Database setup should be repeatable across development and deployment environments.

## 12.5 Observability

The backend should expose appropriate operational metrics, including:

- MongoDB connection status.
- Redis connection status.
- Proxy request counts.
- Rate-limit rejection counts.
- WAF rejection counts.
- Active block counts.
- Authentication failure counts.
- Audit persistence failures.
- Request processing duration.

These operational metrics must be designed to avoid disclosing sensitive data.

---

# 13. Functional Requirements and Acceptance Criteria

| ID | Requirement | Acceptance criteria |
|---|---|---|
| FR-01 | Database initialization | Setup connects using `MONGODB_URI` and ensures required indexes |
| FR-02 | Event persistence | Applicable security and proxy events are saved in `securityevents` |
| FR-03 | Event validation | Invalid categories, outcomes, and field values are rejected |
| FR-04 | Event retention | Records become eligible for TTL removal after the configured duration |
| FR-05 | User signup | New accounts receive the `viewer` role |
| FR-06 | Password security | Passwords are stored as salted scrypt hashes, not plaintext |
| FR-07 | Username uniqueness | Duplicate normalized usernames cannot be inserted |
| FR-08 | Session management | Authenticated sessions are stored in Redis with configured expiration |
| FR-09 | Proxy rate limiting | Excess requests are rejected according to the configured policy |
| FR-10 | Authentication rate limiting | Excessive login attempts are restricted |
| FR-11 | IP block management | Block and unblock actions update Redis and generate audit events |
| FR-12 | WAF enforcement | Requests rejected by the WAF are not forwarded to the origin |
| FR-13 | Dashboard | Authorized users can retrieve filtered and paginated event history |
| FR-14 | Sensitive data protection | Audit records exclude passwords, session tokens, request bodies, and assistant conversation content |
| FR-15 | Logout | A successfully invalidated session no longer authorizes requests |
| FR-16 | Failure handling | Database/cache failures do not silently bypass required security controls |

---

# 14. Testing Strategy

## 14.1 Database Tests

Verify that:

- The database connection succeeds with valid configuration.
- Required collections and indexes are initialized.
- Invalid event documents fail validation.
- Event timestamps are generated correctly.
- TTL configuration is correct.
- Duplicate usernames are rejected.
- User timestamps are maintained.

TTL tests should verify expiration configuration and eventual deletion, not require deletion at an exact second.

## 14.2 Redis Tests

Verify that:

- Proxy counters increment correctly.
- Authentication counters use the intended window.
- Block keys expire according to their configuration.
- Unblock operations remove the relevant key.
- Sessions expire after the configured TTL.
- Logout invalidates the corresponding session.
- Assistant counters expire after 60 seconds.
- Concurrent requests do not bypass configured rate limits.

## 14.3 Authentication Tests

Verify that:

- Valid registered credentials authenticate successfully.
- Invalid credentials are rejected.
- Public signups cannot assign themselves the admin role.
- Passwords are never returned by normal user queries or API responses.
- Session cookies use appropriate security attributes.
- Expired and invalid sessions cannot access protected APIs.

## 14.4 Proxy and Security Tests

Verify that:

- Blocked IP addresses are rejected before reaching the origin.
- Rate-limited requests do not reach the origin.
- WAF-rejected requests do not reach the origin.
- Allowed requests reach the configured origin.
- Completed requests generate appropriate audit records.
- Rejection events contain the correct category and outcome.
- Request bodies and session tokens do not appear in persisted audit records.

## 14.5 Failure Tests

Test behavior when:

- MongoDB becomes unavailable.
- Redis becomes unavailable.
- A database write fails after a Redis update.
- A duplicate signup is submitted concurrently.
- Rate-limit keys are missing or expired.
- An administrative operation fails partway through execution.

These tests must confirm that the backend reports the actual result and does not claim that an operation succeeded when a required step failed.

---

# 15. Risks and Mitigation

| Risk | Impact | Mitigation |
|---|---|---|
| Missing MongoDB indexes | Slow dashboard queries | Ensure indexes during setup and startup |
| Excessive audit growth | Increased storage usage | TTL retention and query optimization |
| Redis outage | Security checks or sessions unavailable | Explicit failure policies and monitoring |
| Misconfigured trusted proxies | Incorrect client IP identification | Trust only known proxy infrastructure |
| Session token exposure | Unauthorized session use | HMAC-keyed Redis records and secure cookies |
| Unauthorized role assignment | Privilege escalation | Server-controlled role assignment and authorization |
| Concurrent rate-limit updates | Incorrect counters | Atomic Redis operations |
| Redis update succeeds but audit fails | Incomplete administrative history | Explicit partial-failure handling and reconciliation |
| Sensitive data in event fields | Privacy or security exposure | Input sanitization and strict event schemas |
| TTL deletion delay | Records retained beyond nominal expiry | Treat TTL as asynchronous retention enforcement |

---

# 16. Implementation Deliverables

The database architecture implementation should include:

1. MongoDB connection configuration.
2. `SecurityEvent` Mongoose model.
3. User Mongoose model.
4. Index initialization and verification.
5. Database setup command.
6. Redis connection and key-management utilities.
7. Proxy and authentication rate-limit middleware.
8. IP block management.
9. Session creation, validation, and invalidation.
10. Authentication and administrative audit-event handling.
11. Dashboard history and metrics queries.
12. Automated tests for schema validation, expiration, security flows, and failure scenarios.
13. Documentation for environment configuration and deployment.

The primary audit schema reference is:

`backend/database/models/SecurityEvent.js`

The implementation should be inspected to verify the exact model definitions, index names, startup behavior, and Redis expiration logic.

---

# 17. Future Enhancements

The following improvements may be considered if the system's scale or security requirements increase:

- Compound indexes tailored to actual dashboard query patterns.
- Cursor-based pagination for high-volume event histories.
- Dedicated archival storage for events requiring retention beyond 30 days.
- Redis persistence or high-availability configuration appropriate to operational needs.
- Automated reconciliation for partially completed administrative actions.
- Centralized monitoring and alerting.
- Audit integrity controls for stronger forensic requirements.
- Automated load and concurrency testing.
- Additional abuse detection using aggregated event patterns.
- Documented backup, restore, and disaster recovery procedures.

These are recommendations for future development, not claims that the current implementation already provides them.

---

# 18. Final Architecture Summary

AntiFlair follows a separation-of-responsibilities design in which MongoDB and Redis serve different data-management needs.

**MongoDB** is the persistent source of truth for registered users and retained security-event history. Its collections, schema validation, indexes, and TTL policies support authentication records, audit investigation, dashboard reporting, and retention management.

**Redis** is the fast operational store for temporary security state. Its expiring keys support rate limiting, IP blocking, sessions, and assistant usage limits without requiring every request to query MongoDB.

**Express.js** coordinates both systems. It authenticates users, enforces security middleware, manages Redis state, forwards permitted proxy requests, and persists relevant audit events.

The principal request flow is:

**Client → Express initialization → Redis block check → Redis rate limit → WAF inspection → Origin server → MongoDB audit event.**

Authenticated API requests follow a separate path through session validation, authorization, and the relevant MongoDB or Redis operation.

Together, these components provide a database architecture intended to be efficient, maintainable, auditable, and suitable for a security-focused reverse proxy application.

**End of Document**
