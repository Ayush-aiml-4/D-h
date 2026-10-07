# DEVILHUNT Production Reliability & Failure Handling Architecture

## 1. Connection Pool Configuration
- **Max Pool Size (`max: 10`)**: Conservative connection allocation designed for Cloud Run container instances to prevent database connection exhaustion.
- **Connection Timeout (`connectionTimeoutMillis: 10000`)**: 10-second max wait time for acquiring an available connection client.
- **Idle Timeout (`idleTimeoutMillis: 30000`)**: 30-second idle connection reaper.
- **Statement Timeout (`statement_timeout: 10000`)**: 10-second query timeout at the PostgreSQL level to prevent long-running queries or database locks from hanging HTTP workers.

## 2. Idempotency & Concurrency Strategy
- **Row-Level Locking (`for('update')`)**: All mutation transactions acquire exclusive row locks on target entities (`hunts`, `findings`, `reports`) to serialize concurrent state mutation requests.
- **Active Hunt De-duplication (`createHunt`)**: Atomic transaction checks for existing active hunt sessions (`Starting`, `Running`, `Hunting`, `Analyzing`) for the user/asset. If found, returns `{ hunt, isExisting: true }` without creating duplicate rows.
- **Report De-duplication (`createReportForFinding`)**: Atomic transaction checks if a report already exists for a target finding. If found, returns `{ report, isExisting: true }` without creating duplicate reports or rewards.
- **State Transition Idempotency**: Status update mutations (`updateHuntStatus`, `updateFindingStatus`, `updateReportStatus`) compare current state with target state. Identical repeated requests return the existing entity state without duplicate side-effects.

## 3. Error Classification & Status Mapping
- `VALIDATION_ERROR` (400 Bad Request): Schema validation and parameter format failures.
- `UNAUTHORIZED` (401 Unauthorized): Missing, expired, or malformed authentication token.
- `FORBIDDEN` (403 Forbidden): Unauthorized cross-user resource access or role mismatch.
- `NOT_FOUND` (404 Not Found): Nonexistent resource entity or unknown API route.
- `CONFLICT` (409 Conflict): Stale state transition attempts or concurrent state conflicts.
- `UNPROCESSABLE_ENTITY` (422 Unprocessable Entity): Semantic business logic failures.
- `TOO_MANY_REQUESTS` (429 Too Many Requests): Rate limit exceeded.
- `PAYLOAD_TOO_LARGE` (413 Payload Too Large): Request payload exceeds 2MB limit.
- `SERVICE_UNAVAILABLE` (503 Service Unavailable): Database connection loss or unreachable downstream dependency.
- `INTERNAL_ERROR` (500 Internal Server Error): Sanitized fallback for unexpected exceptions (secrets & SQL sanitized).

## 4. Rate Limiting Policy
- **General API Limiter**: 500 requests per 15-minute window per IP.
- **Mutation Limiter**: 100 requests per 15-minute window per IP.
- Returns HTTP status `429 Too Many Requests` with standard error JSON structure.
