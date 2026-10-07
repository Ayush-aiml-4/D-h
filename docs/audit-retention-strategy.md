# DevilHunt Audit Event Retention Strategy

## Overview
Audit events record security-sensitive actions and state transitions across the DevilHunt platform.
To ensure non-repudiation, compliance, and post-incident investigation capabilities, audit records must remain intact and immutable.

## Application-Layer Immutability & Append-Only Architecture
1. **Append-Only Operations**:
   - The application layer only exposes `INSERT` and `SELECT` query builders for `audit_events`.
   - No application services or API endpoints allow `UPDATE` or `DELETE` operations on historical audit rows.
2. **Untrusted Client Boundary**:
   - Web browsers and API clients cannot write directly to `audit_events`.
   - All audit records are created strictly by authenticated, server-side services during validated state transitions.

## Retention Strategy
1. **Development & Staging Environments**:
   - All audit logs are retained indefinitely.
   - No automated background cleanup jobs run in initial development.
2. **Production Policy**:
   - Active online retention: 365 days in high-performance PostgreSQL table.
   - Cold storage archival: Audit logs older than 365 days are exported to write-once-read-many (WORM) storage (e.g., Cloud Storage buckets with Object Lock) before purging from primary relational database.
   - Immediate hard deletes are strictly forbidden.
