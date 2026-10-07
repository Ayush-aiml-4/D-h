# Security Program Operations

Operational infrastructure for HackerOne-style program management inside DevilHunt.

## 1. Architecture

```text
configModel → scopeEngine → triageService → repository (in-memory durable)
                ↓
         duplicateIndex / dashboard / livingUpdate / launchReadiness
```

Persistence follows the same **in-memory durable** pattern as `passiveResearch/persistenceStore` when PostgreSQL is unavailable. Drizzle `src/db/schema.ts` remains the SQL schema home for product entities; security-program ops use the dedicated repository module until schema migration is explicitly added.

## 2. Configuration model

| Category | Examples |
|----------|----------|
| **CONFIRMED** | Q5 allowlist-only, Q21 reasonable scanning, Q34 standard Safe Harbor, no mandatory researcher header |
| **PENDING** | Q1–Q4 identity/assets, Q6 third-party, Q30 reward model, special-auth matrix |
| **OPTIONAL / NOT ENABLED** | AI Research Safe Harbor, leaked-credentials exemplary |
| **DERIVED** | Launch readiness (never manually forced READY) |

Default `Q4_authorizedAssets = []`. Missing values **never** become authorization grants.

## 3. Scope engine

`return_scope_decision(raw, config)` → `IN_SCOPE` | `OUT_OF_SCOPE` | `PENDING_SPECIAL_AUTH`

Invariants: empty allowlist ⇒ all out; no inferred wildcards/parents/siblings; third-party not authorized by integration; userinfo URLs malformed.

## 4–5. Report intake & triage

`processSecurityReport()` runs modular stages: scope → safety → duplicate → validity → bounty (deferred) → remediation → disclosure.

`bounty_status` remains `DEFERRED — PROGRAM REWARD MODEL NOT CONFIGURED` while Q30 is unresolved.

## 6. Duplicate / systemic

SHA-256 fingerprints over normalized asset + root_cause + impact (exact) and root_cause + class (related). Same vulnerability **class** alone does not merge reports.

## 7–8. Persistence & dashboard

Repository: config, reports map, scope decisions, config change audit, global audits.  
`buildDashboardSnapshot()` derives counts from store; zeros when empty; launch from `calculateLaunchReadiness`.

## 9–11. Updates, audit, launch

`on_owner_input()` maps partial phrases; ambiguous URLs without authorization language are **not** added to Q4.  
Launch **READY** only if Q1–Q3 set, Q4 ≥1 asset, Q5 true, Q6 resolved (non-null), Q30 ∈ {A,B,C}.

## 12. Testing

```bash
node scripts/security-program-ops-verify.mjs
```

Fictional hosts only (`*.contoso-example.test`).

## 13. Security invariants

No DoS encouragement, no invented rate limits/bounties/SLAs, no Meesho assets, no automatic third-party scope, restrictive defaults.

## 14. Future owner configuration

When owner provides fields, use `on_owner_input` / direct config setters; re-run launch calculator; do not rebuild unrelated state.


## API integration

Authenticated under `/api/v1` (`requireAuth`).

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/security-program/status` | any auth | Launch readiness |
| GET | `/api/v1/security-program/dashboard` | any auth | Dashboard snapshot |
| GET | `/api/v1/security-program/reports` | any auth | Report metadata |
| GET | `/api/v1/security-program/reports/:id` | any auth | Report detail (evidence redacted) |
| POST | `/api/v1/security-program/scope-check` | any auth | Scope decision only |
| POST | `/api/v1/security-program/reports/process` | any auth | Full triage pipeline |
| POST | `/api/v1/security-program/config/update` | **ADMIN** | `on_owner_input` |
| GET | `/api/v1/security-program/config/changes` | **ADMIN** | Change audit |

Unauthenticated requests fail with existing 401 convention.

## UI

`SecurityProgramOpsView` — internal read-only dashboard. Launch readiness is **derived**, never manually set.

## PUBLIC LAUNCH

**BLOCKED** — Q4 has zero confirmed authorized assets.

## Navigation
Internal tab **Program Ops** → `SecurityProgramOpsView` (read-only). Authenticated SPA only.

## Rate limiting
`POST /api/v1/security-program/config/update` uses existing `mutationRateLimiter`.

## Optional SQL schema
`src/db/securityProgramSchema.ts` — not auto-migrated; in-memory remains active.


## Authenticated dashboard flow
`SecurityProgramOpsView` uses `api.securityProgram.getDashboard()` from `src/api/client.ts` (same Bearer mock/dev auth as the rest of the SPA).

## Repository adapters
- Active: in-memory `repository.ts`
- Optional: `drizzleAdapter.ts` + `securityProgramSchema.ts` (not activated, not migrated)

## API mutation protection
- `config/update`: ADMIN + `mutationRateLimiter`
- `scope-check` / `reports/process`: authenticated; input length clamped; no second limiter unless product policy requires

## Verification
`node scripts/security-program-ops-verify.mjs` — latest count documented in engineering reports.

## Persistence backend selection
Env `SECURITY_PROGRAM_PERSISTENCE=IN_MEMORY|DRIZZLE` (default IN_MEMORY).
DRIZZLE requires explicit health + migrated schema; **no silent fallback** to memory.

## Disclosure transitions
`disclosureTransitions.ts` enforces reported→triaged→validated→remediation→fix_verified→disclosure_decision→closed (plus closed shortcuts). Invalid skips rejected.

## POST rate limits
- `config/update` and `reports/process`: existing `mutationRateLimiter`
- `scope-check`: authenticated only (read-like decision); not mutation-limited by default

## Optional ADMIN disclosure UI
Separate nav **Admin Disclosure** → `SecurityProgramAdminDisclosureView`.
Uses `api.securityProgram.disclosureTransition`. Server ADMIN enforcement is authoritative.
Read-only **Program Ops** dashboard does not mutate disclosure state.

### POST route matrix (summary)
| Route | Auth | Authz | Mutation | Rate limit | Persist |
|-------|------|-------|----------|------------|---------|
| scope-check | yes | any | decision log | no | scope decision |
| reports/process | yes | any | yes | mutation | report |
| disclosure-transition | yes | ADMIN | yes | mutation | report if accepted |
| config/update | yes | ADMIN | yes | mutation | config |

## Allowed next states
GET `/api/v1/security-program/reports/:id/disclosure-transitions` (ADMIN) returns `{ currentState, allowedNextStates }` from the same FSM (`getAllowedNextStates`). Admin UI prefers this list; server still validates POST transitions.


## Report / audit listing
GET `/reports` and `/audits` remain backward compatible without query params.
Optional: `page`, `pageSize` (max 100), filters `validity`, `severity`, `scopeResult`, `disclosureStatus`, `remediationStatus` (reports); `action`, `reportId` (audits).
Authorization unchanged (`requireAuth`). Evidence not included in list responses.

## Program Ops UI pagination
SecurityProgramOpsView includes a read-only report table with Prev/Next and optional validity/scope filters via `listReports({ page, pageSize, ... })`. Server enforces pageSize max 100. No mutation controls on this view.


## Program Ops — reports & audits UI
Read-only report table filters: validity, scopeResult, severity, disclosureStatus, remediationStatus.
Read-only audit table: action filter, Prev/Next, metadata only (action, detail, timestamp).
Server clamps page when beyond last page; empty totals resolve to page 1.

## Meesho HackerOne evidence binding
`applyMeeshoHackerOneEvidence()` / `applyProgramEvidenceFromHackerOne()` update living config from program-page evidence:
- Q1 name, Q5 closed/allowlist, Q4 partial (supplier.meesho.com only), Q16 test accounts YES (refs only), Q27 X-Hackerone, Q30 A_PAID, Q31 display ranges informational.
- Does not invent APIs, wildcards, mobile package IDs, or third-party scope.
- Launch remains BLOCKED while Q2/Q3/Q6 unresolved and Q4_registerStatus=PARTIAL.
