# DevilHunt - Autonomous Bug Bounty & Security Research Platform

**DevilHunt** is a full-stack, policy-bounded bug bounty and security research platform designed for modern security teams and independent researchers. It coordinates automated target discovery, active policy enforcement, vulnerability tracking, confidential disclosure report generation, and immutable audit logging.

---

## 🏛️ System Architecture

DevilHunt is built as a full-stack TypeScript application:

- **Frontend**: Single-Page Application built with **React 18**, **Tailwind CSS**, and **Lucide React** icons, styled with a high-contrast dark cybersecurity visual hierarchy.
- **Backend API**: **Node.js** with **Express** (`server.ts`) providing a RESTful API (`/api/v1`) with strictly typed request/response handlers and state-machine validation middleware.
- **Relational Database**: **Cloud SQL (PostgreSQL)** managed through **Drizzle ORM**, providing schema enforcement, transaction support, and relational querying across programs, assets, policy rules, hunts, findings, disclosure reports, and audit logs.
- **Authentication**: **Firebase Admin SDK** token verification middleware (`requireAuth`) for authenticating requests via `Authorization: Bearer <token>` headers.
- **Build Engine**: **Vite** for frontend asset delivery in development, and **esbuild** bundling the backend TypeScript into a standalone CommonJS bundle (`dist/server.cjs`) for production.

---

## 🔒 Security & Credentials Hygiene

DevilHunt enforces strict separation between public client configurations and secret server credentials:

1. **Server-Side Secrets**: Sensitive database credentials (`SQL_PASSWORD`, `SQL_ADMIN_PASSWORD`) and API keys (`GEMINI_API_KEY`) are accessed strictly through `process.env` on the server-side.
2. **Environment Template**: All required environment variables are declared in `.env.example`. Actual `.env` files and credentials are excluded from version control via `.gitignore`.
3. **Firebase Client Config**: `firebase-applet-config.json` contains intentionally public client project identifiers (`projectId`, `appId`, `apiKey`, `authDomain`). These identifiers are non-sensitive web parameters designed for browser initialization. Access control is enforced server-side via Firebase Admin ID token verification and Firestore security rules.
4. **Zero Hardcoded Secrets**: No private keys, passwords, or service account JSON files are committed to source control.

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` when setting up a local environment:

```env
# Relational Database Configuration (Cloud SQL / PostgreSQL)
SQL_HOST=127.0.0.1
SQL_DB_NAME=devilhunt
SQL_USER=devilhunt_app
SQL_PASSWORD=your_secure_password
SQL_ADMIN_USER=postgres
SQL_ADMIN_PASSWORD=your_admin_password

# Gemini AI Integration (Server-side secret)
GEMINI_API_KEY=your_gemini_api_key
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18 or v20+)
- PostgreSQL or Google Cloud SQL instance

### Installation
```bash
npm install
```

### Development Server
Start the full-stack server (Express + Vite middleware) on port `3000`:
```bash
npm run dev
```

### Production Build
Build the client frontend static assets and bundle `server.ts` to `dist/server.cjs`:
```bash
npm run build
npm run start
```

---

## 📡 REST API Structure (`/api/v1`)

| Resource | Endpoint | Method | Description |
| :--- | :--- | :--- | :--- |
| **Health** | `/api/health` | `GET` | Service status health check |
| **Programs** | `/api/v1/programs` | `GET` | List all registered security programs |
| **Programs** | `/api/v1/programs/:id` | `GET` | Retrieve program details and policy rules |
| **Hunts** | `/api/v1/hunts` | `GET` | Retrieve active & historical hunt sessions |
| **Hunts** | `/api/v1/hunts` | `POST` | Initialize a new policy-bounded hunt session |
| **Hunts** | `/api/v1/hunts/:id/stop` | `POST` | Terminate an active hunt session |
| **Findings** | `/api/v1/findings` | `GET` | Retrieve discovered security findings |
| **Findings** | `/api/v1/findings/:id/review` | `POST` | Transition finding state to `Under review` |
| **Findings** | `/api/v1/findings/:id/validate` | `POST` | Transition finding state to `Validated` |
| **Findings** | `/api/v1/findings/:id/verify` | `POST` | Transition finding state to `Verified` |
| **Reports** | `/api/v1/reports` | `GET` | List generated disclosure reports |
| **Reports** | `/api/v1/findings/:id/report` | `POST` | Generate disclosure report for a finding |
| **Reports** | `/api/v1/reports/:id/submit` | `POST` | Submit report for responsible disclosure |
| **Audit** | `/api/v1/audit-events` | `GET` | Query system audit trail |
| **Metrics** | `/api/v1/metrics/rewards` | `GET` | Calculate paid, pending, and potential rewards |

---

## 🧪 End-to-End Verification

An automated verification script tests state persistence, state-machine transitions, duplicate active session protection, and audit logging against Cloud SQL:

```bash
npx tsx scripts/e2e-verify.ts
```

### Automated Verification Coverage
1. **Database Seeding Verification**: Confirms default security programs are loaded from Cloud SQL.
2. **Hunt Lifecycle**: Verifies session launch, database persistence, and duplicate active hunt prevention.
3. **State Machine Integrity**: Rejects invalid state transitions (e.g., transitioning a `Stopped` session to `Hunting`).
4. **Finding & Report Lifecycle**: Verifies finding state transitions (`Potential` → `Under review` → `Validated` → `Verified`) and disclosure report creation.
5. **Audit Logging**: Asserts immutable record keeping in the `audit_events` table.
6. **Persistence Reload Check**: Confirms state survives simulated application restarts.

---

## 📊 Current Development Status

- ✅ **Full-Stack Integration**: Complete (Express API + Vite React + Cloud SQL).
- ✅ **Database Schema**: Managed with Drizzle ORM and auto-seeding on boot.
- ✅ **Security Audit**: Passed (Zero hardcoded secrets, clean `.gitignore`, public Firebase config isolated).
- ✅ **E2E Suite**: 100% PASS across state transitions, duplicate prevention, and persistence.
