import * as dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import v1Router, { handleError } from '../src/api/v1.ts';
import { corsMiddleware, securityHeadersMiddleware, apiRateLimiter } from '../src/middleware/security.ts';
import { requestIdMiddleware } from '../src/middleware/requestId.ts';
import { db } from '../src/db/index.ts';
import { users, programs, discoverySessions, assets } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { syncUserRecord } from '../src/services/userService.ts';

interface TestResult {
  num: number;
  name: string;
  expected: string;
  actual: string;
  status: 'PASS' | 'FAIL';
}

async function runDiscoveryApiVerification() {
  console.log('================================================================');
  console.log('DEVILHUNT #0003.2-B: Phase 2 Discovery API Verification');
  console.log('================================================================\n');

  // Setup express test server
  const app = express();
  app.set('trust proxy', 1);
  app.use(requestIdMiddleware);
  app.use(securityHeadersMiddleware);
  app.use(corsMiddleware);
  app.use('/api', apiRateLimiter);
  app.use(express.json());
  app.use('/api/v1', v1Router);

  // Intentional test route for error sanitization check
  app.get('/api/v1/test-internal-error', (req, res, next) => {
    next(new Error('FATAL_DATABASE_EXPOSE: postgres://user:SuperSecretPass123@localhost:5432/db SELECT * FROM secret_tokens'));
  });

  // Attach global error handler using v1 handleError
  app.use((err: any, req: any, res: any, next: any) => {
    handleError(req, res, err);
  });

  const server = app.listen(0);
  const port = (server.address() as any).port;
  const baseUrl = `http://localhost:${port}/api/v1`;

  const results: TestResult[] = [];
  let testCount = 0;

  // Tokens
  const userAToken = 'Bearer mock-token:user-ayush-001:RESEARCHER:Ayush Singh';
  const userBToken = 'Bearer mock-token:user-bob-002:RESEARCHER:Bob Researcher';
  const adminToken = 'Bearer mock-token:user-admin-001:ADMIN:System Admin';
  const invalidToken = 'Bearer invalid-token-sig-xyz';

  // Seed users in DB
  await syncUserRecord({ uid: 'user-ayush-001', email: 'ayush@devilhunt.sec', name: 'Ayush Singh', role: 'RESEARCHER' });
  await syncUserRecord({ uid: 'user-bob-002', email: 'bob@devilhunt.sec', name: 'Bob Researcher', role: 'RESEARCHER' });
  await syncUserRecord({ uid: 'user-admin-001', email: 'admin@devilhunt.sec', name: 'System Admin', role: 'ADMIN' });

  // Ensure program exists
  const activeProg = await db.select().from(programs).where(eq(programs.id, 'prog-acme-01'));
  if (activeProg.length === 0) {
    await db.insert(programs).values({
      id: 'prog-acme-01',
      name: 'Acme Corp Bug Bounty',
      description: 'Acme Security Program',
      status: 'ACTIVE',
      rewardCeiling: '$10,000',
    });
  }

  let createdSessionId = '';

  try {
    // 1. Missing Authentication -> 401
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ programId: 'prog-acme-01', target: 'api.acme-security.test' }),
      });
      const data = await res.json();
      if (res.status === 401 && data.error?.code === 'UNAUTHORIZED') {
        results.push({ num: testCount, name: 'Missing Authentication -> 401', expected: '401 UNAUTHORIZED', actual: `HTTP ${res.status}: ${data.error.code}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Missing Authentication -> 401', expected: '401 UNAUTHORIZED', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Missing Authentication -> 401', expected: '401 UNAUTHORIZED', actual: err.message, status: 'FAIL' });
    }

    // 2. Invalid Authentication -> 401
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/start`, {
        method: 'POST',
        headers: { Authorization: invalidToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ programId: 'prog-acme-01', target: 'api.acme-security.test' }),
      });
      const data = await res.json();
      if (res.status === 401 && data.error?.code === 'INVALID_TOKEN') {
        results.push({ num: testCount, name: 'Invalid Authentication -> 401', expected: '401 INVALID_TOKEN', actual: `HTTP ${res.status}: ${data.error.code}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Invalid Authentication -> 401', expected: '401 INVALID_TOKEN', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Invalid Authentication -> 401', expected: '401 INVALID_TOKEN', actual: err.message, status: 'FAIL' });
    }

    // 3. Unauthorized Researcher -> 403
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/start`, {
        method: 'POST',
        headers: { Authorization: userBToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ programId: 'prog-acme-01', target: 'unauthorized-target.external.com' }),
      });
      const data = await res.json();
      if (res.status === 403 && data.error?.code === 'FORBIDDEN') {
        results.push({ num: testCount, name: 'Unauthorized Researcher / Target -> 403', expected: '403 FORBIDDEN', actual: `HTTP ${res.status}: ${data.error.code} (${data.error.message})`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Unauthorized Researcher / Target -> 403', expected: '403 FORBIDDEN', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Unauthorized Researcher / Target -> 403', expected: '403 FORBIDDEN', actual: err.message, status: 'FAIL' });
    }

    // 4. Valid Discovery Start -> 201
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/start`, {
        method: 'POST',
        headers: { Authorization: userAToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ programId: 'prog-acme-01', target: 'api.acme-security.test' }),
      });
      const data = await res.json();
      if (res.status === 201 && data.id && data.status === 'COMPLETED') {
        createdSessionId = data.id;
        results.push({ num: testCount, name: 'Valid Discovery Start -> 201', expected: '201 Created with completed session', actual: `HTTP ${res.status}: session ${data.id} (${data.status})`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Valid Discovery Start -> 201', expected: '201 Created', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Valid Discovery Start -> 201', expected: '201 Created', actual: err.message, status: 'FAIL' });
    }

    // 5. Duplicate Active Discovery -> Safely Handled (409)
    testCount++;
    try {
      const mockActiveId = `disc-active-dup-${Date.now()}`;
      await db.insert(discoverySessions).values({
        id: mockActiveId,
        programId: 'prog-acme-01',
        initiatedBy: 'user-ayush-001',
        target: 'dup-target.acme-security.test',
        operation: 'AUTHORIZED_DISCOVERY',
        status: 'DISCOVERING',
        startedAt: new Date(),
      });

      const res = await fetch(`${baseUrl}/discovery/start`, {
        method: 'POST',
        headers: { Authorization: userAToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ programId: 'prog-acme-01', target: 'dup-target.acme-security.test' }),
      });
      const data = await res.json();

      await db.delete(discoverySessions).where(eq(discoverySessions.id, mockActiveId));

      if (res.status === 409 && data.error?.code === 'CONFLICT') {
        results.push({ num: testCount, name: 'Duplicate Active Discovery -> Safely Handled', expected: '409 CONFLICT', actual: `HTTP ${res.status}: ${data.error.message}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Duplicate Active Discovery -> Safely Handled', expected: '409 CONFLICT', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Duplicate Active Discovery -> Safely Handled', expected: '409 CONFLICT', actual: err.message, status: 'FAIL' });
    }

    // 6. Retrieve Owned Discovery Session -> 200
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/${createdSessionId}`, {
        headers: { Authorization: userAToken },
      });
      const data = await res.json();
      if (res.status === 200 && data.id === createdSessionId) {
        results.push({ num: testCount, name: 'Retrieve Owned Discovery Session -> 200', expected: '200 OK', actual: `HTTP ${res.status}: session ${data.id}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Retrieve Owned Discovery Session -> 200', expected: '200 OK', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Retrieve Owned Discovery Session -> 200', expected: '200 OK', actual: err.message, status: 'FAIL' });
    }

    // 7. Retrieve Another User's Session -> 403
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/${createdSessionId}`, {
        headers: { Authorization: userBToken },
      });
      const data = await res.json();
      if (res.status === 403 && data.error?.code === 'FORBIDDEN') {
        results.push({ num: testCount, name: "Retrieve Another User's Session -> 403", expected: '403 FORBIDDEN', actual: `HTTP ${res.status}: ${data.error.message}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: "Retrieve Another User's Session -> 403", expected: '403 FORBIDDEN', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: "Retrieve Another User's Session -> 403", expected: '403 FORBIDDEN', actual: err.message, status: 'FAIL' });
    }

    // 8. ADMIN Retrieval -> 200
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/${createdSessionId}`, {
        headers: { Authorization: adminToken },
      });
      const data = await res.json();
      if (res.status === 200 && data.id === createdSessionId) {
        results.push({ num: testCount, name: 'ADMIN Retrieval -> 200', expected: '200 OK', actual: `HTTP ${res.status}: session ${data.id}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'ADMIN Retrieval -> 200', expected: '200 OK', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'ADMIN Retrieval -> 200', expected: '200 OK', actual: err.message, status: 'FAIL' });
    }

    // 9. Stop Owned Active Discovery -> 200
    testCount++;
    let activeSessionToStop = '';
    try {
      activeSessionToStop = `disc-active-stop-${Date.now()}`;
      await db.insert(discoverySessions).values({
        id: activeSessionToStop,
        programId: 'prog-acme-01',
        initiatedBy: 'user-ayush-001',
        target: 'stoppable.acme-security.test',
        operation: 'AUTHORIZED_DISCOVERY',
        status: 'DISCOVERING',
        startedAt: new Date(),
      });

      const res = await fetch(`${baseUrl}/discovery/${activeSessionToStop}/stop`, {
        method: 'POST',
        headers: { Authorization: userAToken, 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (res.status === 200 && data.status === 'STOPPED') {
        results.push({ num: testCount, name: 'Stop Owned Active Discovery -> 200', expected: '200 OK with status STOPPED', actual: `HTTP ${res.status}: status ${data.status}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Stop Owned Active Discovery -> 200', expected: '200 OK', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Stop Owned Active Discovery -> 200', expected: '200 OK', actual: err.message, status: 'FAIL' });
    }

    // 10. Invalid Discovery Transition -> Appropriate Error (409)
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/${activeSessionToStop}/stop`, {
        method: 'POST',
        headers: { Authorization: userAToken, 'Content-Type': 'application/json' },
      });
      const data = await res.json();

      await db.delete(discoverySessions).where(eq(discoverySessions.id, activeSessionToStop));

      if (res.status === 409 && data.error?.code === 'CONFLICT') {
        results.push({ num: testCount, name: 'Invalid Discovery Transition -> 409 Conflict', expected: '409 CONFLICT', actual: `HTTP ${res.status}: ${data.error.message}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Invalid Discovery Transition -> 409 Conflict', expected: '409 CONFLICT', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Invalid Discovery Transition -> 409 Conflict', expected: '409 CONFLICT', actual: err.message, status: 'FAIL' });
    }

    // 11. Assets Returned -> 200
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/assets`, {
        headers: { Authorization: userAToken },
      });
      const data = await res.json();
      if (res.status === 200 && Array.isArray(data)) {
        results.push({ num: testCount, name: 'Assets Returned -> 200', expected: '200 OK with array', actual: `HTTP ${res.status}: ${data.length} assets`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Assets Returned -> 200', expected: '200 OK', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Assets Returned -> 200', expected: '200 OK', actual: err.message, status: 'FAIL' });
    }

    // 12. Asset Filters Work
    testCount++;
    try {
      const resProg = await fetch(`${baseUrl}/assets?programId=prog-acme-01`, { headers: { Authorization: userAToken } });
      const dataProg = await resProg.json();

      const resSess = await fetch(`${baseUrl}/assets?discoverySessionId=${createdSessionId}`, { headers: { Authorization: userAToken } });
      const dataSess = await resSess.json();

      const resType = await fetch(`${baseUrl}/assets?type=SUBDOMAIN`, { headers: { Authorization: userAToken } });
      const dataType = await resType.json();

      const resStatus = await fetch(`${baseUrl}/assets?status=AUTHORIZED`, { headers: { Authorization: userAToken } });
      const dataStatus = await resStatus.json();

      if (
        resProg.status === 200 && Array.isArray(dataProg) &&
        resSess.status === 200 && Array.isArray(dataSess) &&
        resType.status === 200 && Array.isArray(dataType) &&
        resStatus.status === 200 && Array.isArray(dataStatus)
      ) {
        results.push({ num: testCount, name: 'Asset Filters Work', expected: '200 OK for all filters', actual: `Program: ${dataProg.length}, Session: ${dataSess.length}, Type: ${dataType.length}, Status: ${dataStatus.length}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Asset Filters Work', expected: '200 OK for all filters', actual: `Prog: ${resProg.status}, Sess: ${resSess.status}, Type: ${resType.status}, Status: ${resStatus.status}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Asset Filters Work', expected: '200 OK', actual: err.message, status: 'FAIL' });
    }

    // 13. Malformed IDs -> 400
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/..%2F..%2Fetc%2Fpasswd`, {
        headers: { Authorization: userAToken },
      });
      const data = await res.json();
      if (res.status === 400 && data.error?.code === 'BAD_REQUEST') {
        results.push({ num: testCount, name: 'Malformed IDs -> 400', expected: '400 BAD_REQUEST', actual: `HTTP ${res.status}: ${data.error.message}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Malformed IDs -> 400', expected: '400 BAD_REQUEST', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Malformed IDs -> 400', expected: '400 BAD_REQUEST', actual: err.message, status: 'FAIL' });
    }

    // 14. Mass-Assignment Fields Rejected -> 400
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/start`, {
        method: 'POST',
        headers: { Authorization: userAToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          programId: 'prog-acme-01',
          target: 'api.acme-security.test',
          researcherId: 'user-bob-002',
          role: 'ADMIN',
          scopeStatus: 'In Scope',
          policyStatus: 'ALLOWED',
          decision: 'ALLOW',
        }),
      });
      const data = await res.json();
      if (res.status === 400 && data.error?.code === 'BAD_REQUEST' && data.error?.message.includes('Mass assignment blocked')) {
        results.push({ num: testCount, name: 'Mass-Assignment Fields Rejected -> 400', expected: '400 BAD_REQUEST', actual: `HTTP ${res.status}: ${data.error.message}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Mass-Assignment Fields Rejected -> 400', expected: '400 BAD_REQUEST', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Mass-Assignment Fields Rejected -> 400', expected: '400 BAD_REQUEST', actual: err.message, status: 'FAIL' });
    }

    // 15. Policy Enforcement Server-Side -> 403
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/discovery/start`, {
        method: 'POST',
        headers: { Authorization: userAToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({ programId: 'prog-acme-01', target: 'unauthorized.external-target.com' }),
      });
      const data = await res.json();
      if (res.status === 403 && data.error?.code === 'FORBIDDEN') {
        results.push({ num: testCount, name: 'Policy Enforcement Server-Side -> 403', expected: '403 FORBIDDEN', actual: `HTTP ${res.status}: ${data.error.message}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Policy Enforcement Server-Side -> 403', expected: '403 FORBIDDEN', actual: `HTTP ${res.status}: ${JSON.stringify(data)}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Policy Enforcement Server-Side -> 403', expected: '403 FORBIDDEN', actual: err.message, status: 'FAIL' });
    }

    // 16. Internal Errors Sanitized
    testCount++;
    try {
      const res = await fetch(`${baseUrl}/test-internal-error`, {
        headers: { Authorization: userAToken },
      });
      const data = await res.json();
      const rawBody = JSON.stringify(data);
      const containsLeakedDbPass = rawBody.includes('SuperSecretPass123') || rawBody.includes('postgres://');
      if (res.status === 500 && !containsLeakedDbPass && data.error?.code === 'INTERNAL_ERROR') {
        results.push({ num: testCount, name: 'Internal Errors Sanitized', expected: '500 without credentials or stack trace', actual: `HTTP ${res.status}: ${data.error.message}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'Internal Errors Sanitized', expected: '500 sanitized', actual: `HTTP ${res.status}: ${rawBody}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'Internal Errors Sanitized', expected: '500 sanitized', actual: err.message, status: 'FAIL' });
    }

    // 17. RequestId Returned / Correlated
    testCount++;
    try {
      const customReqId = `req-test-corr-${Date.now()}`;
      const res = await fetch(`${baseUrl}/assets`, {
        headers: { Authorization: userAToken, 'X-Request-ID': customReqId },
      });
      const headerReqId = res.headers.get('x-request-id');

      if (res.status === 200 && headerReqId === customReqId) {
        results.push({ num: testCount, name: 'RequestId Returned / Correlated', expected: `Header X-Request-ID = ${customReqId}`, actual: `Header X-Request-ID = ${headerReqId}`, status: 'PASS' });
      } else {
        results.push({ num: testCount, name: 'RequestId Returned / Correlated', expected: `Header X-Request-ID = ${customReqId}`, actual: `Header X-Request-ID = ${headerReqId}`, status: 'FAIL' });
      }
    } catch (err: any) {
      results.push({ num: testCount, name: 'RequestId Returned / Correlated', expected: 'Correlated header', actual: err.message, status: 'FAIL' });
    }

  } finally {
    server.close();
  }

  // Print summary report
  console.log('----------------------------------------------------------------');
  console.log('RESULTS SUMMARY:');
  console.log('----------------------------------------------------------------');
  let passCount = 0;
  let failCount = 0;

  for (const r of results) {
    if (r.status === 'PASS') passCount++;
    else failCount++;
    console.log(`[${r.status}] #${r.num}: ${r.name}`);
    console.log(`       Expected: ${r.expected}`);
    console.log(`       Actual:   ${r.actual}`);
  }

  console.log('================================================================');
  console.log(`TOTAL TESTS: ${results.length} | PASS: ${passCount} | FAIL: ${failCount}`);
  console.log('================================================================\n');

  if (failCount > 0) {
    process.exit(1);
  }
  process.exit(0);
}

runDiscoveryApiVerification().catch((err) => {
  console.error('Fatal error in verification suite:', err);
  process.exit(1);
});
