import * as dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import v1Router from '../src/api/v1.ts';
import { createHunt } from '../src/services/huntService.ts';
import { AuthUser } from '../src/middleware/auth.ts';

interface TestResult {
  num: number;
  name: string;
  expected: string;
  actual: string;
  status: 'PASS' | 'FAIL';
}

async function runAuthVerification() {
  console.log('Starting Authentication & Authorization Architecture Verification...\n');

  // Setup express test server
  const app = express();
  app.use(express.json());
  app.use('/api/v1', v1Router);

  const server = app.listen(0);
  const port = (server.address() as any).port;
  const baseUrl = `http://localhost:${port}/api/v1`;

  const results: TestResult[] = [];
  let testCount = 0;

  // Create test hunt session for user-ayush-001
  const userA: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayush@devilhunt.sec',
    name: 'Ayush',
    role: 'RESEARCHER',
    dbId: 1,
  };

  const huntRes = await createHunt(
    {
      programId: 'prog-acme-01',
      targetDomain: 'auth-test-target.acme.test',
    },
    userA
  );
  const huntIdA = huntRes.hunt?.id || '';

  // Test 1: Missing Token (Expect 401)
  testCount++;
  try {
    const res = await fetch(`${baseUrl}/hunts`);
    const data = await res.json();
    if (res.status === 401 && data.error?.code === 'UNAUTHORIZED') {
      results.push({
        num: testCount,
        name: 'Missing Authentication Token',
        expected: '401 Unauthorized',
        actual: `HTTP ${res.status}: ${data.error.message}`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Missing Authentication Token',
        expected: '401 Unauthorized',
        actual: `HTTP ${res.status}: ${JSON.stringify(data)}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Missing Authentication Token',
      expected: '401 Unauthorized',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 2: Invalid Token (Expect 401)
  testCount++;
  try {
    const res = await fetch(`${baseUrl}/hunts`, {
      headers: {
        Authorization: 'Bearer invalid-token-xyz-123',
      },
    });
    const data = await res.json();
    if (res.status === 401 && (data.error?.code === 'UNAUTHORIZED' || data.error?.code === 'INVALID_TOKEN')) {
      results.push({
        num: testCount,
        name: 'Invalid Authentication Token',
        expected: '401 Unauthorized',
        actual: `HTTP ${res.status}: ${data.error.message}`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Invalid Authentication Token',
        expected: '401 Unauthorized',
        actual: `HTTP ${res.status}: ${JSON.stringify(data)}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Invalid Authentication Token',
      expected: '401 Unauthorized',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }


  // Test 3: Valid Authenticated User (Expect 200)
  testCount++;
  try {
    const res = await fetch(`${baseUrl}/hunts`, {
      headers: {
        Authorization: 'Bearer mock-token:user-ayush-001:RESEARCHER:Ayush',
      },
    });
    const data = await res.json();
    if (res.status === 200 && Array.isArray(data)) {
      results.push({
        num: testCount,
        name: 'Valid Authenticated User Request',
        expected: '200 OK with list of hunts',
        actual: `HTTP ${res.status}: Returned ${data.length} hunt session(s)`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Valid Authenticated User Request',
        expected: '200 OK with array',
        actual: `HTTP ${res.status}: ${JSON.stringify(data)}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Valid Authenticated User Request',
      expected: '200 OK',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 4: Unauthorized Resource Access - Different User Modifying/Accessing Resource (Expect 403)
  testCount++;
  try {
    const res = await fetch(`${baseUrl}/hunts/${huntIdA}`, {
      headers: {
        Authorization: 'Bearer mock-token:user-bob-002:RESEARCHER:Bob',
      },
    });
    const data = await res.json();
    if (res.status === 403 && data.error?.code === 'FORBIDDEN') {
      results.push({
        num: testCount,
        name: 'Cross-User Resource Access Restriction',
        expected: '403 Forbidden when User B attempts to access User A hunt',
        actual: `HTTP ${res.status}: ${data.error.message}`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Cross-User Resource Access Restriction',
        expected: '403 Forbidden',
        actual: `HTTP ${res.status}: ${JSON.stringify(data)}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Cross-User Resource Access Restriction',
      expected: '403 Forbidden',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 5: Authorized Resource Access - Owner Access (Expect 200)
  testCount++;
  try {
    const res = await fetch(`${baseUrl}/hunts/${huntIdA}`, {
      headers: {
        Authorization: 'Bearer mock-token:user-ayush-001:RESEARCHER:Ayush',
      },
    });
    const data = await res.json();
    if (res.status === 200 && data.id === huntIdA) {
      results.push({
        num: testCount,
        name: 'Authorized Resource Access (Resource Owner)',
        expected: '200 OK with matching hunt details',
        actual: `HTTP ${res.status}: Hunt ID '${data.id}' retrieved`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Authorized Resource Access (Resource Owner)',
        expected: '200 OK',
        actual: `HTTP ${res.status}: ${JSON.stringify(data)}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Authorized Resource Access (Resource Owner)',
      expected: '200 OK',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 6: Authorized Resource Access - Admin Override (Expect 200)
  testCount++;
  try {
    const res = await fetch(`${baseUrl}/hunts/${huntIdA}`, {
      headers: {
        Authorization: 'Bearer mock-token:admin-user-999:ADMIN:SecurityAdmin',
      },
    });
    const data = await res.json();
    if (res.status === 200 && data.id === huntIdA) {
      results.push({
        num: testCount,
        name: 'Authorized Resource Access (Admin Role Override)',
        expected: '200 OK allowing Admin to view any user hunt session',
        actual: `HTTP ${res.status}: Admin accessed hunt '${data.id}'`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Authorized Resource Access (Admin Role Override)',
        expected: '200 OK',
        actual: `HTTP ${res.status}: ${JSON.stringify(data)}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Authorized Resource Access (Admin Role Override)',
      expected: '200 OK',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Print Summary Table
  console.log('========================================================================================');
  console.log('                      AUTHENTICATION & AUTHORIZATION TEST REPORT');
  console.log('========================================================================================');
  for (const r of results) {
    console.log(`[${r.status}] Test #${r.num}: ${r.name}`);
    console.log(`  Expected: ${r.expected}`);
    console.log(`  Actual:   ${r.actual}\n`);
  }
  console.log('========================================================================================');

  server.close();

  const allPassed = results.every((r) => r.status === 'PASS');
  console.log(`FINAL RESULT: ${allPassed ? 'ALL AUTH TESTS PASSED' : 'SOME AUTH TESTS FAILED'}`);

  process.exit(allPassed ? 0 : 1);
}

runAuthVerification();
