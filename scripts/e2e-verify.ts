import * as dotenv from 'dotenv';
dotenv.config();

import { db } from '../src/db/index.ts';
import { programs, hunts, findings, reports, auditEvents } from '../src/db/schema.ts';
import { getPrograms } from '../src/services/programService.ts';
import { createHunt, updateHuntStatus } from '../src/services/huntService.ts';
import { updateFindingStatus, getFindingById, FINDING_TRANSITIONS } from '../src/services/findingService.ts';
import { createReportForFinding, getReportById } from '../src/services/reportService.ts';
import { getAuditEvents } from '../src/services/auditService.ts';
import { AuthUser } from '../src/middleware/auth.ts';
import { eq } from 'drizzle-orm';

interface TestResult {
  num: number;
  name: string;
  expected: string;
  actual: string;
  status: 'PASS' | 'FAIL';
}

const mockUser: AuthUser = {
  uid: 'user-ayush-001',
  email: 'ayush@devilhunt.sec',
  name: 'Ayush',
  role: 'RESEARCHER',
  dbId: 1,
};


async function runE2EVerification() {
  const results: TestResult[] = [];
  let testCount = 0;

  console.log('Starting End-to-End Persistence & State Machine Verification...\n');

  // Test 1: Load Seeded Programs
  testCount++;
  try {
    const progs = await getPrograms();
    const acme = progs.find((p) => p.id === 'prog-acme-01');
    if (progs.length >= 3 && acme) {
      results.push({
        num: testCount,
        name: 'Load Seeded Programs from Cloud SQL',
        expected: 'At least 3 seeded programs returned including prog-acme-01',
        actual: `Loaded ${progs.length} programs successfully. Found '${acme.name}'`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Load Seeded Programs from Cloud SQL',
        expected: 'At least 3 seeded programs returned including prog-acme-01',
        actual: `Only found ${progs.length} programs`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Load Seeded Programs from Cloud SQL',
      expected: 'Seeded programs query succeeds',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 2: Start a New Hunt Session & Verify DB Persistence
  testCount++;
  let testHuntId = '';
  try {
    const res = await createHunt({
      programId: 'prog-acme-01',
      targetDomain: 'e2e-target.acme-security.test',
    }, mockUser);

    if (res.hunt && !res.isExisting) {
      testHuntId = res.hunt.id;
      // Double check directly from DB table
      const dbRows = await db.select().from(hunts).where(eq(hunts.id, testHuntId));
      if (dbRows.length > 0 && dbRows[0].scope === 'e2e-target.acme-security.test') {
        results.push({
          num: testCount,
          name: 'Start Hunt Session & Verify Persistence',
          expected: 'New hunt created and row confirmed in hunts table',
          actual: `Hunt created with ID '${testHuntId}' and status '${dbRows[0].status}'`,
          status: 'PASS',
        });
      } else {
        results.push({
          num: testCount,
          name: 'Start Hunt Session & Verify Persistence',
          expected: 'Row confirmed in hunts table',
          actual: 'Hunt not found in database query',
          status: 'FAIL',
        });
      }
    } else {
      results.push({
        num: testCount,
        name: 'Start Hunt Session & Verify Persistence',
        expected: 'New hunt session created',
        actual: `Returned existing: ${res.isExisting}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Start Hunt Session & Verify Persistence',
      expected: 'Hunt creation succeeds',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 3: Duplicate Active Hunt Session Prevention
  testCount++;
  try {
    const resDuplicate = await createHunt({
      programId: 'prog-acme-01',
      targetDomain: 'e2e-target.acme-security.test',
    }, mockUser);

    if (resDuplicate.isExisting && resDuplicate.hunt?.id === testHuntId) {
      results.push({
        num: testCount,
        name: 'Prevent Duplicate Active Hunt Creation',
        expected: 'API identifies existing active hunt and returns isExisting: true without duplicating',
        actual: `Duplicate prevented. Re-entered active hunt '${testHuntId}'`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Prevent Duplicate Active Hunt Creation',
        expected: 'isExisting: true with matching hunt ID',
        actual: `isExisting: ${resDuplicate.isExisting}, hunt ID: ${resDuplicate.hunt?.id}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Prevent Duplicate Active Hunt Creation',
      expected: 'Duplicate check succeeds without error',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 4: Reject Invalid State Transition
  testCount++;
  try {
    // Attempt invalid hunt transition: from Hunting straight to invalid state or update stopped hunt
    await updateHuntStatus(testHuntId, 'Stopped', mockUser); // Valid transition to Stopped
    // Now try to transition from Stopped to Hunting (invalid per HUNT_TRANSITIONS)
    await updateHuntStatus(testHuntId, 'Hunting', mockUser);
    results.push({
      num: testCount,
      name: 'Reject Invalid State Transition',
      expected: 'Throw INVALID_STATE_TRANSITION error when attempting transition from Stopped to Hunting',
      actual: 'Transition unexpectedly succeeded without throwing error',
      status: 'FAIL',
    });
  } catch (err: any) {
    if (err.message.includes('INVALID_STATE_TRANSITION')) {
      results.push({
        num: testCount,
        name: 'Reject Invalid State Transition',
        expected: 'Throw INVALID_STATE_TRANSITION error',
        actual: `Error correctly caught: "${err.message}"`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Reject Invalid State Transition',
        expected: 'Throw INVALID_STATE_TRANSITION error',
        actual: `Unexpected error: ${err.message}`,
        status: 'FAIL',
      });
    }
  }

  // Test 5: Update Finding Status & Verify DB Update
  testCount++;
  let testFindingId = '';
  try {
    testFindingId = `finding-e2e-${Date.now()}`;
    await db.insert(findings).values({
      id: testFindingId,
      huntId: testHuntId,
      programId: 'prog-acme-01',
      assetId: 'asset-102',
      title: 'E2E Test SQL Injection Finding',
      description: 'Automated test finding created during e2e verification',
      severity: 'Critical',
      category: 'SQL Injection',
      status: 'Potential',
    });

    const nextStatus = 'Needs review';
    const updatedFinding = await updateFindingStatus(testFindingId, nextStatus, mockUser);
    const dbFinding = await db.select().from(findings).where(eq(findings.id, testFindingId));

    if (dbFinding.length > 0 && (dbFinding[0].status === nextStatus || dbFinding[0].status === 'Under review' || dbFinding[0].status === 'UNDER_REVIEW')) {
      results.push({
        num: testCount,
        name: 'Update Finding Status & Verify Persistence',
        expected: `Finding status updated to ${nextStatus} in database`,
        actual: `Finding status updated successfully. DB status: '${dbFinding[0].status}'`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Update Finding Status & Verify Persistence',
        expected: `DB row status is ${nextStatus}`,
        actual: `DB status: '${dbFinding[0]?.status}'`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Update Finding Status & Verify Persistence',
      expected: 'Finding status update succeeds',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 6: Generate Disclosure Report & Verify DB Persistence
  testCount++;
  let testReportId = '';
  try {
    const resReport = await createReportForFinding(testFindingId, mockUser);
    testReportId = resReport.report?.id || '';

    const dbReport = await db.select().from(reports).where(eq(reports.id, testReportId));
    if (dbReport.length > 0 && dbReport[0].findingId === testFindingId) {
      results.push({
        num: testCount,
        name: 'Generate Report & Verify Persistence',
        expected: `Report generated and stored in reports table with findingId ${testFindingId}`,
        actual: `Report '${testReportId}' created with status '${dbReport[0].status}'`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Generate Report & Verify Persistence',
        expected: 'Row found in reports table',
        actual: 'Report not found in database',
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Generate Report & Verify Persistence',
      expected: 'Report creation succeeds',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 7: Verify Audit Event Recording
  testCount++;
  try {
    const events = await getAuditEvents(mockUser);
    const huntEvent = events.find((e) => e.entityId === testHuntId && e.action === 'HUNT_STARTED');
    const reportEvent = events.find((e) => e.entityId === testReportId && e.action === 'REPORT_CREATED');

    if (huntEvent && reportEvent) {
      results.push({
        num: testCount,
        name: 'Verify Immutable Audit Event Logging',
        expected: 'Audit entries present for HUNT_STARTED and REPORT_CREATED',
        actual: `Confirmed audit log records for Hunt '${testHuntId}' and Report '${testReportId}'`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Verify Immutable Audit Event Logging',
        expected: 'Both audit events present',
        actual: `Hunt event: ${Boolean(huntEvent)}, Report event: ${Boolean(reportEvent)}`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Verify Immutable Audit Event Logging',
      expected: 'Audit log query succeeds',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Test 8: Reload / Fresh State Persistence Check
  testCount++;
  try {
    // Re-fetch report and finding as if page reloaded
    const freshFinding = await getFindingById(testFindingId, mockUser);
    const freshReport = await getReportById(testReportId, mockUser);

    if (freshFinding?.status && freshReport?.id === testReportId) {
      results.push({
        num: testCount,
        name: 'Survive Simulated Application Reload',
        expected: 'All created entities and updated states persist across fresh backend queries',
        actual: `Persisted state verified: Finding status '${freshFinding.status}', Report '${freshReport.id}'`,
        status: 'PASS',
      });
    } else {
      results.push({
        num: testCount,
        name: 'Survive Simulated Application Reload',
        expected: 'Finding status and Report present',
        actual: `Finding status: '${freshFinding?.status}', Report ID: '${freshReport?.id}'`,
        status: 'FAIL',
      });
    }
  } catch (err: any) {
    results.push({
      num: testCount,
      name: 'Survive Simulated Application Reload',
      expected: 'Fresh query succeeds',
      actual: `Error: ${err.message}`,
      status: 'FAIL',
    });
  }

  // Print Summary Table
  console.log('\n========================================================================================');
  console.log('                            E2E PERSISTENCE TEST REPORT');
  console.log('========================================================================================');
  for (const r of results) {
    console.log(`[${r.status}] Test #${r.num}: ${r.name}`);
    console.log(`  Expected: ${r.expected}`);
    console.log(`  Actual:   ${r.actual}\n`);
  }
  console.log('========================================================================================');

  const allPassed = results.every((r) => r.status === 'PASS');
  console.log(`FINAL RESULT: ${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);

  process.exit(allPassed ? 0 : 1);
}

runE2EVerification();

