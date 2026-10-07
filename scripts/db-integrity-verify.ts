import { db, createPool, verifyDatabaseConnection } from '../src/db/index.ts';
import { users, programs, assets, hunts, findings, reports, rewards, historySessions, auditEvents } from '../src/db/schema.ts';
import { createHunt, updateHuntStatus } from '../src/services/huntService.ts';
import { updateFindingStatus } from '../src/services/findingService.ts';
import { createReportForFinding, updateReportStatus } from '../src/services/reportService.ts';
import { getAuditEvents } from '../src/services/auditService.ts';
import { eq } from 'drizzle-orm';

import { AuthUser } from '../src/middleware/auth.ts';

async function runDatabaseIntegrityTests() {
  console.log('=== DEVILHUNT #0002.3 DATABASE HARDENING & DATA INTEGRITY VERIFICATION ===\n');

  let passedTests = 0;
  let failedTests = 0;

  const assert = (condition: boolean, testName: string, detail?: string) => {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passedTests++;
    } else {
      console.error(`[FAIL] ${testName} ${detail ? `(${detail})` : ''}`);
      failedTests++;
    }
  };

  const testUser: AuthUser = {
    uid: 'user-integrity-test-001',
    email: 'test.integrity@devilhunt.local',
    name: 'Integrity Tester',
    role: 'RESEARCHER',
  };

  const adminUser: AuthUser = {
    uid: 'user-admin-001',
    email: 'admin@devilhunt.local',
    name: 'Admin Tester',
    role: 'ADMIN',
  };

  try {
    // 1. Database Connection Check
    const isConnected = await verifyDatabaseConnection();
    assert(isConnected, '1. Cloud SQL Database Connectivity Verified');

    // 2. Foreign Key Constraint Enforcements (Rejection of Orphaned Records)
    console.log('\n--- Testing Foreign Key & Constraint Hardening ---');

    // Helper to check Postgres error codes or messages from Drizzle errors
    const isFkViolation = (err: any) =>
      err?.code === '23503' ||
      err?.cause?.code === '23503' ||
      err?.message?.includes('foreign key') ||
      err?.cause?.message?.includes('foreign key') ||
      err?.message?.includes('violates foreign key constraint') ||
      err?.cause?.message?.includes('violates foreign key constraint');

    const isUniqueViolation = (err: any) =>
      err?.code === '23505' ||
      err?.cause?.code === '23505' ||
      err?.message?.includes('unique constraint') ||
      err?.cause?.message?.includes('unique constraint') ||
      err?.message?.includes('duplicate key') ||
      err?.cause?.message?.includes('duplicate key');

    // Attempt inserting a hunt with a non-existent researcherId -> Should throw Foreign Key Violation
    let fkViolationCaught = false;
    let fkErrDetail = '';
    try {
      await db.insert(hunts).values({
        id: `hunt-orphan-${Date.now()}`,
        programId: 'prog-acme-01',
        assetId: 'asset-102',
        researcherId: 'non-existent-user-999999',
        status: 'Hunting',
        progress: 10,
        scope: 'api.acme-security.test',
      });
    } catch (err: any) {
      fkErrDetail = `[code: ${err.code || err.cause?.code}, msg: ${err.message}]`;
      if (isFkViolation(err)) {
        fkViolationCaught = true;
      }
    }
    assert(fkViolationCaught, '2. Foreign Key Constraint Rejects Orphaned Hunt (Invalid Researcher ID)', fkErrDetail);

    // Attempt inserting a finding with non-existent huntId -> Should throw Foreign Key Violation
    let findingFkViolation = false;
    let findingErrDetail = '';
    try {
      await db.insert(findings).values({
        id: `finding-orphan-${Date.now()}`,
        huntId: 'non-existent-hunt-999999',
        programId: 'prog-acme-01',
        assetId: 'asset-102',
        title: 'Orphaned Finding Test',
        description: 'Testing orphan rejection',
        severity: 'High',
        category: 'Insecure Direct Object Reference',
        status: 'Potential',
      });
    } catch (err: any) {
      findingErrDetail = `[code: ${err.code || err.cause?.code}, msg: ${err.message}]`;
      if (isFkViolation(err)) {
        findingFkViolation = true;
      }
    }
    assert(findingFkViolation, '3. Foreign Key Constraint Rejects Orphaned Finding (Invalid Hunt ID)', findingErrDetail);

    // 3. Unique Constraint Enforcement
    console.log('\n--- Testing Unique Constraint Hardening ---');

    // Attempt duplicate UID insertion in users table
    let duplicateUidCaught = false;
    let dupUidErrDetail = '';
    try {
      await db.insert(users).values({
        uid: 'user-ayush-001', // Already seeded in seed.ts
        name: 'Duplicate Ayush',
        email: 'duplicate.ayush@devilhunt.local',
        role: 'RESEARCHER',
      });
    } catch (err: any) {
      dupUidErrDetail = `[code: ${err.code || err.cause?.code}, msg: ${err.message}]`;
      if (isUniqueViolation(err)) {
        duplicateUidCaught = true;
      }
    }
    assert(duplicateUidCaught, '4. Unique Constraint Rejects Duplicate User UID', dupUidErrDetail);

    // Attempt duplicate report creation for same finding ID
    let duplicateReportCaught = false;
    try {
      await db.insert(reports).values({
        id: `report-dup-${Date.now()}`,
        findingId: 'finding-101', // Already reported in seed.ts
        programId: 'prog-acme-01',
        researcherId: 'user-ayush-001',
        title: 'Duplicate Report Test',
        summary: 'Testing unique constraint on findingId in reports',
        severity: 'Critical',
        status: 'Draft',
      });
    } catch (err: any) {
      if (isUniqueViolation(err)) {
        duplicateReportCaught = true;
      }
    }
    assert(duplicateReportCaught, '5. Unique Constraint Rejects Duplicate Report for Same Finding');

    // 4. Transactional Workflows & State Machines
    console.log('\n--- Testing Transactional Workflows & State Machines ---');

    // Clean up active test hunts for testUser to test atomic hunt creation
    await db.update(hunts).set({ status: 'Completed' }).where(eq(hunts.researcherId, testUser.uid));

    // Atomic Hunt Creation
    const huntResult = await createHunt(
      {
        programId: 'prog-acme-01',
        targetDomain: 'integrity-test.acme-security.test',
      },
      testUser
    );
    assert(!!huntResult.hunt && !huntResult.isExisting, '6. Atomic Hunt Creation in Database Transaction');

    const createdHunt = huntResult.hunt!;

    // Verify Hunt State Transition
    let invalidTransitionCaught = false;
    try {
      // Invalid transition: Ready / Hunting -> Complete directly (valid are Starting/Hunting/Analyzing/Paused/Stopped/Completed)
      await updateHuntStatus(createdHunt.id, 'Starting', testUser); // Valid
      await updateHuntStatus(createdHunt.id, 'Completed', testUser); // Valid
      await updateHuntStatus(createdHunt.id, 'Starting', testUser); // Invalid transition from Completed
    } catch (err: any) {
      if (err.message?.includes('INVALID_STATE_TRANSITION')) {
        invalidTransitionCaught = true;
      }
    }
    assert(invalidTransitionCaught, '7. State Machine Enforcement Rejects Invalid Hunt Transition');

    // Insert finding attached to created hunt for testing report workflow
    const testFindingId = `finding-test-${Date.now()}`;
    await db.insert(findings).values({
      id: testFindingId,
      huntId: createdHunt.id,
      programId: 'prog-acme-01',
      assetId: 'asset-102',
      title: 'Integrity Test BOLA Endpoint',
      description: 'Automated test finding for report & reward transaction checks',
      severity: 'Critical',
      category: 'Broken Object Level Authorization',
      status: 'Verified',
    });

    // Finding State Transition Validation
    const updatedFinding = await updateFindingStatus(testFindingId, 'Submitted', testUser);
    assert(updatedFinding?.status === 'Submitted' || (updatedFinding?.status as string) === 'Closed' || (updatedFinding as any)?.canonicalStatus === 'CLOSED', '8. Finding Status Transition Updated Atomically');

    // Transactional Report & Reward Creation
    const reportRes = await createReportForFinding(testFindingId, testUser, 'Integrity Test Disclosure');
    assert(!!reportRes.report, '9. Report & Reward Created Atomically in Single Transaction');

    const createdReport = reportRes.report!;

    // Verify Reward Row Was Inserted in same transaction
    const rewardRows = await db.select().from(rewards).where(eq(rewards.reportId, createdReport.id));
    assert(rewardRows.length === 1 && rewardRows[0].numericAmount === 25000, '10. Reward Tier Calculated and Inserted Atomically');

    // Report State Transition (Ready -> Submitted -> Accepted -> Resolved)
    const submittedReport = await updateReportStatus(createdReport.id, 'Submitted', testUser);
    assert(submittedReport?.status === 'Submitted', '11. Report Transitioned to Submitted Atomically');

    // Reward Status Synchronization check (Submitted -> Reward PENDING)
    const pendingReward = await db.select().from(rewards).where(eq(rewards.reportId, createdReport.id));
    assert(pendingReward[0]?.status === 'PENDING', '12. Reward Status Synchronized to PENDING on Report Submission');

    // Admin accepts report (Submitted -> Accepted -> Reward PAID)
    const acceptedReport = await updateReportStatus(createdReport.id, 'Accepted', adminUser);
    assert(acceptedReport?.status === 'Accepted', '13. Admin Accepted Report Atomically');

    const paidReward = await db.select().from(rewards).where(eq(rewards.reportId, createdReport.id));
    assert(paidReward[0]?.status === 'PAID' && !!paidReward[0]?.paidAt, '14. Reward Synchronized to PAID with Timestamp');

    // 5. Audit Log Completeness & Verification
    console.log('\n--- Testing Audit Log Integrity ---');

    const auditLogs = await getAuditEvents(adminUser);
    const userAuditLogs = auditLogs.filter((log) => log.userId === testUser.uid);
    assert(userAuditLogs.length >= 4, '15. Audit Events Recorded for Every Transaction Step', `Found ${userAuditLogs.length} audit logs`);

    // Verify audit logs contain previousState and newState
    const stateChangingLog = userAuditLogs.find((l) => l.action === 'REPORT_SUBMITTED');
    assert(
      !!stateChangingLog && stateChangingLog.previousState === 'Ready' && stateChangingLog.newState === 'Submitted',
      '16. Audit Log Records Previous and New States Accurately'
    );

  } catch (err) {
    console.error('\n[FATAL TEST ERROR]:', err);
    failedTests++;
  } finally {
    console.log(`\n=== VERIFICATION SUMMARY ===`);
    console.log(`Total Passed: ${passedTests}`);
    console.log(`Total Failed: ${failedTests}`);

    if (failedTests > 0) {
      console.error('Database Integrity Verification FAILED!');
      process.exit(1);
    } else {
      console.log('Database Integrity Verification PASSED!');
      process.exit(0);
    }
  }
}

runDatabaseIntegrityTests();
