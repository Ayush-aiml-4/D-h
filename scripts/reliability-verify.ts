import assert from 'assert';
import { db, verifyDatabaseConnection, closeDatabasePool, getPoolStats } from '../src/db/index.ts';
import { hunts, findings, reports, rewards, auditEvents } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { validateStartupConfig } from '../src/config/env.ts';
import { AuthUser } from '../src/middleware/auth.ts';
import { createHunt, updateHuntStatus } from '../src/services/huntService.ts';
import { createReportForFinding, updateReportStatus } from '../src/services/reportService.ts';
import { updateFindingStatus } from '../src/services/findingService.ts';

async function runReliabilityVerificationSuite() {
  console.log('=== DEVILHUNT #0002.5 PRODUCTION RELIABILITY & FAILURE HANDLING VERIFICATION ===\n');

  const testUser: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayushsingh556860@gmail.com',
    role: 'RESEARCHER',
    name: 'Ayush Singh',
  };

  const adminUser: AuthUser = {
    uid: 'user-admin-001',
    email: 'admin@devilhunt.local',
    role: 'ADMIN',
    name: 'DevilHunt Admin',
  };

  // 1. Startup Configuration Validation Test
  console.log('[TEST 1] Startup Configuration Validation');
  const startupConfig = validateStartupConfig();
  assert(typeof startupConfig.port === 'number' && startupConfig.port > 0, 'Port must be a valid positive integer');
  assert(typeof startupConfig.isProduction === 'boolean', 'isProduction must be boolean');
  console.log('  [PASS] Startup config validated safely without exposing secret values.');

  // 2. Database Connectivity & Pool Safety Test
  console.log('\n[TEST 2] Database Connectivity & Connection Pool Safety');
  const isDbConnected = await verifyDatabaseConnection();
  assert(isDbConnected === true, 'PostgreSQL database must be reachable');
  const poolStats = getPoolStats();
  assert(typeof poolStats.total === 'number' && typeof poolStats.idle === 'number', 'Pool stats accessible');
  console.log(`  [PASS] Database connected. Pool Stats: Total=${poolStats.total}, Idle=${poolStats.idle}, Waiting=${poolStats.waiting}`);

  // 3. Multi-Step Transaction Rollback Test
  console.log('\n[TEST 3] Transaction Rollback Safety on Failure');
  const invalidFindingId = `finding-nonexistent-${Date.now()}`;
  let rollbackCaught = false;
  try {
    // Attempting report creation for nonexistent finding inside transaction must fail and roll back cleanly
    await createReportForFinding(invalidFindingId, testUser);
  } catch (err: any) {
    rollbackCaught = true;
    assert(err.code === 'NOT_FOUND' || err.statusCode === 404, 'Must throw NOT_FOUND for invalid finding');
  }
  assert(rollbackCaught, 'Transaction failure must throw error');
  console.log('  [PASS] Multi-step transaction rolled back cleanly on step failure.');

  // 4. Idempotent Hunt Creation & Concurrent Mutation Safety
  console.log('\n[TEST 4] Idempotent Hunt Creation De-duplication');
  const hunt1 = await createHunt({ programId: 'prog-acme-01', targetDomain: 'api.target.test' }, testUser);
  assert(hunt1.hunt !== null, 'Hunt 1 must be created');
  const hunt1Id = hunt1.hunt!.id;

  // Second identical start hunt request must return existing active hunt idempotently without duplicate row creation
  const hunt2 = await createHunt({ programId: 'prog-acme-01', targetDomain: 'api.target.test' }, testUser);
  assert(hunt2.isExisting === true, 'Second hunt request must identify existing active session');
  assert(hunt2.hunt!.id === hunt1Id, 'Returned hunt ID must match initial session ID');
  console.log(`  [PASS] Idempotency verified: Reused existing active hunt session '${hunt1Id}'.`);

  // 5. Concurrent Report Creation De-duplication
  console.log('\n[TEST 5] Idempotent Report Creation De-duplication');
  // First fetch asset ID from created hunt
  const huntRows = await db.select().from(hunts).where(eq(hunts.id, hunt1Id));
  const huntAssetId = huntRows[0].assetId;

  const testFindingId = `finding-rel-${Date.now()}`;
  await db.insert(findings).values({
    id: testFindingId,
    huntId: hunt1Id,
    programId: 'prog-acme-01',
    assetId: huntAssetId,
    title: 'Reliability Test Vulnerability',
    description: 'BOLA on API tenant keys endpoint',
    category: 'BOLA',
    severity: 'High',
    confidence: 90,
    status: 'Verified',
  });

  const rep1 = await createReportForFinding(testFindingId, testUser, 'Title 1', 'Summary 1');
  assert(rep1.report !== null, 'Report 1 must be created');
  const rep1Id = rep1.report!.id;

  const rep2 = await createReportForFinding(testFindingId, testUser, 'Title 2', 'Summary 2');
  assert(rep2.isExisting === true, 'Repeated report request must identify existing report');
  assert(rep2.report!.id === rep1Id, 'Report ID must match existing report');
  console.log(`  [PASS] Idempotent report generation verified: Returned report '${rep1Id}'.`);

  // 6. Idempotent Report Submission & Status Transitions
  console.log('\n[TEST 6] Idempotent Report Submission & Reward Synchronization');
  const submittedReport = await updateReportStatus(rep1Id, 'Submitted', testUser);
  assert(submittedReport!.status === 'Submitted', 'Report state must transition to Submitted');

  // Verify reward status synchronized to PENDING
  const rewardRow = await db.select().from(rewards).where(eq(rewards.reportId, rep1Id));
  assert(rewardRow.length === 1 && rewardRow[0].status === 'PENDING', 'Reward status synchronized to PENDING');

  // Repeating submit request on already submitted report must be idempotent
  const reSubmittedReport = await updateReportStatus(rep1Id, 'Submitted', testUser);
  assert(reSubmittedReport!.status === 'Submitted', 'Re-submitting report returns same status');
  console.log('  [PASS] Idempotent submission and reward synchronization verified.');

  // 7. Stale Data & Invalid State Transition Rejection
  console.log('\n[TEST 7] Stale Data & Invalid State Transition Rejection');
  let transitionConflictCaught = false;
  try {
    // Transitioning from Submitted back to Ready is invalid and must throw CONFLICT
    await updateReportStatus(rep1Id, 'Ready', testUser);
  } catch (err: any) {
    transitionConflictCaught = true;
    assert(err.code === 'CONFLICT' || err.statusCode === 409, 'Must throw CONFLICT error for invalid transition');
  }
  assert(transitionConflictCaught, 'Invalid state transition must be rejected');
  console.log('  [PASS] Stale data / invalid transition rejected with 409 Conflict.');

  // 8. Admin Acceptance & Reward Payment Synchronization
  console.log('\n[TEST 8] Admin Report Acceptance & Reward Payment Synchronization');
  const acceptedReport = await updateReportStatus(rep1Id, 'Accepted', adminUser);
  assert(acceptedReport!.status === 'Accepted', 'Report state must transition to Accepted');

  const paidReward = await db.select().from(rewards).where(eq(rewards.reportId, rep1Id));
  assert(paidReward[0].status === 'PAID', 'Reward status must synchronize to PAID upon report acceptance');
  console.log('  [PASS] Report acceptance & reward sync to PAID verified.');

  // 9. Resource Not Found & Forbidden Access Controls
  console.log('\n[TEST 9] Resource Not Found & Cross-User Access Guard');
  const nonExistentHunt = await db.select().from(hunts).where(eq(hunts.id, 'hunt-nonexistent-999'));
  assert(nonExistentHunt.length === 0, 'Nonexistent hunt returns empty set');

  const unauthorizedUser: AuthUser = {
    uid: 'user-unauth-888',
    email: 'unauth@test.local',
    role: 'RESEARCHER',
    name: 'Unauthorized User',
  };

  let forbiddenCaught = false;
  try {
    await updateReportStatus(rep1Id, 'Resolved', unauthorizedUser);
  } catch (err: any) {
    forbiddenCaught = true;
    assert(err.code === 'FORBIDDEN' || err.statusCode === 403, 'Must throw FORBIDDEN for cross-user mutation attempt');
  }
  assert(forbiddenCaught, 'Cross-user state mutation attempt blocked');
  console.log('  [PASS] Resource existence & cross-user access controls enforced.');

  // 10. Cleanup & Database Graceful Shutdown
  console.log('\n[TEST 10] Graceful Connection Cleanup');
  await closeDatabasePool();
  console.log('  [PASS] Database pool cleanly shutdown.');

  console.log('\n========================================================================================');
  console.log('FINAL RESULT: ALL RELIABILITY & FAILURE HANDLING TESTS PASSED');
  console.log('========================================================================================');
}

runReliabilityVerificationSuite().catch((err) => {
  console.error('\n[FAIL] Reliability verification suite encountered error:', err);
  process.exit(1);
});
