import assert from 'assert';
import { db, verifyDatabaseConnection, closeDatabasePool } from '../src/db/index.ts';
import { programs, programScopes, users, auditEvents } from '../src/db/schema.ts';
import { eq, desc } from 'drizzle-orm';
import { evaluatePolicy, parseTarget, matchScopeRule } from '../src/services/policyEngine.ts';
import { AuthUser } from '../src/middleware/auth.ts';
import { POLICY_DECISIONS, SCOPE_STATUSES } from '../src/constants/scope.ts';

async function runScopeAuthorizationVerificationSuite() {
  console.log('=== DEVILHUNT #0003.1 SERVER-SIDE SCOPE & AUTHORIZATION ENGINE VERIFICATION ===\n');

  // Verify DB Connection
  const isDbConnected = await verifyDatabaseConnection();
  assert(isDbConnected === true, 'Database must be reachable');

  const validResearcher: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayushsingh556860@gmail.com',
    role: 'RESEARCHER',
    name: 'Ayush Singh',
  };

  const unauthorizedResearcher: AuthUser = {
    uid: 'user-unregistered-999',
    email: 'unauth@attacker.test',
    role: 'RESEARCHER',
    name: 'Unregistered User',
  };

  // Helper to ensure target user exists in DB directory for valid tests
  const existingUser = await db.select().from(users).where(eq(users.uid, validResearcher.uid));
  if (existingUser.length === 0) {
    await db.insert(users).values({
      uid: validResearcher.uid,
      email: validResearcher.email,
      name: validResearcher.name,
      role: validResearcher.role,
    });
  }

  // 1. Authorized researcher + exact in-scope target → ALLOW
  console.log('[TEST 1] Authorized Researcher + Exact In-Scope Target → ALLOW');
  const res1 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'api.acme-security.test',
  });
  assert.strictEqual(res1.decision, POLICY_DECISIONS.ALLOW, 'Exact in-scope target must yield ALLOW');
  console.log('  [PASS] Target api.acme-security.test -> ALLOW');

  // 2. Out-of-scope target → BLOCK
  console.log('\n[TEST 2] Explicit Out-of-Scope Target → BLOCK');
  const res2 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'out-of-scope.acme-security.test',
  });
  assert.strictEqual(res2.decision, POLICY_DECISIONS.BLOCK, 'Out-of-scope target must yield BLOCK');
  console.log('  [PASS] Target out-of-scope.acme-security.test -> BLOCK');

  // 3. Unauthenticated request → BLOCK
  console.log('\n[TEST 3] Unauthenticated Request → BLOCK');
  const res3 = await evaluatePolicy(null as any, {
    programId: 'prog-acme-01',
    target: 'api.acme-security.test',
  });
  assert.strictEqual(res3.decision, POLICY_DECISIONS.BLOCK, 'Unauthenticated request must yield BLOCK');
  console.log('  [PASS] Null user context -> BLOCK');

  // 4. Unauthorized / Unregistered researcher → BLOCK
  console.log('\n[TEST 4] Unauthorized / Unregistered Researcher → BLOCK');
  const res4 = await evaluatePolicy(unauthorizedResearcher, {
    programId: 'prog-acme-01',
    target: 'api.acme-security.test',
  });
  assert.strictEqual(res4.decision, POLICY_DECISIONS.BLOCK, 'Unregistered researcher must yield BLOCK');
  console.log('  [PASS] Unregistered researcher -> BLOCK');

  // 5. Inactive program → BLOCK
  console.log('\n[TEST 5] Inactive Program → BLOCK');
  // Temporarily set a test program status to INACTIVE or test non-existent/archived program
  const inactiveProgId = `prog-inactive-${Date.now()}`;
  await db.insert(programs).values({
    id: inactiveProgId,
    name: 'Inactive Test Program',
    description: 'Testing inactive program policy decision',
    status: 'PAUSED',
    rewardCeiling: '$1,000',
  });

  const res5 = await evaluatePolicy(validResearcher, {
    programId: inactiveProgId,
    target: 'api.acme-security.test',
  });
  assert.strictEqual(res5.decision, POLICY_DECISIONS.BLOCK, 'Inactive program must yield BLOCK');
  console.log('  [PASS] Inactive program -> BLOCK');

  // 6. Disabled scope → BLOCK
  console.log('\n[TEST 6] Disabled Scope → BLOCK');
  const res6 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'legacy.acme-security.test',
  });
  assert.strictEqual(res6.decision, POLICY_DECISIONS.BLOCK, 'Disabled scope must yield BLOCK');
  console.log('  [PASS] Disabled scope -> BLOCK');

  // 7. Unknown policy / non-existent program → BLOCK
  console.log('\n[TEST 7] Unknown Policy / Non-Existent Program → BLOCK');
  const res7 = await evaluatePolicy(validResearcher, {
    programId: 'prog-nonexistent-999',
    target: 'api.acme-security.test',
  });
  assert.strictEqual(res7.decision, POLICY_DECISIONS.BLOCK, 'Unknown program must yield BLOCK');
  console.log('  [PASS] Unknown program -> BLOCK');

  // 8. Prohibited operation → BLOCK
  console.log('\n[TEST 8] Explicitly Prohibited Operation → BLOCK');
  const res8 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'api.acme-security.test',
    operation: 'DOS',
  });
  assert.strictEqual(res8.decision, POLICY_DECISIONS.BLOCK, 'Prohibited operation DOS must yield BLOCK');
  console.log('  [PASS] Operation DOS -> BLOCK');

  // 9. Review-required operation / scope → REVIEW_REQUIRED
  console.log('\n[TEST 9] Review-Required Operation / Scope → REVIEW_REQUIRED');
  const res9 = await evaluatePolicy(validResearcher, {
    programId: 'prog-nexus-02',
    target: 'sensitive.nexus-pay.dev',
  });
  assert.strictEqual(res9.decision, POLICY_DECISIONS.REVIEW_REQUIRED, 'Review-required scope must yield REVIEW_REQUIRED');
  console.log('  [PASS] Sensitive scope sensitive.nexus-pay.dev -> REVIEW_REQUIRED');

  // 10. Hostname-boundary bypass → BLOCK
  console.log('\n[TEST 10] Hostname-Boundary Bypass Attempt → BLOCK');
  const res10 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'api.acme-security.test.attacker.com',
  });
  assert.strictEqual(res10.decision, POLICY_DECISIONS.BLOCK, 'Hostname boundary bypass must yield BLOCK');
  console.log('  [PASS] Target api.acme-security.test.attacker.com -> BLOCK');

  // 11. Subdomain-boundary bypass → BLOCK
  console.log('\n[TEST 11] Subdomain-Boundary Bypass Attempt → BLOCK');
  const res11a = await evaluatePolicy(validResearcher, {
    programId: 'prog-nexus-02',
    target: 'evil-nexus-pay.dev',
  });
  assert.strictEqual(res11a.decision, POLICY_DECISIONS.BLOCK, 'Prefix lookalike domain evil-nexus-pay.dev must yield BLOCK');

  const res11b = await evaluatePolicy(validResearcher, {
    programId: 'prog-nexus-02',
    target: 'nexus-pay.dev.attacker.com',
  });
  assert.strictEqual(res11b.decision, POLICY_DECISIONS.BLOCK, 'Suffix lookalike domain nexus-pay.dev.attacker.com must yield BLOCK');
  console.log('  [PASS] Subdomain boundary bypass targets -> BLOCK');

  // 12. Malformed target → BLOCK
  console.log('\n[TEST 12] Malformed Target Format → BLOCK');
  const res12 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'http://<invalid-url>?script=1',
  });
  assert.strictEqual(res12.decision, POLICY_DECISIONS.BLOCK, 'Malformed target must yield BLOCK');
  console.log('  [PASS] Malformed target -> BLOCK');

  // 13. Malicious lookalike hostname → BLOCK
  console.log('\n[TEST 13] Malicious Lookalike Hostname → BLOCK');
  const res13 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'acme-security-test.com',
  });
  assert.strictEqual(res13.decision, POLICY_DECISIONS.BLOCK, 'Lookalike hostname must yield BLOCK');
  console.log('  [PASS] Lookalike hostname acme-security-test.com -> BLOCK');

  // 14. Spoofed researcherId in payload → Ignored / Evaluated against token user
  console.log('\n[TEST 14] Spoofed researcherId in Payload → Ignored');
  const spoofedReq: any = {
    programId: 'prog-acme-01',
    target: 'api.acme-security.test',
    researcherId: 'admin-user-override',
  };
  const res14 = await evaluatePolicy(validResearcher, spoofedReq);
  assert.strictEqual(res14.decision, POLICY_DECISIONS.ALLOW, 'Spoofed researcherId in payload is ignored');
  console.log('  [PASS] Spoofed researcherId in request body ignored safely.');

  // 15. Spoofed scopeStatus in payload → Ignored
  console.log('\n[TEST 15] Spoofed scopeStatus in Payload → Ignored');
  const spoofedScopeReq: any = {
    programId: 'prog-acme-01',
    target: 'out-of-scope.acme-security.test',
    scopeStatus: 'IN_SCOPE',
  };
  const res15 = await evaluatePolicy(validResearcher, spoofedScopeReq);
  assert.strictEqual(res15.decision, POLICY_DECISIONS.BLOCK, 'Spoofed scopeStatus cannot override DB rule');
  console.log('  [PASS] Spoofed scopeStatus ignored; out-of-scope target remains BLOCK.');

  // 16. Spoofed policy decision in payload → Ignored
  console.log('\n[TEST 16] Spoofed policy decision in Payload → Ignored');
  const spoofedPolicyReq: any = {
    programId: 'prog-acme-01',
    target: 'out-of-scope.acme-security.test',
    decision: 'ALLOW',
  };
  const res16 = await evaluatePolicy(validResearcher, spoofedPolicyReq);
  assert.strictEqual(res16.decision, POLICY_DECISIONS.BLOCK, 'Spoofed decision in payload ignored');
  console.log('  [PASS] Spoofed decision in request body ignored; remains BLOCK.');

  // 17. Valid authorized operation → ALLOW
  console.log('\n[TEST 17] Valid Authorized Operation → ALLOW');
  const res17 = await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'api.acme-security.test',
    operation: 'RECONNAISSANCE',
  });
  assert.strictEqual(res17.decision, POLICY_DECISIONS.ALLOW, 'Valid operation on in-scope target must yield ALLOW');
  console.log('  [PASS] Operation RECONNAISSANCE on api.acme-security.test -> ALLOW');

  // 18. Blocked operation creates audit event
  console.log('\n[TEST 18] Blocked Operation Creates Audit Event');
  const testRequestId = `req-test-audit-${Date.now()}`;
  await evaluatePolicy(validResearcher, {
    programId: 'prog-acme-01',
    target: 'unauthorized-target.com',
  }, testRequestId);

  const auditRows = await db
    .select()
    .from(auditEvents)
    .where(eq(auditEvents.action, 'POLICY_EVALUATE_BLOCK'))
    .orderBy(desc(auditEvents.createdAt))
    .limit(1);

  assert(auditRows.length > 0, 'Audit event row must be recorded for blocked operation');
  console.log('  [PASS] Audit event POLICY_EVALUATE_BLOCK recorded successfully.');

  // 19. Audit event contains no secret/token
  console.log('\n[TEST 19] Audit Event Record Contains No Secret or Token Leak');
  const latestAudit = auditRows[0];
  const auditString = JSON.stringify(latestAudit);
  assert(!auditString.toLowerCase().includes('bearer'), 'Audit log must not contain Bearer tokens');
  assert(!auditString.toLowerCase().includes('secret'), 'Audit log must not contain secret values');
  console.log('  [PASS] Verified audit log contains zero credential leaks.');

  // Clean up test program
  await db.delete(programs).where(eq(programs.id, inactiveProgId));
  await closeDatabasePool();

  console.log('\n========================================================================================');
  console.log('FINAL RESULT: ALL 19 SCOPE & AUTHORIZATION SUITE SCENARIOS PASSED SUCCESSFULLY');
  console.log('========================================================================================');
}

runScopeAuthorizationVerificationSuite().catch((err) => {
  console.error('\n[FAIL] Scope & Authorization verification suite encountered error:', err);
  process.exit(1);
});
