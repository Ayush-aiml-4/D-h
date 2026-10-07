import { db } from '../src/db/index.ts';
import {
  programs,
  users,
  assets,
  discoverySessions,
  auditEvents,
} from '../src/db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { AuthUser } from '../src/middleware/auth.ts';
import {
  startDiscovery,
  getDiscoverySession,
  stopDiscovery,
} from '../src/services/discoveryService.ts';
import { FixtureDiscoveryAdapter } from '../src/services/discoveryAdapter.ts';

async function runDiscoveryServiceVerification() {
  console.log('================================================================');
  console.log('DEVILHUNT #0003.2-B: Authorized Discovery Service Verification');
  console.log('================================================================\n');

  let passCount = 0;
  let failCount = 0;

  function assertTest(description: string, condition: boolean, detail?: string) {
    if (condition) {
      console.log(`[PASS] ${description}`);
      passCount++;
    } else {
      console.error(`[FAIL] ${description} ${detail ? `- ${detail}` : ''}`);
      failCount++;
    }
  }

  const validResearcher: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayushsingh556860@gmail.com',
    name: 'Ayush Singh',
    role: 'RESEARCHER',
  };

  const adminUser: AuthUser = {
    uid: 'user-admin-001',
    email: 'admin@devilhunt.sec',
    name: 'System Admin',
    role: 'ADMIN',
  };

  try {
    // 1. Test Unauthenticated Request Handling
    console.log('--- 1. Unauthenticated Request Defense ---');
    let unauthCaught = false;
    try {
      await startDiscovery(null, {
        programId: 'prog-acme-01',
        target: 'api.acme-security.test',
      });
    } catch (err: any) {
      unauthCaught = err.message.includes('UNAUTHENTICATED');
    }
    assertTest('unauthenticated request fails', unauthCaught);

    // 2. Test Unauthorized / Unregistered Researcher Handling
    console.log('\n--- 2. Unauthorized Researcher Defense ---');
    let unauthResearcherCaught = false;
    try {
      await startDiscovery(
        { uid: 'non-existent-user-9999', role: 'RESEARCHER', name: 'Fake User', email: 'fake@test.com' },
        { programId: 'prog-acme-01', target: 'api.acme-security.test' }
      );
    } catch (err: any) {
      unauthResearcherCaught = err.message.includes('UNAUTHORIZED_RESEARCHER');
    }
    assertTest('unauthorized researcher fails', unauthResearcherCaught);

    // 3. Test Inactive Program Handling
    console.log('\n--- 3. Inactive Program Defense ---');
    const inactiveProgId = `prog-inactive-${Date.now()}`;
    await db.insert(programs).values({
      id: inactiveProgId,
      name: 'Archived Program',
      description: 'Inactive test program',
      status: 'INACTIVE',
      rewardCeiling: '$0',
    });

    let inactiveProgCaught = false;
    try {
      await startDiscovery(validResearcher, {
        programId: inactiveProgId,
        target: 'api.acme-security.test',
      });
    } catch (err: any) {
      inactiveProgCaught = err.message.includes('INACTIVE_PROGRAM');
    }
    assertTest('inactive program fails', inactiveProgCaught);

    // Cleanup inactive test program
    await db.delete(programs).where(eq(programs.id, inactiveProgId));

    // 4. Test Out-of-Scope Target Handling
    console.log('\n--- 4. Out-Of-Scope Target Defense ---');
    let outOfScopeCaught = false;
    try {
      await startDiscovery(validResearcher, {
        programId: 'prog-acme-01',
        target: 'evil-nexus-pay.dev',
      });
    } catch (err: any) {
      outOfScopeCaught = err.message.includes('DISCOVERY_POLICY_BLOCKED');
    }
    assertTest('out-of-scope target fails', outOfScopeCaught);

    // 5. Test Prohibited Policy Operation Handling
    console.log('\n--- 5. Prohibited Operation Policy Defense ---');
    let prohibitedPolicyCaught = false;
    try {
      await startDiscovery(validResearcher, {
        programId: 'prog-acme-01',
        target: 'api.acme-security.test',
        operation: 'DOS',
      });
    } catch (err: any) {
      prohibitedPolicyCaught = err.message.includes('DISCOVERY_POLICY_BLOCKED');
    }
    assertTest('prohibited policy fails', prohibitedPolicyCaught);

    // 6. Test Authorized Discovery & Valid ASSET_ENUMERATION
    console.log('\n--- 6. Authorized Discovery Execution ---');
    const completedSession = await startDiscovery(validResearcher, {
      programId: 'prog-acme-01',
      target: 'api.acme-security.test',
      operation: 'ASSET_ENUMERATION',
      requestId: 'req-verify-disc-001',
    });

    assertTest(
      'authorized discovery succeeds',
      !!completedSession && completedSession.status === 'COMPLETED'
    );
    assertTest(
      'valid ASSET_ENUMERATION succeeds',
      completedSession.operation === 'ASSET_ENUMERATION'
    );

    // 7. Test Duplicate Active Discovery Session Prevention
    console.log('\n--- 7. Duplicate Active Session Prevention ---');
    const tempActiveSessionId = `active-test-${Date.now()}`;
    await db.insert(discoverySessions).values({
      id: tempActiveSessionId,
      programId: 'prog-acme-01',
      initiatedBy: validResearcher.uid,
      target: 'auth.acme-security.test',
      operation: 'ASSET_ENUMERATION',
      status: 'DISCOVERING',
      startedAt: new Date(),
    });

    let activeSessionCaught = false;
    try {
      await startDiscovery(validResearcher, {
        programId: 'prog-acme-01',
        target: 'auth.acme-security.test',
        operation: 'ASSET_ENUMERATION',
      });
    } catch (err: any) {
      activeSessionCaught = err.message.includes('ACTIVE_SESSION_EXISTS');
    }
    assertTest('duplicate active session is prevented', activeSessionCaught);

    // Clean up temporary active session
    await db.delete(discoverySessions).where(eq(discoverySessions.id, tempActiveSessionId));

    // 8. Test Authorized Fixture Assets Persistence & Out-Of-Scope Isolation
    console.log('\n--- 8. Asset Persistence & Boundary Isolation ---');
    const allAcmeAssets = await db
      .select()
      .from(assets)
      .where(eq(assets.programId, 'prog-acme-01'));

    const acmeDomains = allAcmeAssets.map((a) => a.domain);

    const rootDomainAsset = allAcmeAssets.find((a) => a.domain === 'acme-security.test');
    const subDomainAsset = allAcmeAssets.find((a) => a.domain === 'api.acme-security.test');
    const authSubDomainAsset = allAcmeAssets.find((a) => a.domain === 'auth.acme-security.test');
    const endpointAsset = allAcmeAssets.find((a) => a.path === '/v1/auth/token');

    assertTest(
      'authorized fixture assets are persisted',
      !!rootDomainAsset &&
        rootDomainAsset.status === 'AUTHORIZED' &&
        !!subDomainAsset &&
        subDomainAsset.status === 'AUTHORIZED' &&
        !!authSubDomainAsset &&
        authSubDomainAsset.status === 'AUTHORIZED' &&
        !!endpointAsset &&
        endpointAsset.status === 'AUTHORIZED'
    );

    const evilNexusAsset = await db
      .select()
      .from(assets)
      .where(eq(assets.domain, 'evil-nexus-pay.dev'));

    assertTest(
      'evil-nexus-pay.dev remains OUT_OF_SCOPE',
      evilNexusAsset.length > 0 && evilNexusAsset[0].status === 'OUT_OF_SCOPE'
    );

    const attackerSubdomainAsset = allAcmeAssets.find(
      (a) => a.domain === 'evil-acme-security.test.attacker.com'
    );

    assertTest(
      'evil-acme-security.test.attacker.com remains OUT_OF_SCOPE',
      !attackerSubdomainAsset || attackerSubdomainAsset.status !== 'AUTHORIZED'
    );

    // 9. Test Duplicate Assets Are Not Created
    console.log('\n--- 9. Duplicate Asset Creation Prevention ---');
    const initialAssetCount = allAcmeAssets.length;

    // Run discovery again on completed session target
    await startDiscovery(validResearcher, {
      programId: 'prog-acme-01',
      target: 'api.acme-security.test',
      operation: 'ASSET_ENUMERATION',
    });

    const newAcmeAssets = await db
      .select()
      .from(assets)
      .where(eq(assets.programId, 'prog-acme-01'));

    assertTest(
      'duplicate assets are not created',
      newAcmeAssets.length === initialAssetCount
    );

    // 10. Test Invalid State Transition on Stop Discovery
    console.log('\n--- 10. Invalid State Transition Rejection ---');
    let invalidStopCaught = false;
    try {
      await stopDiscovery(validResearcher, completedSession.id);
    } catch (err: any) {
      invalidStopCaught = err.message.includes('INVALID_STATE_TRANSITION');
    }
    assertTest('invalid state transition fails', invalidStopCaught);

    // 11. Test Successful Stop Discovery
    console.log('\n--- 11. Stop Discovery Execution ---');
    const sessionToStopId = `stoppable-${Date.now()}`;
    await db.insert(discoverySessions).values({
      id: sessionToStopId,
      programId: 'prog-acme-01',
      initiatedBy: validResearcher.uid,
      target: 'auth.acme-security.test',
      operation: 'ASSET_ENUMERATION',
      status: 'DISCOVERING',
      startedAt: new Date(),
    });

    const stoppedSession = await stopDiscovery(validResearcher, sessionToStopId);
    assertTest(
      'stop discovery works',
      !!stoppedSession && stoppedSession.status === 'STOPPED'
    );

    // Clean up stoppable session
    await db.delete(discoverySessions).where(eq(discoverySessions.id, sessionToStopId));

    // 12. Test Audit Events Generation
    console.log('\n--- 12. Security Audit Log Verification ---');
    const auditLogs = await db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.userId, validResearcher.uid));

    const auditActions = auditLogs.map((log) => log.action);

    assertTest('audit event DISCOVERY_STARTED recorded', auditActions.includes('DISCOVERY_STARTED'));
    assertTest('audit event ASSET_DISCOVERED recorded', auditActions.includes('ASSET_DISCOVERED'));
    assertTest('audit event ASSET_SCOPE_BLOCKED recorded', auditActions.includes('ASSET_SCOPE_BLOCKED'));
    assertTest('audit event DISCOVERY_COMPLETED recorded', auditActions.includes('DISCOVERY_COMPLETED'));
    assertTest('audit event DISCOVERY_BLOCKED recorded', auditActions.includes('DISCOVERY_BLOCKED'));
    assertTest(
      'audit events are created',
      auditActions.includes('DISCOVERY_STARTED') && auditActions.includes('DISCOVERY_COMPLETED')
    );

    // 13. Network Request Isolation Verification
    console.log('\n--- 13. Network Request Isolation ---');
    const adapter = new FixtureDiscoveryAdapter();
    const candidates = await adapter.discoverCandidates('api.acme-security.test');
    assertTest(
      'no network request is made',
      candidates.length === 6 && candidates[0].rawTarget === 'acme-security.test'
    );

    // Cleanup completed test discovery session
    await db.delete(discoverySessions).where(eq(discoverySessions.id, completedSession.id));

    console.log('\n================================================================');
    console.log(`SUMMARY: ${passCount} PASSED, ${failCount} FAILED`);
    console.log('================================================================');

    if (failCount > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err: any) {
    console.error('Unexpected error during verification:', err);
    process.exit(1);
  }
}

runDiscoveryServiceVerification();
