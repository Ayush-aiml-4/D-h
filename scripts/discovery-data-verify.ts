import { db } from '../src/db/index.ts';
import {
  programs,
  users,
  programScopes,
  assets,
  discoverySessions,
} from '../src/db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { DISCOVERY_SESSION_STATUSES, DISCOVERY_ASSET_TYPES, DISCOVERY_ASSET_STATUSES } from '../src/constants/discovery.ts';

async function runDiscoveryDataVerification() {
  console.log('====================================================');
  console.log('DEVILHUNT #0003.2-A: Discovery Data Foundation Verification');
  console.log('====================================================\n');

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

  try {
    // 1. Fictional Seed Data Verification
    console.log('--- 1. Fictional Seed Data Verification ---');
    const allAssets = await db.select().from(assets);
    const assetDomains = allAssets.map((a) => a.domain);

    const requiredDomains = [
      'acme-security.test',
      'api.acme-security.test',
      'auth.acme-security.test',
      'nexus-pay.dev',
      'checkout.nexus-pay.dev',
      'starlight-cloud.test',
      'vault-auth.starlight-cloud.test',
    ];

    for (const domain of requiredDomains) {
      assertTest(
        `Fictional seed domain present: ${domain}`,
        assetDomains.includes(domain)
      );
    }

    // Check controlled test candidate: out-of-scope lookalike
    const lookalikeAsset = allAssets.find((a) => a.domain === 'evil-nexus-pay.dev');
    assertTest(
      'Controlled test candidate out-of-scope lookalike present (evil-nexus-pay.dev)',
      !!lookalikeAsset && lookalikeAsset.status === 'OUT_OF_SCOPE'
    );

    // Check seeded discovery sessions
    const seededSessions = await db.select().from(discoverySessions);
    assertTest('Seeded DiscoverySessions exist in database', seededSessions.length >= 2);

    // 2. DiscoverySession Creation & Valid Relationships
    console.log('\n--- 2. DiscoverySession Creation & Relationships ---');
    const testSessionId = `test-ds-${Date.now()}`;
    await db.insert(discoverySessions).values({
      id: testSessionId,
      programId: 'prog-acme-01',
      initiatedBy: 'user-ayush-001',
      targetScopeId: 'scope-acme-101',
      target: 'api.acme-security.test',
      operation: 'AUTHORIZED_DISCOVERY',
      status: DISCOVERY_SESSION_STATUSES.READY,
      requestId: 'req-verify-001',
    });

    const [createdSession] = await db
      .select()
      .from(discoverySessions)
      .where(eq(discoverySessions.id, testSessionId));

    assertTest(
      'DiscoverySession creation successfully persisted',
      !!createdSession && createdSession.target === 'api.acme-security.test'
    );

    // Verify program relationship
    const [linkedProgram] = await db
      .select()
      .from(programs)
      .where(eq(programs.id, createdSession.programId));
    assertTest(
      'DiscoverySession -> Program relationship valid',
      !!linkedProgram && linkedProgram.id === 'prog-acme-01'
    );

    // Verify researcher relationship
    const [linkedUser] = await db
      .select()
      .from(users)
      .where(eq(users.uid, createdSession.initiatedBy));
    assertTest(
      'DiscoverySession -> Researcher (User) relationship valid',
      !!linkedUser && linkedUser.uid === 'user-ayush-001'
    );

    // Verify scope relationship
    const [linkedScope] = await db
      .select()
      .from(programScopes)
      .where(eq(programScopes.id, createdSession.targetScopeId!));
    assertTest(
      'DiscoverySession -> Target Scope relationship valid',
      !!linkedScope && linkedScope.id === 'scope-acme-101'
    );

    // 3. Valid Asset Creation & Relationships
    console.log('\n--- 3. Asset Creation & Relationships ---');
    const testAssetId = `test-ast-${Date.now()}`;
    await db.insert(assets).values({
      id: testAssetId,
      programId: 'prog-acme-01',
      scopeId: 'scope-acme-101',
      domain: 'test-api-sub.acme-security.test',
      type: DISCOVERY_ASSET_TYPES.SUBDOMAIN,
      hostname: 'test-api-sub.acme-security.test',
      url: 'https://test-api-sub.acme-security.test',
      path: '/',
      status: DISCOVERY_ASSET_STATUSES.AUTHORIZED,
      scopeStatus: 'In Scope',
      technology: 'Node.js Express',
      discoverySource: 'AUTHORIZED_DISCOVERY',
      confidence: 100,
    });

    const [createdAsset] = await db
      .select()
      .from(assets)
      .where(eq(assets.id, testAssetId));

    assertTest(
      'Asset creation with extended fields persisted',
      !!createdAsset && createdAsset.type === DISCOVERY_ASSET_TYPES.SUBDOMAIN
    );

    // 4. Parent / Child Asset Hierarchy
    console.log('\n--- 4. Parent / Child Asset Hierarchy ---');
    const childAssetId = `test-child-ast-${Date.now()}`;
    await db.insert(assets).values({
      id: childAssetId,
      programId: 'prog-acme-01',
      scopeId: 'scope-acme-101',
      parentAssetId: testAssetId,
      domain: 'test-api-sub.acme-security.test',
      type: DISCOVERY_ASSET_TYPES.API_ENDPOINT,
      hostname: 'test-api-sub.acme-security.test',
      url: 'https://test-api-sub.acme-security.test/v1/health',
      path: '/v1/health',
      httpMethod: 'GET',
      status: DISCOVERY_ASSET_STATUSES.AUTHORIZED,
      scopeStatus: 'In Scope',
      technology: 'JSON REST Endpoint',
      discoverySource: 'AUTHORIZED_DISCOVERY',
      confidence: 100,
    });

    const [createdChild] = await db
      .select()
      .from(assets)
      .where(eq(assets.id, childAssetId));

    assertTest(
      'Child asset successfully references parentAssetId',
      !!createdChild && createdChild.parentAssetId === testAssetId
    );

    // 5. Duplicate Prevention
    console.log('\n--- 5. Duplicate Prevention ---');
    let duplicateCaught = false;
    try {
      // Duplicate insertion with exact same program_id, domain, path, http_method
      await db.insert(assets).values({
        id: `dup-ast-${Date.now()}`,
        programId: 'prog-acme-01',
        scopeId: 'scope-acme-101',
        domain: 'api.acme-security.test',
        type: DISCOVERY_ASSET_TYPES.API_ENDPOINT,
        hostname: 'api.acme-security.test',
        url: 'https://api.acme-security.test/v1/auth/token',
        path: '/v1/auth/token',
        httpMethod: 'POST',
        status: DISCOVERY_ASSET_STATUSES.AUTHORIZED,
      });
    } catch (err: any) {
      duplicateCaught = true;
    }
    assertTest(
      'Duplicate asset insertion rejected by database unique constraint',
      duplicateCaught
    );

    // 6. Invalid Foreign Key Rejection
    console.log('\n--- 6. Invalid Foreign Key Rejection ---');
    let invalidProgFkCaught = false;
    try {
      await db.insert(discoverySessions).values({
        id: `invalid-fk-sess-${Date.now()}`,
        programId: 'non-existent-program-9999',
        initiatedBy: 'user-ayush-001',
        target: 'invalid.test',
        operation: 'AUTHORIZED_DISCOVERY',
        status: 'READY',
      });
    } catch (err: any) {
      invalidProgFkCaught = true;
    }
    assertTest(
      'Invalid programId foreign key rejected by database',
      invalidProgFkCaught
    );

    let invalidUserFkCaught = false;
    try {
      await db.insert(discoverySessions).values({
        id: `invalid-user-sess-${Date.now()}`,
        programId: 'prog-acme-01',
        initiatedBy: 'non-existent-user-9999',
        target: 'api.acme-security.test',
        operation: 'AUTHORIZED_DISCOVERY',
        status: 'READY',
      });
    } catch (err: any) {
      invalidUserFkCaught = true;
    }
    assertTest(
      'Invalid initiatedBy (user) foreign key rejected by database',
      invalidUserFkCaught
    );

    let invalidParentAssetFkCaught = false;
    try {
      await db.insert(assets).values({
        id: `invalid-parent-ast-${Date.now()}`,
        programId: 'prog-acme-01',
        parentAssetId: 'non-existent-parent-asset-9999',
        domain: 'test.acme-security.test',
        type: 'SUBDOMAIN',
        status: 'AUTHORIZED',
      });
    } catch (err: any) {
      invalidParentAssetFkCaught = true;
    }
    assertTest(
      'Invalid parentAssetId foreign key rejected by database',
      invalidParentAssetFkCaught
    );

    // 7. Status and Type Validation
    console.log('\n--- 7. Status and Type Validation ---');
    const validSessionStatuses = Object.values(DISCOVERY_SESSION_STATUSES);
    const validAssetTypes = Object.values(DISCOVERY_ASSET_TYPES);
    const validAssetStatuses = Object.values(DISCOVERY_ASSET_STATUSES);

    assertTest(
      'Session status READY is valid',
      validSessionStatuses.includes('READY')
    );
    assertTest(
      'Session status DISCOVERING is valid',
      validSessionStatuses.includes('DISCOVERING')
    );
    assertTest(
      'Session status BLOCKED is valid',
      validSessionStatuses.includes('BLOCKED')
    );
    assertTest(
      'Asset type SUBDOMAIN is valid',
      validAssetTypes.includes('SUBDOMAIN')
    );
    assertTest(
      'Asset status AUTHORIZED is valid',
      validAssetStatuses.includes('AUTHORIZED')
    );

    // 8. Persistence After Reload
    console.log('\n--- 8. Persistence Verification ---');
    const [reloadedSession] = await db
      .select()
      .from(discoverySessions)
      .where(eq(discoverySessions.id, testSessionId));

    assertTest(
      'DiscoverySession persists upon re-querying database',
      !!reloadedSession && reloadedSession.id === testSessionId
    );

    // Clean up temporary test entries
    await db.delete(assets).where(eq(assets.id, childAssetId));
    await db.delete(assets).where(eq(assets.id, testAssetId));
    await db.delete(discoverySessions).where(eq(discoverySessions.id, testSessionId));

    console.log('\n====================================================');
    console.log(`SUMMARY: ${passCount} PASSED, ${failCount} FAILED`);
    console.log('====================================================');

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

runDiscoveryDataVerification();
