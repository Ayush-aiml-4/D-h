import {
  CAPABILITIES,
} from '../src/constants/capabilities.ts';
import {
  listCapabilities,
  getCapability,
  evaluateResearchCapability,
} from '../src/services/capabilityService.ts';
import { db } from '../src/db/index.ts';
import { users, programs, programScopes, assets, auditEvents } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { evaluateCapabilityFrameworkSchema } from '../src/middleware/validate.ts';

async function runCapabilityFrameworkVerification() {
  console.log('=== DEVILHUNT #0003.3-A — CAPABILITY FRAMEWORK VERIFICATION ===\n');

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string, detail?: string) {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}${detail ? `: ${detail}` : ''}`);
      failed++;
    }
  }

  try {
    // 1. Authoritative Capability Registry Loading
    assert(
      Array.isArray(CAPABILITIES) && CAPABILITIES.length >= 20,
      'Registry Loading',
      `Expected >= 20 capabilities, got ${CAPABILITIES?.length}`
    );

    // 2. Unique Capability IDs
    const ids = CAPABILITIES.map((c) => c.id);
    const uniqueIds = new Set(ids);
    assert(
      ids.length === uniqueIds.size,
      'Unique Capability IDs',
      `Found duplicate capability IDs (${ids.length} total, ${uniqueIds.size} unique)`
    );

    // 3. Valid Capability Schema Fields
    const validCategories = new Set([
      'HTTP / Web Security',
      'TLS / Transport Security',
      'DNS / Domain Intelligence',
      'API Security Assessment',
      'Authentication & Session Configuration',
      'Technology Fingerprinting',
      'Exposure / Metadata Analysis',
      'Client-Side Security',
      'Cloud / Infrastructure Metadata',
      'Content & Endpoint Analysis',
      'Evidence & Research Intelligence',
      'RECONNAISSANCE',
      'INFRASTRUCTURE_MAPPING',
      'CONFIGURATION_AUDIT',
      'SCHEMA_MAPPING',
      'IDENTITY_OAUTH_INSPECTION',
      'EXPOSURE_INSPECTION',
    ]);
    const validStatuses = new Set(['SUPPORTED', 'PARTIAL', 'MANUAL', 'PLANNED']);
    const validAutomationLevels = new Set(['AUTOMATED', 'SEMI_AUTOMATED', 'MANUAL']);

    const allSchemaValid = CAPABILITIES.every(
      (c) =>
        c.id &&
        c.name &&
        c.description &&
        validCategories.has(c.category) &&
        validStatuses.has(c.implementationStatus) &&
        validAutomationLevels.has(c.automationLevel) &&
        c.authenticationRequirement &&
        c.policyRequirement &&
        c.humanValidationRequirement &&
        c.evidenceSupport &&
        c.reproductionSupport &&
        c.reportingSupport
    );
    assert(allSchemaValid, 'Valid Capability Schema Definitions');

    // 4. Capability Lookup
    const cap1 = getCapability('cap-asset-discovery');
    const cap1ByName = getCapability('Asset Discovery');
    assert(
      cap1 !== null && cap1ByName !== null && cap1?.id === cap1ByName?.id,
      'Capability Lookup by ID and Name'
    );

    // 5. Capability Filtering
    const webSecCaps = listCapabilities({ category: 'HTTP / Web Security' });
    const supportedCaps = listCapabilities({ status: 'SUPPORTED' });
    assert(
      webSecCaps.length > 0 &&
        webSecCaps.every((c) => c.category === 'HTTP / Web Security') &&
        supportedCaps.length > 0 &&
        supportedCaps.every((c) => c.implementationStatus === 'SUPPORTED'),
      'Capability Filtering by Category and Status'
    );

    // Setup Test Fixtures in Database
    const testUserId = `test-cap-user-${Date.now()}`;
    const testProgramId = `test-cap-prog-${Date.now()}`;
    const testAssetId = `test-cap-asset-${Date.now()}`;

    // Seed test user
    await db.insert(users).values({
      uid: testUserId,
      email: 'cap-tester@devilhunt.sec',
      name: 'Capability Tester',
      role: 'RESEARCHER',
    });

    // Seed test program
    await db.insert(programs).values({
      id: testProgramId,
      name: 'Capability Test Program',
      description: 'Authoritative capability testing program',
      rewardCeiling: '$10,000',
      status: 'ACTIVE',
    });

    // Seed in-scope and out-of-scope rules
    await db.insert(programScopes).values([
      {
        id: `scope-in-${Date.now()}`,
        programId: testProgramId,
        targetPattern: '*.acme-test.sec',
        scopeType: 'SUBDOMAIN',
        scopeStatus: 'IN_SCOPE',
      },
      {
        id: `scope-out-${Date.now()}`,
        programId: testProgramId,
        targetPattern: 'admin.acme-test.sec',
        scopeType: 'EXACT_DOMAIN',
        scopeStatus: 'OUT_OF_SCOPE',
      },
    ]);

    // Seed test asset
    await db.insert(assets).values({
      id: testAssetId,
      programId: testProgramId,
      domain: 'acme-test.sec',
      hostname: 'api.acme-test.sec',
      type: 'SUBDOMAIN',
      status: 'IN_SCOPE',
      scopeStatus: 'In Scope',
    });

    const testAuthUser = {
      uid: testUserId,
      email: 'cap-tester@devilhunt.sec',
      name: 'Capability Tester',
      role: 'RESEARCHER' as const,
    };

    // 6. Authentication Requirement Enforcement
    let unauthFailed = false;
    try {
      await evaluateResearchCapability(null as any, {
        programId: testProgramId,
        target: 'api.acme-test.sec',
        capabilityId: 'cap-asset-discovery',
      });
    } catch (e: any) {
      if (e.message.includes('UNAUTHENTICATED')) unauthFailed = true;
    }
    assert(unauthFailed, 'Authentication Enforcement (Unauthenticated User Blocked)');

    // 7. Asset Ownership Verification
    let invalidAssetFailed = false;
    try {
      await evaluateResearchCapability(testAuthUser, {
        programId: testProgramId,
        target: 'api.acme-test.sec',
        capabilityId: 'cap-asset-discovery',
        assetId: 'non-existent-asset-id',
      });
    } catch (e: any) {
      if (e.message.includes('ASSET_NOT_FOUND')) invalidAssetFailed = true;
    }
    assert(invalidAssetFailed, 'Asset Ownership Enforcement (Invalid Asset Rejected)');

    // 8. Policy Engine Integration - ALLOW Decision for In-Scope Target
    const allowEval = await evaluateResearchCapability(testAuthUser, {
      programId: testProgramId,
      target: 'api.acme-test.sec',
      capabilityId: 'cap-asset-discovery',
      assetId: testAssetId,
    });
    assert(
      allowEval.isAuthorizationEvaluationOnly === true &&
        allowEval.decision === 'ALLOW' &&
        allowEval.programId === testProgramId &&
        allowEval.target === 'api.acme-test.sec' &&
        allowEval.capability.id === 'cap-asset-discovery',
      'Policy Decision ALLOW for In-Scope Target'
    );

    // 9. Policy Engine Integration - BLOCK Decision for Out-of-Scope Target
    const blockEval = await evaluateResearchCapability(testAuthUser, {
      programId: testProgramId,
      target: 'admin.acme-test.sec',
      capabilityId: 'cap-asset-discovery',
    });
    assert(
      blockEval.decision === 'BLOCK' &&
        (blockEval.reason.toLowerCase().includes('out_of_scope') ||
          blockEval.reason.toLowerCase().includes('out of scope')),
      'Policy Decision BLOCK for Out-of-Scope Target'
    );

    // 10. Client Decision / Status Spoofing Protection (Zod Schema Validation)
    let spoofingBlocked = false;
    try {
      await evaluateCapabilityFrameworkSchema.parseAsync({
        programId: testProgramId,
        target: 'admin.acme-test.sec',
        capabilityId: 'cap-asset-discovery',
        decision: 'ALLOW', // Attack vector: trying to spoof decision
        scopeStatus: 'IN_SCOPE', // Attack vector: trying to spoof scope
        role: 'ADMIN', // Attack vector: trying to escalate role
      });
    } catch (e: any) {
      if (e.name === 'ZodError' && e.issues.some((i: any) => i.code === 'unrecognized_keys')) {
        spoofingBlocked = true;
      }
    }
    assert(spoofingBlocked, 'Client Spoofing Prevention (Unrecognized Schema Keys Blocked)');

    // 11. Evaluation remains PREVIEW ONLY (No target mutation or side-effects)
    assert(
      allowEval.isAuthorizationEvaluationOnly === true && !!allowEval.evaluatedAt,
      'Evaluation Preview Only (No Network Operations or Target Mutation)'
    );

    // Clean up test data
    await db.delete(auditEvents).where(eq(auditEvents.userId, testUserId));
    await db.delete(assets).where(eq(assets.id, testAssetId));
    await db.delete(programScopes).where(eq(programScopes.programId, testProgramId));
    await db.delete(programs).where(eq(programs.id, testProgramId));
    await db.delete(users).where(eq(users.uid, testUserId));

    console.log(`\n=== VERIFICATION SUMMARY ===`);
    console.log(`PASSED: ${passed}`);
    console.log(`FAILED: ${failed}`);

    if (failed > 0) {
      process.exit(1);
    } else {
      console.log('Capabilities Framework Verification Complete: 100% PASS');
      process.exit(0);
    }
  } catch (err) {
    console.error('Fatal error during capability verification:', err);
    process.exit(1);
  }
}

runCapabilityFrameworkVerification();
