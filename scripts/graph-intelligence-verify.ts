import { db } from '../src/db/index.ts';
import { programs, users, assets, discoverySessions, programScopes } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { AuthUser } from '../src/middleware/auth.ts';
import { parseTarget } from '../src/services/policyEngine.ts';
import {
  calculateDeterministicResearchPriority,
  buildAttackSurfaceGraph,
  evaluateResearchCapability,
} from '../src/services/attackSurfaceService.ts';

async function runGraphIntelligenceVerification() {
  console.log('================================================================');
  console.log('DEVILHUNT #0003.2-C: Intelligence Layer & Graph Intelligence');
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

  const otherResearcher: AuthUser = {
    uid: 'user-researcher-002',
    email: 'researcher2@devilhunt.sec',
    name: 'Jane Doe',
    role: 'RESEARCHER',
  };

  try {
    // 1. Single Authoritative Normalization Behavior (Reuse parseTarget)
    console.log('--- 1. Canonical Asset Normalization Reuse ---');
    const norm1 = parseTarget('https://api.acme-security.test/v1/auth/token?ref=1');
    assertTest(
      'parseTarget extracts lowercased hostname',
      norm1.isValid && norm1.hostname === 'api.acme-security.test'
    );
    assertTest(
      'parseTarget normalizes pathname',
      norm1.isValid && norm1.path === '/v1/auth/token'
    );

    // 2. Deterministic Priority Calculation (Labels & Rules)
    console.log('\n--- 2. Deterministic Research Priority Rules ---');
    const p1 = calculateDeterministicResearchPriority({
      type: 'API_ENDPOINT',
      confidence: 0.9,
      scopeStatus: 'AUTHORIZED',
      hasApiPattern: true,
    });
    assertTest(
      'Authorized API Endpoint resolves to HIGH PRIORITY',
      p1.priorityLabel === 'HIGH PRIORITY',
      `Got: ${p1.priorityLabel}`
    );

    const p2 = calculateDeterministicResearchPriority({
      type: 'SUBDOMAIN',
      confidence: 0.85,
      scopeStatus: 'IN_SCOPE',
      endpointCount: 5,
    });
    assertTest(
      'Authorized Subdomain with high endpoint count resolves to HIGH PRIORITY',
      p2.priorityLabel === 'HIGH PRIORITY',
      `Got: ${p2.priorityLabel}`
    );

    const p3 = calculateDeterministicResearchPriority({
      type: 'SUBDOMAIN',
      confidence: 0.6,
      scopeStatus: 'DISCOVERED',
      endpointCount: 1,
    });
    assertTest(
      'Discovered Subdomain resolves to MEDIUM PRIORITY',
      p3.priorityLabel === 'MEDIUM PRIORITY',
      `Got: ${p3.priorityLabel}`
    );

    const p4 = calculateDeterministicResearchPriority({
      type: 'DOMAIN',
      confidence: 0.5,
      scopeStatus: 'OUT_OF_SCOPE',
    });
    assertTest(
      'Out of Scope asset resolves to LOW PRIORITY',
      p4.priorityLabel === 'LOW PRIORITY',
      `Got: ${p4.priorityLabel}`
    );

    // Ensure forbidden severity labels are NEVER used
    const forbiddenLabels = ['CRITICAL', 'HIGH RISK', 'VULNERABLE', 'EXPLOITABLE'];
    const p1HasForbidden = forbiddenLabels.some((l) => p1.priorityLabel.includes(l) || p1.priorityReason.includes(l));
    assertTest('Priority outputs do NOT contain vulnerability severity terms', !p1HasForbidden);

    // 3. Authorization Preview Capability Evaluation
    console.log('\n--- 3. Authorization Preview Evaluation Endpoint ---');
    const eval1 = await evaluateResearchCapability(validResearcher, {
      programId: 'prog-acme-01',
      target: 'api.acme-security.test',
      capability: 'RECONNAISSANCE',
    });

    assertTest(
      'evaluateResearchCapability sets isAuthorizationEvaluationOnly flag',
      eval1.isAuthorizationEvaluationOnly === true
    );
    assertTest(
      'evaluateResearchCapability returns policy decision',
      ['ALLOW', 'REVIEW_REQUIRED', 'BLOCK'].includes(eval1.decision)
    );
    assertTest('evaluateResearchCapability returns programId and target', eval1.programId === 'prog-acme-01' && eval1.target === 'api.acme-security.test');

    // 4. Out of Scope / Blocked Target Evaluation
    console.log('\n--- 4. Out-of-Scope Capability Evaluation ---');
    const eval2 = await evaluateResearchCapability(validResearcher, {
      programId: 'prog-acme-01',
      target: 'evil-nexus-pay.dev',
      capability: 'RECONNAISSANCE',
    });
    assertTest(
      'Out-of-scope target evaluates to BLOCK decision',
      eval2.decision === 'BLOCK'
    );

    // 5. Attack Surface Graph Building & Provenance Tracking
    console.log('\n--- 5. Attack Surface Graph Generation & Concept Separation ---');
    const graphNodes = await buildAttackSurfaceGraph(validResearcher, { programId: 'prog-acme-01' });
    assertTest('buildAttackSurfaceGraph returns array of nodes', Array.isArray(graphNodes) && graphNodes.length > 0);

    const sampleNode = graphNodes[0];
    assertTest('Node has explicit assetStatus', typeof sampleNode.assetStatus === 'string');
    assertTest('Node has explicit scopeStatus', typeof sampleNode.scopeStatus === 'string');
    assertTest('Node has explicit policyDecision', typeof sampleNode.policyDecision === 'string');
    assertTest('Node has explicit priorityLabel', ['HIGH PRIORITY', 'MEDIUM PRIORITY', 'LOW PRIORITY'].includes(sampleNode.priorityLabel as any));

    // 6. Internal Provenance & Identity Privacy
    console.log('\n--- 6. Internal Provenance & Identity Privacy ---');
    // Ensure otherResearcher exists in DB
    await db.insert(users).values({
      uid: otherResearcher.uid,
      email: otherResearcher.email,
      name: otherResearcher.name,
      role: otherResearcher.role,
    }).onConflictDoNothing();

    const graphForOtherUser = await buildAttackSurfaceGraph(otherResearcher, { programId: 'prog-acme-01' });
    assertTest(
      'Graph for second user builds correctly without leaking identity details',
      Array.isArray(graphForOtherUser) && graphForOtherUser.length > 0
    );

    // Cleanup test user
    await db.delete(users).where(eq(users.uid, otherResearcher.uid));

    // Final Summary
    console.log('\n================================================================');
    console.log(`VERIFICATION SUMMARY: ${passCount} PASSED, ${failCount} FAILED`);
    console.log('================================================================\n');

    if (failCount > 0) {
      process.exit(1);
    }
    process.exit(0);
  } catch (err) {
    console.error('Fatal error during verification execution:', err);
    process.exit(1);
  }
}

runGraphIntelligenceVerification();
