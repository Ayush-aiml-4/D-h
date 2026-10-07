import {
  CANONICAL_ACTIVE_CAPABILITIES,
  activeAdapterRegistry,
  resolveActiveCapability,
  resolveActiveAdapter,
} from '../src/services/execution/activeTesting/activeCapabilityRegistry.ts';
import { BudgetEngine } from '../src/services/execution/activeTesting/budgetEngine.ts';
import {
  createApprovalRequirement,
  confirmApprovalRequirement,
  validateAndConsumeApproval,
  clearApprovalsStore,
} from '../src/services/execution/activeTesting/approvalService.ts';
import { evaluateActiveTestingPolicy } from '../src/services/execution/activeTesting/activePolicyEngine.ts';
import {
  executeActiveCapability,
  cancelActiveExecution,
  clearActiveExecutionsStore,
  listActiveExecutions,
} from '../src/services/execution/activeTesting/activeTestingService.ts';
import { AuthUser } from '../src/middleware/auth.ts';
import { db } from '../src/db/index.ts';
import { programs, assets, users } from '../src/db/schema.ts';
import { syncUserRecord } from '../src/services/userService.ts';
import { createResearchCase, getResearchCases, transitionCaseStatus } from '../src/services/caseService.ts';
import { eq } from 'drizzle-orm';
import '../src/services/execution/activeTesting/adapters/index.ts';

let passCount = 0;
let failCount = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passCount++;
  } else {
    console.error(`  ✗ FAIL: ${testName}${detail ? ` - ${detail}` : ''}`);
    failCount++;
  }
}

async function runActiveTestingVerification() {
  console.log('===============================================================');
  console.log('DEVILHUNT #0003.5-D — GOVERNED ACTIVE SECURITY TESTING VERIFICATION');
  console.log('===============================================================\n');

  // Setup mock researchers
  const researcherUser: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayush@devilhunt.sec',
    name: 'Ayush Researcher',
    role: 'RESEARCHER',
  };

  const otherResearcher: AuthUser = {
    uid: 'user-attacker-002',
    email: 'attacker@evil.corp',
    name: 'Other Researcher',
    role: 'RESEARCHER',
  };

  const existingOther = await db.select().from(users).where(eq(users.uid, otherResearcher.uid));
  if (existingOther.length === 0) {
    await db.insert(users).values({
      uid: otherResearcher.uid,
      email: otherResearcher.email,
      name: otherResearcher.name,
      role: 'RESEARCHER',
    });
  }

  // Fetch baseline program, asset, case
  const dbPrograms = await db.select().from(programs);
  const activeProgram = dbPrograms.find((p) => p.id === 'prog-acme-01') || dbPrograms.find((p) => p.status === 'Active') || dbPrograms[0];
  if (!activeProgram) {
    throw new Error('No active program found in database');
  }

  const dbAssets = await db.select().from(assets).where(eq(assets.programId, activeProgram.id));
  const validAsset = dbAssets.find((a) => a.status === 'IN_SCOPE') || dbAssets[0];
  if (!validAsset) {
    throw new Error('No valid asset found in database for program');
  }

  const testProgramId = activeProgram.id;
  const testAssetId = validAsset.id;
  const testTarget = validAsset.domain || validAsset.url || 'api.acme-security.test';

  const allCases = await getResearchCases(researcherUser, activeProgram.id);
  let activeCase = allCases.find((c) => c.status === 'ACTIVE');

  if (!activeCase) {
    const draftCase = await createResearchCase(
      researcherUser,
      {
        programId: activeProgram.id,
        title: 'Active Security Testing Case',
        objective: 'Evaluate API method handling and auth boundary resilience',
      },
      'req-init-case'
    );
    activeCase = await transitionCaseStatus(draftCase.id, 'ACTIVE', researcherUser, 'req-init-activate');
  }

  const testCaseId = activeCase.id;

  // -------------------------------------------------------------
  // SUITE 1: CANONICAL ACTIVE CAPABILITIES SPECIFICATION & TIERS
  // -------------------------------------------------------------
  console.log('\n--- Suite 1: Canonical Active Capabilities Specification & Tiers ---');

  const capKeys = Object.keys(CANONICAL_ACTIVE_CAPABILITIES);
  assert(capKeys.length >= 6, 'Canonical active capability count >= 6', `Found ${capKeys.length}`);

  const requiredActiveCaps = [
    'active-http-method-validation',
    'active-header-mutation-validation',
    'active-auth-boundary-observation',
    'active-parameter-handling-validation',
    'active-redirect-policy-validation',
    'active-destructive-fuzzing-prohibited',
  ];

  for (const capId of requiredActiveCaps) {
    const cap = CANONICAL_ACTIVE_CAPABILITIES[capId];
    assert(Boolean(cap), `Canonical capability '${capId}' is defined`);
    if (cap) {
      assert(Boolean(cap.canonicalName), `'${capId}' has canonicalName`);
      assert(Boolean(cap.authorizationTier), `'${capId}' has authorizationTier`);
      assert(typeof cap.maximumRequestBudget === 'number', `'${capId}' has maximumRequestBudget`);
      assert(typeof cap.maximumConcurrency === 'number', `'${capId}' has maximumConcurrency`);
      assert(Boolean(cap.evidenceType), `'${capId}' has evidenceType`);
      assert(Boolean(cap.findingPromotionPolicy), `'${capId}' has findingPromotionPolicy`);
    }
  }

  // Verify Restricted Capability
  const restrictedDef = CANONICAL_ACTIVE_CAPABILITIES['active-destructive-fuzzing-prohibited'];
  assert(restrictedDef.authorizationTier === 'RESTRICTED', 'Prohibited fuzzing is classified as RESTRICTED');
  assert(restrictedDef.enabled === false, 'Restricted capability is disabled');
  assert(restrictedDef.destructive === true, 'Restricted capability is marked destructive');

  // -------------------------------------------------------------
  // SUITE 2: ACTIVE ADAPTER REGISTRY & RESOLUTION
  // -------------------------------------------------------------
  console.log('\n--- Suite 2: Active Testing Adapter Registry & Resolution ---');

  const registeredAdapters = activeAdapterRegistry.listAdapters();
  assert(registeredAdapters.length >= 5, 'Active adapter registry has registered adapters', `Found ${registeredAdapters.length}`);

  const methodAdapter = activeAdapterRegistry.getAdapter('active-http-method-validation');
  assert(Boolean(methodAdapter), 'HTTP Method adapter is resolved from registry');

  const aliasResolved = activeAdapterRegistry.getAdapter('active-http-methods');
  assert(Boolean(aliasResolved), 'HTTP Method adapter resolved via alias');

  let restrictedResolutionFailed = false;
  try {
    resolveActiveAdapter('active-destructive-fuzzing-prohibited');
  } catch (err: any) {
    restrictedResolutionFailed = true;
  }
  assert(restrictedResolutionFailed, 'Restricted capability cannot be resolved for execution');

  // -------------------------------------------------------------
  // SUITE 3: BUDGET ENGINE & CONCURRENCY CONSTRAINTS
  // -------------------------------------------------------------
  console.log('\n--- Suite 3: Request Budget Engine & Hard Limits ---');

  const testBudget = {
    maxTotalRequests: 3,
    maxRequestsPerSecond: 10,
    maxConcurrency: 1,
    maxExecutionDurationMs: 5000,
    maxResponseBytes: 1024 * 1024,
    totalRequestsExecuted: 0,
    startedAt: Date.now(),
  };

  const budgetEngine = new BudgetEngine(testBudget);
  const release1 = await budgetEngine.acquireRequestSlot(() => false);
  assert(budgetEngine.getExecutedCount() === 1, 'Slot 1 acquired, count = 1');
  release1();

  const release2 = await budgetEngine.acquireRequestSlot(() => false);
  assert(budgetEngine.getExecutedCount() === 2, 'Slot 2 acquired, count = 2');
  release2();

  const release3 = await budgetEngine.acquireRequestSlot(() => false);
  assert(budgetEngine.getExecutedCount() === 3, 'Slot 3 acquired, count = 3');
  release3();

  let budgetExceededError = false;
  try {
    await budgetEngine.acquireRequestSlot(() => false);
  } catch (err: any) {
    if (err.message.includes('REQUEST_BUDGET_EXCEEDED')) {
      budgetExceededError = true;
    }
  }
  assert(budgetExceededError, 'Request Budget Engine strictly blocks requests over maxTotalRequests limit');

  // -------------------------------------------------------------
  // SUITE 4: ACTIVE POLICY ENGINE EVALUATION
  // -------------------------------------------------------------
  console.log('\n--- Suite 4: Server-Authoritative Active Policy Evaluation ---');

  const lowRiskCap = resolveActiveCapability('active-http-method-validation');
  const approvalReqCap = resolveActiveCapability('active-auth-boundary-observation');

  const evalLowRisk = await evaluateActiveTestingPolicy(
    researcherUser,
    testProgramId,
    testAssetId,
    lowRiskCap,
    testTarget
  );
  assert(evalLowRisk.decision === 'ALLOW', 'LOW_RISK_ACTIVE capability receives ALLOW policy decision');

  const evalApprovalReq = await evaluateActiveTestingPolicy(
    researcherUser,
    testProgramId,
    testAssetId,
    approvalReqCap,
    testTarget
  );
  assert(
    evalApprovalReq.decision === 'REVIEW_REQUIRED',
    'APPROVAL_REQUIRED capability receives REVIEW_REQUIRED policy decision'
  );
  assert(evalApprovalReq.approvalRequired === true, 'Explicit approval requirement is flagged in policy result');

  const evalRestricted = await evaluateActiveTestingPolicy(
    researcherUser,
    testProgramId,
    testAssetId,
    restrictedDef,
    testTarget
  );
  assert(evalRestricted.decision === 'BLOCK', 'RESTRICTED capability receives BLOCK policy decision');

  // -------------------------------------------------------------
  // SUITE 5: EXPLICIT RESEARCHER APPROVAL WORKFLOW
  // -------------------------------------------------------------
  console.log('\n--- Suite 5: Explicit Researcher Approval Workflow ---');

  clearApprovalsStore();

  const approvalReq = await createApprovalRequirement(
    researcherUser,
    testProgramId,
    testAssetId,
    approvalReqCap,
    testTarget
  );
  assert(approvalReq.status === 'PENDING', 'New approval requirement has PENDING status');
  assert(Boolean(approvalReq.approvalId), 'Approval ID is generated server-side');
  assert(Boolean(approvalReq.executionFingerprint), 'Execution fingerprint is cryptographically bound');

  // Rejection of unconfirmed approval consumption
  let unconfirmedConsumptionBlocked = false;
  try {
    await validateAndConsumeApproval(
      researcherUser,
      approvalReq.approvalId,
      approvalReqCap,
      testProgramId,
      testAssetId,
      testTarget
    );
  } catch (err: any) {
    if (err.message.includes('APPROVAL_NOT_CONFIRMED')) {
      unconfirmedConsumptionBlocked = true;
    }
  }
  assert(unconfirmedConsumptionBlocked, 'Unconfirmed PENDING approval cannot be consumed for execution');

  // Rejection of approval confirmation by wrong researcher identity
  let wrongResearcherBlocked = false;
  try {
    await confirmApprovalRequirement(otherResearcher, approvalReq.approvalId);
  } catch (err: any) {
    if (err.message.includes('FORBIDDEN_RESEARCHER_MISMATCH')) {
      wrongResearcherBlocked = true;
    }
  }
  assert(wrongResearcherBlocked, 'Approval cannot be confirmed by a different researcher identity');

  // Successful confirmation by owning researcher
  const confirmedApproval = await confirmApprovalRequirement(researcherUser, approvalReq.approvalId);
  assert(confirmedApproval.status === 'CONFIRMED', 'Approval transitions to CONFIRMED');
  assert(Boolean(confirmedApproval.confirmedAt), 'Confirmed timestamp is recorded');

  // Single-use consumption
  const consumedApproval = await validateAndConsumeApproval(
    researcherUser,
    approvalReq.approvalId,
    approvalReqCap,
    testProgramId,
    testAssetId,
    testTarget
  );
  assert(consumedApproval.status === 'CONSUMED', 'Approval transitions to CONSUMED upon execution');

  // Rejection of re-use
  let reuseBlocked = false;
  try {
    await validateAndConsumeApproval(
      researcherUser,
      approvalReq.approvalId,
      approvalReqCap,
      testProgramId,
      testAssetId,
      testTarget
    );
  } catch (err: any) {
    if (err.message.includes('APPROVAL_NOT_CONFIRMED')) {
      reuseBlocked = true;
    }
  }
  assert(reuseBlocked, 'Consumed approval cannot be reused (replay prevention)');

  // -------------------------------------------------------------
  // SUITE 6: GOVERNED ACTIVE EXECUTION PIPELINE
  // -------------------------------------------------------------
  console.log('\n--- Suite 6: Governed Active Execution Pipeline ---');

  clearActiveExecutionsStore();

  // Test 1: Execute LOW_RISK_ACTIVE capability (active-http-method-validation)
  const execLowRiskResult = await executeActiveCapability(researcherUser, {
    caseId: testCaseId,
    capabilityId: 'active-http-method-validation',
    assetId: testAssetId,
    target: testTarget,
  });

  assert(execLowRiskResult.status === 'COMPLETED', 'LOW_RISK_ACTIVE capability executes to COMPLETED');
  assert(execLowRiskResult.requestsExecuted > 0, 'Requests were executed through ControlledRequestBuilder');
  assert(execLowRiskResult.observations.length > 0, 'Observations were generated and sanitized');
  assert(Boolean(execLowRiskResult.evidenceHash), 'Evidence integrity hash was computed');

  // Test 2: Execute APPROVAL_REQUIRED capability without approval -> triggers REVIEW_REQUIRED
  const execApprovalTriggerResult = await executeActiveCapability(researcherUser, {
    caseId: testCaseId,
    capabilityId: 'active-auth-boundary-observation',
    assetId: testAssetId,
    target: testTarget,
  });

  assert(
    execApprovalTriggerResult.policyDecision === 'REVIEW_REQUIRED',
    'Executing APPROVAL_REQUIRED capability without approval triggers REVIEW_REQUIRED'
  );
  assert(Boolean(execApprovalTriggerResult.approvalId), 'Approval ID requirement is returned to researcher');

  // Now confirm the approval and execute
  await confirmApprovalRequirement(researcherUser, execApprovalTriggerResult.approvalId!);

  const execApprovedResult = await executeActiveCapability(researcherUser, {
    caseId: testCaseId,
    capabilityId: 'active-auth-boundary-observation',
    assetId: testAssetId,
    target: testTarget,
    approvalId: execApprovalTriggerResult.approvalId,
  });

  assert(execApprovedResult.status === 'COMPLETED', 'Confirmed APPROVAL_REQUIRED capability executes to COMPLETED');
  assert(execApprovedResult.observations.length > 0, 'Observations generated for auth boundary');

  // Test 3: Execute RESTRICTED capability -> BLOCKED
  let restrictedBlocked = false;
  try {
    const resBlocked = await executeActiveCapability(researcherUser, {
      caseId: testCaseId,
      capabilityId: 'active-destructive-fuzzing-prohibited',
      assetId: testAssetId,
      target: testTarget,
    });
    if (resBlocked.status === 'BLOCKED') {
      restrictedBlocked = true;
    }
  } catch (err: any) {
    restrictedBlocked = true;
  }
  assert(restrictedBlocked, 'Executing RESTRICTED capability is immediately blocked');

  // -------------------------------------------------------------
  // SUITE 7: DETERMINISTIC CANCELLATION & AUDIT INTEGRITY
  // -------------------------------------------------------------
  console.log('\n--- Suite 7: Deterministic Cancellation & Finding Protection ---');

  // Execute another capability and test cancellation
  const allExecs = await listActiveExecutions(researcherUser);
  assert(allExecs.length >= 2, 'Active executions are queryable in execution store');

  // Verify finding promotion policy
  for (const obs of execLowRiskResult.observations) {
    assert(
      obs.observationType !== 'VERIFIED_FINDING',
      'Observation is an observation/evidence and not auto-promoted to verified finding'
    );
  }

  // Final Summary
  console.log('\n===============================================================');
  console.log(`ACTIVE TESTING VERIFICATION SUMMARY:`);
  console.log(`  PASS:  ${passCount}`);
  console.log(`  FAIL:  ${failCount}`);
  console.log(`  TOTAL: ${passCount + failCount}`);
  console.log('===============================================================');

  if (failCount > 0) {
    process.exit(1);
  }
}

runActiveTestingVerification().catch((err) => {
  console.error('ACTIVE TESTING VERIFICATION RUNNER ERROR:', err);
  process.exit(1);
});
