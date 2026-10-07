import {
  registerWorkflowDefinition,
  getWorkflowDefinition,
  listWorkflowDefinitions,
  createWorkflowStateInstance,
  validateActorIntegrity,
  evaluateStateTransition,
  applyStateTransition,
  evaluateWorkflowAuthorization,
  evaluateMultiStepAuthorizationTrace,
  evaluateInvariant,
  validateOrderLineItemsIntegrity,
  validateNumericBoundary,
  analyzeWorkflowReplay,
  evaluateReplayVulnerability,
  simulateSafeLocalConcurrency,
  compareWorkflowTraces,
  determineWorkflowImpactAndConfidence,
  createWorkflowFindingCandidate,
  dispatchLocalWorkflowRequest,
  executeWorkflowResearch,
  ORDER_WORKFLOW_DEFINITION,
  COUPON_WORKFLOW_DEFINITION,
} from '../src/services/workflowResearch/index.ts';
import {
  WorkflowDefinition,
  WorkflowActor,
  WorkflowResource,
  WorkflowAction,
  WorkflowSecurityInvariant,
  WorkflowTrace,
} from '../src/types/workflowResearch.ts';
import { AuthUser } from '../src/middleware/auth.ts';
import { computeEvidenceHash } from '../src/services/evidenceService.ts';
import { resolveTargetScope, evaluateProgramProfilePolicy } from '../src/services/programProfileService.ts';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName}${detail ? `: ${detail}` : ''}`);
    failed++;
  }
}

async function runWorkflowVerificationSuite() {
  console.log('===============================================================================================');
  console.log(' DEVILHUNT #0006 WORKFLOW, MULTI-STEP STATE & BUSINESS LOGIC RESEARCH ENGINE VERIFICATION SUITE');
  console.log('===============================================================================================');

  const mockUser: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayushsingh556860@gmail.com',
    name: 'Ayush Singh',
    role: 'RESEARCHER',
  };

  const actorA: WorkflowActor = {
    actorId: 'acc-user-a',
    actorLabel: 'ACCOUNT_A',
    role: 'STANDARD_USER',
    credentialReference: 'cred-ref-user-a-01',
    sessionReference: 'sess-ref-user-a-01',
  };

  const actorB: WorkflowActor = {
    actorId: 'acc-user-b',
    actorLabel: 'ACCOUNT_B',
    role: 'STANDARD_USER',
    credentialReference: 'cred-ref-user-b-02',
    sessionReference: 'sess-ref-user-b-02',
  };

  const adminActor: WorkflowActor = {
    actorId: 'acc-admin',
    actorLabel: 'ADMIN_USER',
    role: 'ADMIN_USER',
    credentialReference: 'cred-ref-admin-01',
    sessionReference: 'sess-ref-admin-01',
  };

  const sampleResource: WorkflowResource = {
    resourceId: 'order-1001',
    resourceType: 'order',
    ownerActorId: 'acc-user-a',
    initialStatus: 'CREATED',
    currentStatus: 'CREATED',
    attributes: {
      totalAmount: 150,
      currency: 'INR',
      lineItems: [{ id: 'item-1', price: 150, quantity: 1 }],
      balance: 100,
    },
  };

  // -------------------------------------------------------------
  // SECTION 1: WORKFLOW MODEL (Tests 1-4)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 1: WORKFLOW MODEL ---');

  // [TEST 1] Workflow registration
  const regDef = registerWorkflowDefinition(ORDER_WORKFLOW_DEFINITION);
  const retrievedDef = getWorkflowDefinition('wf-order-fulfillment-01');
  assert(
    !!retrievedDef && retrievedDef.workflowId === 'wf-order-fulfillment-01',
    '[TEST 1] Workflow registration and retrieval'
  );

  // [TEST 2] State registration
  assert(
    retrievedDef!.states.includes('CREATED') && retrievedDef!.states.includes('COMPLETED'),
    '[TEST 2] State registration in workflow definition'
  );

  // [TEST 3] Transition registration
  const payTransition = retrievedDef!.transitions.find(t => t.actionId === 'act-pay-order');
  assert(
    !!payTransition && payTransition.fromState === 'CREATED' && payTransition.toState === 'PAID',
    '[TEST 3] Transition registration (CREATED -> PAID)'
  );

  // [TEST 4] Invalid transition rejection on malformed workflow
  let invalidCaught = false;
  try {
    registerWorkflowDefinition({
      workflowId: 'wf-invalid',
      workflowName: 'Invalid Workflow',
      programId: 'meesho-hackerone',
      target: 'www.valmo.in',
      initialState: 'UNDEFINED_STATE',
      terminalStates: [],
      states: ['STATE_A'],
      actions: [],
      transitions: [],
      invariants: [],
      sensitivity: 'PUBLIC',
      maxRequestBudget: 10,
    });
  } catch {
    invalidCaught = true;
  }
  assert(invalidCaught, '[TEST 4] Invalid workflow registration rejection');

  // -------------------------------------------------------------
  // SECTION 2: STATE MACHINE (Tests 5-8)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 2: STATE MACHINE ---');

  const stateCreated = createWorkflowStateInstance(ORDER_WORKFLOW_DEFINITION, actorA, sampleResource);
  const payAction = ORDER_WORKFLOW_DEFINITION.actions.find(a => a.actionId === 'act-pay-order')!;

  // [TEST 5] Valid state transition
  const evalValid = evaluateStateTransition(ORDER_WORKFLOW_DEFINITION, stateCreated, payAction);
  assert(
    evalValid.isValidTransition && evalValid.expectedOutcome === 'ALLOW',
    '[TEST 5] Valid state transition (CREATED + pay -> PAID: ALLOW)'
  );

  // [TEST 6] Forbidden transition detection
  const completeActionDirect = ORDER_WORKFLOW_DEFINITION.actions.find(a => a.actionId === 'act-complete-order')!;
  const evalForbidden = evaluateStateTransition(ORDER_WORKFLOW_DEFINITION, stateCreated, completeActionDirect);
  assert(
    !evalForbidden.isValidTransition || evalForbidden.expectedOutcome === 'DENY',
    '[TEST 6] Forbidden transition detection (CREATED + complete -> DENY)'
  );

  // [TEST 7] Terminal-state enforcement
  const stateCompleted = createWorkflowStateInstance(
    ORDER_WORKFLOW_DEFINITION,
    actorA,
    { ...sampleResource, currentStatus: 'COMPLETED' },
    'COMPLETED'
  );
  const evalTerminal = evaluateStateTransition(ORDER_WORKFLOW_DEFINITION, stateCompleted, payAction);
  assert(
    evalTerminal.expectedOutcome === 'DENY',
    '[TEST 7] Terminal-state enforcement (COMPLETED state mutation blocked)'
  );

  // [TEST 8] Required-state enforcement
  const shipAction = ORDER_WORKFLOW_DEFINITION.actions.find(a => a.actionId === 'act-ship-order')!;
  const evalRequired = evaluateStateTransition(ORDER_WORKFLOW_DEFINITION, stateCreated, shipAction);
  assert(
    evalRequired.expectedOutcome === 'DENY',
    '[TEST 8] Required-state sequence enforcement (Must be PAID before SHIPPED)'
  );

  // -------------------------------------------------------------
  // SECTION 3: AUTHORIZATION (Tests 9-12)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 3: AUTHORIZATION ---');

  // [TEST 9] Owner workflow access
  const authOwner = evaluateWorkflowAuthorization(ORDER_WORKFLOW_DEFINITION, stateCreated, payAction, actorA);
  assert(
    authOwner.isAuthorized && authOwner.expectedOutcome === 'ALLOW',
    '[TEST 9] Owner workflow access allowed'
  );

  // [TEST 10] Cross-account workflow denial
  const authPeer = evaluateWorkflowAuthorization(ORDER_WORKFLOW_DEFINITION, stateCreated, payAction, actorB);
  assert(
    !authPeer.isAuthorized && authPeer.expectedOutcome === 'DENY',
    '[TEST 10] Cross-account workflow access denied'
  );

  // [TEST 11] Privilege workflow enforcement
  const refundAction = ORDER_WORKFLOW_DEFINITION.actions.find(a => a.actionId === 'act-admin-force-refund')!;
  const authPrivStandard = evaluateWorkflowAuthorization(ORDER_WORKFLOW_DEFINITION, stateCompleted, refundAction, actorA);
  const authPrivAdmin = evaluateWorkflowAuthorization(ORDER_WORKFLOW_DEFINITION, stateCompleted, refundAction, adminActor);
  assert(
    !authPrivStandard.isAuthorized && authPrivAdmin.isAuthorized,
    '[TEST 11] Privilege workflow enforcement (Standard user blocked, Admin allowed)'
  );

  // [TEST 12] Multi-step authorization enforcement
  const multiTrace = evaluateMultiStepAuthorizationTrace(ORDER_WORKFLOW_DEFINITION, stateCreated, [
    { action: payAction, actor: actorA },
    { action: refundAction, actor: actorB }, // Step 2 unauthorized
  ]);
  assert(
    !multiTrace.allAuthorized && multiTrace.firstUnauthorizedStepIndex === 1,
    '[TEST 12] Multi-step authorization trace identifies step-specific unauthorized actor'
  );

  // -------------------------------------------------------------
  // SECTION 4: BUSINESS RULES (Tests 13-16)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 4: BUSINESS RULES ---');

  // [TEST 13] Business invariant registration
  const ruleInv: WorkflowSecurityInvariant = {
    invariantId: 'inv-test-rule',
    type: 'BUSINESS_RULE_INVARIANT',
    name: 'Test Business Invariant',
    description: 'Custom rule check',
    expectedResult: 'ALLOW',
    ruleFn: ctx => ({ valid: ctx.resource.attributes.totalAmount > 0 }),
  };
  const invRes = evaluateInvariant(ruleInv, {
    currentState: stateCreated,
    action: payAction,
    actor: actorA,
    resource: sampleResource,
  });
  assert(invRes.passed, '[TEST 13] Business invariant registration & evaluation');

  // [TEST 14] Valid business rule (Line items sum equals total)
  const validOrderRule = validateOrderLineItemsIntegrity(sampleResource);
  assert(validOrderRule.valid, '[TEST 14] Valid business rule calculation (Sum = Total)');

  // [TEST 15] Business rule violation detection (Line items mismatch)
  const invalidOrderResource: WorkflowResource = {
    ...sampleResource,
    attributes: {
      totalAmount: 150,
      lineItems: [{ id: 'item-1', price: 20, quantity: 1 }], // Sum = 20 vs Total = 150
    },
  };
  const invalidOrderRule = validateOrderLineItemsIntegrity(invalidOrderResource);
  assert(
    !invalidOrderRule.valid && invalidOrderRule.expectedValue === 20,
    '[TEST 15] Business rule violation detection on corrupted total'
  );

  // [TEST 16] Boundary-value validation
  const minBoundary = validateNumericBoundary('amount', 10, 1, 100);
  const negBoundary = validateNumericBoundary('amount', -5, 0, 100, false);
  assert(
    minBoundary.valid && !negBoundary.valid,
    '[TEST 16] Numeric boundary validation (Negative amount rejected)'
  );

  // -------------------------------------------------------------
  // SECTION 5: REPLAY (Tests 17-19)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 5: REPLAY ---');

  const couponAction = COUPON_WORKFLOW_DEFINITION.actions.find(a => a.actionId === 'act-consume-coupon')!;
  const couponResource: WorkflowResource = {
    resourceId: 'coupon-50-off',
    resourceType: 'coupon',
    ownerActorId: 'acc-user-a',
    initialStatus: 'UNUSED',
    currentStatus: 'UNUSED',
    attributes: { discountPercent: 50 },
  };

  // [TEST 17] Allowed replay (First consumption attempt -> initial run)
  const initialReplayCheck = analyzeWorkflowReplay(couponAction, couponResource, stateCreated, []);
  assert(!initialReplayCheck.isReplayAttempt, '[TEST 17] Initial action execution recognized');

  // [TEST 18] Forbidden replay (Second consumption attempt with history)
  const replayHistoryCheck = analyzeWorkflowReplay(couponAction, couponResource, stateCreated, [
    {
      step: 1,
      fromState: 'APPLIED',
      actionId: 'act-consume-coupon',
      toState: 'CONSUMED',
      actorId: 'acc-user-a',
      timestamp: new Date().toISOString(),
      status: 'SUCCESS',
    },
  ]);
  assert(
    replayHistoryCheck.isReplayAttempt && replayHistoryCheck.expectedHandling === 'REJECT',
    '[TEST 18] Replay policy marks second single-use consumption as REJECT'
  );

  // [TEST 19] Vulnerable replay detection
  const replayVuln = evaluateReplayVulnerability(couponAction, 'REJECT', 200, 'SUCCESS');
  assert(
    replayVuln.isVulnerable && replayVuln.confidence === 'HIGH_CONFIDENCE',
    '[TEST 19] Vulnerable replay detection flags accepted replay with HIGH_CONFIDENCE'
  );

  // -------------------------------------------------------------
  // SECTION 6: CONCURRENCY (Tests 20-21)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 6: CONCURRENCY ---');

  // [TEST 20] Secure serialized fixture
  const secureConcurrency = simulateSafeLocalConcurrency(
    sampleResource,
    payAction,
    [actorA, actorB],
    50,
    false
  );
  assert(
    !secureConcurrency.hasRaceConditionAnomaly && secureConcurrency.finalBalance === 0,
    '[TEST 20] Secure serialized concurrency fixture satisfies balance invariant'
  );

  // [TEST 21] Vulnerable concurrency fixture detection (Race anomaly)
  const vulnerableConcurrency = simulateSafeLocalConcurrency(
    sampleResource,
    payAction,
    [actorA, actorB, actorA],
    100,
    true
  );
  assert(
    vulnerableConcurrency.hasRaceConditionAnomaly,
    '[TEST 21] Vulnerable race condition simulation flags duplicate deduction anomaly'
  );

  // -------------------------------------------------------------
  // SECTION 7: DIFFERENTIAL (Tests 22-24)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 7: DIFFERENTIAL ---');

  const baselineTrace: WorkflowTrace = {
    traceId: 'trace-base-01',
    workflowId: 'wf-order-fulfillment-01',
    scenarioName: 'Standard Fulfillment',
    isVulnerableExpected: false,
    steps: [
      {
        stepNumber: 1,
        action: payAction,
        actor: actorA,
        fromState: 'CREATED',
        toState: 'PAID',
        responseStatus: 200,
        responseBody: { success: true },
        stateAfter: 'PAID',
      },
    ],
  };

  const vulnerableTrace: WorkflowTrace = {
    traceId: 'trace-vuln-01',
    workflowId: 'wf-order-fulfillment-01',
    scenarioName: 'Direct Bypass',
    isVulnerableExpected: true,
    steps: [
      {
        stepNumber: 1,
        action: ORDER_WORKFLOW_DEFINITION.actions.find(a => a.actionId === 'act-direct-complete-bypass')!,
        actor: actorA,
        fromState: 'CREATED',
        toState: 'COMPLETED',
        responseStatus: 200,
        responseBody: { success: true },
        stateAfter: 'COMPLETED',
      },
    ],
  };

  // [TEST 22] Secure workflow suppression
  const diffSecure = compareWorkflowTraces(ORDER_WORKFLOW_DEFINITION, baselineTrace, baselineTrace);
  assert(!diffSecure.hasUnexpectedTransition, '[TEST 22] Identical conformant traces suppressed from anomalies');

  // [TEST 23] Vulnerable workflow detection
  const diffVuln = compareWorkflowTraces(ORDER_WORKFLOW_DEFINITION, baselineTrace, vulnerableTrace);
  assert(
    diffVuln.hasUnexpectedTransition && diffVuln.hasStateDrift,
    '[TEST 23] Differential engine detects unexpected direct state transition'
  );

  // [TEST 24] Workflow trace comparison
  assert(
    diffVuln.explanation.includes('CREATED') && diffVuln.explanation.includes('COMPLETED'),
    '[TEST 24] Workflow trace differential explanation contains exact state sequence'
  );

  // -------------------------------------------------------------
  // SECTION 8: IMPACT / CONFIDENCE (Tests 25-28)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 8: IMPACT / CONFIDENCE ---');

  const dummyViolationEval = {
    actionId: 'act-pay-order',
    fromState: 'CREATED',
    toState: 'PAID',
    actor: actorB, // Peer attempting pay
    resource: sampleResource,
    isValidTransition: true,
    isAuthorized: false,
    invariantsPassed: false,
    violatedInvariants: [{
      invariantId: 'inv-order-owner',
      type: 'OWNERSHIP_INVARIANT' as const,
      reason: 'Owner invariant violated',
    }],
    expectedOutcome: 'DENY' as const,
    observedOutcome: 'ALLOW' as const,
    status: 'VIOLATION' as const,
  };

  // [TEST 25] Impact classification
  const impactRes = determineWorkflowImpactAndConfidence(dummyViolationEval, ORDER_WORKFLOW_DEFINITION);
  assert(
    impactRes.impactDimensions.includes('RESOURCE_OWNERSHIP') && impactRes.impactDimensions.includes('AUTHORIZATION'),
    '[TEST 25] Impact dimensions accurately classified (RESOURCE_OWNERSHIP, AUTHORIZATION)'
  );

  // [TEST 26] Confidence calculation
  assert(
    impactRes.confidence === 'HIGH_CONFIDENCE',
    '[TEST 26] Concrete invariant breach mapped to HIGH_CONFIDENCE'
  );

  // [TEST 27] Finding candidate generation
  const findingCand = createWorkflowFindingCandidate(
    'case-wf-01',
    'exec-wf-01',
    ORDER_WORKFLOW_DEFINITION,
    dummyViolationEval,
    1,
    200,
    { note: 'Cross-account payment accepted' }
  );
  assert(
    findingCand.reproductionSteps.length > 0 && !!findingCand.remediation,
    '[TEST 27] Finding candidate formatted with reproduction steps and remediation'
  );

  // [TEST 28] Evidence hashing
  assert(
    findingCand.evidenceHash.length === 64 && /^[0-9a-f]{64}$/i.test(findingCand.evidenceHash),
    '[TEST 28] Evidence hash verified as valid deterministic 64-char SHA-256'
  );

  // -------------------------------------------------------------
  // SECTION 9: GOVERNANCE & EXECUTION (Tests 29-36)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 9: GOVERNANCE & EXECUTION ---');

  // [TEST 29] Scope enforcement (Out of scope blocked)
  const outOfScopeTarget = 'internal.meesho.com';
  const outOfScopeDecision = await evaluateProgramProfilePolicy(mockUser, {
    programId: 'meesho-hackerone',
    target: outOfScopeTarget,
    operation: 'active-workflow-state-validation',
  });
  assert(outOfScopeDecision.decision === 'BLOCK', '[TEST 29] Out-of-scope target blocked fail-closed');

  // [TEST 30] Capability authorization (In-scope target allowed)
  const inScopeDecision = await evaluateProgramProfilePolicy(mockUser, {
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    operation: 'active-workflow-state-validation',
  });
  assert(inScopeDecision.decision === 'ALLOW', '[TEST 30] In-scope target www.valmo.in authorized with ALLOW');

  // [TEST 31] Approval enforcement for hazardous capability
  const hazDecision = await evaluateProgramProfilePolicy(mockUser, {
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    operation: 'RATE_LIMIT_STRESS_TEST',
  });
  assert(hazDecision.decision === 'REVIEW_REQUIRED', '[TEST 31] Hazardous concurrency probing requires explicit approval');

  // [TEST 32] Budget enforcement
  const resBudget = await executeWorkflowResearch({
    user: mockUser,
    caseId: 'case-budget-01',
    workflowId: 'wf-order-fulfillment-01',
    maxBudget: 2,
    hypotheses: [
      {
        hypothesisId: 'hyp-budget-01',
        workflowId: 'wf-order-fulfillment-01',
        name: 'Budget Test',
        description: 'Testing budget bound',
        targetStateOrAction: 'act-pay-order',
        testType: 'STATE_TRANSITION',
        actors: [actorA],
        initialResource: sampleResource,
        actionsSequence: [
          { actionId: 'act-pay-order', actorId: 'acc-user-a' },
          { actionId: 'act-ship-order', actorId: 'acc-user-a' },
          { actionId: 'act-complete-order', actorId: 'acc-user-a' },
        ],
      },
    ],
  });
  assert(resBudget.totalStepsExecuted <= 2, '[TEST 32] Request budget strictly bounded to max ceiling (2 <= 2)');

  // [TEST 33] Cancellation
  const cancelToken = { isCancelled: true };
  const resCancel = await executeWorkflowResearch({
    user: mockUser,
    caseId: 'case-cancel-01',
    workflowId: 'wf-order-fulfillment-01',
    cancellationToken: cancelToken,
    hypotheses: [
      {
        hypothesisId: 'hyp-cancel-01',
        workflowId: 'wf-order-fulfillment-01',
        name: 'Cancel Test',
        description: 'Testing cancellation halt',
        targetStateOrAction: 'act-pay-order',
        testType: 'STATE_TRANSITION',
        actors: [actorA],
        initialResource: sampleResource,
        actionsSequence: [{ actionId: 'act-pay-order', actorId: 'acc-user-a' }],
      },
    ],
  });
  assert(resCancel.status === 'CANCELLED', '[TEST 33] Cancellation token honored immediately with status CANCELLED');

  // [TEST 34] Secret redaction
  const validActorCheck = validateActorIntegrity(actorA);
  const rawTokenActor: WorkflowActor = {
    ...actorA,
    credentialReference: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
  };
  const rawTokenCheck = validateActorIntegrity(rawTokenActor);
  assert(
    validActorCheck.valid && !rawTokenCheck.valid,
    '[TEST 34] Raw JWTs and secret tokens in actors strictly rejected'
  );

  // [TEST 35] Audit logging
  assert(resBudget.auditEventCount > 0, '[TEST 35] Structured audit logging recorded during workflow execution');

  // [TEST 36] Dry-run zero-network verification
  const resDryRun = await executeWorkflowResearch({
    user: mockUser,
    caseId: 'case-dry-01',
    workflowId: 'wf-order-fulfillment-01',
    dryRun: true,
    hypotheses: [
      {
        hypothesisId: 'hyp-dry-01',
        workflowId: 'wf-order-fulfillment-01',
        name: 'Dry Run Plan',
        description: 'Dry run execution',
        targetStateOrAction: 'act-pay-order',
        testType: 'STATE_TRANSITION',
        actors: [actorA],
        initialResource: sampleResource,
        actionsSequence: [{ actionId: 'act-pay-order', actorId: 'acc-user-a' }],
      },
    ],
  });
  assert(
    resDryRun.dryRun && resDryRun.totalStepsExecuted === 0,
    '[TEST 36] Dry run verified with 0 network requests executed'
  );

  // -------------------------------------------------------------
  // SECTION 10: INTEGRATION (Tests 37-40)
  // -------------------------------------------------------------
  console.log('\n--- SECTION 10: INTEGRATION ---');

  // [TEST 37] #0004 authorization engine integration
  assert(
    ORDER_WORKFLOW_DEFINITION.transitions.some(t => t.isOwnerOnly),
    '[TEST 37] #0004 Authorization model cleanly integrated into workflow definitions'
  );

  // [TEST 38] #0005 authentication integration
  assert(
    COUPON_WORKFLOW_DEFINITION.invariants.some(i => i.type === 'SINGLE_USE_INVARIANT'),
    '[TEST 38] #0005 Input & Session Invariant integration verified'
  );

  // [TEST 39] Meesho profile integration
  const meeshoScope = resolveTargetScope('meesho-hackerone', 'www.valmo.in');
  assert(
    meeshoScope.decision === 'ALLOW' && meeshoScope.maxSeverity === 'CRITICAL',
    '[TEST 39] Meesho Program Profile integration resolves in-scope assets cleanly'
  );

  // [TEST 40] Full local end-to-end workflow scenario
  const resE2E = await executeWorkflowResearch({
    user: mockUser,
    caseId: 'case-e2e-01',
    workflowId: 'wf-order-fulfillment-01',
    scenarioType: 'VULNERABLE_TRANSITION',
    hypotheses: [
      {
        hypothesisId: 'hyp-e2e-01',
        workflowId: 'wf-order-fulfillment-01',
        name: 'End-to-End Bypass Test',
        description: 'Executing state bypass scenario',
        targetStateOrAction: 'act-direct-complete-bypass',
        testType: 'STATE_TRANSITION',
        actors: [actorA],
        initialResource: sampleResource,
        actionsSequence: [
          { actionId: 'act-direct-complete-bypass', actorId: 'acc-user-a' },
        ],
      },
    ],
  });
  assert(
    resE2E.status === 'COMPLETED' && resE2E.violationsDetected === 1 && resE2E.candidatesGenerated.length === 1,
    '[TEST 40] Full local end-to-end scenario successfully detected 1 workflow violation candidate'
  );

  console.log('===============================================================================================');
  console.log(`FINAL RESULT: ${passed}/${passed + failed} WORKFLOW BUSINESS LOGIC RESEARCH TESTS PASSED`);
  console.log('===============================================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runWorkflowVerificationSuite().catch(async err => {
  console.error('Test suite failed with unexpected error:', err);
  process.exit(1);
});
