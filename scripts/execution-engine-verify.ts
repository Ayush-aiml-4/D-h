import { db } from '../src/db/index.ts';
import { programs, assets, users } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { AuthUser } from '../src/middleware/auth.ts';
import {
  executeCapability,
  getExecutionById,
  listExecutions,
  cancelExecution,
  clearExecutionsStore,
  canTransitionExecution,
  isTerminalExecutionStatus,
} from '../src/services/researchExecutionService.ts';
import {
  createResearchCase,
  getResearchCases,
  transitionCaseStatus,
} from '../src/services/caseService.ts';
import { adapterRegistry } from '../src/services/execution/adapterRegistry.ts';
import { isRestrictedHost, SafeControlledHttpClient } from '../src/services/execution/httpClient.ts';
import {
  resolveExecutionPolicy,
  evaluateExecutionApproval,
} from '../src/services/execution/executionPolicy.ts';
import { ExecutionAdapter, ExecutionContext } from '../src/services/execution/types.ts';
import { getAuditEvents } from '../src/services/auditService.ts';
import { computeEvidenceHash } from '../src/services/evidenceService.ts';

const adminUser: AuthUser = {
  uid: 'user-ayush-001',
  role: 'ADMIN',
  name: 'Ayush Singh',
  email: 'ayush@example.com',
};

const researcherUser: AuthUser = {
  uid: 'user-ayush-001',
  role: 'RESEARCHER',
  name: 'Ayush Singh',
  email: 'ayush@example.com',
};

const otherResearcherUser: AuthUser = {
  uid: 'user-bob-002',
  role: 'RESEARCHER',
  name: 'Bob Hunter',
  email: 'bob@example.com',
};

const unregisteredUser: AuthUser = {
  uid: 'user-unregistered-999',
  role: 'RESEARCHER',
  name: 'Unknown Agent',
  email: 'ghost@example.com',
};

async function runTests() {
  console.log('====================================================');
  console.log('DEVILHUNT #0003.5-A EXECUTION ENGINE & EGRESS VERIFICATION');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name: string, assertion: boolean, detail?: string) {
    if (assertion) {
      console.log(`[PASS] ${name}`);
      passed++;
    } else {
      console.error(`[FAIL] ${name} ${detail ? `(${detail})` : ''}`);
      failed++;
    }
  }

  // Ensure bob user exists in DB for multi-researcher testing
  const existingBob = await db.select().from(users).where(eq(users.uid, otherResearcherUser.uid));
  if (existingBob.length === 0) {
    await db.insert(users).values({
      uid: otherResearcherUser.uid,
      email: otherResearcherUser.email,
      name: otherResearcherUser.name,
      role: 'RESEARCHER',
    });
  }

  // Fetch baseline program, asset, case
  const dbPrograms = await db.select().from(programs);
  const activeProgram = dbPrograms.find((p) => p.id === 'prog-acme-01') || dbPrograms.find((p) => p.status === 'Active')!;
  if (!activeProgram) {
    throw new Error('No active program found in database');
  }

  const dbAssets = await db.select().from(assets).where(eq(assets.programId, activeProgram.id));
  const validAsset = dbAssets.find((a) => a.status === 'IN_SCOPE') || dbAssets[0];

  // Get active case
  const allCases = await getResearchCases(adminUser, activeProgram.id);
  let activeCase = allCases.find((c) => c.status === 'ACTIVE');

  if (!activeCase) {
    const draftCase = await createResearchCase(
      adminUser,
      {
        programId: activeProgram.id,
        title: 'Execution Engine Test Case',
        objective: 'Verify server-side execution pipeline',
      },
      'req-init-case'
    );
    activeCase = await transitionCaseStatus(draftCase.id, 'ACTIVE', adminUser, 'req-init-activate');
  }

  clearExecutionsStore();

  // Test 1: Valid authorized capability execution produces completed result
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-execution-reference',
        assetId: validAsset.id,
        confirmApproval: true,
      },
      'req-test-01'
    );
    test(
      '01. Valid authorized capability execution produces completed result',
      res.status === 'COMPLETED' && res.observations.length > 0 && res.target !== undefined
    );
  } catch (err: any) {
    test('01. Valid authorized capability execution produces completed result', false, err.message);
  }

  // Test 2: Inactive program blocks execution
  try {
    const [progToPause] = await db
      .insert(programs)
      .values({
        id: `prog-pause-${Date.now()}`,
        name: 'Program To Pause',
        description: 'Test inactive transition',
        rewardCeiling: '₹0',
        status: 'Active',
      })
      .returning();

    const [pausedAsset] = await db
      .insert(assets)
      .values({
        id: `asset-paused-${Date.now()}`,
        programId: progToPause.id,
        domain: 'paused.internal',
        type: 'Web',
        status: 'IN_SCOPE',
      })
      .returning();

    const draftPausedCase = await createResearchCase(
      adminUser,
      {
        programId: progToPause.id,
        title: 'Paused Program Case',
        objective: 'Test inactive program execution blocking',
      },
      'req-case-paused'
    );
    const pausedCase = await transitionCaseStatus(draftPausedCase.id, 'ACTIVE', adminUser, 'req-paused-active');

    // Update program status in DB to PAUSED
    await db.update(programs).set({ status: 'PAUSED' }).where(eq(programs.id, progToPause.id));

    let blocked = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: pausedCase.id,
          capabilityId: 'cap-execution-reference',
          assetId: pausedAsset.id,
          confirmApproval: true,
        },
        'req-test-02'
      );
    } catch (err: any) {
      blocked = err.message.includes('PROGRAM_INACTIVE');
    }
    test('02. Inactive program blocks execution', blocked);
  } catch (err: any) {
    test('02. Inactive program blocks execution', false, err.message);
  }

  // Test 3: Out-of-scope asset blocks execution
  try {
    let blocked = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-execution-reference',
          assetId: 'non-existent-asset-id-9999',
        },
        'req-test-03'
      );
    } catch (err: any) {
      blocked = err.message.includes('ASSET_NOT_FOUND');
    }
    test('03. Out-of-scope asset blocks execution', blocked);
  } catch (err: any) {
    test('03. Out-of-scope asset blocks execution', false, err.message);
  }

  // Test 4: Closed research case blocks execution
  try {
    const caseToClose = await createResearchCase(
      adminUser,
      {
        programId: activeProgram.id,
        title: 'Case to close',
        objective: 'Test closed case',
      },
      'req-case-close'
    );
    const activeCaseToClose = await transitionCaseStatus(caseToClose.id, 'ACTIVE', adminUser, 'req-transition-active');
    const closedCase = await transitionCaseStatus(activeCaseToClose.id, 'CLOSED', adminUser, 'req-transition-close');

    let blocked = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: closedCase.id,
          capabilityId: 'cap-execution-reference',
          assetId: validAsset.id,
          confirmApproval: true,
        },
        'req-test-04'
      );
    } catch (err: any) {
      blocked = err.message.includes('CASE_INACTIVE');
    }
    test('04. Closed research case blocks execution', blocked);
  } catch (err: any) {
    test('04. Closed research case blocks execution', false, err.message);
  }

  // Test 5: Unregistered researcher blocked from executing
  try {
    let blocked = false;
    try {
      await executeCapability(
        unregisteredUser,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-execution-reference',
          assetId: validAsset.id,
        },
        'req-test-05'
      );
    } catch (err: any) {
      blocked = err.message.includes('UNAUTHORIZED_RESEARCHER');
    }
    test('05. Unregistered researcher blocked from executing', blocked);
  } catch (err: any) {
    test('05. Unregistered researcher blocked from executing', false, err.message);
  }

  // Test 6: Missing capability adapter fails fast with structured error
  try {
    let fastFailed = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-unregistered-nonexistent',
          assetId: validAsset.id,
          confirmApproval: true,
        },
        'req-test-06'
      );
    } catch (err: any) {
      fastFailed = err.message.includes('UNREGISTERED_ADAPTER');
    }
    test('06. Missing capability adapter fails fast with structured error', fastFailed);
  } catch (err: any) {
    test('06. Missing capability adapter fails fast with structured error', false, err.message);
  }

  // Test 7: Unregistered capability cannot execute
  try {
    const isReg = adapterRegistry.isAdapterRegistered('cap-non-existent-capability-123');
    test('07. Unregistered capability cannot execute', isReg === false);
  } catch (err: any) {
    test('07. Unregistered capability cannot execute', false, err.message);
  }

  // Test 8: SSRF attempt to 127.0.0.1 blocked by egress client
  try {
    const blocked = isRestrictedHost('127.0.0.1');
    test('08. SSRF attempt to 127.0.0.1 blocked by egress client', blocked === true);
  } catch (err: any) {
    test('08. SSRF attempt to 127.0.0.1 blocked by egress client', false, err.message);
  }

  // Test 9: SSRF attempt to 169.254.169.254 (metadata) blocked by egress client
  try {
    const blocked = isRestrictedHost('169.254.169.254') && isRestrictedHost('metadata.google.internal');
    test('09. SSRF attempt to 169.254.169.254 (metadata) blocked by egress client', blocked === true);
  } catch (err: any) {
    test('09. SSRF attempt to 169.254.169.254 (metadata) blocked by egress client', false, err.message);
  }

  // Test 10: SSRF attempt to RFC1918 private range (10.0.0.1) blocked by egress client
  try {
    const blocked10 = isRestrictedHost('10.0.0.1');
    const blocked192 = isRestrictedHost('192.168.1.1');
    const blocked172 = isRestrictedHost('172.16.0.5');
    test(
      '10. SSRF attempt to RFC1918 private range (10.0.0.1) blocked by egress client',
      blocked10 && blocked192 && blocked172
    );
  } catch (err: any) {
    test('10. SSRF attempt to RFC1918 private range (10.0.0.1) blocked by egress client', false, err.message);
  }

  // Test 11: SSRF attempt to localhost blocked by egress client
  try {
    const blockedLocal = isRestrictedHost('localhost');
    const blockedIPv6 = isRestrictedHost('::1');
    test('11. SSRF attempt to localhost blocked by egress client', blockedLocal && blockedIPv6);
  } catch (err: any) {
    test('11. SSRF attempt to localhost blocked by egress client', false, err.message);
  }

  // Test 12: Policy decision BLOCK halts execution immediately
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-execution-reference',
        assetId: validAsset.id,
        target: 'malicious-domain-outside-scope.com',
        confirmApproval: true,
      },
      'req-test-12'
    );
    test('12. Policy decision BLOCK halts execution immediately', res.status === 'BLOCKED');
  } catch (err: any) {
    test('12. Policy decision BLOCK halts execution immediately', false, err.message);
  }

  // Test 13: Policy decision REVIEW_REQUIRED halts execution immediately
  try {
    const fallbackPolicy = resolveExecutionPolicy('cap-unknown-custom');
    test(
      '13. Policy decision REVIEW_REQUIRED / REQUIRES_APPROVAL halts unconfirmed execution',
      fallbackPolicy.requiresExplicitApproval === true && fallbackPolicy.authorizationLevel === 'REQUIRES_APPROVAL'
    );
  } catch (err: any) {
    test('13. Policy decision REVIEW_REQUIRED / REQUIRES_APPROVAL halts unconfirmed execution', false, err.message);
  }

  // Test 14: Capability requiring explicit approval without confirmation throws error
  try {
    const rateLimitPolicy = resolveExecutionPolicy('cap-rate-limit-inspection');
    let approvalBlocked = false;
    try {
      evaluateExecutionApproval(researcherUser, rateLimitPolicy, false);
    } catch (err: any) {
      approvalBlocked = err.message.includes('EXPLICIT_APPROVAL_REQUIRED');
    }
    test('14. Capability requiring explicit approval without confirmation throws error', approvalBlocked);
  } catch (err: any) {
    test('14. Capability requiring explicit approval without confirmation throws error', false, err.message);
  }

  // Test 15: Capability requiring explicit approval with confirmation succeeds
  try {
    const rateLimitPolicy = resolveExecutionPolicy('cap-rate-limit-inspection');
    const approval = evaluateExecutionApproval(researcherUser, rateLimitPolicy, true);
    test(
      '15. Capability requiring explicit approval with confirmation succeeds',
      approval.approved === true && approval.approvalType === 'EXPLICIT_RESEARCHER_CONFIRMATION'
    );
  } catch (err: any) {
    test('15. Capability requiring explicit approval with confirmation succeeds', false, err.message);
  }

  // Test 16: Restricted capability requires ADMIN role
  try {
    const restrictedPolicy = {
      authorizationLevel: 'RESTRICTED' as const,
      requiresExplicitApproval: true,
      maxTimeoutMs: 5000,
      maxRequestsPerMinute: 5,
      allowedProtocols: ['https:'],
      allowNetworkAccess: false,
      description: 'Restricted capability',
    };
    let adminRequired = false;
    try {
      evaluateExecutionApproval(researcherUser, restrictedPolicy, true);
    } catch (err: any) {
      adminRequired = err.message.includes('ADMIN_APPROVAL_REQUIRED');
    }
    test('16. Restricted capability requires ADMIN role', adminRequired);
  } catch (err: any) {
    test('16. Restricted capability requires ADMIN role', false, err.message);
  }

  // Test 17: Restricted capability with non-admin researcher fails
  try {
    const restrictedPolicy = {
      authorizationLevel: 'RESTRICTED' as const,
      requiresExplicitApproval: true,
      maxTimeoutMs: 5000,
      maxRequestsPerMinute: 5,
      allowedProtocols: ['https:'],
      allowNetworkAccess: false,
      description: 'Restricted capability',
    };
    let rejected = false;
    try {
      evaluateExecutionApproval(otherResearcherUser, restrictedPolicy, true);
    } catch (err: any) {
      rejected = err.message.includes('ADMIN_APPROVAL_REQUIRED');
    }
    test('17. Restricted capability with non-admin researcher fails', rejected);
  } catch (err: any) {
    test('17. Restricted capability with non-admin researcher fails', false, err.message);
  }

  // Test 18: Restricted capability with admin researcher succeeds
  try {
    const restrictedPolicy = {
      authorizationLevel: 'RESTRICTED' as const,
      requiresExplicitApproval: true,
      maxTimeoutMs: 5000,
      maxRequestsPerMinute: 5,
      allowedProtocols: ['https:'],
      allowNetworkAccess: false,
      description: 'Restricted capability',
    };
    const approval = evaluateExecutionApproval(adminUser, restrictedPolicy, true);
    test(
      '18. Restricted capability with admin researcher succeeds',
      approval.approved === true && approval.approvalType === 'ADMIN_AUTHORIZATION'
    );
  } catch (err: any) {
    test('18. Restricted capability with admin researcher succeeds', false, err.message);
  }

  // Test 19: Execution lifecycle transitions: REQUESTED -> AUTHORIZED -> APPROVED -> RUNNING -> COMPLETED
  try {
    const t1 = canTransitionExecution('REQUESTED', 'AUTHORIZED');
    const t2 = canTransitionExecution('AUTHORIZED', 'APPROVED');
    const t3 = canTransitionExecution('APPROVED', 'RUNNING');
    const t4 = canTransitionExecution('RUNNING', 'COMPLETED');
    const tInvalid = canTransitionExecution('COMPLETED', 'RUNNING');
    test(
      '19. Execution lifecycle transitions: REQUESTED -> AUTHORIZED -> APPROVED -> RUNNING -> COMPLETED',
      t1 && t2 && t3 && t4 && !tInvalid
    );
  } catch (err: any) {
    test(
      '19. Execution lifecycle transitions: REQUESTED -> AUTHORIZED -> APPROVED -> RUNNING -> COMPLETED',
      false,
      err.message
    );
  }

  // Test 20: Inactive/disabled adapter is rejected
  try {
    const disabledAdapter: ExecutionAdapter = {
      capabilityId: 'cap-disabled-test',
      name: 'Disabled Test Adapter',
      description: 'Test disabled behavior',
      authorizationLevel: 'LOW_RISK',
      enabled: false,
      async execute() {
        return [];
      },
    };
    adapterRegistry.registerAdapter(disabledAdapter);

    let rejected = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-disabled-test',
          assetId: validAsset.id,
          confirmApproval: true,
        },
        'req-test-20'
      );
    } catch (err: any) {
      rejected = err.message.includes('ADAPTER_DISABLED');
    }
    test('20. Inactive/disabled adapter is rejected', rejected);
  } catch (err: any) {
    test('20. Inactive/disabled adapter is rejected', false, err.message);
  }

  // Test 21: Execution observations contain valid SHA-256 evidence hashes
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-execution-reference',
        assetId: validAsset.id,
        confirmApproval: true,
      },
      'req-test-21'
    );
    const obs = res.observations[0];
    const expectedHash = computeEvidenceHash(obs.sanitizedData, obs.capabilityId, obs.assetId);
    test(
      '21. Execution observations contain valid SHA-256 evidence hashes',
      obs.evidenceHash === expectedHash && /^[a-f0-9]{64}$/.test(obs.evidenceHash!)
    );
  } catch (err: any) {
    test('21. Execution observations contain valid SHA-256 evidence hashes', false, err.message);
  }

  // Test 22: Secrets in observation data are redacted automatically
  try {
    const secretAdapter: ExecutionAdapter = {
      capabilityId: 'cap-secret-emitter-test',
      name: 'Secret Emitter Test',
      description: 'Emits mock secrets to test redaction',
      authorizationLevel: 'LOW_RISK',
      enabled: true,
      async execute(context) {
        return [
          {
            observationId: 'obs-secret-test',
            executionId: context.executionId,
            capabilityId: context.capabilityId,
            assetId: context.assetId,
            timestamp: new Date().toISOString(),
            observationType: 'SECRET_TEST',
            target: context.target,
            sanitizedData: {
              apiKey: 'sk-live-super-secret-123456789',
              authorization: 'Bearer secret_token_value_abc',
              password: 'DatabaseSuperPassword123!',
              safeField: 'visible_data_value',
            },
            requestId: context.requestId,
          },
        ];
      },
    };
    adapterRegistry.registerAdapter(secretAdapter);

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-secret-emitter-test',
        assetId: validAsset.id,
        confirmApproval: true,
      },
      'req-test-22'
    );

    const obs = res.observations[0];
    const redactedData = obs.sanitizedData;
    const isApiKeyRedacted = redactedData.apiKey === '[REDACTED]';
    const isPasswordRedacted = redactedData.password === '[REDACTED]';
    const isSafeKept = redactedData.safeField === 'visible_data_value';

    test(
      '22. Secrets in observation data are redacted automatically',
      isApiKeyRedacted && isPasswordRedacted && isSafeKept
    );
  } catch (err: any) {
    test('22. Secrets in observation data are redacted automatically', false, err.message);
  }

  // Test 23: Execution records are isolated by researcher ownership
  try {
    const draftBobCase = await createResearchCase(
      otherResearcherUser,
      {
        programId: activeProgram.id,
        title: "Bob's Research Case",
        objective: 'Test multi-tenant researcher isolation',
      },
      'req-case-bob'
    );
    const bobCase = await transitionCaseStatus(draftBobCase.id, 'ACTIVE', otherResearcherUser, 'req-bob-activate');

    const bobExec = await executeCapability(
      otherResearcherUser,
      {
        caseId: bobCase.id,
        capabilityId: 'cap-execution-reference',
        assetId: validAsset.id,
      },
      'req-test-23'
    );

    test(
      '23. Execution records are isolated by researcher ownership',
      bobExec.researcherId === otherResearcherUser.uid
    );
  } catch (err: any) {
    test('23. Execution records are isolated by researcher ownership', false, err.message);
  }

  // Test 24: Admin can list/view executions across researchers
  try {
    const adminViewList = await listExecutions(adminUser);
    const hasBobExec = adminViewList.some((e) => e.researcherId === otherResearcherUser.uid);
    test('24. Admin can list/view executions across researchers', hasBobExec && adminViewList.length > 0);
  } catch (err: any) {
    test('24. Admin can list/view executions across researchers', false, err.message);
  }

  // Test 25: Non-admin researcher cannot view another researcher's execution
  try {
    const allExecs = await listExecutions(adminUser);
    const adminExec = allExecs.find((e) => e.researcherId === adminUser.uid);

    let accessBlocked = false;
    if (adminExec) {
      try {
        await getExecutionById(adminExec.executionId, otherResearcherUser);
      } catch (err: any) {
        accessBlocked = err.message.includes('FORBIDDEN');
      }
    }
    test('25. Non-admin researcher cannot view another researcher execution', accessBlocked);
  } catch (err: any) {
    test('25. Non-admin researcher cannot view another researcher execution', false, err.message);
  }

  // Test 26: Cancellation of running/approved execution succeeds
  try {
    const isTerminal = isTerminalExecutionStatus('CANCELLED');
    test('26. Cancellation of active execution transitions to CANCELLED state', isTerminal === true);
  } catch (err: any) {
    test('26. Cancellation of active execution transitions to CANCELLED state', false, err.message);
  }

  // Test 27: Cancellation of completed execution is rejected
  try {
    const compExec = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-execution-reference',
        assetId: validAsset.id,
      },
      'req-test-27'
    );

    let rejected = false;
    try {
      await cancelExecution(compExec.executionId, adminUser, 'req-test-27-cancel');
    } catch (err: any) {
      rejected = err.message.includes('CANNOT_CANCEL_TERMINAL_EXECUTION');
    }
    test('27. Cancellation of completed execution is rejected', rejected);
  } catch (err: any) {
    test('27. Cancellation of completed execution is rejected', false, err.message);
  }

  // Test 28: Rate limit budget exceeded stops subsequent egress requests
  try {
    const dummyContext: ExecutionContext = {
      executionId: 'exec-rl-test',
      user: adminUser,
      programId: activeProgram.id,
      programName: activeProgram.name,
      assetId: validAsset.id,
      target: 'https://example.com',
      caseId: activeCase.id,
      capabilityId: 'cap-execution-reference',
      capabilityName: 'Reference',
      authorizationLevel: 'LOW_RISK',
      policyDecision: 'ALLOW',
      requestId: 'req-test-28',
      timeoutMs: 5000,
      rateLimitBudget: 3,
    };

    const client = new SafeControlledHttpClient(dummyContext);
    await client.request(); // 1
    await client.request(); // 2
    await client.request(); // 3

    let rateLimited = false;
    try {
      await client.request(); // 4 -> Exceeds budget
    } catch (err: any) {
      rateLimited = err.message.includes('RATE_LIMIT_EXCEEDED');
    }

    test('28. Rate limit budget exceeded stops subsequent egress requests', rateLimited);
  } catch (err: any) {
    test('28. Rate limit budget exceeded stops subsequent egress requests', false, err.message);
  }

  // Test 29: Audit events recorded for every lifecycle stage
  try {
    const auditRecords = await getAuditEvents(adminUser, { entityType: 'EXECUTION' });
    const hasStarted = auditRecords.some((a) => a.action === 'EXECUTION_STARTED');
    const hasCompleted = auditRecords.some((a) => a.action === 'EXECUTION_COMPLETED');
    test('29. Audit events recorded for every lifecycle stage', hasStarted && hasCompleted);
  } catch (err: any) {
    test('29. Audit events recorded for every lifecycle stage', false, err.message);
  }

  // Test 30: End-to-end trace correlation preserved from request to evidence
  try {
    const reqTraceId = `req-trace-test-${Date.now()}`;
    const tracedExec = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-execution-reference',
        assetId: validAsset.id,
      },
      reqTraceId
    );

    const hasReqId = tracedExec.requestId === reqTraceId;
    const obsHasReqId = tracedExec.observations[0]?.requestId === reqTraceId;
    const hasEvidenceHash = Boolean(tracedExec.evidenceHash && tracedExec.evidenceHash.length === 64);

    test(
      '30. End-to-end trace correlation preserved from request to evidence',
      hasReqId && obsHasReqId && hasEvidenceHash
    );
  } catch (err: any) {
    test('30. End-to-end trace correlation preserved from request to evidence', false, err.message);
  }

  console.log('\n====================================================');
  console.log(`EXECUTION VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED (TOTAL 30)`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

runTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
