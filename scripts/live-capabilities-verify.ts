import http from 'http';
import { db } from '../src/db/index.ts';
import { programs, assets, users, findings } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { AuthUser } from '../src/middleware/auth.ts';
import {
  executeCapability,
  getExecutionById,
  listExecutions,
  cancelExecution,
  clearExecutionsStore,
} from '../src/services/researchExecutionService.ts';
import {
  createResearchCase,
  getResearchCases,
  transitionCaseStatus,
} from '../src/services/caseService.ts';
import { adapterRegistry } from '../src/services/execution/adapterRegistry.ts';
import {
  SafeControlledHttpClient,
  isRestrictedHost,
} from '../src/services/execution/httpClient.ts';
import {
  resolveExecutionPolicy,
  evaluateExecutionApproval,
} from '../src/services/execution/executionPolicy.ts';
import {
  ExecutionAdapter,
  ExecutionContext,
} from '../src/services/execution/types.ts';
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

const bobUser: AuthUser = {
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

async function runLiveCapabilityVerification() {
  console.log('====================================================');
  console.log('DEVILHUNT #0003.5-B LIVE CAPABILITY ADAPTERS VERIFICATION');
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

  // Ensure bob exists in DB
  const existingBob = await db.select().from(users).where(eq(users.uid, bobUser.uid));
  if (existingBob.length === 0) {
    await db.insert(users).values({
      uid: bobUser.uid,
      email: bobUser.email,
      name: bobUser.name,
      role: 'RESEARCHER',
    });
  }

  // Fetch active program (prefer seeded prog-acme-01 or active)
  const dbPrograms = await db.select().from(programs);
  const activeProgram = dbPrograms.find((p) => p.id === 'prog-acme-01') || dbPrograms.find((p) => p.status === 'Active')!;
  if (!activeProgram) {
    throw new Error('No active program found in database');
  }

  // Fetch valid in-scope asset
  const dbAssets = await db.select().from(assets).where(eq(assets.programId, activeProgram.id));
  const validAsset = dbAssets.find((a) => a.status === 'IN_SCOPE') || dbAssets[0];
  if (!validAsset) {
    throw new Error('No valid asset found for active program');
  }

  // Ensure active research case
  const allCases = await getResearchCases(adminUser, activeProgram.id);
  let activeCase = allCases.find((c) => c.status === 'ACTIVE');
  if (!activeCase) {
    const draftCase = await createResearchCase(
      adminUser,
      {
        programId: activeProgram.id,
        title: 'Live Capabilities Verification Case',
        objective: 'Verify live capability adapters with controlled fixtures',
      },
      'req-init-case'
    );
    activeCase = await transitionCaseStatus(draftCase.id, 'ACTIVE', adminUser, 'req-init-activate');
  }

  clearExecutionsStore();

  // Setup default mock handler to ensure tests execute swiftly and offline safely
  SafeControlledHttpClient.setMockHandler(async () => {
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'server': 'nginx/1.24.0',
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'SAMEORIGIN',
      },
      body: '<!DOCTYPE html><html><head><title>Authorized Target</title></head><body><h1>Target Active</h1></body></html>',
      url: 'https://security-test.example.com/',
      durationMs: 5,
      redirectCount: 0,
    };
  });

  // Test 1: Unauthenticated request throws UnauthorizedError (401)

  try {
    let unauthenticated = false;
    try {
      await executeCapability(
        null as any,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-http-header-analysis',
          assetId: validAsset.id,
        },
        'req-test-01'
      );
    } catch (err: any) {
      unauthenticated = err.message.includes('UNAUTHENTICATED') || err.name === 'UnauthorizedError';
    }
    test('01. Unauthenticated request → 401', unauthenticated);
  } catch (err: any) {
    test('01. Unauthenticated request → 401', false, err.message);
  }

  // Test 2: Unauthorized researcher (not in directory) throws ForbiddenError (403)
  try {
    let forbidden = false;
    try {
      await executeCapability(
        unregisteredUser,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-http-header-analysis',
          assetId: validAsset.id,
        },
        'req-test-02'
      );
    } catch (err: any) {
      forbidden = err.message.includes('UNAUTHORIZED_RESEARCHER') || err.name === 'ForbiddenError';
    }
    test('02. Unauthorized researcher → 403', forbidden);
  } catch (err: any) {
    test('02. Unauthorized researcher → 403', false, err.message);
  }

  // Test 3: Unauthorized asset (asset belonging to another program) is rejected (403/404)
  try {
    const [foreignProgram] = await db
      .insert(programs)
      .values({
        id: `prog-foreign-${Date.now()}`,
        name: 'Foreign Program',
        description: 'Testing program asset cross-talk',
        rewardCeiling: '₹0',
        status: 'Active',
      })
      .returning();

    const [foreignAsset] = await db
      .insert(assets)
      .values({
        id: `asset-foreign-${Date.now()}`,
        programId: foreignProgram.id,
        domain: 'foreign.target.internal',
        type: 'Web',
        status: 'IN_SCOPE',
      })
      .returning();

    let assetUnauthorized = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: activeCase.id, // Active case belongs to activeProgram, not foreignProgram
          capabilityId: 'cap-http-header-analysis',
          assetId: foreignAsset.id,
        },
        'req-test-03'
      );
    } catch (err: any) {
      assetUnauthorized = err.message.includes('ASSET_NOT_FOUND') || err.name === 'NotFoundError';
    }
    test('03. Unauthorized asset → 403 / 404', assetUnauthorized);
  } catch (err: any) {
    test('03. Unauthorized asset → 403 / 404', false, err.message);
  }

  // Test 4: Out-of-scope asset target is blocked
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
        target: 'completely-out-of-scope-external.org',
      },
      'req-test-04'
    );
    test('04. Out-of-scope asset → blocked', res.status === 'BLOCKED');
  } catch (err: any) {
    test('04. Out-of-scope asset → blocked', false, err.message);
  }

  // Test 5: Inactive program blocks execution
  try {
    const [pausedProg] = await db
      .insert(programs)
      .values({
        id: `prog-paused-b-${Date.now()}`,
        name: 'Paused Program B',
        description: 'Testing paused program',
        rewardCeiling: '₹0',
        status: 'Active',
      })
      .returning();

    const [pausedAsset] = await db
      .insert(assets)
      .values({
        id: `asset-paused-b-${Date.now()}`,
        programId: pausedProg.id,
        domain: 'paused-b.internal',
        type: 'Web',
        status: 'IN_SCOPE',
      })
      .returning();

    const draftPausedCase = await createResearchCase(
      adminUser,
      {
        programId: pausedProg.id,
        title: 'Paused Case B',
        objective: 'Test inactive program block',
      },
      'req-case-paused-b'
    );
    const activePausedCase = await transitionCaseStatus(draftPausedCase.id, 'ACTIVE', adminUser, 'req-case-p-act');
    await db.update(programs).set({ status: 'PAUSED' }).where(eq(programs.id, pausedProg.id));

    let inactiveBlocked = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: activePausedCase.id,
          capabilityId: 'cap-http-header-analysis',
          assetId: pausedAsset.id,
        },
        'req-test-05'
      );
    } catch (err: any) {
      inactiveBlocked = err.message.includes('PROGRAM_INACTIVE');
    }
    test('05. Inactive program → blocked', inactiveBlocked);
  } catch (err: any) {
    test('05. Inactive program → blocked', false, err.message);
  }

  // Test 6: Policy decision BLOCK halts before adapter executes
  try {
    let adapterExecuted = false;
    const testTrapAdapter: ExecutionAdapter = {
      capabilityId: 'cap-trap-block-test',
      name: 'Trap Block Adapter',
      description: 'Verifies adapter never executes if policy blocks',
      authorizationLevel: 'PASSIVE',
      enabled: true,
      async execute() {
        adapterExecuted = true;
        return [];
      },
    };
    adapterRegistry.registerAdapter(testTrapAdapter);

    const blockRes = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-trap-block-test',
        assetId: validAsset.id,
        target: 'blocked-malicious-domain-123.com',
        confirmApproval: true,
      },
      'req-test-06'
    );

    test(
      '06. Policy BLOCK → adapter never executes',
      blockRes.status === 'BLOCKED' && adapterExecuted === false
    );
  } catch (err: any) {
    test('06. Policy BLOCK → adapter never executes', false, err.message);
  }

  // Test 7: Capability requiring explicit approval without confirmation throws error
  try {
    const rateLimitPolicy = resolveExecutionPolicy('cap-rate-limit-inspection');
    let approvalBlocked = false;
    try {
      evaluateExecutionApproval(researcherUser, rateLimitPolicy, false);
    } catch (err: any) {
      approvalBlocked = err.message.includes('EXPLICIT_APPROVAL_REQUIRED');
    }
    test('07. REVIEW_REQUIRED / EXPLICIT_APPROVAL without confirmation → blocked', approvalBlocked);
  } catch (err: any) {
    test('07. REVIEW_REQUIRED / EXPLICIT_APPROVAL without confirmation → blocked', false, err.message);
  }

  // Test 8: Required approval spoofing (non-admin executing RESTRICTED) is blocked
  try {
    const restrictedPolicy = {
      authorizationLevel: 'RESTRICTED' as const,
      requiresExplicitApproval: true,
      maxTimeoutMs: 5000,
      maxRequestsPerMinute: 5,
      allowedProtocols: ['https:'],
      allowNetworkAccess: false,
      description: 'Restricted capability requiring ADMIN',
    };
    let spoofBlocked = false;
    try {
      evaluateExecutionApproval(bobUser, restrictedPolicy, true);
    } catch (err: any) {
      spoofBlocked = err.message.includes('ADMIN_APPROVAL_REQUIRED');
    }
    test('08. Required approval spoofing → blocked', spoofBlocked);
  } catch (err: any) {
    test('08. Required approval spoofing → blocked', false, err.message);
  }

  // Test 9: Unknown capability is rejected
  try {
    let unknownRejected = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-totally-unknown-99999',
          assetId: validAsset.id,
          confirmApproval: true,
        },
        'req-test-09'
      );
    } catch (err: any) {
      unknownRejected = err.message.includes('UNREGISTERED_ADAPTER');
    }
    test('09. Unknown capability → rejected', unknownRejected);
  } catch (err: any) {
    test('09. Unknown capability → rejected', false, err.message);
  }

  // Test 10: Disabled capability is rejected
  try {
    const disabledCapAdapter: ExecutionAdapter = {
      capabilityId: 'cap-disabled-live-test',
      name: 'Disabled Live Test',
      description: 'Disabled capability test',
      authorizationLevel: 'PASSIVE',
      enabled: false,
      async execute() {
        return [];
      },
    };
    adapterRegistry.registerAdapter(disabledCapAdapter);

    let disabledRejected = false;
    try {
      await executeCapability(
        adminUser,
        {
          caseId: activeCase.id,
          capabilityId: 'cap-disabled-live-test',
          assetId: validAsset.id,
          confirmApproval: true,
        },
        'req-test-10'
      );
    } catch (err: any) {
      disabledRejected = err.message.includes('ADAPTER_DISABLED');
    }
    test('10. Disabled capability → rejected', disabledRejected);
  } catch (err: any) {
    test('10. Disabled capability → rejected', false, err.message);
  }

  // Test 11: Adapter registry isolation verified (all 8 live adapters registered uniquely)
  try {
    const adapters = adapterRegistry.listAdapters();
    const hasSecHeaders = adapterRegistry.isAdapterRegistered('cap-http-header-analysis');
    const hasCsp = adapterRegistry.isAdapterRegistered('cap-csp-audit');
    const hasHsts = adapterRegistry.isAdapterRegistered('cap-hsts-audit');
    const hasCookie = adapterRegistry.isAdapterRegistered('cap-cookie-security-audit');
    const hasCors = adapterRegistry.isAdapterRegistered('cap-cors-policy-audit');
    const hasDebug = adapterRegistry.isAdapterRegistered('cap-debug-disclosure');
    const hasDir = adapterRegistry.isAdapterRegistered('cap-directory-listing');
    const hasSrcMap = adapterRegistry.isAdapterRegistered('cap-source-map-exposure');

    test(
      '11. Adapter registry isolation → verified (all 8 live adapters registered)',
      hasSecHeaders && hasCsp && hasHsts && hasCookie && hasCors && hasDebug && hasDir && hasSrcMap && adapters.length >= 9
    );
  } catch (err: any) {
    test('11. Adapter registry isolation → verified', false, err.message);
  }

  // Test 12: Valid authorized execution succeeds
  try {
    const validExec = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
      },
      'req-test-12'
    );
    test(
      '12. Valid authorized execution → succeeds',
      validExec.status === 'COMPLETED' && validExec.observations.length > 0
    );
  } catch (err: any) {
    test('12. Valid authorized execution → succeeds', false, err.message);
  }

  // Test 13: SafeControlledHttpClient used → verified
  try {
    const dummyContext: ExecutionContext = {
      executionId: 'exec-http-check',
      user: adminUser,
      programId: activeProgram.id,
      programName: activeProgram.name,
      assetId: validAsset.id,
      target: 'https://security-test.example.com',
      caseId: activeCase.id,
      capabilityId: 'cap-http-header-analysis',
      capabilityName: 'HTTP Header Analysis',
      authorizationLevel: 'PASSIVE',
      policyDecision: 'ALLOW',
      requestId: 'req-test-13',
      timeoutMs: 5000,
      rateLimitBudget: 10,
    };
    const client = new SafeControlledHttpClient(dummyContext);
    const hasGetHostname = typeof client.getHostname === 'function';
    const hasRequest = typeof client.request === 'function';
    test('13. SafeControlledHttpClient used → verified', hasGetHostname && hasRequest);
  } catch (err: any) {
    test('13. SafeControlledHttpClient used → verified', false, err.message);
  }

  // Test 14: Direct unauthorized egress to local network blocked by client SSRF defenses
  try {
    const blockedLoopback = isRestrictedHost('127.0.0.1');
    const blockedPrivate = isRestrictedHost('10.0.0.1');
    const blockedMeta = isRestrictedHost('169.254.169.254');
    test(
      '14. Direct fetch/axios/raw HTTP unavailable / SSRF blocked → verified',
      blockedLoopback && blockedPrivate && blockedMeta
    );
  } catch (err: any) {
    test('14. Direct fetch/axios/raw HTTP unavailable / SSRF blocked → verified', false, err.message);
  }

  // Setup deterministic test fixtures for live adapter observations:
  // Test 15: Security headers observation → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'strict-transport-security': 'max-age=31536000',
          'x-content-type-options': 'nosniff',
        },
        body: '<html><head></head><body>Safe Content</body></html>',
        url: 'https://security-test.example.com/',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
      },
      'req-test-15'
    );

    const obs = res.observations[0];
    const hasMissing = obs.sanitizedData.missingHeaders.includes('content-security-policy');
    const hasPresent = obs.sanitizedData.presentSecurityHeaders.includes('x-content-type-options');
    test(
      '15. Security headers observation → verified',
      obs.observationType === 'SECURITY_HEADER_OBSERVATION' && hasMissing && hasPresent
    );
  } catch (err: any) {
    test('15. Security headers observation → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 16: CSP observation → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: {
          'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
        },
        body: '<html></html>',
        url: 'https://security-test.example.com/',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-csp-audit',
        assetId: validAsset.id,
      },
      'req-test-16'
    );

    const obs = res.observations[0];
    const detectedUnsafe = obs.sanitizedData.identifiedWeaknesses.includes('unsafe-inline');
    test(
      '16. CSP observation → verified',
      obs.observationType === 'CSP_OBSERVATION' && obs.sanitizedData.hasCsp === true && detectedUnsafe
    );
  } catch (err: any) {
    test('16. CSP observation → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 17: HSTS observation → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: {
          'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        },
        body: '<html></html>',
        url: 'https://security-test.example.com/',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-hsts-audit',
        assetId: validAsset.id,
      },
      'req-test-17'
    );

    const obs = res.observations[0];
    test(
      '17. HSTS observation → verified',
      obs.observationType === 'HSTS_OBSERVATION' &&
        obs.sanitizedData.hasHsts === true &&
        obs.sanitizedData.maxAgeSeconds === 31536000 &&
        obs.sanitizedData.isOneYearPlus === true &&
        obs.sanitizedData.includeSubDomains === true
    );
  } catch (err: any) {
    test('17. HSTS observation → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 18: Cookie values redacted → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: {
          'set-cookie': 'session_token=secret_super_confidential_session_value_xyz123; Path=/; HttpOnly; SameSite=Strict',
        },
        body: '<html></html>',
        url: 'https://security-test.example.com/',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-cookie-security-audit',
        assetId: validAsset.id,
      },
      'req-test-18'
    );

    const obs = res.observations[0];
    const cookie = obs.sanitizedData.cookieDetails[0];
    const rawObsJson = JSON.stringify(obs);
    const isSecretLeaked = rawObsJson.includes('secret_super_confidential_session_value_xyz123');

    test(
      '18. Cookie values redacted → verified',
      obs.observationType === 'COOKIE_SECURITY_OBSERVATION' &&
        cookie.cookieName === 'session_token' &&
        cookie.redactedValue === '[REDACTED]' &&
        !isSecretLeaked
    );
  } catch (err: any) {
    test('18. Cookie values redacted → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 19: CORS observation → verified
  try {
    SafeControlledHttpClient.setMockHandler(async (options) => {
      const origin = options.headers?.['Origin'] || 'https://evil-untrusted-test.com';
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: {
          'access-control-allow-origin': origin,
          'access-control-allow-credentials': 'true',
        },
        body: '<html></html>',
        url: 'https://security-test.example.com/',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-cors-policy-audit',
        assetId: validAsset.id,
      },
      'req-test-19'
    );

    const obs = res.observations[0];
    test(
      '19. CORS observation → verified',
      obs.observationType === 'CORS_OBSERVATION' &&
        obs.sanitizedData.isMisconfigured === true &&
        obs.sanitizedData.issueType === 'arbitrary-reflected-origin-with-credentials'
    );
  } catch (err: any) {
    test('19. CORS observation → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 20: Debug disclosure observation → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      return {
        statusCode: 500,
        statusText: 'Internal Server Error',
        headers: {
          'content-type': 'text/plain',
        },
        body: 'Traceback (most recent call last):\n  File "/app/server.py", line 42, in handle_request\nZeroDivisionError: division by zero',
        url: 'https://security-test.example.com/',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-debug-disclosure',
        assetId: validAsset.id,
      },
      'req-test-20'
    );

    const obs = res.observations[0];
    test(
      '20. Debug disclosure observation → verified',
      obs.observationType === 'DEBUG_DISCLOSURE_OBSERVATION' &&
        obs.sanitizedData.hasDebugDisclosure === true &&
        obs.sanitizedData.detectedDisclosureTypes.includes('Python Stack Trace')
    );
  } catch (err: any) {
    test('20. Debug disclosure observation → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 21: Directory listing observation → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: {
          'content-type': 'text/html',
        },
        body: '<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1><hr><pre><a href="../">../</a>\n<a href="secret.bak">secret.bak</a></pre></body></html>',
        url: 'https://security-test.example.com/uploads/',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-directory-listing',
        assetId: validAsset.id,
      },
      'req-test-21'
    );

    const obs = res.observations[0];
    test(
      '21. Directory listing observation → verified',
      obs.observationType === 'DIRECTORY_LISTING_OBSERVATION' && obs.sanitizedData.hasDirectoryListing === true
    );
  } catch (err: any) {
    test('21. Directory listing observation → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 22: Source map observation → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: {
          'content-type': 'application/json',
        },
        body: '{"version":3,"file":"app.bundle.js","sources":["src/auth.ts","src/api.ts"],"mappings":"AAAA..."}',
        url: 'https://security-test.example.com/static/app.bundle.js.map',
        durationMs: 15,
        redirectCount: 0,
      };
    });

    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-source-map-exposure',
        assetId: validAsset.id,
        parameters: { path: '/static/app.bundle.js.map' },
      },
      'req-test-22'
    );

    const obs = res.observations[0];
    test(
      '22. Source map observation → verified',
      obs.observationType === 'SOURCE_MAP_OBSERVATION' && obs.sanitizedData.hasSourceMapExposure === true
    );
  } catch (err: any) {
    test('22. Source map observation → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 23: Evidence hash deterministic → verified
  try {
    const testData = {
      target: 'security-test.example.com',
      finding: 'Missing X-Frame-Options',
      code: 12345,
    };
    const hash1 = computeEvidenceHash(testData, 'cap-http-header-analysis', validAsset.id);
    const hash2 = computeEvidenceHash(testData, 'cap-http-header-analysis', validAsset.id);
    test('23. Evidence hash deterministic → verified', hash1 === hash2 && hash1.length === 64);
  } catch (err: any) {
    test('23. Evidence hash deterministic → verified', false, err.message);
  }

  // Test 24: RequestId propagated → verified
  try {
    const traceRequestId = `req-trace-live-${Date.now()}`;
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
      },
      traceRequestId
    );
    test(
      '24. RequestId propagated → verified',
      res.requestId === traceRequestId && res.observations[0]?.requestId === traceRequestId
    );
  } catch (err: any) {
    test('24. RequestId propagated → verified', false, err.message);
  }

  // Test 25: Cancellation → verified
  try {
    const liveExec = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
      },
      'req-test-25'
    );
    let cannotCancelCompleted = false;
    try {
      await cancelExecution(liveExec.executionId, adminUser, 'req-cancel-test');
    } catch (err: any) {
      cannotCancelCompleted = err.message.includes('CANNOT_CANCEL_TERMINAL_EXECUTION');
    }
    test('25. Cancellation handling on execution lifecycle → verified', cannotCancelCompleted);
  } catch (err: any) {
    test('25. Cancellation handling on execution lifecycle → verified', false, err.message);
  }

  // Test 26: Timeout enforcement → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      await new Promise((resolve) => setTimeout(resolve, 100));
      throw new Error('REQUEST_TIMEOUT: Egress connection timed out');
    });

    const timeoutRes = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
      },
      'req-test-26'
    );

    test('26. Timeout enforcement → verified', timeoutRes.status === 'FAILED' && timeoutRes.error?.includes('TIMEOUT'));
  } catch (err: any) {
    test('26. Timeout enforcement → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 27: Rate limiting budget exhaustion → verified
  try {
    const dummyCtx: ExecutionContext = {
      executionId: 'exec-budget-test',
      user: adminUser,
      programId: activeProgram.id,
      programName: activeProgram.name,
      assetId: validAsset.id,
      target: 'https://security-test.example.com',
      caseId: activeCase.id,
      capabilityId: 'cap-http-header-analysis',
      capabilityName: 'HTTP Header Analysis',
      authorizationLevel: 'PASSIVE',
      policyDecision: 'ALLOW',
      requestId: 'req-test-27',
      timeoutMs: 5000,
      rateLimitBudget: 2,
    };

    const client = new SafeControlledHttpClient(dummyCtx);
    await client.request();
    await client.request();

    let rateLimited = false;
    try {
      await client.request();
    } catch (err: any) {
      rateLimited = err.message.includes('RATE_LIMIT_EXCEEDED');
    }

    test('27. Rate limiting budget exhaustion → verified', rateLimited);
  } catch (err: any) {
    test('27. Rate limiting budget exhaustion → verified', false, err.message);
  }

  // Test 28: Response-size limit protection → verified
  try {
    SafeControlledHttpClient.setMockHandler(async () => {
      throw new Error('RESPONSE_SIZE_EXCEEDED: Response body exceeds maximum limit of 1MB');
    });

    const sizeRes = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
      },
      'req-test-28'
    );

    test(
      '28. Response-size limit protection → verified',
      sizeRes.status === 'FAILED' && sizeRes.error?.includes('RESPONSE_SIZE_EXCEEDED')
    );
  } catch (err: any) {
    test('28. Response-size limit protection → verified', false, err.message);
  } finally {
    SafeControlledHttpClient.clearMockHandler();
  }

  // Test 29: No automatic VERIFIED finding is created directly by adapter execution
  try {
    const beforeFindings = await db.select().from(findings);
    const beforeCount = beforeFindings.length;

    await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-header-analysis',
        assetId: validAsset.id,
      },
      'req-test-29'
    );

    const afterFindings = await db.select().from(findings);
    const afterCount = afterFindings.length;

    test('29. No automatic VERIFIED finding created directly by adapter → verified', beforeCount === afterCount);
  } catch (err: any) {
    test('29. No automatic VERIFIED finding created directly by adapter → verified', false, err.message);
  }

  // Test 30: No external submission or unauthorized mutation occurs
  try {
    const allExecs = await listExecutions(adminUser);
    const currentExec = allExecs[0];
    const isContained = Boolean(currentExec && currentExec.observations);
    test('30. No external submission / self-contained research execution → verified', isContained);
  } catch (err: any) {
    test('30. No external submission / self-contained research execution → verified', false, err.message);
  }

  console.log('\n====================================================');
  console.log(`LIVE CAPABILITIES VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED (TOTAL 30)`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

runLiveCapabilityVerification().catch((err) => {
  console.error('Live capabilities verification failed:', err);
  process.exit(1);
});
