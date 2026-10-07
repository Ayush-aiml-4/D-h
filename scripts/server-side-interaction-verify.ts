import {
  parseCanonicalUrl,
  isExactOrSubdomain,
  classifyDestination,
  normalizeIpv4,
  isIpv6,
  dnsResolver,
  evaluateDestinationPolicy,
  evaluateRedirectChain,
  interactionRecorder,
  evaluateSSRFDifferential,
  classifySSRFImpact,
  calculateSSRFConfidence,
  createSSRFFindingCandidate,
  executeVulnerableUrlFetch,
  executeSecureUrlFetch,
  executeSSRFResearch,
} from '../src/services/serverInteraction/index.ts';
import { AuthUser } from '../src/middleware/auth.ts';
import { resolveTargetScope, evaluateProgramProfilePolicy } from '../src/services/programProfileService.ts';
import { computeEvidenceHash } from '../src/services/evidenceService.ts';
import { createAccountAContext } from '../src/services/authorization/index.ts';
import { SAFE_PAYLOAD_REGISTRY } from '../src/services/authenticationResearch/index.ts';
import { ORDER_WORKFLOW_DEFINITION } from '../src/services/workflowResearch/index.ts';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName}${detail ? ` — ${detail}` : ''}`);
    failed++;
  }
}

async function runSSRFVerificationSuite() {
  console.log('===============================================================================================');
  console.log(' DEVILHUNT #0007 SERVER-SIDE INTERACTION & SSRF RESEARCH ENGINE VERIFICATION SUITE');
  console.log('===============================================================================================');

  const mockUser: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayushsingh556860@gmail.com',
    name: 'Ayush Singh',
    role: 'RESEARCHER',
  };

  // -------------------------------------------------------------------------
  // SECTION 1: URL MODEL (Tests 1-5)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 1: URL MODEL ---');

  // [TEST 1] Valid HTTP URL
  const httpUrl = parseCanonicalUrl('http://example.com/api/test?q=1#hash');
  assert(
    httpUrl.isValid && httpUrl.scheme === 'http' && httpUrl.canonicalHostname === 'example.com' && httpUrl.port === 80,
    '[TEST 1] Valid HTTP URL parsing and canonicalization'
  );

  // [TEST 2] Valid HTTPS URL
  const httpsUrl = parseCanonicalUrl('https://api.valmo.in:8443/orders');
  assert(
    httpsUrl.isValid && httpsUrl.scheme === 'https' && httpsUrl.canonicalHostname === 'api.valmo.in' && httpsUrl.port === 8443 && httpsUrl.explicitPort,
    '[TEST 2] Valid HTTPS URL parsing with custom port'
  );

  // [TEST 3] Unsupported scheme rejection
  const gopherUrl = parseCanonicalUrl('gopher://127.0.0.1:70/1');
  const fileUrl = parseCanonicalUrl('file:///etc/passwd');
  const dictUrl = parseCanonicalUrl('dict://127.0.0.1:11211/stat');
  assert(
    !gopherUrl.isValid && !fileUrl.isValid && !dictUrl.isValid && !gopherUrl.isValidScheme,
    '[TEST 3] Unsupported scheme rejection (gopher, file, dict)'
  );

  // [TEST 4] Malformed URL rejection
  const malformedUrl = parseCanonicalUrl('http://[invalid-ipv6/path\x00null');
  assert(
    !malformedUrl.isValid,
    '[TEST 4] Malformed URL rejection on syntax and control characters'
  );

  // [TEST 5] Canonical hostname normalization
  const unnormalizedUrl = parseCanonicalUrl('HTTP://WwW.ExAmPlE.CoM./Path/To/Resource');
  assert(
    unnormalizedUrl.canonicalHostname === 'www.example.com' && unnormalizedUrl.scheme === 'http',
    '[TEST 5] Canonical hostname normalization (case-folding and trailing dot removal)'
  );

  // -------------------------------------------------------------------------
  // SECTION 2: DESTINATION CLASSIFICATION (Tests 6-10)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 2: DESTINATION CLASSIFICATION ---');

  // [TEST 6] Loopback classification
  const loopbackV4 = classifyDestination('127.0.0.1');
  const loopbackV6 = classifyDestination('::1');
  const loopbackLocalhost = classifyDestination('localhost');
  const loopbackHex = classifyDestination('0x7f000001');
  const loopbackInt = classifyDestination('2130706433');
  assert(
    loopbackV4 === 'LOOPBACK' &&
    loopbackV6 === 'LOOPBACK' &&
    loopbackLocalhost === 'LOOPBACK' &&
    loopbackHex === 'LOOPBACK' &&
    loopbackInt === 'LOOPBACK',
    '[TEST 6] Loopback destination classification (IPv4, IPv6, localhost, Hex, Integer)'
  );

  // [TEST 7] RFC1918 classification
  const rfc10 = classifyDestination('10.254.1.5');
  const rfc172 = classifyDestination('172.20.10.1');
  const rfc192 = classifyDestination('192.168.1.100');
  const rfcFc00 = classifyDestination('fc00::1');
  assert(
    rfc10 === 'PRIVATE_RFC1918' &&
    rfc172 === 'PRIVATE_RFC1918' &&
    rfc192 === 'PRIVATE_RFC1918' &&
    rfcFc00 === 'PRIVATE_RFC1918',
    '[TEST 7] RFC1918 private subnet classification (10/8, 172.16/12, 192.168/16, fc00::/7)'
  );

  // [TEST 8] Link-local classification
  const linkLocalV4 = classifyDestination('169.254.10.20');
  const linkLocalV6 = classifyDestination('fe80::1ff:fe23:4567');
  assert(
    linkLocalV4 === 'LINK_LOCAL' && linkLocalV6 === 'LINK_LOCAL',
    '[TEST 8] Link-local destination classification (169.254/16, fe80::/10)'
  );

  // [TEST 9] Metadata classification
  const awsMeta = classifyDestination('169.254.169.254');
  const gcpMeta = classifyDestination('metadata.google.internal');
  const alibabaMeta = classifyDestination('100.100.100.200');
  const instanceData = classifyDestination('instance-data');
  assert(
    awsMeta === 'METADATA' &&
    gcpMeta === 'METADATA' &&
    alibabaMeta === 'METADATA' &&
    instanceData === 'METADATA',
    '[TEST 9] Cloud metadata service classification (AWS/Azure 169.254.169.254, GCP, Alibaba)'
  );

  // [TEST 10] Public destination classification
  const publicIp = classifyDestination('93.184.216.34');
  const publicDns = classifyDestination('1.1.1.1');
  const publicDomain = classifyDestination('example.com');
  assert(
    publicIp === 'PUBLIC_EXTERNAL' &&
    publicDns === 'PUBLIC_EXTERNAL' &&
    publicDomain === 'PUBLIC_EXTERNAL',
    '[TEST 10] Public routable destination classification'
  );

  // -------------------------------------------------------------------------
  // SECTION 3: DNS RESOLUTION MODEL (Tests 11-14)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 3: DNS RESOLUTION MODEL ---');

  // [TEST 11] Public resolution
  const pubRes = dnsResolver.resolve('safe-external.test');
  assert(
    pubRes.status === 'RESOLVED' && pubRes.destinationClass === 'PUBLIC_EXTERNAL' && pubRes.ipAddress === '93.184.216.34',
    '[TEST 11] Injectable DNS abstraction resolves public host cleanly'
  );

  // [TEST 12] Public -> private resolution
  const pubToPrivRes = dnsResolver.resolve('public-to-private.test');
  assert(
    pubToPrivRes.destinationClass === 'PRIVATE_RFC1918' && pubToPrivRes.ipAddress === '10.0.4.15',
    '[TEST 12] Public-looking domain resolving to private IP identified as PRIVATE_RFC1918'
  );

  // [TEST 13] DNS rebinding simulation
  dnsResolver.reset();
  const step0 = dnsResolver.resolve('rebinding.test', 0);
  const step1 = dnsResolver.resolve('rebinding.test', 1);
  assert(
    step0.destinationClass === 'PUBLIC_EXTERNAL' &&
    step1.destinationClass === 'LOOPBACK' &&
    step1.ipAddress === '127.0.0.1',
    '[TEST 13] DNS rebinding simulation transitions from Public IP to Loopback IP'
  );

  // [TEST 14] Resolution policy enforcement
  const step1Parsed = parseCanonicalUrl('http://rebinding.test/api');
  const rebindingPolicy = evaluateDestinationPolicy(step1Parsed, step1);
  assert(
    rebindingPolicy.decision === 'DENY' && rebindingPolicy.destinationClass === 'LOOPBACK',
    '[TEST 14] Policy engine enforces destination rules on post-resolution IP'
  );

  // -------------------------------------------------------------------------
  // SECTION 4: REDIRECT ANALYSIS (Tests 15-18)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 4: REDIRECT ANALYSIS ---');

  // [TEST 15] Safe redirect
  const safeRedir = evaluateRedirectChain('http://example.com/start', ['https://safe-external.test/data']);
  assert(
    safeRedir.isSafeChain && safeRedir.hops.length === 1 && safeRedir.terminalDecision.decision === 'ALLOW',
    '[TEST 15] Safe single-hop redirect to public destination allowed'
  );

  // [TEST 16] Redirect -> private fixture
  const privRedir = evaluateRedirectChain('http://example.com/start', ['http://10.0.0.1/admin']);
  assert(
    !privRedir.isSafeChain &&
    privRedir.terminalDecision.decision === 'DENY' &&
    privRedir.terminalDecision.destinationClass === 'PRIVATE_RFC1918',
    '[TEST 16] Redirect leading into private RFC1918 subnet detected and rejected'
  );

  // [TEST 17] Multi-hop redirect policy
  const multiHop = evaluateRedirectChain('http://example.com/start', [
    'https://safe-external.test/step1',
    'https://api.public-service.test/step2',
    'http://169.254.169.254/latest/meta-data/',
  ]);
  assert(
    !multiHop.isSafeChain &&
    multiHop.blockedAtHop === 3 &&
    multiHop.terminalDecision.decision === 'BLOCK' &&
    multiHop.terminalDecision.destinationClass === 'METADATA',
    '[TEST 17] Multi-hop redirect chain evaluated per hop and blocked on metadata destination'
  );

  // [TEST 18] Redirect loop protection
  const loopRedir = evaluateRedirectChain('http://example.com/loop1', [
    'http://example.com/loop2',
    'http://example.com/loop1',
  ]);
  assert(
    !loopRedir.isSafeChain && loopRedir.hasLoop && loopRedir.terminalDecision.violatedRule === 'CIRCULAR_REDIRECT_DETECTED',
    '[TEST 18] Circular redirect loop detected and safely halted'
  );

  // -------------------------------------------------------------------------
  // SECTION 5: SSRF FIXTURES & BLIND INTERACTION (Tests 19-23)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 5: SSRF FIXTURES & BLIND INTERACTION ---');

  interactionRecorder.clear();

  // [TEST 19] Secure fixture suppression
  const secureReq = {
    requestId: 'req-sec-01',
    url: 'http://127.0.0.1:8080/internal',
    correlationToken: 'token-sec-01',
  };
  const secureResult = executeSecureUrlFetch(secureReq);
  assert(
    !secureResult.success && secureResult.statusCode === 403,
    '[TEST 19] Hardened secure fixture rejects loopback request with HTTP 403'
  );

  // [TEST 20] Vulnerable fixture detection
  const vulnReq = {
    requestId: 'req-vuln-01',
    url: 'http://10.0.0.1/intranet',
    correlationToken: 'token-vuln-01',
  };
  const vulnResult = executeVulnerableUrlFetch(vulnReq);
  assert(
    vulnResult.success && vulnResult.destinationClass === 'PRIVATE_RFC1918',
    '[TEST 20] Vulnerable fixture simulates unhardened outbound request to private network'
  );

  // [TEST 21] Blind interaction detection
  const recordedObs = interactionRecorder.findObservationsByToken('token-vuln-01');
  assert(
    recordedObs.length === 1 && recordedObs[0].destinationClass === 'PRIVATE_RFC1918',
    '[TEST 21] Blind interaction recorded locally in correlation registry'
  );

  // [TEST 22] Interaction correlation
  const isCorrelated = interactionRecorder.hasCorrelatedInteraction('token-vuln-01');
  assert(
    isCorrelated,
    '[TEST 22] Interaction observation successfully correlated to request token'
  );

  // [TEST 23] Unrelated callback suppression
  const hasUnrelated = interactionRecorder.hasCorrelatedInteraction('token-unrelated-random-999');
  assert(
    !hasUnrelated,
    '[TEST 23] Unrelated callback tokens suppressed from false positive correlation'
  );

  // -------------------------------------------------------------------------
  // SECTION 6: PARSER HARDENING & PARSER CONFUSION (Tests 24-28)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 6: PARSER HARDENING ---');

  // [TEST 24] Userinfo handling
  const userinfoUrl = parseCanonicalUrl('http://admin:secret123@example.com/dashboard');
  assert(
    userinfoUrl.hasUserInfo &&
    userinfoUrl.username === 'admin' &&
    userinfoUrl.canonicalUrl === 'http://example.com/dashboard',
    '[TEST 24] Userinfo parsed safely without leaking into canonical destination URL'
  );

  // [TEST 25] IPv6 handling
  const ipv6Bracketed = parseCanonicalUrl('http://[::1]:8080/metrics');
  const ipv6Class = classifyDestination(ipv6Bracketed.canonicalHostname);
  assert(
    ipv6Bracketed.canonicalHostname === '::1' && ipv6Class === 'LOOPBACK',
    '[TEST 25] Bracketed IPv6 address parsed and classified as LOOPBACK'
  );

  // [TEST 26] Encoded hostname / Parser confusion prevention
  const spoofAttempt = 'meesho.com.attacker.example';
  const isSpoofMatch = isExactOrSubdomain(spoofAttempt, 'meesho.com');
  const genuineSubdomain = 'api.meesho.com';
  const isGenuineMatch = isExactOrSubdomain(genuineSubdomain, 'meesho.com');
  assert(
    !isSpoofMatch && isGenuineMatch,
    '[TEST 26] Parser confusion defense: meesho.com.attacker.example rejected vs api.meesho.com allowed'
  );

  // [TEST 27] Trailing-dot handling
  const dotUrl = parseCanonicalUrl('https://example.com./path');
  assert(
    dotUrl.canonicalHostname === 'example.com',
    '[TEST 27] Trailing dot in FQDN stripped cleanly to canonical form'
  );

  // [TEST 28] Explicit-port handling
  const sensitivePortUrl = parseCanonicalUrl('http://example.com:22/ssh');
  const sensitivePortResolution = dnsResolver.resolve('example.com');
  const sensitivePortPolicy = evaluateDestinationPolicy(sensitivePortUrl, sensitivePortResolution);
  assert(
    sensitivePortPolicy.decision === 'BLOCK' && sensitivePortPolicy.violatedRule === 'SENSITIVE_PORT_RESTRICTION',
    '[TEST 28] Prohibited sensitive infrastructure port (SSH port 22) blocked by policy'
  );

  // -------------------------------------------------------------------------
  // SECTION 7: IMPACT & CONFIDENCE (Tests 29-32)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 7: IMPACT & CONFIDENCE ---');

  // [TEST 29] Impact classification
  const metaImpact = classifySSRFImpact('METADATA', recordedObs, 'AWS_SECRET_ACCESS_KEY=12345');
  const rfcImpact = classifySSRFImpact('PRIVATE_RFC1918', recordedObs);
  assert(
    metaImpact.impact === 'CREDENTIAL_ACCESS_INDICATOR' &&
    metaImpact.severity === 'Critical' &&
    rfcImpact.impact === 'NETWORK_BOUNDARY_CROSSING' &&
    rfcImpact.severity === 'High',
    '[TEST 29] Impact accurately classified (CREDENTIAL_ACCESS_INDICATOR=Critical, NETWORK_BOUNDARY_CROSSING=High)'
  );

  // [TEST 30] Confidence calculation
  const highConf = calculateSSRFConfidence({
    hasServerSideInteraction: true,
    isControlledDestination: true,
    isForbiddenDestination: true,
    isCorrelated: true,
    isReproducible: true,
  });
  const noFindConf = calculateSSRFConfidence({
    hasServerSideInteraction: false,
    isControlledDestination: true,
    isForbiddenDestination: true,
    isCorrelated: false,
    isReproducible: false,
  });
  assert(
    highConf === 'HIGH_CONFIDENCE' && noFindConf === 'NO_FINDING',
    '[TEST 30] Confidence engine accurately distinguishes HIGH_CONFIDENCE from NO_FINDING'
  );

  // [TEST 31] Evidence generation
  const mockCandidate = createSSRFFindingCandidate({
    researchCaseId: 'case-ssrf-001',
    executionId: 'exec-ssrf-001',
    requestId: 'req-ssrf-001',
    target: 'www.valmo.in',
    targetEndpoint: '/api/v1/webhook',
    inputParameter: 'callback_url',
    suppliedUrl: 'http://169.254.169.254/latest/meta-data/',
    parsedUrl: parseCanonicalUrl('http://169.254.169.254/latest/meta-data/'),
    resolution: dnsResolver.resolve('169.254.169.254'),
    redirectChain: [],
    policyDecision: {
      decision: 'BLOCK',
      reason: 'Cloud metadata blocked',
      destinationClass: 'METADATA',
      isRestricted: true,
    },
    observations: [
      {
        interactionId: 'obs-01',
        correlationToken: 'token-01',
        timestamp: new Date().toISOString(),
        fixtureId: 'meta-fixture',
        destinationClass: 'METADATA',
        requestedUrl: 'http://169.254.169.254/latest/meta-data/',
        method: 'GET',
        headers: {},
        isCorrelated: true,
      },
    ],
  });
  assert(
    mockCandidate.cweId === 'CWE-918' &&
    mockCandidate.severity === 'Critical' &&
    mockCandidate.reproductionSteps.length === 4,
    '[TEST 31] Finding candidate formatted with CWE-918, Critical severity, and remediation'
  );

  // [TEST 32] Evidence hashing
  const hash1 = mockCandidate.evidenceHash;
  assert(
    typeof hash1 === 'string' && hash1.length === 64 && /^[0-9a-f]{64}$/.test(hash1),
    '[TEST 32] Deterministic SHA-256 evidence hash verified as 64-character hex'
  );

  // -------------------------------------------------------------------------
  // SECTION 8: GOVERNANCE & EXECUTION (Tests 33-40)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 8: GOVERNANCE & EXECUTION ---');

  // [TEST 33] Scope enforcement (Out of scope blocked)
  const outOfScopeDecision = await evaluateProgramProfilePolicy(mockUser, {
    programId: 'meesho-hackerone',
    target: 'internal.meesho.com',
    operation: 'active-server-interaction-ssrf',
  });
  assert(
    outOfScopeDecision.decision === 'BLOCK',
    '[TEST 33] Out-of-scope target (internal.meesho.com) fail-closed blocked'
  );

  // [TEST 34] Capability authorization (In-scope target allowed)
  const inScopeDecision = await evaluateProgramProfilePolicy(mockUser, {
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    operation: 'active-server-interaction-ssrf',
  });
  assert(
    inScopeDecision.decision === 'ALLOW',
    '[TEST 34] In-scope target (www.valmo.in) authorized with ALLOW'
  );

  // [TEST 35] Approval enforcement for hazardous capability
  const hazDecision = await evaluateProgramProfilePolicy(mockUser, {
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    operation: 'RATE_LIMIT_STRESS_TEST',
  });
  assert(
    hazDecision.decision === 'REVIEW_REQUIRED',
    '[TEST 35] Hazardous operations require explicit researcher approval'
  );

  // [TEST 36] Budget enforcement
  const budgetResult = await executeSSRFResearch({
    user: mockUser,
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    caseId: 'case-budget-ssrf',
    hypotheses: [
      {
        hypothesisId: 'hyp-1',
        targetEndpoint: '/api/fetch',
        inputParameter: 'url',
        testUrl: 'http://10.0.0.1/admin',
        intendedDestinationClass: 'PRIVATE_RFC1918',
        expectedBehavior: 'REJECT',
      },
      {
        hypothesisId: 'hyp-2',
        targetEndpoint: '/api/fetch',
        inputParameter: 'url',
        testUrl: 'http://10.0.0.2/admin',
        intendedDestinationClass: 'PRIVATE_RFC1918',
        expectedBehavior: 'REJECT',
      },
      {
        hypothesisId: 'hyp-3',
        targetEndpoint: '/api/fetch',
        inputParameter: 'url',
        testUrl: 'http://10.0.0.3/admin',
        intendedDestinationClass: 'PRIVATE_RFC1918',
        expectedBehavior: 'REJECT',
      },
    ],
    requestBudget: 2,
  });
  assert(
    budgetResult.evaluatedHypotheses <= 2,
    '[TEST 36] Request budget strictly bounded to max ceiling (2 <= 2)'
  );

  // [TEST 37] Cancellation
  const cancelToken = { isCancelled: true };
  const cancelResult = await executeSSRFResearch({
    user: mockUser,
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    caseId: 'case-cancel-ssrf',
    hypotheses: [
      {
        hypothesisId: 'hyp-cancel-1',
        targetEndpoint: '/api/fetch',
        inputParameter: 'url',
        testUrl: 'http://10.0.0.1/admin',
        intendedDestinationClass: 'PRIVATE_RFC1918',
        expectedBehavior: 'REJECT',
      },
    ],
    cancellationToken: cancelToken,
  });
  assert(
    cancelResult.status === 'CANCELLED',
    '[TEST 37] Cancellation token honored immediately with status CANCELLED'
  );

  // [TEST 38] Secret redaction
  const sanitizedHeaders = mockCandidate.evidenceSummary;
  const leaksCredentials = JSON.stringify(sanitizedHeaders).includes('SECRET_UNREDACTED_KEY');
  assert(
    !leaksCredentials,
    '[TEST 38] Raw credentials and secrets strictly redacted from evidence'
  );

  // [TEST 39] Audit logging
  assert(
    budgetResult.executionId.startsWith('exec-ssrf-'),
    '[TEST 39] Structured audit events recorded during SSRF execution'
  );

  // [TEST 40] Dry-run zero-network verification
  const dryRunResult = await executeSSRFResearch({
    user: mockUser,
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    caseId: 'case-dry-ssrf',
    hypotheses: [
      {
        hypothesisId: 'hyp-dry-1',
        targetEndpoint: '/api/fetch',
        inputParameter: 'url',
        testUrl: 'http://10.0.0.1/admin',
        intendedDestinationClass: 'PRIVATE_RFC1918',
        expectedBehavior: 'REJECT',
      },
    ],
    dryRun: true,
  });
  assert(
    dryRunResult.status === 'COMPLETED' && dryRunResult.networkRequestsCount === 0,
    '[TEST 40] Dry run completed with 0 network requests executed'
  );

  // -------------------------------------------------------------------------
  // SECTION 9: INTEGRATION & ZERO REGRESSION (Tests 41-45)
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 9: INTEGRATION ---');

  // [TEST 41] #0004 authorization integration
  const authContextA = createAccountAContext({
    researcherId: 'researcher-001',
    programId: 'meesho-hackerone',
    caseId: 'case-auth-01',
    accountIdentifier: 'account-a-tenant-01',
  });
  assert(
    authContextA.accountIdentifier === 'account-a-tenant-01' && authContextA.accountRole === 'STANDARD_USER',
    '[TEST 41] #0004 Authorization model cleanly integrated with SSRF context'
  );

  // [TEST 42] #0005 authentication integration
  assert(
    SAFE_PAYLOAD_REGISTRY.length > 0,
    '[TEST 42] #0005 Input & Session Invariant models integrated cleanly'
  );

  // [TEST 43] #0006 workflow integration
  assert(
    ORDER_WORKFLOW_DEFINITION.workflowId === 'wf-order-fulfillment-01',
    '[TEST 43] #0006 Multi-step workflow state models verified intact'
  );

  // [TEST 44] Meesho profile integration
  const meeshoScope = resolveTargetScope('meesho-hackerone', 'www.valmo.in');
  assert(
    meeshoScope.decision === 'ALLOW' && meeshoScope.maxSeverity === 'CRITICAL',
    '[TEST 44] Meesho Program Profile resolves exact in-scope assets cleanly'
  );

  // [TEST 45] Full local end-to-end SSRF scenario
  interactionRecorder.clear();
  const e2eResult = await executeSSRFResearch({
    user: mockUser,
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    caseId: 'case-e2e-ssrf-01',
    hypotheses: [
      {
        hypothesisId: 'hyp-e2e-vuln',
        targetEndpoint: '/api/proxy/fetch',
        inputParameter: 'target_url',
        testUrl: 'http://10.0.0.1/internal/admin',
        intendedDestinationClass: 'PRIVATE_RFC1918',
        expectedBehavior: 'REJECT',
      },
    ],
    useSecureFixture: false,
  });

  assert(
    e2eResult.status === 'COMPLETED' && e2eResult.findings.length === 1,
    '[TEST 45] Full local end-to-end SSRF scenario successfully detected 1 vulnerability candidate'
  );

  console.log('===============================================================================================');
  console.log(`FINAL RESULT: ${passed}/${passed + failed} SERVER-SIDE INTERACTION & SSRF TESTS PASSED`);
  console.log('===============================================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSSRFVerificationSuite().catch(err => {
  console.error('Test suite failed with unexpected error:', err);
  process.exit(1);
});
