import assert from 'assert';
import { db, verifyDatabaseConnection, closeDatabasePool } from '../src/db/index.ts';
import { users, auditEvents } from '../src/db/schema.ts';
import { eq, desc } from 'drizzle-orm';
import { AuthUser } from '../src/middleware/auth.ts';
import {
  getProgramProfile,
  resolveTargetScope,
  evaluateFindingEligibility,
  evaluateProgramProfilePolicy,
  executeDryRunCapability,
  listProgramProfiles,
} from '../src/services/programProfileService.ts';
import { MEESHO_PROGRAM_PROFILE } from '../src/profiles/meesho.profile.ts';

async function runMeeshoProgramProfileVerificationSuite() {
  console.log('========================================================================================');
  console.log('=== DEVILHUNT #0003.5-C MEESHO PROGRAM PROFILE FIDELITY & SCOPE VERIFICATION SUITE ===');
  console.log('========================================================================================\n');

  // Verify DB Connection
  const isDbConnected = await verifyDatabaseConnection();
  assert(isDbConnected === true, 'Database must be reachable');

  const validResearcher: AuthUser = {
    uid: 'user-ayush-001',
    email: 'ayushsingh556860@gmail.com',
    role: 'RESEARCHER',
    name: 'Ayush Singh',
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

  const profileId = MEESHO_PROGRAM_PROFILE.id;
  const profile = getProgramProfile(profileId);
  assert(profile !== null, 'Meesho program profile must be registered and retrieved');
  console.log(`[INIT] Loaded program profile '${profile.name}' (Platform: ${profile.platform}, Exact In-Scope: ${profile.inScopeAssets.length}, Exclusions: ${profile.outOfScopeAssets.length})`);

  // [TEST 1] Exact In-Scope Assets Resolution (All 12 Explicitly Enumerated Assets)
  console.log('\n[TEST 1] Exact In-Scope Assets Resolution (12 Explicit Program Assets) → ALLOW');
  const expectedInScope = [
    { target: 'www.valmo.in', severity: 'CRITICAL' },
    { target: 'www.meesho.com', severity: 'CRITICAL' },
    { target: 'supplier.meesho.com', severity: 'CRITICAL' },
    { target: 'prod.meeshoapi.com', severity: 'CRITICAL' },
    { target: 'com.valmo.valmo', severity: 'CRITICAL' },
    { target: 'com.meesho.supply', severity: 'CRITICAL' },
    { target: 'affiliate.meesho.com', severity: 'CRITICAL' },
    { target: 'admin.meeshosupply.com', severity: 'CRITICAL' },
    { target: '1457958492', severity: 'CRITICAL' },
    { target: 'superstoreapp.meesho.com', severity: 'HIGH' },
    { target: 'meesho.io', severity: 'LOW' },
    { target: 'investor.meesho.com', severity: 'LOW' },
  ];

  for (const item of expectedInScope) {
    const res = resolveTargetScope(profileId, item.target);
    assert.strictEqual(res.decision, 'ALLOW', `Target ${item.target} must yield ALLOW`);
    assert.strictEqual(res.isBountyEligible, true, `Target ${item.target} must be bounty eligible`);
    assert.strictEqual(res.maxSeverity, item.severity, `Target ${item.target} max severity must be ${item.severity}`);
  }
  console.log('  [PASS] All 12 exact supplied in-scope assets resolved to ALLOW with exact program severities.');

  // [TEST 2] Explicit Out-of-Scope Named Assets Resolution
  console.log('\n[TEST 2] Explicit Out-of-Scope Named Assets Resolution → DENY');
  const expectedOutOfScope = [
    'warehouse.meesho.com',
    'Rider App',
    'Other Asset',
    'log10-web-staging.valmo.in',
    'grocery-supplier.meesho.com',
    'farmiso.meeshosupply.com',
    'di-prd-superset.meesho.com',
    'console.valmo.in',
    'com.valmo.ops',
    'atlas.valmo.in',
    'agency.meesho.com',
    'affiliate-c.meesho.com',
    'admin.meesho.io',
  ];

  for (const target of expectedOutOfScope) {
    const res = resolveTargetScope(profileId, target);
    assert.strictEqual(res.decision, 'DENY', `Explicit out-of-scope target ${target} must yield DENY`);
    assert.strictEqual(res.isBountyEligible, false, `Target ${target} must not be bounty eligible`);
  }
  console.log('  [PASS] All 13 explicit named exclusions resolved to DENY.');

  // [TEST 3] Explicitly Ineligible Wildcards Resolution
  console.log('\n[TEST 3] Explicitly Ineligible Wildcards Evaluation (*.meesho.com, *.valmo.in, *.meeshoapi.com, etc.) → DENY');
  const ineligibleWildcardMatches = [
    'random.meesho.com',
    'api2.meesho.com',
    'foo.valmo.in',
    'random.meeshoapi.com',
    'test.meeshosupply.com',
    'dev.meeshogcp.in',
    'model.meeshoaiservices.ai',
    'admin.meesho.com',
  ];

  for (const target of ineligibleWildcardMatches) {
    const res = resolveTargetScope(profileId, target);
    assert.strictEqual(res.decision, 'DENY', `Target under ineligible wildcard ${target} must yield DENY`);
    assert.strictEqual(res.isBountyEligible, false, `Target ${target} must not be bounty eligible`);
    assert(res.reason.includes('ineligible wildcard') || res.reason.includes('unlisted'), 'Reason must explain ineligible wildcard');
  }
  console.log('  [PASS] Unlisted subdomains under ineligible wildcard scopes properly rejected with DENY.');

  // [TEST 4] Unsupported Inferred Assets (Removed from Scope)
  console.log('\n[TEST 4] Unsupported Inferred Assets (farmiso.com, supply.meesho.com, etc.) → DENY');
  const unsupportedInferred = [
    'farmiso.com',
    'www.farmiso.com',
    'api.farmiso.com',
    'supply.meesho.com',
    'core.meesho.io',
    'meeshosupply.com',
  ];

  for (const target of unsupportedInferred) {
    const res = resolveTargetScope(profileId, target);
    assert.strictEqual(res.decision, 'DENY', `Unsupported target ${target} must yield DENY`);
  }
  console.log('  [PASS] Unsupported inferred assets correctly rejected (fail-closed).');

  // [TEST 5] Lookalike Hostname Spoof Attempts
  console.log('\n[TEST 5] Lookalike Suffix & Prefix Spoof Attempts → DENY');
  const spoofAttempts = [
    'www.meesho.com.attacker.com',
    'www.valmo.in.evil.com',
    'supplier.meesho.com.phishing.test',
    'evil-meesho.com',
    'fakemeesho.com',
    'notvalmo.in',
  ];

  for (const target of spoofAttempts) {
    const res = resolveTargetScope(profileId, target);
    assert.strictEqual(res.decision, 'DENY', `Spoof target ${target} must yield DENY`);
  }
  console.log('  [PASS] Lookalike and suffix spoof attempts safely rejected.');

  // [TEST 6] Exact iOS App Identifier Verification
  console.log('\n[TEST 6] Exact iOS App Identifier Resolution (1457958492) vs Invented Identifier');
  const exactIosRes = resolveTargetScope(profileId, '1457958492');
  assert.strictEqual(exactIosRes.decision, 'ALLOW', 'Exact iOS App Store ID 1457958492 must yield ALLOW');
  assert.strictEqual(exactIosRes.maxSeverity, 'CRITICAL', 'iOS app max severity must be CRITICAL');

  const inventedIosRes = resolveTargetScope(profileId, 'com.meesho.supply.ios');
  assert.strictEqual(inventedIosRes.decision, 'DENY', 'Invented identifier com.meesho.supply.ios must yield DENY');
  console.log('  [PASS] Exact iOS ID 1457958492 authorized; invented package rejected.');

  // [TEST 7] Special Operational Constraints on superstoreapp.meesho.com
  console.log('\n[TEST 7] Superstore Operational Constraints & Max Severity (HIGH)');
  const superstoreRes = resolveTargetScope(profileId, 'superstoreapp.meesho.com');
  assert.strictEqual(superstoreRes.decision, 'ALLOW', 'superstoreapp.meesho.com must yield ALLOW');
  assert.strictEqual(superstoreRes.maxSeverity, 'HIGH', 'Superstore max severity must be HIGH');
  assert(superstoreRes.operationalWarnings.some((w) => w.includes('440002')), 'Must contain Nagpur PIN constraint');
  assert(superstoreRes.operationalWarnings.some((w) => w.includes('30 minutes')), 'Must contain 30m cancellation constraint');
  console.log('  [PASS] superstoreapp.meesho.com resolved to ALLOW (HIGH) with mandatory warnings.');

  // [TEST 8] Rate Limit Policy Fidelity (No Invented 60/min Claim)
  console.log('\n[TEST 8] Rate Limit Policy Audit (No Invented 60/min Claim)');
  assert.strictEqual(profile.rateLimitPolicy.numericLimitSpecified, false, 'Numeric limit must not be specified');
  assert(!profile.rateLimitPolicy.description.includes('60 requests'), 'Must not claim 60 req/min limit');
  assert(profile.rateLimitPolicy.description.includes('NOT SPECIFIED'), 'Must state rate limit is not specified');
  console.log('  [PASS] Rate limit policy correctly reflects NOT SPECIFIED without invented numerical claims.');

  // [TEST 9] Hazardous Operations Policy (Requires Explicit Authorization, Not Permanently Disabled)
  console.log('\n[TEST 9] Hazardous Capabilities (Brute Force / High-Volume) → REVIEW_REQUIRED');
  const bruteForceRes = await evaluateProgramProfilePolicy(validResearcher, {
    programId: profileId,
    target: 'supplier.meesho.com',
    operation: 'BRUTE_FORCE',
  });
  assert.strictEqual(bruteForceRes.decision, 'REVIEW_REQUIRED', 'Brute force must yield REVIEW_REQUIRED');
  assert(bruteForceRes.reason.includes('explicit authorization'), 'Reason must indicate explicit authorization required');

  const credStuffRes = await evaluateProgramProfilePolicy(validResearcher, {
    programId: profileId,
    target: 'www.meesho.com',
    operation: 'CREDENTIAL_STUFFING',
  });
  assert.strictEqual(credStuffRes.decision, 'REVIEW_REQUIRED', 'Credential stuffing must yield REVIEW_REQUIRED');

  const highVolRes = await evaluateProgramProfilePolicy(validResearcher, {
    programId: profileId,
    target: 'prod.meeshoapi.com',
    operation: 'HIGH_VOLUME_AUTOMATED_SCAN',
  });
  assert.strictEqual(highVolRes.decision, 'REVIEW_REQUIRED', 'High-volume automated scan must yield REVIEW_REQUIRED');
  console.log('  [PASS] Hazardous capabilities correctly trigger REVIEW_REQUIRED rather than permanent blanket bans.');

  // [TEST 10] Strictly Prohibited Unethical / Destructive Vectors → BLOCK
  console.log('\n[TEST 10] Strictly Prohibited Operations (DoS, Phishing, Social Engineering) → BLOCK');
  const dosRes = await evaluateProgramProfilePolicy(validResearcher, {
    programId: profileId,
    target: 'prod.meeshoapi.com',
    operation: 'DOS',
  });
  assert.strictEqual(dosRes.decision, 'BLOCK', 'DoS must yield BLOCK');

  const phishingRes = await evaluateProgramProfilePolicy(validResearcher, {
    programId: profileId,
    target: 'www.meesho.com',
    operation: 'PHISHING',
  });
  assert.strictEqual(phishingRes.decision, 'BLOCK', 'Phishing must yield BLOCK');
  console.log('  [PASS] Unethical / destructive attack vectors blocked unconditionally.');

  // [TEST 11] Finding Eligibility Matrix — HackerOne Core Ineligible Findings
  console.log('\n[TEST 11] Finding Eligibility — HackerOne Core Ineligible Reports → INELIGIBLE');
  const coreIneligible = [
    { cat: 'Missing SPF/DKIM/DMARC Records', title: 'Missing DMARC policy' },
    { cat: 'Self-XSS', title: 'Self-XSS on personal profile edit' },
    { cat: 'Banner Grabbing / Version Disclosure', title: 'Nginx version banner in response' },
    { cat: 'Missing Security Headers (CSP, HSTS, X-Frame-Options)', title: 'Missing CSP header' },
    { cat: 'Clickjacking on Non-Sensitive Pages', title: 'Clickjacking on static FAQ page' },
    { cat: 'Tabnabbing / Reverse Tabnabbing', title: 'Target _blank missing rel="noopener"' },
    { cat: 'Missing Cookie Flags (SameSite, Secure, HttpOnly on non-sensitive cookies)', title: 'Tracking cookie missing Secure' },
    { cat: 'Weak TLS / SSL Ciphers without PoC', title: 'TLS 1.1 cipher suites supported' },
  ];

  for (const item of coreIneligible) {
    const fRes = evaluateFindingEligibility(profileId, item.cat, { title: item.title });
    assert.strictEqual(fRes.isEligible, false, `Category ${item.cat} must be INELIGIBLE`);
    assert.strictEqual(fRes.classification, 'HACKERONE_CORE_INELIGIBLE', 'Must classify as HACKERONE_CORE_INELIGIBLE');
  }
  console.log('  [PASS] All HackerOne core ineligible report classes properly rejected.');

  // [TEST 12] Finding Eligibility Matrix — Impact-Dependent Findings
  console.log('\n[TEST 12] Finding Eligibility — Impact-Dependent Findings (XSS, CORS, Open Redirect)');
  const impactDependent = [
    { cat: 'Cross-Site Scripting (XSS)', title: 'Stored XSS in user review' },
    { cat: 'Cross-Origin Resource Sharing (CORS) Misconfiguration', title: 'Permissive CORS leaking user data' },
    { cat: 'Open Redirect', title: 'Open redirect leaking OAuth token' },
    { cat: 'Rate Limiting / Account Takeover via Brute Force', title: 'OTP brute force allowing account takeover' },
  ];

  for (const item of impactDependent) {
    const fRes = evaluateFindingEligibility(profileId, item.cat, { title: item.title });
    assert.strictEqual(fRes.isEligible, true, `Category ${item.cat} should be eligible with impact requirement`);
    assert.strictEqual(fRes.classification, 'IMPACT_DEPENDENT', 'Must classify as IMPACT_DEPENDENT');
    assert(fRes.impactRequirement && fRes.impactRequirement.length > 5, 'Must provide impact requirement');
  }
  console.log('  [PASS] Impact-dependent findings classified with clear impact requirements.');

  // [TEST 13] Finding Eligibility Matrix — Qualifying Core Flaws (BOLA, RCE, SQLi, SSRF)
  console.log('\n[TEST 13] Finding Eligibility — Qualifying Core Flaws (BOLA, RCE, SQLi, SSRF) → ELIGIBLE');
  const qualifyingFlaws = [
    { cat: 'Broken Object Level Authorization (BOLA / IDOR)', title: 'BOLA on order API' },
    { cat: 'Remote Code Execution (RCE)', title: 'RCE via file parsing' },
    { cat: 'SQL Injection (SQLi)', title: 'SQLi on search query' },
    { cat: 'Authentication Bypass / Privilege Escalation', title: 'Auth bypass in admin portal' },
    { cat: 'Server-Side Request Forgery (SSRF)', title: 'SSRF reaching cloud metadata' },
    { cat: 'Business Logic Flaw / Payment Tampering', title: 'Price tampering in checkout' },
  ];

  for (const item of qualifyingFlaws) {
    const fRes = evaluateFindingEligibility(profileId, item.cat, { title: item.title });
    assert.strictEqual(fRes.isEligible, true, `Category ${item.cat} must be ELIGIBLE`);
    assert.strictEqual(fRes.classification, 'QUALIFYING', 'Must classify as QUALIFYING');
  }
  console.log('  [PASS] Core high-impact vulnerabilities evaluated as bounty ELIGIBLE.');

  // [TEST 14] Independent Scope Authorization vs Finding Eligibility
  console.log('\n[TEST 14] Independence of Target Scope Authorization vs Finding Eligibility');
  const targetScopeResult = resolveTargetScope(profileId, 'www.meesho.com');
  assert.strictEqual(targetScopeResult.decision, 'ALLOW', 'www.meesho.com must be in-scope');

  const findingIneligibleResult = evaluateFindingEligibility(profileId, 'Missing Security Headers (CSP, HSTS, X-Frame-Options)', {
    title: 'www.meesho.com missing CSP header',
  });
  assert.strictEqual(findingIneligibleResult.isEligible, false, 'Finding must be INELIGIBLE even though target is authorized');
  console.log('  [PASS] Target authorization and finding bounty eligibility evaluated independently.');

  // [TEST 15] Dry-Run Capability Evaluation (Network Traffic: ZERO)
  console.log('\n[TEST 15] Dry-Run Capability Simulation (Network Traffic: ZERO)');
  const testRequestId = `req-dryrun-fidelity-${Date.now()}`;
  const dryRunRes = await executeDryRunCapability(
    validResearcher,
    {
      programId: profileId,
      target: 'www.meesho.com',
      capabilityId: 'cap-surface-mapping',
    },
    testRequestId
  );

  assert.strictEqual(dryRunRes.dryRun, true, 'dryRun flag must be true');
  assert.strictEqual(dryRunRes.simulatedNetworkTraffic, false, 'simulatedNetworkTraffic must be false');
  assert.strictEqual(dryRunRes.policyDecision, 'ALLOW', 'Policy decision must be ALLOW');
  assert(dryRunRes.reproductionStepsSimulated.length > 0, 'Must produce simulated reproduction steps');
  console.log('  [PASS] Dry-run executed with zero live network traffic.');

  // [TEST 16] Audit Event Logging & Zero Credential Leakage
  console.log('\n[TEST 16] Audit Event Recording (Zero Credential Leakage)');
  const latestAudits = await db
    .select()
    .from(auditEvents)
    .where(eq(auditEvents.userId, validResearcher.uid))
    .orderBy(desc(auditEvents.createdAt))
    .limit(10);

  assert(latestAudits.length > 0, 'Audit events must be recorded');
  for (const audit of latestAudits) {
    const serialized = JSON.stringify(audit).toLowerCase();
    assert(!serialized.includes('bearer ey'), 'Must not contain bearer tokens');
    assert(!serialized.includes('password123'), 'Must not contain passwords');
    assert(!serialized.includes('sec_live_'), 'Must not contain secrets');
  }
  console.log('  [PASS] Audit logs verified cleanly with zero secret/token leaks.');

  await closeDatabasePool();

  console.log('\n========================================================================================');
  console.log('FINAL RESULT: ALL 16 MEESHO PROGRAM PROFILE FIDELITY & SCOPE TESTS PASSED');
  console.log('========================================================================================');
  process.exit(0);
}

runMeeshoProgramProfileVerificationSuite().catch((err) => {
  console.error('\n[FAIL] Meesho Program Profile verification suite encountered error:', err);
  process.exit(1);
});
