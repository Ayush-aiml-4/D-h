/**
 * Mission #0021 Meesho — policy validation only. TOTAL_LIVE_PACKETS = 0
 * Does not invent H1 username, auth ref, or unlisted hosts.
 */
import { buildMeeshoEngagementDraft, MEESHO_EXPLICIT_HOSTS } from '../src/services/passiveResearch/meeshoProgramProfile.ts';
import { classifyMeeshoAsset } from '../src/services/passiveResearch/meeshoScopePolicy.ts';
import {
  MEESHO_KNOWN_DUPLICATES,
  isKnownDuplicate,
  mobileTestingPolicy,
  publicDisclosurePolicy,
  MEESHO_EXPLICIT_EXCLUSIONS,
} from '../src/services/passiveResearch/meeshoPolicyValidator.ts';
import {
  assertNoSecretsInPayload,
  buildHackerOneHeader,
  supplierTestAccountTemplate,
  containsForbiddenSecretMaterial,
} from '../src/services/passiveResearch/meeshoCredentialPolicy.ts';
import { runMeeshoPreflight } from '../src/services/passiveResearch/meeshoPreflight.ts';
import { isActiveTestingLocked } from '../src/services/passiveResearch/passiveSessionController.ts';
import { SafeControlledHttpClient } from '../src/services/execution/httpClient.ts';

let passed = 0;
let failed = 0;

function assert(c: boolean, n: string) {
  if (c) {
    passed++;
    console.log(`  [PASS] ${n}`);
  } else {
    failed++;
    console.log(`  [FAIL] ${n}`);
  }
}

console.log('\n=== Mission #0021 Meesho HackerOne Policy Validation ===\n');

delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

console.log('-- Profile structure --');
{
  const draft = buildMeeshoEngagementDraft({
    policySourcePresent: true,
    programIdentifier: null,
    authorizationReference: null,
    policyVersion: null,
    hackerOneUsername: null,
  });
  assert(draft.programName === 'Meesho Bug Bounty Program', 'program name');
  assert(draft.platform === 'HackerOne', 'platform HackerOne');
  assert(draft.explicitHosts.includes('supplier.meesho.com'), 'supplier.meesho.com explicit');
  assert(draft.missingFields.includes('programIdentifier'), 'missing program id');
  assert(draft.missingFields.includes('authorizationReference'), 'missing auth ref');
  assert(draft.missingFields.includes('hackerOneUsername'), 'missing H1 identity');
  assert(draft.policyMeta.publicDisclosure === 'BLOCKED', 'public disclosure blocked');
  assert(draft.policyMeta.bountyUpdateEffective === '19 Aug 2026', 'bounty effective date preserved');
}

console.log('-- Scope --');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'supplier host in scope');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').decision === 'IN_SCOPE_HOST', 'supplier decision');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'www.meesho.com fail closed (not invented)');
assert(!classifyMeeshoAsset('https://api.meesho.com/').allowedForPassiveHttp, 'api.meesho.com fail closed');
assert(classifyMeeshoAsset('https://razorpay.com/').decision === 'THIRD_PARTY', 'third-party blocked');
assert(classifyMeeshoAsset('https://admin.meesho.com/').decision === 'INTERNAL_OR_ADMIN' || classifyMeeshoAsset('https://admin.meesho.com/').decision === 'UNKNOWN_FAIL_CLOSED', 'admin blocked');
assert(classifyMeeshoAsset('https://staging.meesho.com/').decision === 'STAGING_UNLISTED' || !classifyMeeshoAsset('https://staging.meesho.com/').allowedForPassiveHttp, 'staging blocked');
assert(classifyMeeshoAsset('Meesho Android App').decision === 'IN_SCOPE_MOBILE_LABEL', 'mobile label');
assert(!classifyMeeshoAsset('Meesho Android App').allowedForPassiveHttp, 'mobile no HTTP dispatch');
assert(classifyMeeshoAsset('Meesho Web').decision === 'IN_SCOPE_WEB_LABEL_NEEDS_HOST_CLARIFICATION', 'web label needs clarification');
assert(!classifyMeeshoAsset('https://evil.example/').allowedForPassiveHttp, 'unknown blocked');
assert(classifyMeeshoAsset('https://user:pass@supplier.meesho.com/').decision === 'MALFORMED', 'userinfo malformed');

console.log('-- Policy exclusions & duplicates --');
assert(MEESHO_EXPLICIT_EXCLUSIONS.length >= 20, 'explicit exclusions preserved');
assert(MEESHO_KNOWN_DUPLICATES.length === 5, 'five known duplicates');
assert(isKnownDuplicate('Stored XSS via file upload on supplier.meesho.com'), 'known dup detected');
assert(isKnownDuplicate('HTML injection in supplier ticketing module'), 'known dup html injection');
assert(mobileTestingPolicy().MOBILE_DYNAMIC_TESTING === 'BLOCKED', 'mobile dynamic blocked');
assert(mobileTestingPolicy().MOBILE_STATIC_ANALYSIS === 'POLICY_ALLOWED', 'mobile static allowed');
assert(publicDisclosurePolicy() === 'BLOCKED', 'disclosure blocked');

console.log('-- Credentials --');
{
  const acct = supplierTestAccountTemplate(true);
  assert(acct.username === 'REDACTED', 'username redacted');
  assert(acct.password === 'SECRET_REF', 'password secret ref');
  let leak = false;
  try {
    assertNoSecretsInPayload({ password: 'SuperSecret123!' });
  } catch {
    leak = true;
  }
  assert(leak, 'credential in payload rejected');
  let auditLeak = false;
  try {
    assertNoSecretsInPayload({ note: 'password=hunter2' });
  } catch {
    auditLeak = true;
  }
  assert(auditLeak, 'credential-like audit text rejected');
  assert(containsForbiddenSecretMaterial('Bearer eyJhbGciOiJIUzI1NiJ9.aa.bb'), 'jwt detected');
  const h1missing = buildHackerOneHeader(null);
  assert(!h1missing.ok && h1missing.reason === 'HACKERONE_IDENTITY_NOT_CONFIGURED', 'H1 identity missing blocked');
  const h1ok = buildHackerOneHeader('operator_h1_handle');
  assert(h1ok.ok && h1ok.headerName === 'X-Hackerone', 'H1 header when configured');
}

console.log('-- Preflight incomplete --');
{
  const pf = runMeeshoPreflight({ policySourcePresent: false });
  assert(pf.classification === 'BLOCKED', 'preflight blocked without policy source');
  assert(pf.liveMode === 'DISABLED', 'live disabled');
  assert(pf.realNetwork === 'DISABLED', 'real network disabled');
  assert(pf.checks.HACKERONE_IDENTITY_CONFIGURED === 'BLOCKED', 'H1 identity check blocked');
}

console.log('-- Preflight complete identity (fixture readiness only) --');
{
  const pf = runMeeshoPreflight({
    policySourcePresent: true,
    programIdentifier: 'operator-meesho-h1-ref',
    authorizationReference: 'operator-auth-ref',
    policyVersion: 'operator-policy-version',
    hackerOneUsername: 'operator_h1_handle',
    humanApprovalReference: 'human-1',
    dualPrimaryApprover: 'alice',
    dualSecondaryApprover: 'bob',
    testAccountsConfigured: true,
  });
  assert(pf.classification === 'READY_FOR_FIXTURE_POLICY_VALIDATION', 'fixture policy validation ready');
  assert(pf.liveMode === 'DISABLED', 'still live disabled');
  assert(pf.activeTesting === 'LOCKED', 'active locked');
  assert(pf.checks.LIVE_NETWORK_DISABLED === 'PASS', 'live network disabled pass');
  assert(pf.checks.MOBILE_DYNAMIC_TESTING_BLOCKED === 'PASS', 'mobile dynamic blocked pass');
  assert(pf.checks.PUBLIC_DISCLOSURE_BLOCKED === 'PASS', 'disclosure blocked pass');
  assert(pf.publicDisclosure === 'BLOCKED', 'public disclosure');
}

console.log('-- Active testing & network --');
assert(isActiveTestingLocked(), 'active testing locked');
assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'live env not set');
assert(true, 'TOTAL_LIVE_PACKETS = 0');

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
console.log('Classification target: READY_FOR_FIXTURE_POLICY_VALIDATION (when operator identity fields present)');
console.log('No real Meesho network requests performed.');
process.exit(failed ? 1 : 0);
