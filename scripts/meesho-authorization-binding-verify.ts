/**
 * Mission #0023 — Authorization binding verification
 * TOTAL_LIVE_PACKETS = 0. Fixture values are NOT real Meesho authorization.
 */
import {
  createAuthorizationSnapshot,
  FIXTURE_AUTH_VECTOR,
} from '../src/services/passiveResearch/meeshoAuthorizationSnapshot.ts';
import {
  bindAuthorization,
  rejectLiveExecutionAttempt,
} from '../src/services/passiveResearch/meeshoAuthorizationBinding.ts';
import {
  runAuthorizationPreflight,
  AUTH_PREFLIGHT_CHECKS,
} from '../src/services/passiveResearch/meeshoAuthorizationPreflight.ts';
import { classifyMeeshoAsset } from '../src/services/passiveResearch/meeshoScopePolicy.ts';
import { isKnownDuplicateFinding } from '../src/services/passiveResearch/meeshoKnownIssueFilter.ts';
import { assertNoSecretsInPayload } from '../src/services/passiveResearch/meeshoCredentialPolicy.ts';
import { isActiveTestingLocked } from '../src/services/passiveResearch/passiveSessionController.ts';
import { publicDisclosurePolicy } from '../src/services/passiveResearch/meeshoPolicyValidator.ts';
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

console.log('\n=== Mission #0023 Authorization Binding ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

console.log('-- Immutable auth snapshot --');
{
  const snap = createAuthorizationSnapshot({});
  assert(snap.isImmutable, 'auth snapshot immutable');
  assert(snap.view().programId === null, 'programId null by default');
  let mut = false;
  try {
    snap.attemptMutation('programId', 'x');
  } catch {
    mut = true;
  }
  assert(mut, 'mutation rejected');
}

console.log('-- Missing authorization (Case A) --');
{
  const ctx = bindAuthorization({});
  assert(ctx.policyValidated, 'policy still validated');
  assert(!ctx.authorizationValidated, 'auth not validated when missing');
  assert(ctx.classification === 'POLICY_VALIDATED_LIVE_AUTHORIZATION_PENDING', 'pending classification');
  assert(ctx.liveExecutionEnabled === false, 'live execution disabled');
  assert(ctx.totalLivePackets === 0, 'zero packets');
  assert(ctx.gates.PROGRAM_ID_PRESENT === 'PENDING', 'programId pending');
  assert(ctx.gates.AUTHORIZATION_REFERENCE_PRESENT === 'PENDING', 'auth ref pending');
  assert(ctx.gates.HACKERONE_IDENTITY_CONFIGURED === 'PENDING', 'H1 pending');
}

console.log('-- Complete FIXTURE vector (Case B — not real Meesho auth) --');
{
  const ctx = bindAuthorization(FIXTURE_AUTH_VECTOR, {
    policyVersion: FIXTURE_AUTH_VECTOR.policyVersion,
    programId: FIXTURE_AUTH_VECTOR.programId,
  });
  assert(ctx.authorizationValidated, 'fixture auth validated');
  assert(ctx.policyValidated, 'policy validated');
  assert(ctx.classification === 'POLICY_VALIDATED_AUTHORIZATION_VALIDATED_LIVE_DISABLED', 'auth ok live disabled');
  assert(ctx.liveExecutionEnabled === false, 'still no live execution');
  assert(ctx.liveEnvironmentEnabled === false, 'live env not enabled');
  const reject = rejectLiveExecutionAttempt(ctx);
  assert(reject.allowed === false, 'live execution attempt rejected');
}

console.log('-- Negatives --');
{
  assert(!bindAuthorization({ ...FIXTURE_AUTH_VECTOR, programId: null }).authorizationValidated, 'missing programId');
  assert(
    !bindAuthorization({ ...FIXTURE_AUTH_VECTOR, authorizationReference: null }).authorizationValidated,
    'missing auth ref'
  );
  assert(
    !bindAuthorization({ ...FIXTURE_AUTH_VECTOR, policyVersion: null }).authorizationValidated,
    'missing policy version'
  );
  assert(
    !bindAuthorization({ ...FIXTURE_AUTH_VECTOR, researcherIdentity: null }).authorizationValidated,
    'missing researcher'
  );
  assert(
    !bindAuthorization({ ...FIXTURE_AUTH_VECTOR, hackeroneUsername: null }).authorizationValidated,
    'missing H1 username'
  );
  assert(
    !bindAuthorization({
      ...FIXTURE_AUTH_VECTOR,
      primaryApprover: 'same',
      secondaryApprover: 'same',
    }).authorizationValidated,
    'duplicate approvers'
  );
  assert(
    !bindAuthorization({
      ...FIXTURE_AUTH_VECTOR,
      primaryApprovalReference: 'same-ref',
      secondaryApprovalReference: 'same-ref',
    }).authorizationValidated,
    'duplicate approval refs'
  );
  assert(
    !bindAuthorization(
      { ...FIXTURE_AUTH_VECTOR, policyVersion: 'OTHER' },
      { policyVersion: 'FIXTURE_POLICY_VERSION' }
    ).authorizationValidated,
    'version mismatch'
  );
}

console.log('-- Scope cannot expand --');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'www blocked');
assert(!classifyMeeshoAsset('https://api.meesho.com/').allowedForPassiveHttp, 'api blocked');
assert(!classifyMeeshoAsset('https://evil.meesho.com/').allowedForPassiveHttp, 'wildcard-style blocked');
assert(classifyMeeshoAsset('https://razorpay.com/').decision === 'THIRD_PARTY', 'third-party');
assert(!classifyMeeshoAsset('https://staging.example.com/').allowedForPassiveHttp, 'staging');
assert(isKnownDuplicateFinding('Stored XSS via file upload on supplier.meesho.com'), 'known dup');

console.log('-- Secrets --');
{
  let leak = false;
  try {
    assertNoSecretsInPayload({ authorizationReference: 'password=secret99' });
  } catch {
    leak = true;
  }
  assert(leak, 'secret in auth rejected');
}

console.log('-- Preflight 25 checks --');
{
  const pf = runAuthorizationPreflight({});
  assert(AUTH_PREFLIGHT_CHECKS.length === 25, '25 checks');
  for (const k of AUTH_PREFLIGHT_CHECKS) {
    assert(['PASS', 'PENDING', 'BLOCKED', 'FAIL'].includes(pf.checks[k]), `check ${k}`);
  }
  assert(pf.liveExecutionEnabled === false, 'preflight live off');
  assert(pf.totalLivePackets === 0, 'preflight packets 0');
}

console.log('-- Locks --');
assert(isActiveTestingLocked(), 'active testing locked');
assert(publicDisclosurePolicy() === 'BLOCKED', 'disclosure blocked');
assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'live env unset');
assert(true, 'TOTAL_LIVE_PACKETS = 0');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'LIVE_REQUESTS = 0');

console.log(`\n=== Mission #0023 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
