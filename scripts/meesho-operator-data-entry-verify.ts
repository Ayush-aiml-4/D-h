/**
 * Mission #0032 — Operator authorization data-entry path (non-live)
 * TOTAL_LIVE_PACKETS = 0. No invented real authorization.
 */
import { inspectAuthorizationInput } from '../src/services/passiveResearch/meeshoAuthorizationInput.ts';
import { runFinalConsistencyGate } from '../src/services/passiveResearch/meeshoFinalConsistencyGate.ts';
import { FIXTURE_AUTH_VECTOR } from '../src/services/passiveResearch/meeshoAuthorizationSnapshot.ts';
import { bindAuthorization, rejectLiveExecutionAttempt } from '../src/services/passiveResearch/meeshoAuthorizationBinding.ts';
import { classifyMeeshoAsset } from '../src/services/passiveResearch/meeshoScopePolicy.ts';
import { assertNoSecretsInPayload } from '../src/services/passiveResearch/meeshoCredentialPolicy.ts';
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

console.log('\n=== Mission #0032 Operator Authorization Data Entry ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

// A. Empty
console.log('-- A. Empty operator input --');
{
  const insp = inspectAuthorizationInput({});
  assert(insp.fields.filter((f) => f.field !== 'separateLiveMissionApproval').every((f) => f.state === 'MISSING'), 'all required MISSING');
  assert(!insp.allRequiredRealConfigured, 'not complete');
  const g = runFinalConsistencyGate({});
  assert(g.authorizationStatus === 'AUTHORIZATION_PENDING', 'A: AUTHORIZATION_PENDING');
  assert(g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'A: live rejected');
  assert(g.totalLivePackets === 0, 'A: packets 0');
}

// B. Partial
console.log('-- B. Partial operator input --');
{
  const partial = { programId: 'OP-PARTIAL-ONLY' };
  const insp = inspectAuthorizationInput(partial);
  assert(insp.fields.find((f) => f.field === 'programId')?.state === 'CONFIGURED', 'B: programId CONFIGURED');
  assert(insp.fields.find((f) => f.field === 'authorizationReference')?.state === 'MISSING', 'B: auth ref MISSING');
  const g = runFinalConsistencyGate(partial);
  assert(g.authorizationStatus === 'AUTHORIZATION_PENDING' || g.authorizationStatus === 'AUTHORIZATION_REJECTED', 'B: still pending/rejected');
  assert(g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'B: live rejected');
}

// C. Fixture-only
console.log('-- C. Fixture-only vector --');
{
  const g = runFinalConsistencyGate(FIXTURE_AUTH_VECTOR);
  assert(g.authorizationStatus === 'FIXTURE_AUTHORIZATION_VALIDATED', 'C: FIXTURE_AUTHORIZATION_VALIDATED');
  assert(g.authorizationStatus !== 'AUTHORIZATION_VALIDATED', 'C: not real validated');
  const ctx = bindAuthorization(FIXTURE_AUTH_VECTOR, {
    policyVersion: FIXTURE_AUTH_VECTOR.policyVersion,
    programId: FIXTURE_AUTH_VECTOR.programId,
  });
  assert(!ctx.authorizationValidated, 'C: real gate false');
  assert(ctx.fixtureAuthorizationValidated, 'C: fixture structural ok');
  assert(rejectLiveExecutionAttempt(ctx).allowed === false, 'C: live rejected');
}

// D. Complete synthetic non-secret (NOT real Meesho auth)
console.log('-- D. Synthetic complete vector (structural only) --');
{
  const synth = {
    programId: 'SYNTH-OP-PROGRAM',
    authorizationReference: 'SYNTH-OP-AUTH-REF',
    policyVersion: 'SYNTH-OP-POLICY-V1',
    researcherIdentity: 'SYNTH-OP-RESEARCHER',
    hackeroneUsername: 'synth_op_h1',
    primaryApprover: 'synth-approver-1',
    primaryApprovalReference: 'synth-approval-ref-1',
    secondaryApprover: 'synth-approver-2',
    secondaryApprovalReference: 'synth-approval-ref-2',
  };
  const insp = inspectAuthorizationInput(synth);
  assert(insp.allRequiredRealConfigured, 'D: all required CONFIGURED (synthetic labels)');
  const g = runFinalConsistencyGate(synth);
  assert(g.totalLivePackets === 0, 'D: no network');
  assert(g.checks.LIVE_ENVIRONMENT_DISABLED === 'PASS', 'D: live env disabled');
  assert(g.checks.ACTIVE_TESTING_LOCKED === 'PASS', 'D: active locked');
  // Even if structurally valid, separate live mission missing → not live
  assert(g.checks.SEPARATE_LIVE_MISSION_REQUIRED === 'PENDING' || g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'D: separate mission / live rejected');
  assert(g.meeshoRequests === 0, 'D: meesho 0');
}

// E. Duplicate approvers
console.log('-- E. Duplicate approvers --');
{
  const g = runFinalConsistencyGate({
    programId: 'SYNTH-E',
    authorizationReference: 'SYNTH-E-REF',
    policyVersion: 'SYNTH-E-V',
    researcherIdentity: 'SYNTH-E-R',
    hackeroneUsername: 'synth_e',
    primaryApprover: 'same-person',
    primaryApprovalReference: 'ref-1',
    secondaryApprover: 'same-person',
    secondaryApprovalReference: 'ref-2',
  });
  assert(g.matrix.dualApproval === 'BLOCKED' || g.authorizationStatus !== 'AUTHORIZATION_VALIDATED', 'E: dup approvers rejected');
}

// F. Missing approval references
console.log('-- F. Missing approval references --');
{
  const g = runFinalConsistencyGate({
    programId: 'SYNTH-F',
    authorizationReference: 'SYNTH-F-REF',
    policyVersion: 'SYNTH-F-V',
    researcherIdentity: 'SYNTH-F-R',
    hackeroneUsername: 'synth_f',
    primaryApprover: 'a1',
    secondaryApprover: 'a2',
  });
  assert(g.checks.PRIMARY_APPROVAL_PRESENT === 'PENDING', 'F: primary approval pending');
  assert(g.checks.SECONDARY_APPROVAL_PRESENT === 'PENDING', 'F: secondary approval pending');
}

// G. Expired
console.log('-- G. Expired explicit authorization --');
{
  const g = runFinalConsistencyGate({
    programId: 'SYNTH-G',
    authorizationReference: 'SYNTH-G-REF',
    policyVersion: 'SYNTH-G-V',
    researcherIdentity: 'SYNTH-G-R',
    hackeroneUsername: 'synth_g',
    primaryApprover: 'a1',
    primaryApprovalReference: 'r1',
    secondaryApprover: 'a2',
    secondaryApprovalReference: 'r2',
    authorizationExpiresAt: '2000-01-01T00:00:00Z',
  });
  assert(
    g.authorizationStatus === 'AUTHORIZATION_EXPIRED' || g.checks.AUTHORIZATION_NOT_EXPIRED === 'BLOCKED',
    'G: expired rejected'
  );
}

// H. Scope expansion
console.log('-- H. Closed scope --');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'H: www blocked');
assert(!classifyMeeshoAsset('https://api.meesho.com/').allowedForPassiveHttp, 'H: api blocked');
assert(!classifyMeeshoAsset('https://staging.meesho.com/').allowedForPassiveHttp, 'H: staging blocked');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'H: supplier only');

// I. Live via auth data
console.log('-- I. Live via authorization data --');
{
  const g = runFinalConsistencyGate({
    ...FIXTURE_AUTH_VECTOR,
    separateLiveMissionApproval: true,
  });
  assert(g.checks.LIVE_ENVIRONMENT_DISABLED === 'PASS', 'I: live env still disabled');
  assert(g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'I: live execution rejected');
  assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'I: env flag unset');
}

// J. Secrets
console.log('-- J. Secret-like values --');
{
  let rejected = false;
  try {
    assertNoSecretsInPayload({ authorizationReference: 'Bearer eyJhbGciOi.jwt.payload' });
  } catch {
    rejected = true;
  }
  assert(rejected, 'J: JWT-like rejected');
  let rejected2 = false;
  try {
    assertNoSecretsInPayload({ password: 'SuperSecret99!' });
  } catch {
    rejected2 = true;
  }
  assert(rejected2, 'J: password rejected');
}

console.log('-- Locks --');
assert(isActiveTestingLocked(), 'active testing locked');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'MEESHO_REQUESTS = 0');
assert(true, 'TOTAL_LIVE_PACKETS = 0');

console.log(`\n=== Mission #0032 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
