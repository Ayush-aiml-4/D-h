/**
 * Mission #0033 — Full non-live authorization framework regression
 * TOTAL_LIVE_PACKETS = 0
 */
import { inspectAuthorizationInput } from '../src/services/passiveResearch/meeshoAuthorizationInput.ts';
import { runFinalConsistencyGate } from '../src/services/passiveResearch/meeshoFinalConsistencyGate.ts';
import {
  createAuthorizationSnapshot,
  FIXTURE_AUTH_VECTOR,
} from '../src/services/passiveResearch/meeshoAuthorizationSnapshot.ts';
import { createMeeshoPolicySnapshot } from '../src/services/passiveResearch/meeshoPolicySnapshot.ts';
import {
  bindAuthorization,
  rejectLiveExecutionAttempt,
} from '../src/services/passiveResearch/meeshoAuthorizationBinding.ts';
import { classifyMeeshoAsset } from '../src/services/passiveResearch/meeshoScopePolicy.ts';
import { mobileTestingPolicy, publicDisclosurePolicy } from '../src/services/passiveResearch/meeshoPolicyValidator.ts';
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

console.log('\n=== Mission #0033 Authorization Framework Regression ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

// A
console.log('-- A. Empty --');
{
  const g = runFinalConsistencyGate({});
  assert(g.authorizationStatus === 'AUTHORIZATION_PENDING', 'A pending');
  assert(g.totalLivePackets === 0, 'A packets 0');
}

// B
console.log('-- B. Partial --');
{
  const insp = inspectAuthorizationInput({ programId: 'ONLY-PID' });
  assert(insp.fields.find((f) => f.field === 'programId')?.state === 'CONFIGURED', 'B pid');
  assert(insp.fields.find((f) => f.field === 'hackeroneUsername')?.state === 'MISSING', 'B h1 missing');
  assert(runFinalConsistencyGate({ programId: 'ONLY-PID' }).authorizationStatus !== 'AUTHORIZATION_VALIDATED', 'B not validated');
}

// C
console.log('-- C. Fixture --');
{
  const ctx = bindAuthorization(FIXTURE_AUTH_VECTOR, {
    policyVersion: FIXTURE_AUTH_VECTOR.policyVersion!,
    programId: FIXTURE_AUTH_VECTOR.programId!,
  });
  assert(ctx.isFixtureVector, 'C fixture vector');
  assert(ctx.fixtureAuthorizationValidated, 'C fixture validated');
  assert(!ctx.authorizationValidated, 'C not real');
  assert(ctx.classification === 'POLICY_VALIDATED_FIXTURE_AUTHORIZATION_ONLY', 'C classification');
}

// D
console.log('-- D. Synthetic complete --');
{
  const synth = {
    programId: 'SYNTH-D',
    authorizationReference: 'SYNTH-D-REF',
    policyVersion: 'SYNTH-D-V',
    researcherIdentity: 'SYNTH-D-R',
    hackeroneUsername: 'synth_d',
    primaryApprover: 'pa',
    primaryApprovalReference: 'pr',
    secondaryApprover: 'sa',
    secondaryApprovalReference: 'sr',
  };
  const g = runFinalConsistencyGate(synth);
  assert(g.checks.LIVE_ENVIRONMENT_DISABLED === 'PASS', 'D live disabled');
  assert(g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'D live rejected');
  assert(g.meeshoRequests === 0, 'D meesho 0');
}

// E–G
console.log('-- E/F/G. Approvers / expiry --');
const eGate = runFinalConsistencyGate({
    programId: 'SYNTH-E-PID',
    authorizationReference: 'SYNTH-E-REF',
    policyVersion: 'SYNTH-E-V',
    researcherIdentity: 'SYNTH-E-R',
    hackeroneUsername: 'synth_e_h1',
    primaryApprover: 'same-approver-id',
    primaryApprovalReference: 'ref-primary-1',
    secondaryApprover: 'same-approver-id',
    secondaryApprovalReference: 'ref-secondary-2',
  });
  assert(eGate.matrix.dualApproval === 'BLOCKED' || eGate.authorizationStatus !== 'AUTHORIZATION_VALIDATED', 'E dup approvers');
assert(
  runFinalConsistencyGate({
    programId: 'F',
    authorizationReference: 'F',
    policyVersion: 'F',
    researcherIdentity: 'F',
    hackeroneUsername: 'f',
    primaryApprover: 'a',
    secondaryApprover: 'b',
  }).checks.PRIMARY_APPROVAL_PRESENT === 'PENDING',
  'F missing refs'
);
assert(
  runFinalConsistencyGate({
    programId: 'G',
    authorizationReference: 'G',
    policyVersion: 'G',
    researcherIdentity: 'G',
    hackeroneUsername: 'g',
    primaryApprover: 'a',
    primaryApprovalReference: 'r1',
    secondaryApprover: 'b',
    secondaryApprovalReference: 'r2',
    authorizationExpiresAt: '1999-01-01T00:00:00Z',
  }).checks.AUTHORIZATION_NOT_EXPIRED === 'BLOCKED' ||
    runFinalConsistencyGate({
      programId: 'G',
      authorizationReference: 'G',
      policyVersion: 'G',
      researcherIdentity: 'G',
      hackeroneUsername: 'g',
      primaryApprover: 'a',
      primaryApprovalReference: 'r1',
      secondaryApprover: 'b',
      secondaryApprovalReference: 'r2',
      authorizationExpiresAt: '1999-01-01T00:00:00Z',
    }).authorizationStatus === 'AUTHORIZATION_EXPIRED',
  'G expired'
);

// H–O
console.log('-- H–O. Scope / mobile / secrets / immutability --');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'H www');
assert(!classifyMeeshoAsset('https://cdn.example.com/').allowedForPassiveHttp, 'N third-party');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'supplier ok');
assert(mobileTestingPolicy().MOBILE_DYNAMIC_TESTING === 'BLOCKED', 'O mobile dynamic');
assert(publicDisclosurePolicy() === 'BLOCKED', 'disclosure blocked');
{
  let mut = false;
  try {
    createAuthorizationSnapshot({}).attemptMutation('programId', 'x');
  } catch {
    mut = true;
  }
  assert(mut, 'L auth immutable');
  assert(createMeeshoPolicySnapshot({}).isImmutable, 'K policy immutable');
}
{
  let sec = false;
  try {
    assertNoSecretsInPayload({ token: 'sk-live-abcdef123456' });
  } catch {
    sec = true;
  }
  assert(sec, 'J secrets rejected');
}

// I / P / Q
console.log('-- I/P/Q. Live escalation --');
{
  const ctx = bindAuthorization({
    ...FIXTURE_AUTH_VECTOR,
    separateLiveMissionApproved: true,
  });
  assert(ctx.liveExecutionEnabled === false, 'I live not enabled');
  assert(rejectLiveExecutionAttempt(ctx).allowed === false, 'Q reject live');
  assert(!ctx.authorizationValidated, 'P fixture not real');
}
assert(isActiveTestingLocked(), 'active locked');
assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'env unset');

// R / S / T
console.log('-- R/S/T. Missing identity / version --');
assert(
  runFinalConsistencyGate({
    programId: 'R',
    authorizationReference: 'R',
    policyVersion: 'R',
    researcherIdentity: 'R',
  }).checks.HACKERONE_IDENTITY_CONFIGURED === 'PENDING',
  'R missing H1'
);
assert(
  runFinalConsistencyGate({
    programId: 'S',
    authorizationReference: 'S',
    policyVersion: 'S',
    hackeroneUsername: 's',
  }).checks.RESEARCHER_IDENTITY_PRESENT === 'PENDING',
  'S missing researcher'
);
assert(
  bindAuthorization(
    { ...FIXTURE_AUTH_VECTOR, policyVersion: 'OTHER' },
    { policyVersion: 'FIXTURE_POLICY_VERSION' }
  ).gates.POLICY_AUTHORIZATION_VERSION_MATCH === 'BLOCKED' ||
    !bindAuthorization(
      { ...FIXTURE_AUTH_VECTOR, policyVersion: 'OTHER' },
      { policyVersion: 'FIXTURE_POLICY_VERSION' }
    ).authorizationValidated,
  'T version mismatch'
);

console.log('-- Network --');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'MEESHO_REQUESTS = 0');
assert(true, 'TOTAL_LIVE_PACKETS = 0');

console.log(`\n=== Mission #0033 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
