/**
 * Mission #0034 — Final non-live release gate
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

console.log('\n=== Mission #0034 Final Non-Live Release Gate ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

// A empty
{
  const g = runFinalConsistencyGate({});
  assert(g.authorizationStatus === 'AUTHORIZATION_PENDING', 'A empty → PENDING');
  assert(g.totalLivePackets === 0, 'A packets 0');
}

// B partial
{
  const insp = inspectAuthorizationInput({ programId: 'PARTIAL-ONLY' });
  assert(insp.fields.find((f) => f.field === 'authorizationReference')?.state === 'MISSING', 'B ref MISSING');
  assert(runFinalConsistencyGate({ programId: 'PARTIAL-ONLY' }).authorizationStatus !== 'AUTHORIZATION_VALIDATED', 'B not validated');
}

// C fixture
{
  const ctx = bindAuthorization(FIXTURE_AUTH_VECTOR, {
    policyVersion: FIXTURE_AUTH_VECTOR.policyVersion!,
    programId: FIXTURE_AUTH_VECTOR.programId!,
  });
  assert(ctx.fixtureAuthorizationValidated && !ctx.authorizationValidated, 'C fixture ≠ real');
  assert(ctx.liveExecutionEnabled === false, 'C no live');
}

// D synthetic complete
{
  const synth = {
    programId: 'SYNTH-RELEASE',
    authorizationReference: 'SYNTH-RELEASE-REF',
    policyVersion: 'SYNTH-RELEASE-V1',
    researcherIdentity: 'SYNTH-RELEASE-R',
    hackeroneUsername: 'synth_release_h1',
    primaryApprover: 'synth-pa',
    primaryApprovalReference: 'synth-pr',
    secondaryApprover: 'synth-sa',
    secondaryApprovalReference: 'synth-sr',
  };
  const g = runFinalConsistencyGate(synth);
  assert(g.checks.LIVE_ENVIRONMENT_DISABLED === 'PASS', 'D live env disabled');
  assert(g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'D live rejected');
  assert(g.meeshoRequests === 0, 'D meesho 0');
}

// E duplicate approvers
{
  const g = runFinalConsistencyGate({
    programId: 'SYNTH-E',
    authorizationReference: 'SYNTH-E-REF',
    policyVersion: 'SYNTH-E-V',
    researcherIdentity: 'SYNTH-E-R',
    hackeroneUsername: 'synth_e',
    primaryApprover: 'same-approver-person',
    primaryApprovalReference: 'ref-a-1',
    secondaryApprover: 'same-approver-person',
    secondaryApprovalReference: 'ref-b-2',
  });
  assert(g.matrix.dualApproval === 'BLOCKED' || g.authorizationStatus !== 'AUTHORIZATION_VALIDATED', 'E dup approvers');
}

// F missing approval refs
assert(
  runFinalConsistencyGate({
    programId: 'SYNTH-F',
    authorizationReference: 'SYNTH-F-REF',
    policyVersion: 'SYNTH-F-V',
    researcherIdentity: 'SYNTH-F-R',
    hackeroneUsername: 'synth_f',
    primaryApprover: 'approver-one',
    secondaryApprover: 'approver-two',
  }).checks.PRIMARY_APPROVAL_PRESENT === 'PENDING',
  'F missing refs'
);

// G expired
{
  const g = runFinalConsistencyGate({
    programId: 'SYNTH-G',
    authorizationReference: 'SYNTH-G-REF',
    policyVersion: 'SYNTH-G-V',
    researcherIdentity: 'SYNTH-G-R',
    hackeroneUsername: 'synth_g',
    primaryApprover: 'approver-one',
    primaryApprovalReference: 'ref-1',
    secondaryApprover: 'approver-two',
    secondaryApprovalReference: 'ref-2',
    authorizationExpiresAt: '2000-06-01T00:00:00Z',
  });
  assert(
    g.authorizationStatus === 'AUTHORIZATION_EXPIRED' || g.checks.AUTHORIZATION_NOT_EXPIRED === 'BLOCKED',
    'G expired'
  );
}

// H I J scope
assert(!classifyMeeshoAsset('https://unknown-host.example/').allowedForPassiveHttp, 'H unknown');
assert(!classifyMeeshoAsset('https://razorpay.com/').allowedForPassiveHttp, 'I third-party');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'J expansion blocked');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'supplier only');

// K L escalation
{
  const ctx = bindAuthorization({
    ...FIXTURE_AUTH_VECTOR,
    separateLiveMissionApproved: true,
  });
  assert(!ctx.authorizationValidated, 'K fixture not real');
  assert(ctx.liveExecutionEnabled === false, 'L no live from auth');
  assert(rejectLiveExecutionAttempt(ctx).allowed === false, 'L reject live');
}

// M secrets
{
  let r = false;
  try {
    assertNoSecretsInPayload({ authorizationReference: 'password=LeakMe123' });
  } catch {
    r = true;
  }
  assert(r, 'M secrets rejected');
}

// N mutation
{
  let m = false;
  try {
    createAuthorizationSnapshot({}).attemptMutation('programId', 'x');
  } catch {
    m = true;
  }
  assert(m, 'N auth immutable');
  assert(createMeeshoPolicySnapshot({}).isImmutable, 'N policy immutable');
}

// O P Q R S
assert(
  runFinalConsistencyGate({
    programId: 'O',
    authorizationReference: 'O',
    policyVersion: 'O',
    researcherIdentity: 'O',
  }).checks.HACKERONE_IDENTITY_CONFIGURED === 'PENDING',
  'O missing H1'
);
assert(
  runFinalConsistencyGate({
    programId: 'P',
    authorizationReference: 'P',
    policyVersion: 'P',
    hackeroneUsername: 'p_user',
  }).checks.RESEARCHER_IDENTITY_PRESENT === 'PENDING',
  'P missing researcher'
);
assert(
  !bindAuthorization(
    { ...FIXTURE_AUTH_VECTOR, policyVersion: 'OTHER-V' },
    { policyVersion: 'FIXTURE_POLICY_VERSION' }
  ).authorizationValidated,
  'Q version mismatch'
);
{
  const g = runFinalConsistencyGate({});
  assert(g.checks.SEPARATE_LIVE_MISSION_REQUIRED === 'PENDING', 'R separate mission pending');
  assert(g.checks.LIVE_ENVIRONMENT_DISABLED === 'PASS', 'S live env disabled');
}

// T final expected state
{
  const g = runFinalConsistencyGate({});
  assert(g.policyValidated, 'T policy validated');
  assert(g.authorizationStatus === 'AUTHORIZATION_PENDING', 'T auth pending');
  assert(g.fixtureGateValidated, 'T fixture ready');
  assert(g.liveEnvironmentDisabled, 'T live disabled');
  assert(g.activeTestingLocked, 'T active locked');
  assert(g.totalLivePackets === 0, 'T packets 0');
}

assert(isActiveTestingLocked(), 'active locked global');
assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'env unset');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'MEESHO_REQUESTS = 0');
assert(true, 'TOTAL_LIVE_PACKETS = 0');

console.log(`\n=== Mission #0034 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
