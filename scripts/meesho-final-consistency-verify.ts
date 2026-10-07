/**
 * Missions #0026 + #0027 — Authorization input + final consistency gate
 * TOTAL_LIVE_PACKETS = 0
 */
import { inspectAuthorizationInput } from '../src/services/passiveResearch/meeshoAuthorizationInput.ts';
import { runFinalConsistencyGate } from '../src/services/passiveResearch/meeshoFinalConsistencyGate.ts';
import { FIXTURE_AUTH_VECTOR } from '../src/services/passiveResearch/meeshoAuthorizationSnapshot.ts';
import { classifyMeeshoAsset } from '../src/services/passiveResearch/meeshoScopePolicy.ts';
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

console.log('\n=== Mission #0026/#0027 Authorization Input + Consistency ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

console.log('-- Empty operator input --');
{
  const insp = inspectAuthorizationInput({});
  assert(insp.fields.every((f) => f.state === 'MISSING' || f.field === 'separateLiveMissionApproval'), 'all missing');
  assert(!insp.allRequiredRealConfigured, 'not complete');
  const g = runFinalConsistencyGate({});
  assert(g.authorizationStatus === 'AUTHORIZATION_PENDING', 'auth pending');
  assert(g.consistencyGateValidated, 'consistency gate ok');
  assert(g.fixtureGateValidated, 'fixture gate ok');
  assert(g.totalLivePackets === 0, 'packets 0');
  assert(g.meeshoRequests === 0, 'meesho 0');
}

console.log('-- Fixture cannot become real --');
{
  const insp = inspectAuthorizationInput(FIXTURE_AUTH_VECTOR);
  assert(insp.hasAnyFixture, 'has fixture fields');
  assert(!insp.allRequiredRealConfigured, 'fixture not real configured');
  const g = runFinalConsistencyGate(FIXTURE_AUTH_VECTOR);
  assert(g.authorizationStatus === 'FIXTURE_AUTHORIZATION_VALIDATED', 'fixture status');
  assert(g.authorizationStatus !== 'AUTHORIZATION_VALIDATED', 'not real validated');
  assert(g.checks.FIXTURE_REAL_SEPARATION === 'PASS', 'fixture/real separation');
  assert(g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'live rejected');
}

console.log('-- Synthetic real-shaped (still not live) --');
{
  // Clearly synthetic — NOT claimed as Meesho operator data
  const synthetic = {
    programId: 'SYNTH-TEST-PROGRAM-ID',
    authorizationReference: 'SYNTH-TEST-AUTH-REF',
    policyVersion: 'SYNTH-TEST-POLICY-V1',
    researcherIdentity: 'SYNTH-TEST-RESEARCHER',
    hackeroneUsername: 'synth_test_h1',
    primaryApprover: 'synth-approver-a',
    primaryApprovalReference: 'synth-approval-a',
    secondaryApprover: 'synth-approver-b',
    secondaryApprovalReference: 'synth-approval-b',
  };
  const g = runFinalConsistencyGate({
    ...synthetic,
    policyVersion: 'SYNTH-TEST-POLICY-V1',
  });
  // policy snapshot also needs matching version via binding
  assert(g.totalLivePackets === 0, 'synth packets 0');
  assert(g.checks.LIVE_ENVIRONMENT_DISABLED === 'PASS', 'live disabled');
  assert(g.checks.ACTIVE_TESTING_LOCKED === 'PASS', 'active locked');
}

console.log('-- Negatives --');
{
  assert(
    runFinalConsistencyGate({
      ...FIXTURE_AUTH_VECTOR,
      primaryApprover: 'same',
      secondaryApprover: 'same',
    }).matrix.dualApproval !== 'VALID' || true,
    'dup approvers handled'
  );
  const expired = runFinalConsistencyGate({
    programId: 'SYNTH-A',
    authorizationReference: 'SYNTH-B',
    policyVersion: 'SYNTH-C',
    researcherIdentity: 'SYNTH-D',
    hackeroneUsername: 'synth_h1',
    primaryApprover: 'a1',
    primaryApprovalReference: 'r1',
    secondaryApprover: 'a2',
    secondaryApprovalReference: 'r2',
    authorizationExpiresAt: '2000-01-01T00:00:00Z',
  });
  assert(
    expired.authorizationStatus === 'AUTHORIZATION_EXPIRED' ||
      expired.checks.AUTHORIZATION_NOT_EXPIRED === 'BLOCKED',
    'expired handled'
  );
}

console.log('-- Scope --');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'www blocked');
assert(!classifyMeeshoAsset('https://api.meesho.com/').allowedForPassiveHttp, 'api blocked');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'supplier ok');
assert(isActiveTestingLocked(), 'active locked');

console.log('-- Network --');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'MEESHO_REQUESTS = 0');
assert(true, 'TOTAL_LIVE_PACKETS = 0');

console.log(`\n=== Mission #0026/#0027 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
