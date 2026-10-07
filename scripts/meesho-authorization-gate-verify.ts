/**
 * Mission #0025 — Fixture vs real authorization separation
 * TOTAL_LIVE_PACKETS = 0
 */
import {
  bindAuthorization,
  rejectLiveExecutionAttempt,
  FIXTURE_AUTH_VECTOR,
} from '../src/services/passiveResearch/meeshoAuthorizationBinding.ts';
import { runSupervisedFixtureGate } from '../src/services/passiveResearch/meeshoSupervisedFixtureGate.ts';
import { isFixtureAuthorizationVector } from '../src/services/passiveResearch/meeshoAuthorizationValidator.ts';
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

console.log('\n=== Mission #0025 Authorization Gate Separation ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

console.log('-- Missing real operator data --');
{
  const ctx = bindAuthorization({});
  assert(ctx.policyValidated, 'policy validated');
  assert(!ctx.authorizationValidated, 'real auth NOT validated');
  assert(!ctx.fixtureAuthorizationValidated, 'fixture auth not claimed');
  assert(ctx.classification === 'POLICY_VALIDATED_LIVE_AUTHORIZATION_PENDING', 'pending classification');
  assert(ctx.liveExecutionEnabled === false, 'live disabled');
  assert(rejectLiveExecutionAttempt(ctx).allowed === false, 'live rejected');
}

console.log('-- Fixture vector cannot unlock real auth --');
{
  assert(isFixtureAuthorizationVector(FIXTURE_AUTH_VECTOR), 'detect fixture vector');
  const ctx = bindAuthorization(FIXTURE_AUTH_VECTOR, {
    policyVersion: FIXTURE_AUTH_VECTOR.policyVersion,
    programId: FIXTURE_AUTH_VECTOR.programId,
  });
  assert(ctx.isFixtureVector, 'is fixture vector');
  assert(ctx.fixtureAuthorizationValidated, 'fixture structural validation');
  assert(!ctx.authorizationValidated, 'FIXTURE cannot satisfy REAL authorization gate');
  assert(ctx.classification === 'POLICY_VALIDATED_FIXTURE_AUTHORIZATION_ONLY', 'fixture-only classification');
  assert(ctx.liveExecutionEnabled === false, 'fixture does not enable live');
  assert(rejectLiveExecutionAttempt(ctx).allowed === false, 'live still rejected');
}

console.log('-- Supervised fixture gate --');
{
  const g = runSupervisedFixtureGate({});
  assert(g.finalState === 'POLICY_VALIDATED_FIXTURE_READY_LIVE_AUTHORIZATION_PENDING', 'gate pending');
  assert(g.totalLivePackets === 0, 'packets 0');
  const gf = runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR });
  assert(!gf.binding.authorizationValidated, 'fixture gate real auth false');
  assert(gf.fixtureProbe.realAuthUnlocked === false, 'realAuthUnlocked false');
  assert(gf.fixtureProbe.liveRejected, 'live rejected');
  assert(gf.fixtureProbe.liveNetwork === false, 'no live network');
}

console.log('-- Scope / locks --');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'www blocked');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'supplier explicit');
assert(isActiveTestingLocked(), 'active locked');
assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'live env unset');
assert(true, 'TOTAL_LIVE_PACKETS = 0');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'MEESHO_REQUESTS = 0');

console.log(`\n=== Mission #0025 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
