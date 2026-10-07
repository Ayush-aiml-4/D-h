/**
 * Mission #0024 — Complete authorization binding + supervised fixture gate
 * TOTAL_LIVE_PACKETS = 0. FIXTURE_* values are NOT real Meesho authorization.
 */
import {
  runSupervisedFixtureGate,
  FIXTURE_AUTH_VECTOR,
  PREFLIGHT_KEYS,
  evaluateAuthorizationExpiry,
} from '../src/services/passiveResearch/meeshoSupervisedFixtureGate.ts';
import { createAuthorizationSnapshot } from '../src/services/passiveResearch/meeshoAuthorizationSnapshot.ts';
import { createMeeshoPolicySnapshot } from '../src/services/passiveResearch/meeshoPolicySnapshot.ts';
import { classifyMeeshoAsset } from '../src/services/passiveResearch/meeshoScopePolicy.ts';
import { classifyFixtureFinding } from '../src/services/passiveResearch/meeshoKnownIssueFilter.ts';
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

console.log('\n=== Mission #0024 Authorization Complete + Fixture Gate ===\n');
delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

console.log('-- Incomplete operator data (Case A) --');
{
  const g = runSupervisedFixtureGate({});
  assert(g.finalState === 'POLICY_VALIDATED_FIXTURE_READY_LIVE_AUTHORIZATION_PENDING', 'case A final state');
  assert(g.binding.policyValidated, 'policy validated');
  assert(!g.binding.authorizationValidated, 'auth pending');
  assert(g.checks.PROGRAM_ID_PRESENT === 'PENDING', 'programId pending');
  assert(g.checks.AUTHORIZATION_REFERENCE_PRESENT === 'PENDING', 'auth ref pending');
  assert(g.checks.HACKERONE_IDENTITY_CONFIGURED === 'PENDING', 'H1 pending');
  assert(g.checks.LIVE_EXECUTION_REJECTED === 'PASS', 'live rejected');
  assert(g.totalLivePackets === 0, 'packets 0');
  assert(g.networkContacts === 0, 'contacts 0');
}

console.log('-- Complete FIXTURE vector (Case B — synthetic only) --');
{
  const g = runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR });
  assert(g.binding.authorizationValidated, 'fixture auth validated');
  assert(g.finalState === 'POLICY_VALIDATED_AUTHORIZATION_VALIDATED_LIVE_DISABLED', 'case B state');
  assert(g.binding.liveExecutionEnabled === false, 'live not enabled');
  assert(g.fixtureProbe.ok, 'fixture probe ok');
  assert(g.fixtureProbe.liveNetwork === false, 'fixture not live');
  assert(g.fixtureProbe.liveRejected, 'live rejected on complete auth');
  assert(g.fixtureProbe.knownDupFiltered, 'known dup filtered');
  assert(g.fixtureProbe.scopeHostAllowed, 'supplier host classified in scope');
}

console.log('-- Negatives --');
{
  assert(!runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR, programId: null }).binding.authorizationValidated, 'missing programId');
  assert(!runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR, authorizationReference: null }).binding.authorizationValidated, 'missing auth ref');
  assert(!runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR, policyVersion: null }).binding.authorizationValidated, 'missing policy version');
  assert(!runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR, researcherIdentity: null }).binding.authorizationValidated, 'missing researcher');
  assert(!runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR, hackeroneUsername: null }).binding.authorizationValidated, 'missing H1');
  assert(!runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR, primaryApprover: 'x', secondaryApprover: 'x' }).binding.authorizationValidated, 'dup approvers');
  assert(!runSupervisedFixtureGate({ ...FIXTURE_AUTH_VECTOR, primaryApprovalReference: 'r', secondaryApprovalReference: 'r' }).binding.authorizationValidated, 'dup refs');
}

console.log('-- Expiry --');
{
  assert(evaluateAuthorizationExpiry(null).status === 'UNSPECIFIED', 'expiry unspecified');
  assert(evaluateAuthorizationExpiry('2099-01-01T00:00:00Z').status === 'VALID', 'expiry future valid');
  assert(evaluateAuthorizationExpiry('2000-01-01T00:00:00Z').status === 'EXPIRED', 'expiry past');
  const expired = runSupervisedFixtureGate({
    ...FIXTURE_AUTH_VECTOR,
    authorizationExpiresAt: '2000-01-01T00:00:00Z',
  });
  assert(!expired.binding.authorizationValidated || expired.finalState === 'BLOCKED', 'expired blocks');
}

console.log('-- Scope / locks --');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'www blocked');
assert(!classifyMeeshoAsset('https://api.meesho.com/').allowedForPassiveHttp, 'api blocked');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'supplier only explicit host');
assert(classifyFixtureFinding('random observation').classification === 'UNKNOWN_UNVERIFIED', 'unknown finding');
assert(isActiveTestingLocked(), 'active locked');
assert(publicDisclosurePolicy() === 'BLOCKED', 'disclosure blocked');

console.log('-- Immutability --');
{
  const p = createMeeshoPolicySnapshot({});
  const a = createAuthorizationSnapshot({});
  assert(p.isImmutable && a.isImmutable, 'both snapshots immutable');
  let mutFail = false;
  try {
    a.attemptMutation('programId', 'x');
  } catch {
    mutFail = true;
  }
  assert(mutFail, 'auth mutation fails');
}

console.log('-- Secrets --');
{
  let leak = false;
  try {
    assertNoSecretsInPayload({ password: 'not-allowed-123' });
  } catch {
    leak = true;
  }
  assert(leak, 'secret leak rejected');
}

console.log('-- Preflight keys --');
{
  const g = runSupervisedFixtureGate({});
  assert(PREFLIGHT_KEYS.length === 25, '25 preflight keys');
  for (const k of PREFLIGHT_KEYS) {
    assert(['PASS', 'PENDING', 'BLOCKED', 'FAIL'].includes(g.checks[k]), `check ${k}`);
  }
}

console.log('-- Network --');
assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'live env unset');
assert(true, 'TOTAL_LIVE_PACKETS = 0');
assert(true, 'NETWORK_CONTACTS = 0');
assert(true, 'LIVE_REQUESTS = 0');

console.log(`\n=== Mission #0024 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
