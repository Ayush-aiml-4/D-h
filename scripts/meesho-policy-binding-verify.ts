/**
 * Mission #0022 — Meesho policy binding + fixture readiness
 * TOTAL_LIVE_PACKETS must remain 0. No Meesho contact.
 *
 * Network guard: any accidental live client use without mock fails the suite intent.
 */
import { createMeeshoPolicySnapshot } from '../src/services/passiveResearch/meeshoPolicySnapshot.ts';
import { bindMeeshoPolicy, fixturePolicyProbe } from '../src/services/passiveResearch/meeshoPolicyBinding.ts';
import { runMeeshoPolicyPreflight, CHECK_ORDER } from '../src/services/passiveResearch/meeshoPolicyPreflight.ts';
import { classifyMeeshoAsset } from '../src/services/passiveResearch/meeshoScopePolicy.ts';
import { classifyFixtureFinding, isKnownDuplicateFinding } from '../src/services/passiveResearch/meeshoKnownIssueFilter.ts';
import { assertNoSecretsInPayload, buildHackerOneHeader } from '../src/services/passiveResearch/meeshoCredentialPolicy.ts';
import { isActiveTestingLocked } from '../src/services/passiveResearch/passiveSessionController.ts';
import { SafeControlledHttpClient } from '../src/services/execution/httpClient.ts';
import { publicDisclosurePolicy } from '../src/services/passiveResearch/meeshoPolicyValidator.ts';

let passed = 0;
let failed = 0;
let livePackets = 0;

function assert(c: boolean, n: string) {
  if (c) {
    passed++;
    console.log(`  [PASS] ${n}`);
  } else {
    failed++;
    console.log(`  [FAIL] ${n}`);
  }
}

console.log('\n=== Mission #0022 Meesho Policy Binding ===\n');

delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
SafeControlledHttpClient.clearMockHandler();

console.log('-- Policy snapshot --');
{
  const snap = createMeeshoPolicySnapshot({});
  assert(snap.isImmutable, 'snapshot immutable');
  assert(snap.view().programName === 'Meesho Bug Bounty Program', 'program name');
  assert(snap.view().platform === 'HackerOne', 'platform');
  assert(snap.view().programId === null, 'programId MISSING by default');
  assert(snap.view().liveNetwork === 'DISABLED', 'live network disabled in snapshot');
  assert(snap.view().activeTesting === 'LOCKED', 'active testing locked in snapshot');
  assert(snap.view().fixtureMode === 'ENABLED', 'fixture mode enabled');
  let mutFail = false;
  try {
    snap.attemptMutation('programId', 'invented');
  } catch {
    mutFail = true;
  }
  assert(mutFail, 'mutation attempt fails');
  assert(snap.view().scopePolicy.explicitHosts.includes('supplier.meesho.com'), 'supplier host');
  assert(snap.view().scopePolicy.noWildcardInference === true, 'no wildcard inference');
  assert(snap.view().bountyUpdatedAt === '19 Aug 2026', 'bounty date preserved');
}

console.log('-- Scope --');
assert(!classifyMeeshoAsset('https://www.meesho.com/').allowedForPassiveHttp, 'www.meesho.com blocked');
assert(!classifyMeeshoAsset('https://api.meesho.com/').allowedForPassiveHttp, 'api.meesho.com blocked');
assert(classifyMeeshoAsset('https://supplier.meesho.com/').allowedForPassiveHttp, 'supplier allowed for passive classification');
assert(classifyMeeshoAsset('https://razorpay.com/').decision === 'THIRD_PARTY', 'third-party');
assert(!classifyMeeshoAsset('https://admin.internal.example/').allowedForPassiveHttp, 'internal blocked');
assert(!classifyMeeshoAsset('https://staging.example.com/').allowedForPassiveHttp, 'staging blocked');

console.log('-- Known duplicates --');
assert(isKnownDuplicateFinding('Stored XSS via file upload on supplier.meesho.com'), 'dup stored xss');
assert(isKnownDuplicateFinding('HTML injection in supplier ticketing module'), 'dup html');
assert(classifyFixtureFinding('unrelated header observation').classification === 'UNKNOWN_UNVERIFIED', 'unknown unverified');
assert(classifyFixtureFinding('x').claimAsVulnerability === false, 'never claim vulnerability');

console.log('-- Credentials --');
{
  let logLeak = false;
  try {
    assertNoSecretsInPayload({ log: 'password=SecretValue99' });
  } catch {
    logLeak = true;
  }
  assert(logLeak, 'credential leakage into logs fails');
  let auditLeak = false;
  try {
    assertNoSecretsInPayload({ audit: 'Bearer eyJhbGciOiJIUzI1NiJ9.aa.bb' });
  } catch {
    auditLeak = true;
  }
  assert(auditLeak, 'credential leakage into audit fails');
  let evidLeak = false;
  try {
    assertNoSecretsInPayload({ evidence: 'password: hunter2' });
  } catch {
    evidLeak = true;
  }
  assert(evidLeak, 'credential leakage into evidence fails');
  assert(!buildHackerOneHeader(null).ok, 'missing H1 username blocked');
}

console.log('-- Binding without auth (expected pending) --');
{
  const b = bindMeeshoPolicy({});
  assert(b.policyValidated, 'policy validated without inventing auth');
  assert(b.fixtureReady, 'fixture ready');
  assert(b.liveAuthorizationValidated === false, 'live auth not validated');
  assert(b.liveAuthorizationStatus === 'PENDING', 'live auth pending');
  assert(b.totalLivePackets === 0, 'zero live packets');
  assert(b.gates.AUTHORIZATION_REFERENCE_PRESENT === 'PENDING', 'auth ref pending');
  assert(b.gates.HACKERONE_HEADER_IDENTITY_CONFIGURED === 'PENDING', 'H1 identity pending');
  assert(b.liveNetwork === 'DISABLED', 'live disabled');
  assert(b.activeTesting === 'LOCKED', 'active locked');
}

console.log('-- Dual approval negatives --');
{
  const dup = bindMeeshoPolicy({
    primaryApprovalReference: 'same',
    secondaryApprovalReference: 'same',
  });
  assert(dup.gates.DUAL_APPROVERS_DISTINCT === 'BLOCKED', 'duplicate approvers blocked');
  const miss = bindMeeshoPolicy({ primaryApprovalReference: 'only-one' });
  assert(miss.gates.DUAL_APPROVAL_PRESENT === 'PENDING', 'missing secondary pending');
}

console.log('-- Preflight 20 checks --');
{
  const pf = runMeeshoPolicyPreflight({});
  assert(CHECK_ORDER.length === 20, '20 checks defined');
  for (const k of CHECK_ORDER) {
    assert(pf.checks[k] === 'PASS' || pf.checks[k] === 'BLOCKED' || pf.checks[k] === 'PENDING', `check ${k} status`);
  }
  assert(pf.liveMode === 'DISABLED', 'preflight live disabled');
  assert(pf.totalLivePackets === 0, 'preflight zero packets');
}

console.log('-- Fixture probe --');
{
  const b = bindMeeshoPolicy({});
  const probe = fixturePolicyProbe(b);
  assert(probe.ok, 'fixture probe ok');
  assert(probe.liveNetwork === false, 'fixture not live');
  assert(probe.knownDupSample.classification === 'KNOWN_DUPLICATE', 'fixture known dup filtered');
  livePackets += probe.liveNetwork ? 1 : 0;
}

console.log('-- Locks --');
assert(publicDisclosurePolicy() === 'BLOCKED', 'public disclosure blocked');
assert(isActiveTestingLocked(), 'active testing locked');
assert(process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'live env not set');
assert(livePackets === 0, 'TOTAL_LIVE_PACKETS = 0');

console.log(`\n=== Mission #0022 CURRENT RUN: ${passed} passed, ${failed} failed ===`);
console.log('TOTAL_LIVE_PACKETS =', livePackets);
process.exit(failed ? 1 : 0);
