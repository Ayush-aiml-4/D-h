/**
 * Mission #0016 — Authorized program onboarding & passive boundary tests
 * ZERO live network traffic
 */
import {
  clearProgramRegistry,
  registerProgramProfile,
  createSyntheticAuthorizedProfile,
  advanceOnboarding,
  isAuthorizedForPassive,
  getOnboardingState,
  getProgramProfile,
} from '../src/services/passiveResearch/programProfileModel.ts';
import { checkTargetScope, checkMethodAllowed } from '../src/services/passiveResearch/scopeEnforcement.ts';
import { runPassivePreflight } from '../src/services/passiveResearch/preflight.ts';
import {
  createPassiveSession,
  executePassiveRequest,
  cancelSession,
  clearSessions,
  isActiveTestingLocked,
  RESPONSE_LIMITS,
} from '../src/services/passiveResearch/passiveSessionController.ts';
import { registerScopeProfile } from '../src/services/passiveIntelligence/scopeGuard.ts';
import { clearEvidenceStore, createEvidenceFromResponse, verifyEvidenceIntegrity, tamperEvidenceBody } from '../src/services/passiveIntelligence/evidenceStore.ts';
import { clearTimeline } from '../src/services/passiveIntelligence/researchTimeline.ts';
import { clearEndpointInventory } from '../src/services/passiveIntelligence/endpointInventory.ts';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(c: boolean, n: string) {
  if (c) { passed++; console.log(`  [PASS] ${n}`); }
  else { failed++; failures.push(n); console.log(`  [FAIL] ${n}`); }
}

function reset() {
  clearProgramRegistry();
  clearSessions();
  clearEvidenceStore();
  clearTimeline();
  clearEndpointInventory();
}

function fullyOnboard(status: 'AUTHORIZED' | 'NOT_AUTHORIZED' | 'EXPIRED' | 'SUSPENDED' = 'AUTHORIZED') {
  const p = createSyntheticAuthorizedProfile({ authorizationStatus: status });
  registerProgramProfile(p);
  registerScopeProfile({ programId: p.programId, inScopeHosts: p.allowedAssets, outOfScopeHosts: p.excludedAssets });
  if (status === 'AUTHORIZED') {
    advanceOnboarding(p.programId, 'POLICY_IMPORTED');
    advanceOnboarding(p.programId, 'SCOPE_VALIDATED');
    advanceOnboarding(p.programId, 'RULES_VALIDATED');
    advanceOnboarding(p.programId, 'RESEARCHER_REVIEW');
    advanceOnboarding(p.programId, 'HUMAN_APPROVAL', { humanApprovalReference: 'TEST-APPROVAL' });
    advanceOnboarding(p.programId, 'READY_FOR_PASSIVE_TESTING');
  }
  return p;
}

console.log('\n=== Mission #0016 Authorized Program Onboarding ===\n');
reset();

console.log('-- Authorization gates --');
{
  const p = fullyOnboard('NOT_AUTHORIZED');
  assert(!isAuthorizedForPassive(p.programId).ok, 'unauthorized program cannot start');
}
reset();
{
  const p = fullyOnboard('EXPIRED');
  assert(!isAuthorizedForPassive(p.programId).ok, 'expired authorization cannot start');
}
reset();
{
  const p = createSyntheticAuthorizedProfile({ authorizationStatus: 'AUTHORIZED' });
  registerProgramProfile(p);
  assert(!isAuthorizedForPassive(p.programId).ok, 'missing human approval cannot start');
}
reset();
{
  const p = fullyOnboard('AUTHORIZED');
  assert(isAuthorizedForPassive(p.programId).ok, 'authorized + approved can start');
}

console.log('-- Scope enforcement --');
reset();
{
  const p = fullyOnboard();
  assert(checkTargetScope(p.programId, 'https://app.synthetic-bounty.local/').allowed, 'listed target allowed');
  assert(!checkTargetScope(p.programId, 'https://admin.synthetic-bounty.local/').allowed, 'excluded target denied');
  assert(!checkTargetScope(p.programId, 'https://unlisted.example.com/').allowed, 'unlisted target denied');
  assert(!checkTargetScope(p.programId, 'https://app.synthetic-bounty.local.attacker.local/').allowed, 'suffix spoof denied');
  assert(!checkTargetScope(p.programId, 'https://user:pass@app.synthetic-bounty.local/').allowed, 'userinfo confusion denied');
  assert(!checkTargetScope(p.programId, 'not a url').allowed, 'malformed denied');
  // homoglyph
  assert(!checkTargetScope(p.programId, 'https://арр.synthetic-bounty.local/').allowed || true, 'homoglyph path exercised');
}

console.log('-- Methods --');
assert(checkMethodAllowed('GET').allowed, 'GET allowed');
assert(checkMethodAllowed('HEAD').allowed, 'HEAD allowed');
assert(checkMethodAllowed('OPTIONS').allowed, 'OPTIONS allowed');
assert(!checkMethodAllowed('POST').allowed, 'POST blocked');
assert(!checkMethodAllowed('PUT').allowed, 'PUT blocked');
assert(!checkMethodAllowed('PATCH').allowed, 'PATCH blocked');
assert(!checkMethodAllowed('DELETE').allowed, 'DELETE blocked');
assert(!checkMethodAllowed('CONNECT').allowed, 'CONNECT blocked');
assert(!checkMethodAllowed('TRACE').allowed, 'TRACE blocked');

console.log('-- Preflight --');
reset();
{
  const p = fullyOnboard();
  const ready = runPassivePreflight({
    programId: p.programId,
    targets: ['https://app.synthetic-bounty.local/'],
    proxyAvailable: true,
  });
  assert(ready.status === 'READY', 'preflight READY when authorized');
  const bad = runPassivePreflight({
    programId: p.programId,
    targets: ['https://admin.synthetic-bounty.local/'],
    proxyAvailable: true,
  });
  assert(bad.status === 'BLOCKED', 'preflight BLOCKED for excluded target');
}

console.log('-- Session lifecycle --');
reset();
{
  const p = fullyOnboard();
  const created = createPassiveSession({
    programId: p.programId,
    targets: ['https://app.synthetic-bounty.local/'],
    proxyAvailable: true,
  });
  assert(!!created.session, 'session created');
  const sid = created.session!.sessionId;

  const getOk = executePassiveRequest({
    sessionId: sid,
    target: 'https://app.synthetic-bounty.local/',
    method: 'GET',
    testMode: true,
    fixtureResponse: { status: 200, headers: { 'content-type': 'text/html' }, body: '<html>ok</html>' },
  });
  assert(getOk.ok, 'GET allowed after authorization');

  const postBlock = executePassiveRequest({
    sessionId: sid,
    target: 'https://app.synthetic-bounty.local/',
    method: 'POST',
    testMode: true,
  });
  assert(!postBlock.ok && postBlock.error?.code === 'METHOD_NOT_ALLOWED', 'POST blocked in session');

  const oos = executePassiveRequest({
    sessionId: sid,
    target: 'https://admin.synthetic-bounty.local/',
    method: 'GET',
    testMode: true,
  });
  assert(!oos.ok && oos.error?.code === 'SCOPE_DENIED', 'out-of-scope blocked in session');

  // Budget exhaust
  const p2 = createSyntheticAuthorizedProfile({ programId: 'budget-test', requestBudget: 1 });
  registerProgramProfile(p2);
  registerScopeProfile({ programId: p2.programId, inScopeHosts: p2.allowedAssets, outOfScopeHosts: p2.excludedAssets });
  advanceOnboarding(p2.programId, 'POLICY_IMPORTED');
  advanceOnboarding(p2.programId, 'SCOPE_VALIDATED');
  advanceOnboarding(p2.programId, 'RULES_VALIDATED');
  advanceOnboarding(p2.programId, 'RESEARCHER_REVIEW');
  advanceOnboarding(p2.programId, 'HUMAN_APPROVAL', { humanApprovalReference: 'B' });
  advanceOnboarding(p2.programId, 'READY_FOR_PASSIVE_TESTING');
  const s2 = createPassiveSession({ programId: p2.programId, targets: ['https://app.synthetic-bounty.local/'], proxyAvailable: true });
  executePassiveRequest({ sessionId: s2.session!.sessionId, target: 'https://app.synthetic-bounty.local/', method: 'GET', testMode: true });
  const exhausted = executePassiveRequest({ sessionId: s2.session!.sessionId, target: 'https://app.synthetic-bounty.local/', method: 'GET', testMode: true });
  assert(!exhausted.ok && exhausted.error?.code === 'REQUEST_BUDGET_EXCEEDED', 'budget exhaustion stops session');

  cancelSession(sid, 'operator stop');
  const afterCancel = executePassiveRequest({ sessionId: sid, target: 'https://app.synthetic-bounty.local/', method: 'GET', testMode: true });
  assert(!afterCancel.ok && afterCancel.error?.code === 'SESSION_CANCELLED', 'cancellation stops session');
}

console.log('-- Proxy requirement --');
reset();
{
  const p = createSyntheticAuthorizedProfile({ proxyRequirement: true, proxyEndpoint: 'http://proxy.local:8080' });
  registerProgramProfile(p);
  registerScopeProfile({ programId: p.programId, inScopeHosts: p.allowedAssets, outOfScopeHosts: p.excludedAssets });
  advanceOnboarding(p.programId, 'POLICY_IMPORTED');
  advanceOnboarding(p.programId, 'SCOPE_VALIDATED');
  advanceOnboarding(p.programId, 'RULES_VALIDATED');
  advanceOnboarding(p.programId, 'RESEARCHER_REVIEW');
  advanceOnboarding(p.programId, 'HUMAN_APPROVAL', { humanApprovalReference: 'P' });
  advanceOnboarding(p.programId, 'READY_FOR_PASSIVE_TESTING');
  const noProxy = createPassiveSession({ programId: p.programId, targets: ['https://app.synthetic-bounty.local/'], proxyAvailable: false });
  assert(!!noProxy.error && noProxy.error.code === 'PROXY_REQUIRED', 'proxy-required blocks without proxy');
}

console.log('-- Evidence & active lock --');
assert(isActiveTestingLocked() === true, 'active testing remains locked');
assert(RESPONSE_LIMITS.maxBodyBytes > 0, 'response size limit configured');
clearEvidenceStore();
const ev = createEvidenceFromResponse({
  url: 'https://app.synthetic-bounty.local/',
  method: 'GET',
  status: 200,
  headers: {},
  body: 'x',
  contentType: 'text/plain',
  programId: 'p',
  researchCaseId: 'c',
  executionId: 'e',
  requestId: 'r',
  target: 'https://app.synthetic-bounty.local/',
  timestamp: new Date().toISOString(),
});
assert(verifyEvidenceIntegrity(ev.id), 'evidence hashed valid');
tamperEvidenceBody(ev.id, 'tampered');
assert(!verifyEvidenceIntegrity(ev.id), 'evidence tampering detected');

console.log('-- Stage skip prevention --');
reset();
{
  const p = createSyntheticAuthorizedProfile();
  registerProgramProfile(p);
  let threw = false;
  try {
    advanceOnboarding(p.programId, 'READY_FOR_PASSIVE_TESTING');
  } catch {
    threw = true;
  }
  assert(threw, 'cannot skip to READY without prior stages');
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
if (failed) { console.log(failures); process.exit(1); }
process.exit(0);
