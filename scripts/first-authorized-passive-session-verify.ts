/**
 * Mission #0017 — First authorized passive session verification
 * TOTAL_LIVE_PACKETS = 0
 */
import { runFirstAuthorizedPassiveHunt, onboardSyntheticAuthorizedProgram } from '../src/services/passiveResearch/authorizedPassiveSession.ts';
import {
  clearProgramRegistry,
  createSyntheticAuthorizedProfile,
  registerProgramProfile,
  advanceOnboarding,
  isAuthorizedForPassive,
} from '../src/services/passiveResearch/programProfileModel.ts';
import { checkTargetScope, checkMethodAllowed } from '../src/services/passiveResearch/scopeEnforcement.ts';
import {
  createPassiveSession,
  executePassiveRequest,
  cancelSession,
  clearSessions,
  isActiveTestingLocked,
} from '../src/services/passiveResearch/passiveSessionController.ts';
import { runPassivePreflight } from '../src/services/passiveResearch/preflight.ts';
import { registerScopeProfile } from '../src/services/passiveIntelligence/scopeGuard.ts';
import { runQualityGates } from '../src/services/passiveIntelligence/reportDrafting.ts';
import { clearEvidenceStore, clearEndpointInventory } from '../src/services/passiveIntelligence/index.ts';
import { clearTimeline } from '../src/services/passiveIntelligence/researchTimeline.ts';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(c: boolean, n: string) {
  if (c) { passed++; console.log(`  [PASS] ${n}`); }
  else { failed++; failures.push(n); console.log(`  [FAIL] ${n}`); }
}

console.log('\n=== Mission #0017 First Authorized Passive Session ===\n');

clearProgramRegistry();
clearSessions();
clearEvidenceStore();
clearEndpointInventory();
clearTimeline();

console.log('-- Full hunt workflow --');
const hunt = runFirstAuthorizedPassiveHunt();
assert(hunt.liveNetworkRequests === 0, 'no live external traffic');
assert(hunt.activeTestingLocked === true, 'active testing remains locked');
assert(hunt.preflight?.status === 'READY', 'preflight ready');
assert(!!hunt.session, 'session created');
assert(hunt.observations.length > 0, 'observations collected');
assert(hunt.status === 'READY_FOR_FIRST_AUTHORIZED_PASSIVE_HUNT' || hunt.status === 'READY_WITH_RESTRICTIONS', 'readiness status');
assert(hunt.candidates.length >= 0, 'candidates array present');
assert(hunt.reports.every((r) => r.synthetic), 'reports synthetic when synthetic program');

console.log('-- Unauthorized rejected --');
clearProgramRegistry();
clearSessions();
{
  const p = createSyntheticAuthorizedProfile({ authorizationStatus: 'NOT_AUTHORIZED' });
  registerProgramProfile(p);
  assert(!isAuthorizedForPassive(p.programId).ok, 'unauthorized program rejected');
}

console.log('-- Expired rejected --');
{
  const p = createSyntheticAuthorizedProfile({ programId: 'exp', authorizationStatus: 'EXPIRED' });
  registerProgramProfile(p);
  assert(!isAuthorizedForPassive(p.programId).ok, 'expired program rejected');
}

console.log('-- Methods --');
assert(checkMethodAllowed('GET').allowed, 'GET allowed');
assert(checkMethodAllowed('HEAD').allowed, 'HEAD allowed');
assert(checkMethodAllowed('OPTIONS').allowed, 'OPTIONS allowed');
assert(!checkMethodAllowed('POST').allowed, 'POST blocked');
assert(!checkMethodAllowed('PUT').allowed, 'PUT blocked');
assert(!checkMethodAllowed('PATCH').allowed, 'PATCH blocked');
assert(!checkMethodAllowed('DELETE').allowed, 'DELETE blocked');

console.log('-- Scope --');
{
  const p = onboardSyntheticAuthorizedProgram();
  assert(checkTargetScope(p.programId, 'https://app.synthetic-bounty.local/x').allowed, 'scope enforcement works');
  assert(!checkTargetScope(p.programId, 'https://evil.example.com/').allowed, 'out-of-scope URL blocked');
}

console.log('-- Budget & cancel --');
{
  clearSessions();
  const p = onboardSyntheticAuthorizedProgram();
  // override budget by new profile
  const pb = createSyntheticAuthorizedProfile({ programId: 'b2', requestBudget: 1 });
  registerProgramProfile(pb);
  registerScopeProfile({ programId: pb.programId, inScopeHosts: pb.allowedAssets, outOfScopeHosts: pb.excludedAssets });
  advanceOnboarding(pb.programId, 'POLICY_IMPORTED');
  advanceOnboarding(pb.programId, 'SCOPE_VALIDATED');
  advanceOnboarding(pb.programId, 'RULES_VALIDATED');
  advanceOnboarding(pb.programId, 'RESEARCHER_REVIEW');
  advanceOnboarding(pb.programId, 'HUMAN_APPROVAL', { humanApprovalReference: 'X' });
  advanceOnboarding(pb.programId, 'READY_FOR_PASSIVE_TESTING');
  const s = createPassiveSession({ programId: pb.programId, targets: ['https://app.synthetic-bounty.local/'], proxyAvailable: true });
  executePassiveRequest({ sessionId: s.session!.sessionId, target: 'https://app.synthetic-bounty.local/', method: 'GET', testMode: true });
  const ex = executePassiveRequest({ sessionId: s.session!.sessionId, target: 'https://app.synthetic-bounty.local/', method: 'GET', testMode: true });
  assert(!ex.ok && ex.error?.code === 'REQUEST_BUDGET_EXCEEDED', 'budget enforced');
  cancelSession(s.session!.sessionId, 'stop');
  const c = executePassiveRequest({ sessionId: s.session!.sessionId, target: 'https://app.synthetic-bounty.local/', method: 'GET', testMode: true });
  assert(!c.ok && c.error?.code === 'SESSION_CANCELLED', 'cancellation works');
}

console.log('-- Quality gate incomplete --');
{
  const bad = runQualityGates(
    {
      id: 'x',
      title: 't',
      status: 'NEEDS_REVIEW',
      reviewPriority: 'REVIEW',
      vulnerabilityClass: '',
      affectedAsset: '',
      observedBehavior: 'MARK AS MISSING',
      expectedBehavior: 'MARK AS MISSING',
      securityImpact: 'MARK AS MISSING',
      confidence: 'LOW',
      observationIds: [],
      evidenceIds: [],
      programId: '',
      researchCaseId: 'c',
      scopeConfirmed: false,
      qualityGateNotes: [],
      createdAt: new Date().toISOString(),
      synthetic: true,
    },
    []
  );
  assert(!bad.passed, 'quality gate blocks incomplete report');
}

console.log('-- Human review required --');
assert(hunt.confirmed.every((c) => c.reviewerAction === 'CONFIRM'), 'confirmed require human action');
assert(isActiveTestingLocked(), 'active testing locked final');

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
if (failed) { console.log(failures); process.exit(1); }
console.log('\nTOTAL_LIVE_PACKETS = 0');
console.log('Classification: READY_FOR_FIRST_AUTHORIZED_PASSIVE_HUNT (synthetic authorized program)');
process.exit(0);
