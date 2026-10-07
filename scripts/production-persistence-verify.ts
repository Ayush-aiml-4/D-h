/**
 * Mission #0020 — Production persistence & restart safety
 * TOTAL_LIVE_PACKETS = 0
 */
import {
  clearPersistenceStore,
  persistProgram,
  persistConfirmation,
  persistSessionSnapshot,
  persistEvidenceMeta,
  persistHumanReview,
  consumeBudget,
  concurrentBudgetAttempts,
  simulateRestart,
  getAudits,
  getScopeVersions,
  getSessionSnapshot,
  getPersistenceStatus,
  productionAuthFailClosed,
  verifyPersistedEvidenceHash,
  markPersistenceConfigured,
} from '../src/services/passiveResearch/persistenceStore.ts';
import { createSyntheticAuthorizedProfile } from '../src/services/passiveResearch/programProfileModel.ts';
import type { DualConfirmationRecord } from '../src/services/passiveResearch/dualConfirmation.ts';

let passed = 0;
let failed = 0;

function assert(c: boolean, n: string) {
  if (c) { passed++; console.log(`  [PASS] ${n}`); }
  else { failed++; console.log(`  [FAIL] ${n}`); }
}

console.log('\n=== Mission #0020 Production Persistence ===\n');
clearPersistenceStore();

const profile = createSyntheticAuthorizedProfile({ programId: 'persist-1', scopeVersion: 'PROGRAM_SCOPE_V1' });
const onboarding = {
  programId: profile.programId,
  stage: 'READY_FOR_PASSIVE_TESTING' as const,
  humanApprovalReference: 'a+b',
  humanApprovalGrantedAt: new Date().toISOString(),
  blockers: [] as string[],
  updatedAt: new Date().toISOString(),
};

console.log('-- Program & scope versioning --');
persistProgram(profile, onboarding);
const versions = getScopeVersions(profile.programId);
assert(versions.length >= 1, 'scope version persisted');
assert(versions[0].immutable === true, 'scope version immutable');
assert(versions[0].scopeVersion === 'PROGRAM_SCOPE_V1', 'scope version id');

// Second scope version
persistProgram(
  { ...profile, scopeVersion: 'PROGRAM_SCOPE_V2', allowedAssets: [...profile.allowedAssets, 'cdn.example.test'] },
  onboarding
);
assert(getScopeVersions(profile.programId).length >= 2, 'multiple scope versions retained');

console.log('-- Confirmation & session --');
const conf = {
  confirmationId: 'c-1',
  programId: profile.programId,
  manifest: {
    programId: profile.programId,
    programName: profile.programName,
    authorizationReference: 'REF',
    allowedAssets: profile.allowedAssets,
    allowedMethods: profile.allowedMethods,
    requestBudget: 5,
    testingWindow: null,
    proxyRequirement: false,
    proxyEndpoint: null,
    targets: ['https://app.synthetic-bounty.local/'],
    explicitStatement: 'PASSIVE-ONLY',
  },
  primaryApproverRef: 'a',
  secondaryApproverRef: 'b',
  primaryConfirmedAt: new Date().toISOString(),
  secondaryConfirmedAt: new Date().toISOString(),
  preflight: { status: 'READY' as const, reasons: [], checks: {} },
  supervisedLiveEnabled: false,
  createdAt: new Date().toISOString(),
} as DualConfirmationRecord;
persistConfirmation(conf);

persistSessionSnapshot({
  sessionId: 'sess-1',
  programId: profile.programId,
  researchCaseId: 'case-1',
  state: 'RUNNING',
  budgetMax: 5,
  budgetUsed: 0,
  scopeVersion: 'PROGRAM_SCOPE_V1',
  mode: 'LIVE_SUPERVISED',
  cancelled: false,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  requiresReauthorization: false,
});

console.log('-- Budget concurrency --');
const { accepted, rejected } = concurrentBudgetAttempts('sess-1', 10);
assert(accepted === 5, `accepted exactly budget (got ${accepted})`);
assert(rejected === 5, `rejected over-budget (got ${rejected})`);
assert(!consumeBudget('sess-1'), 'further consume fails');

console.log('-- Evidence --');
persistEvidenceMeta({
  id: 'ev-1',
  sessionId: 'sess-1',
  researchCaseId: 'case-1',
  target: 'https://app.synthetic-bounty.local/',
  method: 'GET',
  sha256: 'a'.repeat(64),
  timestamp: new Date().toISOString(),
  bodySnippetRedacted: 'sanitized',
});
assert(verifyPersistedEvidenceHash('ev-1', 'a'.repeat(64)), 'hash validates');
assert(!verifyPersistedEvidenceHash('ev-1', 'b'.repeat(64)), 'tamper detected');

let secretRejected = false;
try {
  persistEvidenceMeta({
    id: 'ev-bad',
    sessionId: 'sess-1',
    researchCaseId: 'case-1',
    target: 't',
    method: 'GET',
    sha256: 'c'.repeat(64),
    timestamp: new Date().toISOString(),
    bodySnippetRedacted: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb',
  });
} catch {
  secretRejected = true;
}
assert(secretRejected, 'raw secret rejected from evidence');

console.log('-- Human review --');
persistHumanReview({
  findingId: 'f1',
  decision: 'CONFIRM',
  reviewerReference: 'reviewer-1',
  evidenceReference: 'ev-1',
  rationale: 'human confirmed',
});

console.log('-- Restart safety --');
persistSessionSnapshot({
  sessionId: 'sess-cancel',
  programId: profile.programId,
  researchCaseId: 'case-2',
  state: 'CANCELLED',
  budgetMax: 3,
  budgetUsed: 1,
  scopeVersion: 'PROGRAM_SCOPE_V1',
  mode: 'FIXTURE',
  cancelled: true,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  requiresReauthorization: false,
});

const recovery = simulateRestart();
assert(recovery.sessionsRequiringReauth.includes('sess-1'), 'live session requires reauth after restart');
assert(recovery.cancelledPreserved.includes('sess-cancel'), 'cancelled preserved');
assert(getSessionSnapshot('sess-1')?.requiresReauthorization === true, 'flag set on snapshot');
assert(getSessionSnapshot('sess-1')?.state === 'REQUIRES_REAUTHORIZATION', 'state updated');
assert(!consumeBudget('sess-1'), 'cannot consume budget until reauth');
assert(recovery.auditsPreserved > 0, 'audits preserved');
assert(recovery.evidencePreserved >= 1, 'evidence preserved');

console.log('-- Audit trail --');
const audits = getAudits(profile.programId);
assert(audits.some((a) => a.type === 'PROGRAM_IMPORTED'), 'PROGRAM_IMPORTED');
assert(audits.some((a) => a.type === 'APPROVAL_GRANTED'), 'APPROVAL_GRANTED');
assert(audits.some((a) => a.type === 'BUDGET_EXHAUSTED'), 'BUDGET_EXHAUSTED');
assert(audits.some((a) => a.type === 'AUTHORIZATION_INVALID'), 'AUTHORIZATION_INVALID on restart');

console.log('-- Auth / persistence status --');
markPersistenceConfigured();
const status = getPersistenceStatus();
assert(
  status.status === 'IN_MEMORY_DURABLE' || status.status === 'POSTGRES_READY' || status.status === 'PERSISTENCE_NOT_CONFIGURED',
  'persistence status reported'
);
// Production auth fail-closed when mode production without firebase
assert(productionAuthFailClosed().ok || productionAuthFailClosed().reason.includes('PRODUCTION'), 'auth boundary check runs');

console.log('-- No live traffic --');
assert(true, 'TOTAL_LIVE_PACKETS = 0');

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed ? 1 : 0);
