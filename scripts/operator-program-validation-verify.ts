/**
 * Mission #0021 — Operator-supplied program validation
 * Does NOT fabricate a real HackerOne program.
 * When no operator data is present → PENDING_OPERATOR_DATA.
 * Fixture-only when a complete synthetic-shaped operator payload is used for negative/path tests.
 * TOTAL_LIVE_PACKETS = 0
 */
import { validateOperatorSuppliedProgram } from '../src/services/passiveResearch/operatorProgramValidation.ts';
import type { ProgramImportInput } from '../src/services/passiveResearch/realProgramImport.ts';

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

async function main() {
  console.log('\n=== Mission #0021 Operator Program Validation ===\n');

  console.log('-- No operator data --');
  const none = await validateOperatorSuppliedProgram(null);
  assert(none.classification === 'REAL_PROGRAM_PROFILE_PENDING_OPERATOR_DATA', 'pending when no data');
  assert(none.blockers.some((b) => b.includes('NO_OPERATOR_PROFILE')), 'blocker explains no data');
  assert(none.totalLivePackets === 0, 'zero live packets (no data)');
  assert(none.activeTestingLocked, 'active testing locked');
  assert(none.fixtureSession.attempted === false, 'no fixture without data');
  assert(none.rateLimit.programLimit === 'UNSPECIFIED', 'rate limit not invented');

  console.log('-- Incomplete operator payload --');
  const incomplete = await validateOperatorSuppliedProgram({
    programId: '',
    programName: '',
    platform: 'HackerOne',
    authorizationStatus: 'AUTHORIZED',
    authorizationReference: null,
    policyVersion: '',
    scopeVersion: '',
    allowedAssets: [],
    excludedAssets: [],
    requestBudget: 0,
    researcherAccountReferences: [],
    proxyRequirement: false,
  } as ProgramImportInput);
  assert(incomplete.classification !== 'REAL_PROGRAM_PROFILE_VALIDATED', 'incomplete not validated');
  assert(incomplete.fields.some((f) => f.status === 'MISSING'), 'missing fields marked');
  assert(incomplete.totalLivePackets === 0, 'zero live (incomplete)');

  console.log('-- Complete operator-shaped payload (fixture path only, not a real H1 claim) --');
  // This is an operator-shaped test vector, explicitly labeled as test — not claimed as real HackerOne engagement
  const operatorShaped: ProgramImportInput = {
    programId: 'operator-supplied-test-vector-001',
    programName: 'Operator Supplied Test Vector (NOT a real bounty claim)',
    platform: 'Direct',
    authorizationStatus: 'AUTHORIZED',
    authorizationReference: 'OPERATOR-AUTH-REF-TEST-ONLY',
    policyVersion: 'op-policy-1',
    scopeVersion: 'op-scope-1',
    allowedAssets: ['app.operator-test.local', 'api.operator-test.local'],
    excludedAssets: ['admin.operator-test.local'],
    allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
    requestBudget: 8,
    researcherAccountReferences: ['operator-researcher-ref'],
    proxyRequirement: false,
  };

  const full = await validateOperatorSuppliedProgram(operatorShaped, {
    primaryApprover: 'approver-one',
    secondaryApprover: 'approver-two',
    supervisedLiveEnabled: true,
    runFixtureSession: true,
  });
  assert(full.importOk, 'complete import ok');
  assert(full.classification === 'REAL_PROGRAM_PROFILE_VALIDATED', 'validated when complete + fixture');
  assert(full.authorizationStatus === 'VALID', 'authorization valid');
  assert(full.dualConfirmationStatus === 'VALID', 'dual confirmation valid');
  assert(full.preflightStatus === 'READY', 'preflight ready');
  assert(full.fixtureSession.attempted && full.fixtureSession.ok, 'fixture session ok');
  assert(full.fixtureSession.liveNetwork === false, 'fixture not live');
  assert(full.fixtureSession.cancelOk === true, 'fixture session cancelled cleanly');
  assert(full.totalLivePackets === 0, 'zero live packets');
  assert(
    full.methodRows.some((r) => r.method === 'POST' && r.executionStatus === 'ACTIVE_OR_STATE_CHANGING_METHOD_AVAILABLE_BUT_LOCKED'),
    'POST locked even if program lists it'
  );
  assert(full.scopeChecks.some((s) => s.target.includes('admin') && !s.allowed), 'exclusion denied');
  assert(full.scopeChecks.some((s) => !s.allowed && s.target.includes('unlisted')), 'unlisted denied');
  assert(full.activeTestingLocked, 'active testing locked after validation');

  console.log('-- Negative: duplicate approvers --');
  const dup = await validateOperatorSuppliedProgram(operatorShaped, {
    primaryApprover: 'same',
    secondaryApprover: 'same',
    runFixtureSession: true,
  });
  assert(dup.dualConfirmationStatus === 'BLOCKED' || dup.blockers.some((b) => b.includes('DISTINCT')), 'duplicate approvers blocked');

  console.log('-- Negative: proxy required missing endpoint --');
  const proxy = await validateOperatorSuppliedProgram({
    ...operatorShaped,
    programId: 'op-proxy',
    proxyRequirement: true,
    proxyEndpoint: null,
  });
  assert(proxy.proxyStatus === 'BLOCKED' || proxy.blockers.some((b) => b.includes('PROXY')), 'proxy block');

  console.log('-- Negative: expired auth --');
  const exp = await validateOperatorSuppliedProgram({
    ...operatorShaped,
    programId: 'op-exp',
    authorizationStatus: 'EXPIRED',
  });
  assert(exp.classification !== 'REAL_PROGRAM_PROFILE_VALIDATED', 'expired not validated');

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  console.log('TOTAL_LIVE_PACKETS = 0');
  console.log('NOTE: No real HackerOne program was supplied by the operator in chat.');
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
