/**
 * Mission #0019 — Operator UI console safety tests (service-level; no browser)
 * TOTAL_LIVE_PACKETS = 0
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  clearProgramRegistry,
  importRealProgram,
  submitDualConfirmation,
  clearConfirmations,
  startSupervisedCollection,
  supervisedPassiveRequest,
  emergencyStop,
  clearSessions,
  isActiveTestingLocked,
  checkMethodAllowed,
} from '../src/services/passiveResearch/index.ts';

let passed = 0;
let failed = 0;

function assert(c: boolean, n: string) {
  if (c) { passed++; console.log(`  [PASS] ${n}`); }
  else { failed++; console.log(`  [FAIL] ${n}`); }
}

console.log('\n=== Mission #0019 Operator UI Console ===\n');

clearProgramRegistry();
clearConfirmations();
clearSessions();

const uiPath = join(process.cwd(), 'src/views/OperatorEngagementConsoleView.tsx');
const uiSrc = readFileSync(uiPath, 'utf8');

assert(uiSrc.includes('STOP SESSION'), 'UI has STOP SESSION');
assert(uiSrc.includes('FIXTURE MODE'), 'UI labels FIXTURE MODE unambiguously');
assert(uiSrc.includes('LIVE SUPERVISED MODE'), 'UI labels LIVE SUPERVISED MODE');
assert(uiSrc.includes('ACTIVE TESTING LOCKED'), 'UI shows active testing locked');
assert(uiSrc.includes('supervisedLiveEnabled'), 'UI exposes supervisedLiveEnabled');
assert(uiSrc.includes('Dual Confirmation'), 'UI has dual confirmation section');
assert(uiSrc.includes('Preflight'), 'UI has preflight section');
assert(!uiSrc.includes('meesho.com'), 'UI does not fabricate meesho scope');
assert(uiSrc.includes('will not invent'), 'UI states no invention of scope');

// Cannot bypass dual confirmation
const imp = importRealProgram({
  programId: 'ui-test-1',
  programName: 'UI Test',
  platform: 'HackerOne',
  authorizationStatus: 'AUTHORIZED',
  authorizationReference: 'REF-UI-1',
  policyVersion: '1',
  scopeVersion: '1',
  allowedAssets: ['app.example.test'],
  excludedAssets: [],
  requestBudget: 5,
  researcherAccountReferences: ['r1'],
  proxyRequirement: false,
});
assert(imp.ok, 'import for UI test');

const same = submitDualConfirmation({
  programId: 'ui-test-1',
  targets: ['https://app.example.test/'],
  primaryApproverRef: 'same',
  secondaryApproverRef: 'same',
});
assert(!same.ok, 'UI cannot use same approver twice');

const conf = submitDualConfirmation({
  programId: 'ui-test-1',
  targets: ['https://app.example.test/'],
  primaryApproverRef: 'op1',
  secondaryApproverRef: 'op2',
  supervisedLiveEnabled: true,
});
assert(conf.ok, 'dual confirmation ok');

const start = startSupervisedCollection({
  confirmationId: conf.ok ? conf.confirmation.confirmationId : '',
  programId: 'ui-test-1',
  targets: ['https://app.example.test/'],
});
assert(start.ok && start.mode === 'FIXTURE', 'live not enabled without env flag');

assert(!checkMethodAllowed('POST').allowed, 'UI cannot submit POST');
assert(isActiveTestingLocked(), 'active testing inaccessible');

async function finish() {
  if (start.ok) {
    const stopped = emergencyStop(start.session.sessionId, 'ui-test');
    assert(stopped?.state === 'CANCELLED', 'STOP cancels session');
    const again = await supervisedPassiveRequest({
      sessionId: start.session.sessionId,
      confirmationId: conf.ok ? conf.confirmation.confirmationId : '',
      target: 'https://app.example.test/',
      method: 'GET',
      mode: 'FIXTURE',
    });
    assert(!again.ok, 'cancelled session cannot continue');
  }
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  console.log('TOTAL_LIVE_PACKETS = 0');
  process.exit(failed ? 1 : 0);
}
finish();
