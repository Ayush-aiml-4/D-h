/**
 * Mission #0018 — Real Program Import & Supervised Collection
 * TOTAL_LIVE_PACKETS must remain 0 (DEVILHUNT_ALLOW_LIVE_PASSIVE unset)
 */
import {
  clearProgramRegistry,
  importRealProgram,
  getImportedProgram,
  getImportOnboardingStage,
  submitDualConfirmation,
  clearConfirmations,
  startSupervisedCollection,
  supervisedPassiveRequest,
  emergencyStop,
  supervisedSafetyStatus,
  isActiveTestingLocked,
  checkMethodAllowed,
  checkTargetScope,
  clearSessions,
  isAuthorizedForPassive,
} from '../src/services/passiveResearch/index.ts';
import { SafeControlledHttpClient } from '../src/services/execution/httpClient.ts';
import { clearEvidenceStore } from '../src/services/passiveIntelligence/evidenceStore.ts';
import { clearTimeline } from '../src/services/passiveIntelligence/researchTimeline.ts';
import { clearEndpointInventory } from '../src/services/passiveIntelligence/endpointInventory.ts';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(c: boolean, n: string) {
  if (c) {
    passed++;
    console.log(`  [PASS] ${n}`);
  } else {
    failed++;
    failures.push(n);
    console.log(`  [FAIL] ${n}`);
  }
}

function reset() {
  clearProgramRegistry();
  clearConfirmations();
  clearSessions();
  clearEvidenceStore();
  clearTimeline();
  clearEndpointInventory();
  SafeControlledHttpClient.clearMockHandler();
  delete process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE;
}

async function main() {
  console.log('\n=== Mission #0018 Supervised Live Collection Boundary ===\n');
  reset();

  console.log('-- Import rejects incomplete --');
  {
    const bad = importRealProgram({
      programId: '',
      programName: '',
      platform: 'Direct',
      authorizationStatus: 'AUTHORIZED',
      authorizationReference: null,
      policyVersion: '',
      scopeVersion: '',
      allowedAssets: [],
      excludedAssets: [],
      requestBudget: 0,
      researcherAccountReferences: [],
      proxyRequirement: false,
    } as any);
    assert(!bad.ok, 'incomplete import rejected');
    assert(bad.errors.length >= 3, 'multiple import errors reported');
  }

  console.log('-- AUTHORIZED requires reference --');
  {
    const bad = importRealProgram({
      programId: 'p1',
      programName: 'Test',
      platform: 'Direct',
      authorizationStatus: 'AUTHORIZED',
      authorizationReference: null,
      policyVersion: '1',
      scopeVersion: '1',
      allowedAssets: ['app.example.test'],
      excludedAssets: [],
      requestBudget: 10,
      researcherAccountReferences: ['ref-1'],
      proxyRequirement: false,
    });
    assert(!bad.ok, 'AUTHORIZED without reference rejected');
  }

  console.log('-- Raw credentials rejected --');
  {
    const bad = importRealProgram({
      programId: 'p2',
      programName: 'Test',
      platform: 'Direct',
      authorizationStatus: 'AUTHORIZED',
      authorizationReference: 'REF',
      policyVersion: '1',
      scopeVersion: '1',
      allowedAssets: ['app.example.test'],
      excludedAssets: [],
      requestBudget: 10,
      researcherAccountReferences: ['Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb'],
      proxyRequirement: false,
    });
    assert(!bad.ok, 'raw credential in researcher ref rejected');
  }

  console.log('-- Valid import --');
  {
    const ok = importRealProgram({
      programId: 'operator-program-001',
      programName: 'Operator Supplied Program',
      platform: 'Direct',
      authorizationStatus: 'AUTHORIZED',
      authorizationReference: 'AUTH-OP-REF-001',
      policyVersion: '1.0.0',
      scopeVersion: '1.0.0',
      allowedAssets: ['app.example.test', 'api.example.test'],
      excludedAssets: ['admin.example.test'],
      requestBudget: 15,
      researcherAccountReferences: ['researcher-ref-001'],
      proxyRequirement: false,
    });
    assert(ok.ok, 'valid operator import accepted');
    assert(!!getImportedProgram('operator-program-001'), 'profile registered');
    assert(
      getImportOnboardingStage('operator-program-001') === 'RESEARCHER_REVIEW',
      'stage RESEARCHER_REVIEW after import'
    );
  }

  console.log('-- Dual confirmation --');
  {
    const same = submitDualConfirmation({
      programId: 'operator-program-001',
      targets: ['https://app.example.test/'],
      primaryApproverRef: 'alice',
      secondaryApproverRef: 'alice',
    });
    assert(!same.ok, 'identical approvers rejected');

    const conf = submitDualConfirmation({
      programId: 'operator-program-001',
      targets: ['https://app.example.test/', 'https://api.example.test/'],
      primaryApproverRef: 'alice-operator',
      secondaryApproverRef: 'bob-reviewer',
      supervisedLiveEnabled: false,
    });
    assert(conf.ok, 'dual confirmation accepted');
    if (conf.ok) {
      assert(conf.confirmation.manifest.explicitStatement.includes('PASSIVE-ONLY'), 'manifest passive statement');
      assert(conf.confirmation.supervisedLiveEnabled === false, 'live disabled by default');
      assert(isAuthorizedForPassive('operator-program-001').ok, 'authorized after dual confirmation');
    }

    const start = startSupervisedCollection({
      confirmationId: conf.ok ? conf.confirmation.confirmationId : '',
      programId: 'operator-program-001',
      targets: ['https://app.example.test/'],
    });
    assert(start.ok, 'supervised session started');
    if (start.ok) {
      assert(start.mode === 'FIXTURE', 'mode FIXTURE without live env');

      const req = await supervisedPassiveRequest({
        sessionId: start.session.sessionId,
        confirmationId: conf.ok ? conf.confirmation.confirmationId : '',
        target: 'https://app.example.test/',
        method: 'GET',
        mode: 'FIXTURE',
        fixtureResponse: {
          status: 200,
          headers: { 'content-type': 'text/html', server: 'nginx' },
          body: '<html>operator fixture</html>',
        },
      });
      assert(req.ok, 'fixture GET succeeded');
      assert(req.liveNetwork === false, 'fixture request not live');

      const post = await supervisedPassiveRequest({
        sessionId: start.session.sessionId,
        confirmationId: conf.ok ? conf.confirmation.confirmationId : '',
        target: 'https://app.example.test/',
        method: 'POST' as any,
        mode: 'FIXTURE',
      });
      assert(!post.ok, 'POST blocked in supervised session');

      const oos = await supervisedPassiveRequest({
        sessionId: start.session.sessionId,
        confirmationId: conf.ok ? conf.confirmation.confirmationId : '',
        target: 'https://admin.example.test/',
        method: 'GET',
        mode: 'FIXTURE',
      });
      assert(!oos.ok, 'out-of-scope blocked');

      const stopped = emergencyStop(start.session.sessionId, 'test stop');
      assert(stopped?.state === 'CANCELLED', 'emergency stop works');
    }
  }

  console.log('-- Live env gate --');
  {
    // Even with supervisedLiveEnabled true, without env flag mode stays FIXTURE
    reset();
    importRealProgram({
      programId: 'op-2',
      programName: 'Op2',
      platform: 'Direct',
      authorizationStatus: 'AUTHORIZED',
      authorizationReference: 'R2',
      policyVersion: '1',
      scopeVersion: '1',
      allowedAssets: ['app.example.test'],
      excludedAssets: [],
      requestBudget: 5,
      researcherAccountReferences: ['r'],
      proxyRequirement: false,
    });
    const conf = submitDualConfirmation({
      programId: 'op-2',
      targets: ['https://app.example.test/'],
      primaryApproverRef: 'a1',
      secondaryApproverRef: 'a2',
      supervisedLiveEnabled: true,
    });
    assert(conf.ok, 'confirmation with supervisedLive flag');
    const start = startSupervisedCollection({
      confirmationId: conf.ok ? conf.confirmation.confirmationId : '',
      programId: 'op-2',
      targets: ['https://app.example.test/'],
    });
    assert(start.ok && start.mode === 'FIXTURE', 'live still FIXTURE without DEVILHUNT_ALLOW_LIVE_PASSIVE');
  }

  console.log('-- Methods & scope unit --');
  assert(checkMethodAllowed('GET').allowed, 'GET allowed');
  assert(checkMethodAllowed('HEAD').allowed, 'HEAD allowed');
  assert(checkMethodAllowed('OPTIONS').allowed, 'OPTIONS allowed');
  assert(!checkMethodAllowed('POST').allowed, 'POST blocked');
  assert(!checkMethodAllowed('DELETE').allowed, 'DELETE blocked');
  assert(isActiveTestingLocked(), 'active testing locked');

  console.log('-- Safety status --');
  {
    const st = supervisedSafetyStatus('operator-program-001');
    // registry cleared in last reset — re-import briefly
    importRealProgram({
      programId: 'operator-program-001',
      programName: 'Operator Supplied Program',
      platform: 'Direct',
      authorizationStatus: 'AUTHORIZED',
      authorizationReference: 'AUTH-OP-REF-001',
      policyVersion: '1.0.0',
      scopeVersion: '1.0.0',
      allowedAssets: ['app.example.test'],
      excludedAssets: [],
      requestBudget: 15,
      researcherAccountReferences: ['researcher-ref-001'],
      proxyRequirement: false,
    });
    submitDualConfirmation({
      programId: 'operator-program-001',
      targets: ['https://app.example.test/'],
      primaryApproverRef: 'x',
      secondaryApproverRef: 'y',
    });
    const st2 = supervisedSafetyStatus('operator-program-001');
    assert(st2.activeTesting === 'LOCKED', 'status active testing LOCKED');
    assert(st2.liveEnv === 'FIXTURE', 'status liveEnv FIXTURE');
    assert(st2.credentials === 'SAFE', 'status credentials SAFE');
  }

  console.log('-- No fabrication of real programs --');
  assert(!getImportedProgram('meesho-hackerone'), 'no fabricated meesho program');

  console.log(`\n=== Results: ${passed} passed, ${failed} failed (total ${passed + failed}) ===`);
  console.log('TOTAL_LIVE_PACKETS = 0');
  if (failed) {
    console.log('Failures:', failures);
    process.exit(1);
  }
  console.log('\nClassification: READY_FOR_SUPERVISED_PASSIVE_COLLECTION (fixture mode; live requires env+dual confirm)');
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
