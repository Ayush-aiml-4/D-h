import { createEvidence, getEvidenceForFinding, transitionEvidenceStatus, computeEvidenceHash, clearEvidenceStore } from '../src/services/evidenceService.ts';
import { generateReportIntelligenceForFinding, assembleReportIntelligence, transitionReportStatusIntelligence, canTransitionReportStatus } from '../src/services/reportIntelligenceService.ts';
import { db } from '../src/db/index.ts';
import { findings, reports, auditEvents, users, hunts, programs, programScopes } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { AuthUser } from '../src/middleware/auth.ts';
import { sanitizeAndRedact } from '../src/services/capabilities/utils.ts';

async function runVerification() {
  console.log('===========================================================');
  console.log('DEVILHUNT #0003.4-B — EVIDENCE & REPORT INTELLIGENCE VERIFY');
  console.log('===========================================================');

  let pass = 0;
  let fail = 0;

  function assert(condition: boolean, message: string) {
    if (condition) {
      pass++;
      console.log(`[PASS] ${message}`);
    } else {
      fail++;
      console.log(`[FAIL] ${message}`);
    }
  }

  // Set up mock test user contexts
  const researcherUser: AuthUser = {
    uid: 'user-ayush-001',
    role: 'RESEARCHER',
    email: 'ayush@devilhunt.sec',
    name: 'Ayush Singh',
  };

  const adminUser: AuthUser = {
    uid: 'user-admin-001',
    role: 'ADMIN',
    email: 'admin@devilhunt.sec',
    name: 'Admin User',
  };

  const unauthorizedUser: AuthUser = {
    uid: 'user-unauth-999',
    role: 'RESEARCHER',
    email: 'unauth@devilhunt.sec',
    name: 'Unauth User',
  };

  try {
    // Reset evidence store
    clearEvidenceStore();

    // 1. Setup seed finding
    const findingRows = await db.select().from(findings);
    if (findingRows.length === 0) {
      console.log('No findings present in database to test.');
      process.exit(1);
    }
    const testFinding = findingRows[0];

    // Ensure researcher user exists in DB
    await db.insert(users).values({
      uid: researcherUser.uid,
      name: 'Ayush Singh',
      email: researcherUser.email,
      role: researcherUser.role,
    }).onConflictDoNothing();

    await db.insert(users).values({
      uid: adminUser.uid,
      name: 'Admin User',
      email: adminUser.email,
      role: adminUser.role,
    }).onConflictDoNothing();

    await db.insert(users).values({
      uid: unauthorizedUser.uid,
      name: 'Unauth User',
      email: unauthorizedUser.email,
      role: unauthorizedUser.role,
    }).onConflictDoNothing();

    console.log('\n--- 1. EVIDENCE INTELLIGENCE TESTS ---');

    // Test 1.1: Create evidence with secrets & verify sanitization
    const rawObs = {
      endpoint: '/api/v1/user/keys',
      password: 'super-secret-password-123!',
      bearerToken: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretToken',
      apiKey: 'sk-live-99999999999999',
      snippet: 'User key endpoint returned status 200 OK',
    };

    const evItem = await createEvidence(
      researcherUser,
      {
        findingId: testFinding.id,
        observation: rawObs,
        observationType: 'SECURITY_POSTURE_OBSERVATION',
        source: 'CONTROLLED_ANALYZER',
      },
      'req-evid-001'
    );

    assert(Boolean(evItem.id), 'Evidence item created with unique ID');
    assert(evItem.findingId === testFinding.id, 'Evidence correctly linked to findingId');

    // Verify sanitization
    const sanitizedJson = JSON.stringify(evItem.sanitizedObservation);
    assert(!sanitizedJson.includes('super-secret-password-123!'), 'Raw password redacted from evidence');
    assert(!sanitizedJson.includes('sk-live-99999999999999'), 'Raw API key redacted from evidence');
    assert(sanitizedJson.includes('[REDACTED'), 'Redaction token inserted for password');

    // Test 1.2: Deterministic SHA-256 Evidence Hashing
    const hash1 = computeEvidenceHash({ a: 1, b: 'test' }, 'cap-01', 'asset-01');
    const hash2 = computeEvidenceHash({ b: 'test', a: 1 }, 'cap-01', 'asset-01');
    assert(hash1 === hash2, 'computeEvidenceHash is key-order independent and canonical');
    assert(hash1.length === 64, 'computeEvidenceHash produces 64-character SHA-256 hex string');

    // Test 1.3: Evidence retrieval
    const evidenceList = await getEvidenceForFinding(testFinding.id, researcherUser);
    assert(evidenceList.length >= 1, 'getEvidenceForFinding returns evidence list for finding');

    // Test 1.4: Evidence state machine transitions
    const transitionedEv = await transitionEvidenceStatus(evItem.id, 'SANITIZED', researcherUser, 'req-evid-002');
    assert(transitionedEv.validationStatus === 'SANITIZED', 'Evidence transitioned from CAPTURED to SANITIZED');

    const validatedEv = await transitionEvidenceStatus(evItem.id, 'VALIDATED', researcherUser, 'req-evid-003');
    assert(validatedEv.validationStatus === 'VALIDATED', 'Evidence transitioned from SANITIZED to VALIDATED');

    const acceptedEv = await transitionEvidenceStatus(evItem.id, 'ACCEPTED', researcherUser, 'req-evid-004');
    assert(acceptedEv.validationStatus === 'ACCEPTED', 'Evidence transitioned from VALIDATED to ACCEPTED');

    // Test 1.5: Invalid evidence transition fails
    let invalidEvErr = false;
    try {
      await transitionEvidenceStatus(evItem.id, 'CAPTURED', researcherUser, 'req-evid-005');
    } catch (err: any) {
      invalidEvErr = err.message.includes('INVALID_STATE_TRANSITION');
    }
    assert(invalidEvErr, 'Invalid evidence transition (ACCEPTED -> CAPTURED) blocked with INVALID_STATE_TRANSITION');

    console.log('\n--- 2. REPORT INTELLIGENCE TESTS ---');

    // Clean up or reset any existing test reports for finding to ensure fresh state machine execution
    await db.update(reports).set({ status: 'Draft', submittedAt: null, resolvedAt: null }).where(eq(reports.findingId, testFinding.id));

    // Test 2.1: Generate Report Intelligence
    const reportIntel = await generateReportIntelligenceForFinding(
      testFinding.id,
      researcherUser,
      'Test Report Title',
      'Test Executive Summary',
      'req-rep-001'
    );

    assert(Boolean(reportIntel.id), 'Report generated with unique ID');
    assert(reportIntel.findingId === testFinding.id, 'Report correctly linked to findingId');
    assert(Boolean(reportIntel.title), 'Report includes Title section');
    assert(Boolean(reportIntel.executiveSummary), 'Report includes Executive Summary section');
    assert(Boolean(reportIntel.affectedAsset), 'Report includes Affected Asset section');
    assert(Boolean(reportIntel.programName), 'Report includes Program section');
    assert(Boolean(reportIntel.scopeReference), 'Report includes Scope Reference section');
    assert(Boolean(reportIntel.capabilityId), 'Report includes Capability section');
    assert(Boolean(reportIntel.observation), 'Report includes Observation section');
    assert(Array.isArray(reportIntel.evidenceSummary), 'Report includes Evidence Summary array');
    assert(Boolean(reportIntel.validationResult), 'Report includes Validation Result section');
    assert(Array.isArray(reportIntel.reproductionSteps), 'Report includes Reproduction Steps section');
    assert(Boolean(reportIntel.impactDescription), 'Report includes Impact Description section');
    assert(Boolean(reportIntel.remediationGuidance), 'Report includes Remediation Guidance section');
    assert(Boolean(reportIntel.evidenceIntegrityHash), 'Report includes Evidence Integrity Hash');
    assert(Boolean(reportIntel.auditProvenance), 'Report includes Audit Provenance timeline');
    assert(Boolean(reportIntel.findingLifecycleStatus), 'Report includes Finding Lifecycle Status');

    // Test 2.2: Report State Machine
    assert(canTransitionReportStatus('DRAFT', 'UNDER_REVIEW'), 'State machine permits DRAFT -> UNDER_REVIEW');
    assert(canTransitionReportStatus('UNDER_REVIEW', 'READY'), 'State machine permits UNDER_REVIEW -> READY');
    assert(canTransitionReportStatus('READY', 'SUBMITTED'), 'State machine permits READY -> SUBMITTED');
    assert(canTransitionReportStatus('SUBMITTED', 'ACCEPTED'), 'State machine permits SUBMITTED -> ACCEPTED');

    // Transition through lifecycle
    const reviewReport = await transitionReportStatusIntelligence(reportIntel.id, 'UNDER_REVIEW', researcherUser, 'req-rep-002');
    assert(reviewReport.canonicalStatus === 'UNDER_REVIEW', 'Report transitioned to UNDER_REVIEW');

    const readyReport = await transitionReportStatusIntelligence(reportIntel.id, 'READY', researcherUser, 'req-rep-003');
    assert(readyReport.canonicalStatus === 'READY', 'Report transitioned to READY');

    const submittedReport = await transitionReportStatusIntelligence(reportIntel.id, 'SUBMITTED', researcherUser, 'req-rep-004');
    assert(submittedReport.canonicalStatus === 'SUBMITTED', 'Report transitioned to SUBMITTED');

    const acceptedReport = await transitionReportStatusIntelligence(reportIntel.id, 'ACCEPTED', researcherUser, 'req-rep-005');
    assert(acceptedReport.canonicalStatus === 'ACCEPTED', 'Report transitioned to ACCEPTED');

    // Test 2.3: Invalid Report Transition
    let invalidRepErr = false;
    try {
      await transitionReportStatusIntelligence(reportIntel.id, 'DRAFT', researcherUser, 'req-rep-006');
    } catch (err: any) {
      invalidRepErr = err.message.includes('INVALID_STATE_TRANSITION');
    }
    assert(invalidRepErr, 'Invalid report transition (ACCEPTED -> DRAFT) blocked with INVALID_STATE_TRANSITION');

    console.log('\n--- 3. SECURITY & AUTHORIZATION INVARIANTS ---');

    // Test 3.1: Unauthorized user access blocked
    let unauthErr = false;
    try {
      await assembleReportIntelligence(reportIntel.id, unauthorizedUser);
    } catch (err: any) {
      unauthErr = err.message.includes('FORBIDDEN') || err.message.includes('UNAUTHORIZED');
    }
    assert(unauthErr, 'Unauthorized researcher blocked from accessing another user report');

    // Test 3.2: Audit events recorded
    const auditRows = await db.select().from(auditEvents).where(eq(auditEvents.entityId, reportIntel.id));
    assert(auditRows.length > 0, 'Report state transitions successfully recorded in auditEvents');

  } catch (err: any) {
    console.error('VERIFICATION_SCRIPT_ERROR:', err);
    fail++;
  }

  const total = pass + fail;
  console.log('\n===========================================================');
  console.log(`REPORT: PASS: ${pass} | FAIL: ${fail} | TOTAL: ${total}`);
  console.log('===========================================================');

  if (fail > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runVerification();
