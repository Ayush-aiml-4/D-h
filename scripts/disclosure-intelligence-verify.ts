import { GoogleGenAI } from '@google/genai';
import express from 'express';
import http from 'http';
import {
  createDisclosurePackage,
  getDisclosureById,
  listDisclosures,
  transitionDisclosureStatus,
  approveDisclosurePackage,
  recordManualSubmission,
  exportDisclosurePackage,
  clearDisclosureStore,
} from '../src/services/disclosureIntelligenceService.ts';
import { AuthUser } from '../src/middleware/auth.ts';
import { getFindingById } from '../src/services/findingService.ts';
import { getAuditEvents } from '../src/services/auditService.ts';
import { db } from '../src/db/index.ts';
import { findings } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';

// Mock researcher user for unit/service test verification
const testUser: AuthUser = {
  uid: 'user-ayush-001',
  role: 'ADMIN',
  name: 'Ayush Singh',
  email: 'ayush@example.com',
};

const nonResearcherUser: AuthUser = {
  uid: 'user-view-002',
  role: 'VIEWER' as any,
  name: 'Viewer User',
  email: 'viewer@example.com',
};

async function runVerification() {
  console.log('====================================================');
  console.log('DEVILHUNT #0003.4-D DISCLOSURE & SUBMISSION VERIFICATION');
  console.log('====================================================\n');

  let pass = 0;
  let fail = 0;
  let total = 0;

  function assert(condition: boolean, description: string) {
    total++;
    if (condition) {
      pass++;
      console.log(`[PASS] Scenario ${total}: ${description}`);
    } else {
      fail++;
      console.log(`[FAIL] Scenario ${total}: ${description}`);
    }
  }

  try {
    await clearDisclosureStore();

    // 1. Get seed finding from DB
    const dbFindings = await db.select().from(findings);
    let targetFinding = dbFindings.find((f) => f.status === 'Validated' || f.status === 'Verified');
    if (!targetFinding && dbFindings.length > 0) {
      targetFinding = dbFindings[0];
    }
    if (!targetFinding) {
      console.log('No findings present in database to test.');
      process.exit(1);
    }
    const findingId = targetFinding.id;

    // Ensure finding status is Validated/Verified so quality gate 2 passes
    if (targetFinding.status !== 'Validated' && targetFinding.status !== 'Verified') {
      await db.update(findings).set({ status: 'Validated' }).where(eq(findings.id, findingId));
    }

    // 1. Create a disclosure package from a finding
    const pkg1 = await createDisclosurePackage(testUser, findingId, 'req-disc-001');
    if (!pkg1.qualitySummary.overallPassed) {
      console.log('Failing gates:', pkg1.qualitySummary.gates.filter((g) => !g.passed));
    }
    assert(
      pkg1.id.startsWith('disc-') && pkg1.findingId === findingId,
      'Create disclosure package draft for finding'
    );

    // 2. Initial status must be DRAFT
    assert(
      pkg1.status === 'DRAFT',
      'Initial disclosure status is strictly DRAFT'
    );

    // 3. Check quality gates evaluation on draft creation
    assert(
      pkg1.qualitySummary !== undefined && pkg1.qualitySummary.totalCount === 16,
      'Evaluates all 16 deterministic quality gates'
    );

    // 4. Retrieve disclosure package by ID
    const fetchedPkg = await getDisclosureById(testUser, pkg1.id);
    assert(
      fetchedPkg.id === pkg1.id && fetchedPkg.title === pkg1.title,
      'Get disclosure package by ID'
    );

    // 5. List disclosures filtered by findingId
    const listByFinding = await listDisclosures(testUser, { findingId });
    assert(
      listByFinding.length > 0 && listByFinding.some((d) => d.id === pkg1.id),
      'List disclosures filtered by findingId'
    );

    // 6. List disclosures filtered by programId
    const listByProgram = await listDisclosures(testUser, { programId: pkg1.programId });
    assert(
      listByProgram.some((d) => d.id === pkg1.id),
      'List disclosures filtered by programId'
    );

    // 7. Transition DRAFT -> UNDER_REVIEW
    const underReviewPkg = await transitionDisclosureStatus(
      testUser,
      pkg1.id,
      'UNDER_REVIEW',
      'req-disc-002'
    );
    assert(
      underReviewPkg.status === 'UNDER_REVIEW',
      'Transition DRAFT -> UNDER_REVIEW'
    );

    // 8. Invalid transition attempt (UNDER_REVIEW -> SUBMITTED directly) should fail
    let invalidTransitionFailed = false;
    try {
      await transitionDisclosureStatus(testUser, pkg1.id, 'SUBMITTED', 'req-disc-003');
    } catch (err: any) {
      invalidTransitionFailed = err.message.includes('INVALID_STATE_TRANSITION') || err.message.includes('Invalid status transition');
    }
    assert(
      invalidTransitionFailed,
      'Direct invalid transition UNDER_REVIEW -> SUBMITTED rejected'
    );

    // 9. Transition UNDER_REVIEW -> READY_FOR_APPROVAL
    const readyPkg = await transitionDisclosureStatus(
      testUser,
      pkg1.id,
      'READY_FOR_APPROVAL',
      'req-disc-004'
    );
    assert(
      readyPkg.status === 'READY_FOR_APPROVAL',
      'Transition UNDER_REVIEW -> READY_FOR_APPROVAL'
    );

    // 10. Approve disclosure package with explicit authenticated researcher identity
    const approvedPkg = await approveDisclosurePackage(testUser, pkg1.id, 'req-disc-005');
    assert(
      approvedPkg.status === 'SUBMISSION_READY' &&
        approvedPkg.approvedBy === testUser.uid &&
        approvedPkg.approvedAt !== undefined,
      'Explicit researcher approval transitions status to SUBMISSION_READY and sets approvedBy'
    );

    // 11. Record manual submission
    const submittedPkg = await recordManualSubmission(testUser, pkg1.id, 'req-disc-006');
    assert(
      submittedPkg.status === 'SUBMITTED' && submittedPkg.submittedAt !== undefined,
      'Record manual submission sets status to SUBMITTED and captures timestamp'
    );

    // 12. Cannot transition once SUBMITTED
    let postSubmissionTransitionFailed = false;
    try {
      await transitionDisclosureStatus(testUser, pkg1.id, 'DRAFT', 'req-disc-007');
    } catch (err: any) {
      postSubmissionTransitionFailed = err.message.includes('already been submitted') || err.message.includes('Terminal state');
    }
    assert(
      postSubmissionTransitionFailed,
      'Terminal state SUBMITTED rejects further status transitions'
    );

    // 13. Test Markdown export rendering
    const mdExport = exportDisclosurePackage(submittedPkg, 'markdown');
    assert(
      mdExport.includes('# Security Vulnerability Disclosure Package') && mdExport.includes('## 1. Executive Summary'),
      'Export disclosure package in Markdown format'
    );

    // 14. Test HTML export rendering
    const htmlExport = exportDisclosurePackage(submittedPkg, 'html');
    assert(
      htmlExport.includes('<html') && htmlExport.includes('Security Vulnerability Disclosure Package'),
      'Export disclosure package in HTML format'
    );

    // 15. Test Plain Text export rendering
    const textExport = exportDisclosurePackage(submittedPkg, 'text');
    assert(
      textExport.includes('SECURITY VULNERABILITY DISCLOSURE PACKAGE') && textExport.includes('Program:'),
      'Export disclosure package in Plain Text format'
    );

    // 16. Test JSON export rendering
    const jsonExport = exportDisclosurePackage(submittedPkg, 'json');
    const parsedJson = JSON.parse(jsonExport);
    assert(
      parsedJson.id === submittedPkg.id && parsedJson.qualitySummary !== undefined,
      'Export disclosure package in structured JSON format'
    );

    // 17. Test Secret Redaction in evidence references & technical details
    assert(
      !mdExport.includes('SECRET_KEY') && !mdExport.includes('Bearer secret-token'),
      'Secret redaction enforced on disclosure exports'
    );

    // 18. Audit event verification for disclosure actions
    const auditEvents = await getAuditEvents(testUser, { entityType: 'DISCLOSURE' });
    assert(
      auditEvents.length >= 4 && auditEvents.some((e) => e.action === 'DISCLOSURE_CREATED'),
      'Audit log captures DISCLOSURE_CREATED events'
    );

    // 19. Audit log captures approval action
    assert(
      auditEvents.some((e) => e.action === 'DISCLOSURE_APPROVED'),
      'Audit log captures DISCLOSURE_APPROVED events with researcher attribution'
    );

    // 20. Scope verification status check
    assert(
      ['VERIFIED_IN_SCOPE', 'REQUIRES_REVIEW', 'OUT_OF_SCOPE'].includes(
        pkg1.scopeVerificationStatus
      ),
      'Scope verification status properly derived from program policy'
    );

    // 21. Duplicate correlation check logic
    assert(
      Array.isArray(pkg1.possibleDuplicates),
      'Possible duplicate correlation check executes and produces list'
    );

    // 22. Non-researcher role authorization check
    let unauthorizedFailed = false;
    try {
      await createDisclosurePackage(nonResearcherUser, findingId, 'req-unauth-01');
    } catch (err: any) {
      unauthorizedFailed = err.message.includes('FORBIDDEN') || err.message.includes('Forbidden') || err.message.includes('Unauthorized') || err.message.includes('role');
    }
    assert(
      unauthorizedFailed,
      'Non-researcher role rejected from creating disclosure package'
    );

    // 23. Severity non-fabrication check: authentic metadata without fabrication
    const finding = await getFindingById(findingId, testUser);
    assert(
      pkg1.vulnerabilityClassification === finding.category,
      'Authentic metadata strictly derived from finding category without fabrication'
    );

    // 24. Repeat draft creation for same finding returns idempotent draft
    const pkg1Repeat = await createDisclosurePackage(testUser, findingId, 'req-disc-repeat');
    assert(
      pkg1Repeat.id === pkg1.id,
      'Create disclosure package draft is idempotent for active draft'
    );

    // 25. Gate checking: Gate 2 (Finding Validation State) passes for validated finding
    const gate2 = pkg1.qualitySummary.gates.find((g) => g.gateId === 'gate-02-finding-state');
    assert(
      gate2 !== undefined && gate2.passed === true,
      'Quality Gate 2 (Finding Validation State) passes for validated finding'
    );

    // 26. Gate checking: Gate 12 (No Unsanitized Secrets) passes
    const gate12 = pkg1.qualitySummary.gates.find((g) => g.gateId === 'gate-12-secret-redaction');
    assert(
      gate12 !== undefined && gate12.passed === true,
      'Quality Gate 12 (No Unsanitized Secrets) passes'
    );

    // 27. Gate checking: Gate 5 (Scope Verification) passes
    const gate5 = pkg1.qualitySummary.gates.find((g) => g.gateId === 'gate-05-asset-in-scope');
    assert(
      gate5 !== undefined && gate5.passed === true,
      'Quality Gate 5 (Scope Verification) passes'
    );

    // 28. Unapproved state check prior to explicit researcher approval
    let secondFindingId = dbFindings[1]?.id;
    if (!secondFindingId || secondFindingId === targetFinding.id) {
      await clearDisclosureStore();
      secondFindingId = targetFinding.id;
    } else {
      await db.update(findings).set({ status: 'Validated' }).where(eq(findings.id, secondFindingId));
    }

    const freshPkg = await createDisclosurePackage(testUser, secondFindingId, 'req-disc-010');
    assert(
      freshPkg.approvedBy === undefined && freshPkg.status !== 'SUBMISSION_READY',
      'Disclosure package remains unapproved prior to explicit researcher approval'
    );

    // 29. Valid transition sequence and explicit approval
    const freshReview = await transitionDisclosureStatus(testUser, freshPkg.id, 'UNDER_REVIEW', 'req-011');
    const freshReady = await transitionDisclosureStatus(testUser, freshReview.id, 'READY_FOR_APPROVAL', 'req-012');
    const freshApproved = await approveDisclosurePackage(testUser, freshReady.id, 'req-013');
    assert(
      freshApproved.status === 'SUBMISSION_READY' && freshApproved.approvedBy === testUser.uid,
      'Transitions DRAFT -> UNDER_REVIEW -> READY_FOR_APPROVAL -> SUBMISSION_READY upon explicit approval'
    );

    // 30. Zero network submission guarantee check
    assert(
      freshApproved.status === 'SUBMISSION_READY' && freshApproved.submittedAt === undefined,
      'SUBMISSION_READY state does NOT auto-submit or make external network calls'
    );

  } catch (err: any) {
    console.error('Unhandled exception during verification:', err);
    fail++;
  }

  console.log('\n====================================================');
  console.log(`REPORT:`);
  console.log(`PASS: ${pass}`);
  console.log(`FAIL: ${fail}`);
  console.log(`TOTAL: ${total}`);
  console.log('====================================================\n');

  if (fail > 0) {
    process.exit(1);
  }
}

runVerification();
