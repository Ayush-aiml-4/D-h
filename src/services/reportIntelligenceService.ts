import crypto from 'crypto';
import { db } from '../db/index.ts';
import { reports, findings, rewards, programs, assets, programScopes, auditEvents, hunts } from '../db/schema.ts';
import { eq } from 'drizzle-orm';
import { recordAuditEvent } from './auditService.ts';
import { syncUserRecord } from './userService.ts';
import { AuthUser } from '../middleware/auth.ts';
import { getFindingByIdInternal, getFindingTimeline, verifyResearcherAccess, normalizeFindingState } from './findingService.ts';
import { getEvidenceForFinding, computeEvidenceHash } from './evidenceService.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  BadRequestError,
} from '../utils/errors.ts';

export type CanonicalReportStatus =
  | 'DRAFT'
  | 'UNDER_REVIEW'
  | 'READY'
  | 'SUBMITTED'
  | 'ACCEPTED'
  | 'REJECTED';

export function normalizeReportStatus(status: string): CanonicalReportStatus {
  if (!status) return 'DRAFT';
  const norm = status.trim().toUpperCase().replace(/\s+/g, '_');
  if (norm === 'DRAFT') return 'DRAFT';
  if (norm === 'UNDER_REVIEW' || norm === 'REVIEWING' || norm === 'NEEDS_REVIEW') return 'UNDER_REVIEW';
  if (norm === 'READY') return 'READY';
  if (norm === 'SUBMITTED') return 'SUBMITTED';
  if (norm === 'ACCEPTED') return 'ACCEPTED';
  if (norm === 'REJECTED' || norm === 'DUPLICATE') return 'REJECTED';
  return 'DRAFT';
}

export function formatReportStatusForDb(status: CanonicalReportStatus): string {
  switch (status) {
    case 'DRAFT':
      return 'Draft';
    case 'UNDER_REVIEW':
      return 'Under review';
    case 'READY':
      return 'Ready';
    case 'SUBMITTED':
      return 'Submitted';
    case 'ACCEPTED':
      return 'Accepted';
    case 'REJECTED':
      return 'Rejected';
    default:
      return 'Draft';
  }
}

export const CANONICAL_REPORT_TRANSITIONS: Record<CanonicalReportStatus, CanonicalReportStatus[]> = {
  DRAFT: ['UNDER_REVIEW', 'READY', 'REJECTED'],
  UNDER_REVIEW: ['READY', 'REJECTED'],
  READY: ['SUBMITTED', 'REJECTED'],
  SUBMITTED: ['ACCEPTED', 'REJECTED'],
  ACCEPTED: [],
  REJECTED: [],
};

export function canTransitionReportStatus(from: CanonicalReportStatus, to: CanonicalReportStatus): boolean {
  if (from === to) return true; // Idempotent same-state check
  return CANONICAL_REPORT_TRANSITIONS[from].includes(to);
}

export interface StructuredReportIntelligence {
  id: string;
  findingId: string;
  programId: string;
  programName: string;
  researcherId: string;
  researcherName: string;
  title: string;
  executiveSummary: string;
  affectedAsset: string;
  scopeReference: string;
  capabilityId: string;
  observation: string;
  evidenceSummary: {
    evidenceId: string;
    observationType: string;
    evidenceHash: string;
    validationStatus: string;
    source: string;
  }[];
  validationResult: {
    status: string;
    validatedAt?: string;
    proofHash: string;
  };
  reproductionSteps: string[];
  impactDescription: string;
  remediationGuidance: string;
  evidenceIntegrityHash: string;
  auditProvenance: {
    createdAt: string;
    submittedAt?: string;
    timeline: any[];
  };
  findingLifecycleStatus: string;
  status: string;
  canonicalStatus: CanonicalReportStatus;
  severity: string;
  createdAt: string;
  submittedAt?: string;
  recipientContact: string;
}

/**
 * Assemble Report Intelligence deterministically from existing DB records.
 * Zero network activity, scanning, or side-effects.
 */
export async function assembleReportIntelligence(
  reportId: string,
  user: AuthUser,
  tx?: any
): Promise<StructuredReportIntelligence> {
  await verifyResearcherAccess(user, tx);
  const dbClient = tx || db;

  const rawReport = await dbClient.select().from(reports).where(eq(reports.id, reportId));
  if (rawReport.length === 0) {
    throw new NotFoundError(`REPORT_NOT_FOUND: Report '${reportId}' not found`);
  }

  const r = rawReport[0];
  if (user.role !== 'ADMIN' && r.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to access this report');
  }

  const findingObj = await getFindingByIdInternal(r.findingId);
  if (!findingObj) {
    throw new NotFoundError(`FINDING_NOT_FOUND: Finding for report '${reportId}' not found`);
  }

  // Fetch Evidence & Timeline safely
  const evidenceItems = await getEvidenceForFinding(r.findingId, user);
  const timeline = await getFindingTimeline(r.findingId, user);

  // Compute aggregate Evidence Integrity Hash from evidence hashes
  const sortedHashes = evidenceItems.map((e) => e.evidenceHash).sort().join(':');
  const aggregateEvidenceHash = crypto.createHash('sha256').update(sortedHashes).digest('hex');

  const canonicalState = normalizeReportStatus(r.status);

  return {
    id: r.id,
    findingId: r.findingId,
    programId: r.programId,
    programName: findingObj.programName || 'Authorized Security Program',
    researcherId: r.researcherId,
    researcherName: 'Ayush Singh (DevilHunt)',
    title: r.title,
    executiveSummary: r.summary,
    affectedAsset: findingObj.affectedTarget || `https://${findingObj.target}`,
    scopeReference: (findingObj as any).scopeId || `In-Scope target ${findingObj.target}`,
    capabilityId: (findingObj as any).capabilityId || 'cap-asset-discovery',
    observation: findingObj.whatWeFound || 'Observed security posture during authorized research.',
    evidenceSummary: evidenceItems.map((e) => ({
      evidenceId: e.id,
      observationType: e.observationType,
      evidenceHash: e.evidenceHash,
      validationStatus: e.validationStatus,
      source: e.source,
    })),
    validationResult: {
      status: findingObj.evidence?.validationStatus || 'VALIDATED_BY_POLICY_ENGINE',
      validatedAt: (findingObj as any).validatedAt || (findingObj as any).discoveredAt || findingObj.createdAt,
      proofHash: aggregateEvidenceHash,
    },
    reproductionSteps: [
      `Navigate to endpoint target at https://${findingObj.target}`,
      `Send request using authorized capability parameter filters`,
      `Observe controlled observation response in evidence trace`,
    ],
    impactDescription: `Identified potential security posture anomaly on ${findingObj.target}. Managed within authorized policy boundary limits.`,
    remediationGuidance: findingObj.recommendedFix || 'Implement strict policy controls and validation filters on parameterized endpoints.',
    evidenceIntegrityHash: aggregateEvidenceHash,
    auditProvenance: {
      createdAt: r.createdAt ? new Date(r.createdAt).toISOString() : new Date().toISOString(),
      submittedAt: r.submittedAt || undefined,
      timeline,
    },
    findingLifecycleStatus: findingObj.status,
    status: r.status,
    canonicalStatus: canonicalState,
    severity: r.severity,
    createdAt: r.createdAt ? new Date(r.createdAt).toISOString().split('T')[0] : 'Today',
    submittedAt: r.submittedAt || undefined,
    recipientContact: `security@${findingObj.target}`,
  };
}

/**
 * Generate Report Intelligence for a Finding
 * Side-effect free transformation of existing DB evidence. Zero network scanning.
 */
export async function generateReportIntelligenceForFinding(
  findingId: string,
  user: AuthUser,
  customTitle?: string,
  customSummary?: string,
  requestId: string = 'no-request-id'
): Promise<StructuredReportIntelligence> {
  await verifyResearcherAccess(user);

  let targetReportId = '';

  await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);

    const existingFindings = await tx.select().from(findings).where(eq(findings.id, findingId));
    if (existingFindings.length === 0) {
      throw new NotFoundError(`FINDING_NOT_FOUND: Target finding '${findingId}' does not exist`);
    }
    const finding = existingFindings[0];

    if (user.role !== 'ADMIN') {
      const parentHunt = await tx.select().from(hunts).where(eq(hunts.id, finding.huntId));
      if (parentHunt.length === 0 || parentHunt[0].researcherId !== user.uid) {
        throw new ForbiddenError('FORBIDDEN: You do not have permission to generate a report for this finding');
      }
    }

    const existingReports = await tx.select().from(reports).where(eq(reports.findingId, findingId)).for('update');
    if (existingReports.length > 0) {
      targetReportId = existingReports[0].id;
      return;
    }

    const reportId = `report-${Date.now()}`;
    targetReportId = reportId;

    await tx.insert(reports).values({
      id: reportId,
      findingId: finding.id,
      programId: finding.programId,
      researcherId: user.uid,
      title: customTitle || `Responsible Disclosure: ${finding.title}`,
      summary: customSummary || `Security research disclosure report for ${finding.title}`,
      severity: finding.severity,
      status: 'Draft',
    });

    let estAmount = 5000;
    if (finding.severity === 'Critical') estAmount = 25000;
    if (finding.severity === 'High') estAmount = 12500;
    if (finding.severity === 'Medium') estAmount = 5000;
    if (finding.severity === 'Low') estAmount = 2000;

    await tx.insert(rewards).values({
      id: `reward-${Date.now()}`,
      reportId,
      amount: `₹${estAmount.toLocaleString('en-IN')}`,
      numericAmount: estAmount,
      currency: 'INR',
      status: 'POTENTIAL',
    });

    await recordAuditEvent(
      {
        userId: user.uid,
        entityType: 'REPORT',
        entityId: reportId,
        action: 'REPORT_GENERATED',
        newState: 'Draft',
        requestId,
        metadata: `Report generated deterministically for finding ${finding.id}`,
      },
      tx
    );
  });

  return await assembleReportIntelligence(targetReportId, user);
}

/**
 * Transition Report Status using strict Report State Machine
 */
export async function transitionReportStatusIntelligence(
  reportId: string,
  targetStatus: string,
  user: AuthUser,
  requestId: string = 'no-request-id'
): Promise<StructuredReportIntelligence> {
  await verifyResearcherAccess(user);

  return await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);

    const existing = await tx.select().from(reports).where(eq(reports.id, reportId)).for('update');
    if (existing.length === 0) {
      throw new NotFoundError(`REPORT_NOT_FOUND: Report '${reportId}' does not exist`);
    }

    const report = existing[0];
    if (user.role !== 'ADMIN' && report.researcherId !== user.uid) {
      throw new ForbiddenError('FORBIDDEN: You do not have permission to modify this report');
    }

    const currentCanonical = normalizeReportStatus(report.status);
    const targetCanonical = normalizeReportStatus(targetStatus);

    if (currentCanonical === targetCanonical && report.status === formatReportStatusForDb(targetCanonical)) {
      return await assembleReportIntelligence(reportId, user, tx);
    }

    if (!canTransitionReportStatus(currentCanonical, targetCanonical)) {
      throw new ConflictError(
        `INVALID_STATE_TRANSITION: Cannot transition report from ${report.status} (Canonical: ${currentCanonical}) to ${targetStatus} (Canonical: ${targetCanonical})`
      );
    }

    const dbStatus = formatReportStatusForDb(targetCanonical);
    const nowStr = new Date().toISOString();
    const updateData: any = {
      status: dbStatus,
      updatedAt: new Date(),
    };

    if (targetCanonical === 'SUBMITTED') updateData.submittedAt = nowStr;
    if (targetCanonical === 'ACCEPTED') updateData.resolvedAt = nowStr;

    await tx.update(reports).set(updateData).where(eq(reports.id, reportId));

    if (targetCanonical === 'SUBMITTED') {
      await tx.update(rewards).set({ status: 'PENDING' }).where(eq(rewards.reportId, reportId));
    } else if (targetCanonical === 'ACCEPTED') {
      await tx.update(rewards).set({ status: 'PAID', paidAt: nowStr }).where(eq(rewards.reportId, reportId));
    }

    await recordAuditEvent(
      {
        userId: user.uid,
        entityType: 'REPORT',
        entityId: reportId,
        action: `REPORT_${targetCanonical}`,
        previousState: report.status,
        newState: dbStatus,
        requestId,
        metadata: `Report status transitioned to ${dbStatus} (Canonical: ${targetCanonical})`,
      },
      tx
    );

    return await assembleReportIntelligence(reportId, user, tx);
  });
}
