import { db } from '../db/index.ts';
import { reports, findings, rewards, programs, assets, hunts } from '../db/schema.ts';
import { eq } from 'drizzle-orm';
import { recordAuditEvent } from './auditService.ts';
import { syncUserRecord } from './userService.ts';
import { Report } from '../types.ts';
import { AuthUser } from '../middleware/auth.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
} from '../utils/errors.ts';

export const REPORT_TRANSITIONS: Record<string, string[]> = {
  Draft: ['Ready'],
  Ready: ['Submitted'],
  Submitted: ['Accepted', 'Rejected', 'Duplicate'],
  Accepted: ['Resolved'],
  Rejected: [],
  Duplicate: [],
  Resolved: [],
};

export const canTransitionReport = (from: string, to: string): boolean => {
  if (from === to) return true; // Idempotent same-state check
  return (REPORT_TRANSITIONS[from] || []).includes(to);
};

export const getReportByIdInternal = async (id: string, client?: any): Promise<Report | null> => {
  const dbClient = client || db;
  const res = await dbClient.select().from(reports).where(eq(reports.id, id));
  if (res.length === 0) return null;
  const r = res[0];

  const f = await dbClient.select().from(findings).where(eq(findings.id, r.findingId));
  const findObj = f[0];
  const prog = await dbClient.select().from(programs).where(eq(programs.id, r.programId));
  const asset = findObj ? await dbClient.select().from(assets).where(eq(assets.id, findObj.assetId)) : [];
  const targetDomain = asset[0] ? asset[0].domain : 'target.test';

  return {
    id: r.id,
    findingId: r.findingId,
    programName: prog[0] ? prog[0].name : 'Security Program',
    title: r.title,
    severity: r.severity as any,
    researcher: 'Ayush Singh (DevilHunt)',
    target: targetDomain,
    status: r.status as any,
    summary: r.summary,
    impact: `Potential unauthorized disclosure or manipulation on ${targetDomain}`,
    technicalDetails: `Verified automated proof of concept executing within zero policy boundary violations.`,
    evidenceSnippet: findObj ? findObj.evidence || 'PoC trace' : 'GET /api/v2/tenants/1042/keys HTTP/1.1\nHost: ' + targetDomain,
    reproductionSteps: [
      `Send request to endpoint on ${targetDomain}`,
      `Observe response containing unauthorized tenant data`,
    ],
    recommendedFix: 'Apply authorization middleware checks on tenant key endpoint',
    testingPolicy: 'Testing was conducted strictly inside authorized program rules.',
    timeline: [
      { date: r.submittedAt || 'Today', action: `Report state changed to ${r.status}` },
    ],
    createdAt: r.createdAt ? new Date(r.createdAt).toISOString().split('T')[0] : 'Today',
    recipientContact: `security@${targetDomain}`,
  };
};

export const getReports = async (user: AuthUser): Promise<Report[]> => {
  const allReports = user.role === 'ADMIN'
    ? await db.select().from(reports)
    : await db.select().from(reports).where(eq(reports.researcherId, user.uid));

  const allFindings = await db.select().from(findings);
  const allPrograms = await db.select().from(programs);
  const allAssets = await db.select().from(assets);

  return allReports.map((r) => {
    const f = allFindings.find((find) => find.id === r.findingId);
    const prog = allPrograms.find((p) => p.id === r.programId);
    const asset = f ? allAssets.find((a) => a.id === f.assetId) : null;
    const targetDomain = asset ? asset.domain : 'target.test';

    return {
      id: r.id,
      findingId: r.findingId,
      programName: prog ? prog.name : 'Security Program',
      title: r.title,
      severity: r.severity as any,
      researcher: 'Ayush Singh (DevilHunt)',
      target: targetDomain,
      status: r.status as any,
      summary: r.summary,
      impact: `Potential unauthorized disclosure or manipulation on ${targetDomain}`,
      technicalDetails: `Verified automated proof of concept executing within zero policy boundary violations.`,
      evidenceSnippet: f ? f.evidence || 'PoC trace' : 'GET /api/v2/tenants/1042/keys HTTP/1.1\nHost: ' + targetDomain,
      reproductionSteps: [
        `Send request to endpoint on ${targetDomain}`,
        `Observe response containing unauthorized tenant data`,
      ],
      recommendedFix: 'Apply authorization middleware checks on tenant key endpoint',
      testingPolicy: 'Testing was conducted strictly inside authorized program rules.',
      timeline: [
        { date: r.submittedAt || 'Today', action: `Report state changed to ${r.status}` },
      ],
      createdAt: r.createdAt ? new Date(r.createdAt).toISOString().split('T')[0] : 'Today',
      recipientContact: `security@${targetDomain}`,
    };
  });
};

export const getReportById = async (id: string, user: AuthUser): Promise<Report | null> => {
  const rawReport = await db.select().from(reports).where(eq(reports.id, id));
  if (rawReport.length === 0) return null;

  const r = rawReport[0];
  if (user.role !== 'ADMIN' && r.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to access this report');
  }

  return await getReportByIdInternal(id);
};

export const createReportForFinding = async (
  findingId: string,
  user: AuthUser,
  customTitle?: string,
  customSummary?: string
) => {
  let targetReportId = '';
  let isExisting = false;

  await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);

    const existingFindings = await tx.select().from(findings).where(eq(findings.id, findingId));
    if (existingFindings.length === 0) {
      throw new NotFoundError('FINDING_NOT_FOUND: Target finding does not exist');
    }
    const finding = existingFindings[0];

    if (user.role !== 'ADMIN') {
      const parentHunt = await tx.select().from(hunts).where(eq(hunts.id, finding.huntId));
      if (parentHunt.length === 0 || parentHunt[0].researcherId !== user.uid) {
        throw new ForbiddenError('FORBIDDEN: You do not have permission to create a report for this finding');
      }
    }

    // Row-level lock on existing reports for this finding ID
    const existingReports = await tx.select().from(reports).where(eq(reports.findingId, findingId)).for('update');
    if (existingReports.length > 0) {
      targetReportId = existingReports[0].id;
      isExisting = true;
      return;
    }

    const reportId = `report-${Date.now()}`;
    targetReportId = reportId;

    await tx.insert(reports).values({
      id: reportId,
      findingId: finding.id,
      programId: finding.programId,
      researcherId: user.uid,
      title: customTitle || `Confidential Disclosure: ${finding.title}`,
      summary: customSummary || `Vulnerability report for ${finding.title}`,
      severity: finding.severity,
      status: 'Ready',
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
        action: 'REPORT_CREATED',
        newState: 'Ready',
        metadata: `Report generated for finding ${finding.id}`,
      },
      tx
    );
  });

  const reportObj = await getReportByIdInternal(targetReportId);
  return { report: reportObj, isExisting };
};

export const updateReportStatus = async (
  reportId: string,
  targetStatus: string,
  user: AuthUser
) => {
  return await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);

    const existing = await tx.select().from(reports).where(eq(reports.id, reportId)).for('update');
    if (existing.length === 0) {
      throw new NotFoundError('REPORT_NOT_FOUND: Report does not exist');
    }

    const report = existing[0];
    if (user.role !== 'ADMIN' && report.researcherId !== user.uid) {
      throw new ForbiddenError('FORBIDDEN: You do not have permission to modify this report');
    }

    // Idempotent same-state check
    if (report.status === targetStatus) {
      return await getReportByIdInternal(reportId, tx);
    }

    if (!canTransitionReport(report.status, targetStatus)) {
      throw new ConflictError(
        `INVALID_STATE_TRANSITION: Cannot transition report from ${report.status} to ${targetStatus}`
      );
    }

    const nowStr = 'Just now';
    const updateData: any = {
      status: targetStatus,
      updatedAt: new Date(),
    };

    if (targetStatus === 'Submitted') updateData.submittedAt = nowStr;
    if (targetStatus === 'Resolved') updateData.resolvedAt = nowStr;

    await tx
      .update(reports)
      .set(updateData)
      .where(eq(reports.id, reportId));

    if (targetStatus === 'Submitted') {
      await tx
        .update(rewards)
        .set({ status: 'PENDING' })
        .where(eq(rewards.reportId, reportId));
    } else if (targetStatus === 'Accepted') {
      await tx
        .update(rewards)
        .set({ status: 'PAID', paidAt: nowStr })
        .where(eq(rewards.reportId, reportId));
    }

    await recordAuditEvent(
      {
        userId: user.uid,
        entityType: 'REPORT',
        entityId: reportId,
        action: `REPORT_${targetStatus.toUpperCase()}`,
        previousState: report.status,
        newState: targetStatus,
        metadata: `Report status transitioned to ${targetStatus}`,
      },
      tx
    );

    return await getReportByIdInternal(reportId, tx);
  });
};
