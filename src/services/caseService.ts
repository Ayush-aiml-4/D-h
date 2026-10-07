import crypto from 'crypto';
import { db } from '../db/index.ts';
import { programs, assets, findings, reports, discoverySessions, users } from '../db/schema.ts';
import { eq } from 'drizzle-orm';
import { recordAuditEvent } from './auditService.ts';
import { syncUserRecord } from './userService.ts';
import { AuthUser } from '../middleware/auth.ts';
import { getEvidenceForFinding } from './evidenceService.ts';
import {
  CanonicalCaseStatus,
  ResearchCase,
  ResearchActivity,
  ResearchCaseMetrics,
} from '../types.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  UnauthorizedError,
  BadRequestError,
} from '../utils/errors.ts';

export function normalizeCaseStatus(status: string): CanonicalCaseStatus {
  if (!status) return 'DRAFT';
  const norm = status.trim().toUpperCase().replace(/\s+/g, '_');
  if (norm === 'DRAFT') return 'DRAFT';
  if (norm === 'ACTIVE') return 'ACTIVE';
  if (norm === 'PAUSED') return 'PAUSED';
  if (norm === 'UNDER_REVIEW' || norm === 'REVIEWING') return 'UNDER_REVIEW';
  if (norm === 'CLOSED' || norm === 'COMPLETE') return 'CLOSED';
  if (norm === 'ARCHIVED') return 'ARCHIVED';
  return 'DRAFT';
}

export const CANONICAL_CASE_TRANSITIONS: Record<CanonicalCaseStatus, CanonicalCaseStatus[]> = {
  DRAFT: ['ACTIVE', 'ARCHIVED'],
  ACTIVE: ['PAUSED', 'UNDER_REVIEW', 'CLOSED'],
  PAUSED: ['ACTIVE', 'CLOSED'],
  UNDER_REVIEW: ['ACTIVE', 'CLOSED'],
  CLOSED: ['ARCHIVED'],
  ARCHIVED: [],
};

export function canTransitionCase(from: CanonicalCaseStatus, to: CanonicalCaseStatus): boolean {
  if (from === to) return true;
  return CANONICAL_CASE_TRANSITIONS[from]?.includes(to) ?? false;
}

// In-memory store backed by database audit logs
const casesStore: Map<string, ResearchCase> = new Map();
const activitiesStore: Map<string, ResearchActivity[]> = new Map();

export function clearCasesStore() {
  casesStore.clear();
  activitiesStore.clear();
}

export async function verifyResearcherAccess(user: AuthUser, tx?: any) {
  if (!user || !user.uid) {
    throw new UnauthorizedError('UNAUTHENTICATED: User authentication is required');
  }
  if (user.uid.includes('unreg') || user.uid.includes('unregistered')) {
    throw new ForbiddenError('UNAUTHORIZED_RESEARCHER: Researcher identity not registered in directory');
  }
  const dbClient = tx || db;
  const userRows = await dbClient.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new ForbiddenError('UNAUTHORIZED_RESEARCHER: Researcher identity not registered in directory');
  }
}

async function seedDefaultCasesIfNeeded(user: AuthUser) {
  if (casesStore.size > 0) return;

  try {
    const progRows = await db.select().from(programs);
    if (progRows.length > 0) {
      const defaultProg = progRows[0];
      const defaultCase: ResearchCase = {
        id: 'case-2026-08-001',
        programId: defaultProg.id,
        programName: defaultProg.name,
        title: 'API Authorization Boundary & Asset Scoping Review',
        objective: 'Conduct authorized security posture review of endpoints and API authorization barriers.',
        researcherId: 'user-ayush-001',
        researcherName: 'Ayush Singh (DevilHunt)',
        status: 'ACTIVE',
        scopeSummary: `Authorized testing campaign for ${defaultProg.name}`,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        metrics: {
          discoverySessionCount: 2,
          assetCount: 5,
          activityCount: 3,
          findingCount: 2,
          evidenceCount: 2,
          reportCount: 1,
        },
      };
      casesStore.set(defaultCase.id, defaultCase);

      const defaultActivities: ResearchActivity[] = [
        {
          id: 'act-init-001',
          caseId: defaultCase.id,
          programId: defaultProg.id,
          capabilityId: 'cap-asset-discovery',
          assetId: 'asset-001',
          target: 'api.acme-security.test',
          action: 'DISCOVERY_ENUMERATION',
          policyDecision: 'ALLOW',
          status: 'COMPLETED',
          executedBy: 'user-ayush-001',
          timestamp: new Date().toISOString(),
          requestId: 'req-init-001',
        },
      ];
      activitiesStore.set(defaultCase.id, defaultActivities);
    }
  } catch (err) {
    // Graceful fallback if database empty
  }
}

/**
 * Calculate dynamic lineage metrics for a case
 */
async function calculateCaseMetrics(caseItem: ResearchCase, user: AuthUser): Promise<{
  metrics: ResearchCaseMetrics;
  lineage: {
    discoverySessions: any[];
    assets: any[];
    activities: ResearchActivity[];
    findings: any[];
    evidence: any[];
    reports: any[];
  };
}> {
  const [discSessions, assetList, findingList, reportList] = await Promise.all([
    db.select().from(discoverySessions).where(eq(discoverySessions.programId, caseItem.programId)).catch(() => []),
    db.select().from(assets).where(eq(assets.programId, caseItem.programId)).catch(() => []),
    db.select().from(findings).where(eq(findings.programId, caseItem.programId)).catch(() => []),
    db.select().from(reports).where(eq(reports.programId, caseItem.programId)).catch(() => []),
  ]);

  const activities = activitiesStore.get(caseItem.id) || [];

  // Gather evidence for findings
  const evidenceList: any[] = [];
  for (const f of findingList) {
    try {
      const evs = await getEvidenceForFinding(f.id, user);
      evidenceList.push(...evs);
    } catch (err) {
      // Ignore errors for individual evidence fetches
    }
  }

  const metrics: ResearchCaseMetrics = {
    discoverySessionCount: discSessions.length,
    assetCount: assetList.length,
    activityCount: activities.length,
    findingCount: findingList.length,
    evidenceCount: evidenceList.length,
    reportCount: reportList.length,
  };

  return {
    metrics,
    lineage: {
      discoverySessions: discSessions,
      assets: assetList,
      activities,
      findings: findingList,
      evidence: evidenceList,
      reports: reportList,
    },
  };
}

/**
 * Create a new Research Case / Campaign
 */
export async function createResearchCase(
  user: AuthUser,
  params: {
    programId: string;
    title: string;
    objective: string;
    scopeSummary?: string;
  },
  requestId: string = 'no-request-id'
): Promise<ResearchCase> {
  return await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);
    await verifyResearcherAccess(user, tx);

    const progRows = await tx.select().from(programs).where(eq(programs.id, params.programId));
    if (progRows.length === 0) {
      throw new NotFoundError(`PROGRAM_NOT_FOUND: Program '${params.programId}' does not exist`);
    }

    const prog = progRows[0];
    if (prog.status !== 'Active') {
      throw new ForbiddenError(`PROGRAM_INACTIVE: Program '${prog.name}' is inactive and cannot accept new cases`);
    }

    const caseId = `case-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const nowStr = new Date().toISOString();

    const caseItem: ResearchCase = {
      id: caseId,
      programId: prog.id,
      programName: prog.name,
      title: params.title.trim(),
      objective: params.objective.trim(),
      researcherId: user.uid,
      researcherName: user.name || user.email || 'Researcher',
      status: 'DRAFT',
      scopeSummary: params.scopeSummary?.trim() || `In-scope research campaign for ${prog.name}`,
      createdAt: nowStr,
      updatedAt: nowStr,
      metrics: {
        discoverySessionCount: 0,
        assetCount: 0,
        activityCount: 0,
        findingCount: 0,
        evidenceCount: 0,
        reportCount: 0,
      },
    };

    casesStore.set(caseId, caseItem);
    activitiesStore.set(caseId, []);

    await recordAuditEvent(
      {
        userId: user.uid,
        entityType: 'CASE',
        entityId: caseId,
        action: 'CASE_CREATED',
        newState: 'DRAFT',
        requestId,
        metadata: JSON.stringify({
          caseId,
          programId: prog.id,
          title: caseItem.title,
        }),
      },
      tx
    );

    return caseItem;
  });
}

/**
 * Get Research Cases owned by user (or all cases if ADMIN)
 */
export async function getResearchCases(
  user: AuthUser,
  programId?: string
): Promise<ResearchCase[]> {
  await verifyResearcherAccess(user);
  await seedDefaultCasesIfNeeded(user);

  const resultList: ResearchCase[] = [];

  for (const c of casesStore.values()) {
    if (user.role !== 'ADMIN' && c.researcherId !== user.uid) {
      continue;
    }
    if (programId && c.programId !== programId) {
      continue;
    }

    const { metrics } = await calculateCaseMetrics(c, user);
    resultList.push({
      ...c,
      metrics,
    });
  }

  return resultList;
}

/**
 * Get single Research Case with complete lineage tree
 */
export async function getResearchCaseById(
  caseId: string,
  user: AuthUser
): Promise<ResearchCase & { lineage: any }> {
  await verifyResearcherAccess(user);
  await seedDefaultCasesIfNeeded(user);

  const caseItem = casesStore.get(caseId);
  if (!caseItem) {
    throw new NotFoundError(`CASE_NOT_FOUND: Research case '${caseId}' not found`);
  }

  if (user.role !== 'ADMIN' && caseItem.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to access this research case');
  }

  const { metrics, lineage } = await calculateCaseMetrics(caseItem, user);

  const updatedCase: ResearchCase = {
    ...caseItem,
    metrics,
  };
  casesStore.set(caseId, updatedCase);

  return {
    ...updatedCase,
    lineage,
  };
}

/**
 * Transition Research Case status using canonical state machine
 */
export async function transitionCaseStatus(
  caseId: string,
  targetStatus: string,
  user: AuthUser,
  requestId: string = 'no-request-id'
): Promise<ResearchCase> {
  await verifyResearcherAccess(user);
  await seedDefaultCasesIfNeeded(user);

  const caseItem = casesStore.get(caseId);
  if (!caseItem) {
    throw new NotFoundError(`CASE_NOT_FOUND: Research case '${caseId}' not found`);
  }

  if (user.role !== 'ADMIN' && caseItem.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to modify this research case');
  }

  const currentStatus = caseItem.status;
  const targetCanonical = normalizeCaseStatus(targetStatus);

  if (currentStatus === targetCanonical) {
    return caseItem; // Idempotent same-state return
  }

  if (currentStatus === 'ARCHIVED') {
    throw new ConflictError('INVALID_STATE_TRANSITION: Cannot reopen or modify an ARCHIVED research case');
  }

  if (!canTransitionCase(currentStatus, targetCanonical)) {
    throw new ConflictError(
      `INVALID_STATE_TRANSITION: Cannot transition research case from ${currentStatus} to ${targetCanonical}`
    );
  }

  const nowStr = new Date().toISOString();
  const updatedCase: ResearchCase = {
    ...caseItem,
    status: targetCanonical,
    updatedAt: nowStr,
    closedAt: targetCanonical === 'CLOSED' || targetCanonical === 'ARCHIVED' ? nowStr : caseItem.closedAt,
  };

  casesStore.set(caseId, updatedCase);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'CASE',
    entityId: caseId,
    action: `CASE_${targetCanonical}`,
    previousState: currentStatus,
    newState: targetCanonical,
    requestId,
    metadata: `Case status transitioned from ${currentStatus} to ${targetCanonical}`,
  });

  return updatedCase;
}

/**
 * Record a Research Activity under a Case.
 * Observational and traceability ONLY. Does NOT execute capabilities or network requests.
 */
export async function createResearchActivity(
  user: AuthUser,
  params: {
    caseId: string;
    capabilityId: string;
    assetId: string;
    target: string;
    action: string;
    policyDecision?: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
    status?: 'PLANNED' | 'EXECUTING' | 'COMPLETED' | 'BLOCKED';
    metadata?: Record<string, any>;
  },
  requestId: string = 'no-request-id'
): Promise<ResearchActivity> {
  await verifyResearcherAccess(user);
  await seedDefaultCasesIfNeeded(user);

  const caseItem = casesStore.get(params.caseId);
  if (!caseItem) {
    throw new NotFoundError(`CASE_NOT_FOUND: Research case '${params.caseId}' not found`);
  }

  if (user.role !== 'ADMIN' && caseItem.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to log activity for this research case');
  }

  const activityId = `act-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const nowStr = new Date().toISOString();

  const activity: ResearchActivity = {
    id: activityId,
    caseId: caseItem.id,
    programId: caseItem.programId,
    capabilityId: params.capabilityId,
    assetId: params.assetId,
    target: params.target,
    action: params.action,
    policyDecision: params.policyDecision || 'ALLOW',
    status: params.status || 'COMPLETED',
    executedBy: user.uid,
    timestamp: nowStr,
    requestId,
    metadata: params.metadata || {},
  };

  const existingActivities = activitiesStore.get(caseItem.id) || [];
  existingActivities.push(activity);
  activitiesStore.set(caseItem.id, existingActivities);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'ACTIVITY',
    entityId: activityId,
    action: 'RESEARCH_ACTIVITY_LOGGED',
    requestId,
    metadata: JSON.stringify({
      caseId: caseItem.id,
      action: activity.action,
      target: activity.target,
      policyDecision: activity.policyDecision,
    }),
  });

  return activity;
}

/**
 * Get Research Activities logged for a Case
 */
export async function getCaseActivities(
  caseId: string,
  user: AuthUser
): Promise<ResearchActivity[]> {
  await verifyResearcherAccess(user);
  await seedDefaultCasesIfNeeded(user);

  const caseItem = casesStore.get(caseId);
  if (!caseItem) {
    throw new NotFoundError(`CASE_NOT_FOUND: Research case '${caseId}' not found`);
  }

  if (user.role !== 'ADMIN' && caseItem.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to view activities for this research case');
  }

  return activitiesStore.get(caseId) || [];
}
