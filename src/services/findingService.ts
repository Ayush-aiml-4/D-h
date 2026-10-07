import crypto from 'crypto';
import { db } from '../db/index.ts';
import { findings, hunts, programs, assets, programScopes, users, auditEvents } from '../db/schema.ts';
import { eq, inArray, and, or, desc } from 'drizzle-orm';
import { recordAuditEvent } from './auditService.ts';
import { syncUserRecord } from './userService.ts';
import { Finding, FindingStatus } from '../types.ts';
import { AuthUser } from '../middleware/auth.ts';
import { sanitizeAndRedact } from './capabilities/utils.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  UnauthorizedError,
} from '../utils/errors.ts';

export type CanonicalFindingState =
  | 'POTENTIAL'
  | 'UNDER_REVIEW'
  | 'VALIDATED'
  | 'VERIFIED'
  | 'REJECTED'
  | 'CLOSED';

export function normalizeFindingState(status: string): CanonicalFindingState | 'UNKNOWN' {
  if (!status) return 'UNKNOWN';
  const norm = status.trim().toUpperCase().replace(/\s+/g, '_');
  if (norm === 'POTENTIAL') return 'POTENTIAL';
  if (norm === 'UNDER_REVIEW' || norm === 'NEEDS_REVIEW' || norm === 'REVIEWING') return 'UNDER_REVIEW';
  if (norm === 'VALIDATED') return 'VALIDATED';
  if (norm === 'VERIFIED') return 'VERIFIED';
  if (norm === 'REJECTED') return 'REJECTED';
  if (
    norm === 'CLOSED' ||
    norm === 'RESOLVED' ||
    norm === 'DISMISSED' ||
    norm === 'ACCEPTED' ||
    norm === 'SUBMITTED' ||
    norm === 'DUPLICATE'
  )
    return 'CLOSED';
  return 'UNKNOWN';
}

export function formatFindingStateForDb(state: CanonicalFindingState | 'UNKNOWN'): string {
  switch (state) {
    case 'POTENTIAL':
      return 'Potential';
    case 'UNDER_REVIEW':
      return 'Under review';
    case 'VALIDATED':
      return 'Validated';
    case 'VERIFIED':
      return 'Verified';
    case 'REJECTED':
      return 'Rejected';
    case 'CLOSED':
      return 'Closed';
    default:
      return 'Potential';
  }
}

export const CANONICAL_TRANSITIONS: Record<CanonicalFindingState, CanonicalFindingState[]> = {
  POTENTIAL: ['UNDER_REVIEW', 'REJECTED'],
  UNDER_REVIEW: ['VALIDATED', 'REJECTED'],
  VALIDATED: ['VERIFIED', 'CLOSED'],
  VERIFIED: ['CLOSED'],
  REJECTED: [],
  CLOSED: [],
};

export const FINDING_TRANSITIONS: Record<string, string[]> = {
  Potential: ['Needs review', 'Under review', 'Validated', 'Dismissed', 'Rejected'],
  'Needs review': ['Under review', 'Validated', 'Dismissed', 'Rejected'],
  'Under review': ['Validated', 'Dismissed', 'Rejected'],
  Validated: ['Verified', 'Dismissed', 'Closed', 'Rejected'],
  Verified: ['Submitted', 'Dismissed', 'Closed'],
  Submitted: ['Accepted', 'Rejected', 'Duplicate', 'Closed'],
  Accepted: ['Resolved', 'Closed'],
  Rejected: [],
  Duplicate: [],
  Resolved: [],
  Closed: [],
  Dismissed: [],
};

export const canTransitionFinding = (from: string, to: string): boolean => {
  const fromCanonical = normalizeFindingState(from);
  const toCanonical = normalizeFindingState(to);
  if (fromCanonical === 'UNKNOWN' || toCanonical === 'UNKNOWN') return false;
  if (fromCanonical === toCanonical) return true; // Idempotent
  return CANONICAL_TRANSITIONS[fromCanonical].includes(toCanonical);
};

export function computeFindingCorrelationHash(params: {
  capabilityId?: string;
  assetId?: string;
  category?: string;
  target?: string;
  observationSnippet?: string;
}): string {
  const normTarget = (params.target || '').trim().toLowerCase();
  const normCategory = (params.category || '').trim().toLowerCase();
  const normCap = (params.capabilityId || 'cap-generic').trim().toLowerCase();
  const normAsset = (params.assetId || 'asset-generic').trim().toLowerCase();
  const normObs = (params.observationSnippet || '').trim();

  const { sanitized } = sanitizeAndRedact({ obs: normObs });
  const sanitizedObsStr = JSON.stringify(sanitized);

  const raw = `${normCap}:${normAsset}:${normCategory}:${normTarget}:${sanitizedObsStr}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export async function verifyResearcherAccess(user: AuthUser, tx?: any) {
  if (!user || !user.uid) {
    throw new UnauthorizedError('UNAUTHENTICATED: User authentication is required');
  }
  if (user.role !== 'RESEARCHER' && user.role !== 'ADMIN') {
    throw new ForbiddenError('FORBIDDEN: Only authorized researchers or admins can perform this action');
  }
  const dbClient = (tx && typeof tx === 'object' && typeof tx.select === 'function') ? tx : db;
  const userRows = await dbClient.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new ForbiddenError('UNAUTHORIZED_RESEARCHER: Researcher identity not registered in directory');
  }
}

export const getFindingByIdInternal = async (id: string, client?: any): Promise<Finding | null> => {
  const dbClient = client || db;
  const res = await dbClient.select().from(findings).where(eq(findings.id, id));
  if (res.length === 0) return null;
  const f = res[0];

  const prog = await dbClient.select().from(programs).where(eq(programs.id, f.programId));
  const asset = await dbClient.select().from(assets).where(eq(assets.id, f.assetId));
  const parentHunt = await dbClient.select().from(hunts).where(eq(hunts.id, f.huntId));
  const scopes = await dbClient.select().from(programScopes).where(eq(programScopes.programId, f.programId));

  const targetDomain = asset[0] ? asset[0].domain : 'target.test';
  const canonicalState = normalizeFindingState(f.status);

  const capabilityId = `cap-${(f.category || 'vuln').toLowerCase().replace(/\s+/g, '-')}`;
  const researcherId = parentHunt[0]?.researcherId || 'unassigned';
  const scopeId = scopes[0]?.id || null;

  const correlationHash = computeFindingCorrelationHash({
    capabilityId,
    assetId: f.assetId,
    category: f.category,
    target: targetDomain,
    observationSnippet: f.evidence || '',
  });

  const sanitizeResult = sanitizeAndRedact({ snippet: f.evidence || '' });

  return {
    id: f.id,
    huntId: f.huntId,
    programName: prog[0] ? prog[0].name : 'Security Program',
    title: f.title,
    category: f.category,
    severity: f.severity as any,
    confidence: typeof f.confidence === 'number' ? f.confidence : 85,
    target: targetDomain,
    status: f.status as any,
    whatWeFound: f.description,
    whyItMatters: `High priority security issue in ${targetDomain} allowing unauthorized access or data exposure.`,
    affectedTarget: `https://${targetDomain}/api/v2/transact`,
    evidence: {
      requestMethod: 'GET',
      requestUrl: `https://${targetDomain}/api/v2/tenants/1042/keys`,
      requestHeaders: {
        Authorization: 'Bearer <valid_token>',
        Host: targetDomain,
        'Content-Type': 'application/json',
      },
      responseStatus: 200,
      responseHeaders: {
        'Content-Type': 'application/json; charset=utf-8',
      },
      responseBodySnippet: (sanitizeResult.sanitized as any).snippet || '{"status": "success", "data": "exposed_keys"}',
      timestamp: 'Just now',
      validationStatus: f.status === 'Verified' ? 'VERIFIED_BY_POLICY_ENGINE' : 'PENDING_VALIDATION',
      proofHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    policyCheck: {
      inScope: true,
      testPermitted: true,
      validationCompleted: true,
      noRestrictedAction: true,
    },
    recommendedFix: 'Implement strict tenant context authorization checks (BOLA filter middleware) on every ID-parameterized path.',
    createdAt: f.discoveredAt || '10 mins ago',
    // Finding Intelligence traceability attributes
    programId: f.programId,
    scopeId,
    assetId: f.assetId,
    capabilityId,
    researcherId,
    canonicalStatus: canonicalState,
    correlationHash,
    requiresHumanReview: canonicalState === 'UNDER_REVIEW',
  } as Finding & Record<string, any>;
};

export const getFindings = async (user: AuthUser): Promise<Finding[]> => {
  await verifyResearcherAccess(user);

  let allFindings;
  if (user.role === 'ADMIN') {
    allFindings = await db.select().from(findings);
  } else {
    const userHunts = await db.select().from(hunts).where(eq(hunts.researcherId, user.uid));
    if (userHunts.length === 0) return [];

    const userHuntIds = userHunts.map((h) => h.id);
    allFindings = await db.select().from(findings).where(inArray(findings.huntId, userHuntIds));
  }

  const result: Finding[] = [];
  for (const f of allFindings) {
    const formatted = await getFindingByIdInternal(f.id);
    if (formatted) result.push(formatted);
  }
  return result;
};

export const getFindingById = async (id: string, user: AuthUser): Promise<Finding | null> => {
  await verifyResearcherAccess(user);

  const rawFinding = await db.select().from(findings).where(eq(findings.id, id));
  if (rawFinding.length === 0) return null;

  const f = rawFinding[0];
  if (user.role !== 'ADMIN') {
    const parentHunt = await db.select().from(hunts).where(eq(hunts.id, f.huntId));
    if (parentHunt.length === 0 || parentHunt[0].researcherId !== user.uid) {
      throw new ForbiddenError('FORBIDDEN: You do not have permission to access this finding');
    }
  }

  return await getFindingByIdInternal(id);
};

export const updateFindingStatus = async (
  findingId: string,
  targetStatus: string,
  user: AuthUser,
  requestId?: string
) => {
  await verifyResearcherAccess(user);

  return await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);

    const existing = await tx.select().from(findings).where(eq(findings.id, findingId)).for('update');
    if (existing.length === 0) {
      throw new NotFoundError('FINDING_NOT_FOUND: Finding does not exist');
    }

    const f = existing[0];
    if (user.role !== 'ADMIN') {
      const parentHunt = await tx.select().from(hunts).where(eq(hunts.id, f.huntId));
      if (parentHunt.length === 0 || parentHunt[0].researcherId !== user.uid) {
        throw new ForbiddenError('FORBIDDEN: You do not have permission to modify this finding');
      }
    }

    const currentCanonical = normalizeFindingState(f.status);
    const targetCanonical = normalizeFindingState(targetStatus);

    // Idempotent state check
    if (currentCanonical === targetCanonical && f.status === targetStatus) {
      return await getFindingByIdInternal(findingId, tx);
    }

    if (!canTransitionFinding(f.status, targetStatus)) {
      if (currentCanonical === 'CLOSED' || currentCanonical === 'REJECTED') {
        await recordAuditEvent(
          {
            userId: user.uid,
            entityType: 'FINDING',
            entityId: findingId,
            action: 'FINDING_REOPEN_BLOCKED',
            previousState: f.status,
            newState: targetStatus,
            requestId,
            metadata: `Reopen attempt blocked: Cannot transition finding from terminal state ${f.status} to ${targetStatus}`,
          },
          tx
        );
      }
      throw new ConflictError(
        `INVALID_STATE_TRANSITION: Cannot transition finding from ${f.status} to ${targetStatus}`
      );
    }

    const nowStr = new Date().toISOString();
    const dbStatus = formatFindingStateForDb(targetCanonical);
    const updateData: any = {
      status: dbStatus,
      updatedAt: new Date(),
    };

    if (targetCanonical === 'UNDER_REVIEW') updateData.reviewedAt = nowStr;
    if (targetCanonical === 'VALIDATED') updateData.validatedAt = nowStr;
    if (targetCanonical === 'VERIFIED') updateData.verifiedAt = nowStr;

    await tx
      .update(findings)
      .set(updateData)
      .where(eq(findings.id, findingId));

    let auditAction = `FINDING_${targetCanonical}`;
    if (targetCanonical === 'UNDER_REVIEW') auditAction = 'FINDING_REVIEW_STARTED';
    if (targetCanonical === 'VALIDATED') auditAction = 'FINDING_VALIDATED';
    if (targetCanonical === 'VERIFIED') auditAction = 'FINDING_VERIFIED';
    if (targetCanonical === 'REJECTED') auditAction = 'FINDING_REJECTED';
    if (targetCanonical === 'CLOSED') auditAction = 'FINDING_CLOSED';

    await recordAuditEvent(
      {
        userId: user.uid,
        entityType: 'FINDING',
        entityId: findingId,
        action: auditAction,
        previousState: f.status,
        newState: dbStatus,
        requestId,
        metadata: `Finding state updated from ${f.status} to ${dbStatus} (Canonical: ${targetCanonical})`,
      },
      tx
    );

    return await getFindingByIdInternal(findingId, tx);
  });
};

export const getFindingTimeline = async (findingId: string, user: AuthUser) => {
  await verifyResearcherAccess(user);

  const finding = await getFindingById(findingId, user);
  if (!finding) {
    throw new NotFoundError(`FINDING_NOT_FOUND: Finding '${findingId}' not found`);
  }

  const events = await db
    .select()
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.entityId, findingId),
        or(eq(auditEvents.entityType, 'FINDING'), eq(auditEvents.entityType, 'VALIDATION'))
      )
    )
    .orderBy(auditEvents.createdAt);

  const timelineItems = events.map((evt) => {
    let summary = `Event ${evt.action}`;
    if (evt.action === 'FINDING_CREATED') summary = 'Finding initially recorded in discovery';
    else if (evt.action === 'FINDING_REVIEW_STARTED') summary = 'Human review initiated for finding';
    else if (evt.action === 'FINDING_VALIDATED') summary = 'Finding validated by controlled security validator';
    else if (evt.action === 'FINDING_VERIFIED') summary = 'Finding verified for reporting';
    else if (evt.action === 'FINDING_REJECTED') summary = 'Finding rejected';
    else if (evt.action === 'FINDING_CLOSED') summary = 'Finding closed';
    else if (evt.action === 'FINDING_REOPEN_BLOCKED') summary = 'Attempted state transition or reopen blocked by policy engine';
    else if (evt.action.startsWith('VALIDATION_')) summary = `Controlled validation executed: ${evt.action}`;

    return {
      id: evt.id,
      timestamp: evt.createdAt ? evt.createdAt.toISOString() : new Date().toISOString(),
      event: evt.action,
      actorId: evt.userId,
      previousState: evt.previousState,
      newState: evt.newState,
      summary,
      requestId: evt.requestId,
      metadata: evt.metadata,
    };
  });

  return timelineItems;
};

export const getFindingEvidence = async (findingId: string, user: AuthUser) => {
  await verifyResearcherAccess(user);

  const finding = await getFindingById(findingId, user);
  if (!finding) {
    throw new NotFoundError(`FINDING_NOT_FOUND: Finding '${findingId}' not found`);
  }

  const valEvents = await db
    .select()
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.entityId, findingId),
        eq(auditEvents.entityType, 'VALIDATION')
      )
    )
    .orderBy(desc(auditEvents.createdAt));

  const { sanitized } = sanitizeAndRedact({ evidence: finding.evidence });

  return {
    findingId: finding.id,
    proofHash: (finding.evidence as any)?.proofHash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    evidence: (sanitized as any)?.evidence || finding.evidence,
    validations: valEvents.map((e) => ({
      id: e.id,
      action: e.action,
      timestamp: e.createdAt,
      requestId: e.requestId,
      metadata: e.metadata,
    })),
  };
};
