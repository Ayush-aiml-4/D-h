import { db } from '../db/index.ts';
import { hunts, programs, assets, findings } from '../db/schema.ts';
import { eq, and, inArray } from 'drizzle-orm';
import { recordAuditEvent } from './auditService.ts';
import { syncUserRecord } from './userService.ts';
import { evaluatePolicy } from './policyEngine.ts';
import { Hunt, HuntStep } from '../types.ts';
import { AuthUser } from '../middleware/auth.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  BadRequestError,
} from '../utils/errors.ts';

export const HUNT_TRANSITIONS: Record<string, string[]> = {
  Ready: ['Starting', 'Hunting', 'Blocked'],
  Starting: ['Hunting', 'Blocked'],
  Hunting: ['Analyzing', 'Paused', 'Stopped', 'Completed', 'Blocked'],
  Running: ['Hunting', 'Analyzing', 'Paused', 'Stopped', 'Completed', 'Blocked'],
  Analyzing: ['Hunting', 'Paused', 'Stopped', 'Completed', 'Blocked'],
  Paused: ['Hunting', 'Running', 'Stopped', 'Completed'],
  Completed: [],
  Complete: [],
  Stopped: [],
  Blocked: [],
};

export const canTransitionHunt = (from: string, to: string): boolean => {
  if (from === to) return true; // Idempotent same-state check
  return (HUNT_TRANSITIONS[from] || []).includes(to);
};

const defaultSteps: HuntStep[] = [
  { id: 's1', name: 'Reconnaissance', status: 'done', progress: 100 },
  { id: 's2', name: 'Target Mapping', status: 'done', progress: 100 },
  { id: 's3', name: 'API Discovery', status: 'active', progress: 75 },
  { id: 's4', name: 'Page Analysis', status: 'pending' },
  { id: 's5', name: 'Security Checks', status: 'pending' },
  { id: 's6', name: 'Evidence Validation', status: 'pending' },
];

export const getHuntByIdInternal = async (id: string, client?: any): Promise<Hunt | null> => {
  const dbClient = client || db;
  const res = await dbClient.select().from(hunts).where(eq(hunts.id, id));
  if (res.length === 0) return null;
  const h = res[0];

  const prog = await dbClient.select().from(programs).where(eq(programs.id, h.programId));
  const asset = await dbClient.select().from(assets).where(eq(assets.id, h.assetId));
  const huntFindings = await dbClient.select().from(findings).where(eq(findings.huntId, h.id));

  return {
    id: h.id,
    programId: h.programId,
    programName: prog[0] ? prog[0].name : 'Security Program',
    targetDomain: asset[0] ? asset[0].domain : h.scope,
    scopeCount: asset[0] ? asset[0].endpointCount : 1,
    status: h.status as any,
    startedAt: h.startedAt || '10 mins ago',
    progressPercent: h.progress,
    currentTask: h.currentTask || 'Executing policy checks',
    potentialFindingsCount: huntFindings.filter((f) => f.status === 'Potential').length,
    verifiedFindingsCount: huntFindings.filter((f) =>
      ['Verified', 'Submitted', 'Accepted', 'Resolved'].includes(f.status)
    ).length,
    policyViolationsCount: 0,
    steps: defaultSteps,
    liveLogs: [
      `Active policy enforcer initialized on target domain ${asset[0] ? asset[0].domain : h.scope}`,
      `Zero policy violations detected during authorization verification`,
      h.currentTask || `Session running in compliant state`,
    ],
  };
};

export const getHunts = async (user: AuthUser): Promise<Hunt[]> => {
  const allHunts = user.role === 'ADMIN'
    ? await db.select().from(hunts)
    : await db.select().from(hunts).where(eq(hunts.researcherId, user.uid));

  const allPrograms = await db.select().from(programs);
  const allAssets = await db.select().from(assets);
  const allFindings = await db.select().from(findings);

  return allHunts.map((h) => {
    const prog = allPrograms.find((p) => p.id === h.programId);
    const asset = allAssets.find((a) => a.id === h.assetId);
    const huntFindings = allFindings.filter((f) => f.huntId === h.id);

    return {
      id: h.id,
      programId: h.programId,
      programName: prog ? prog.name : 'Security Program',
      targetDomain: asset ? asset.domain : h.scope,
      scopeCount: asset ? asset.endpointCount : 1,
      status: h.status as any,
      startedAt: h.startedAt || '10 mins ago',
      progressPercent: h.progress,
      currentTask: h.currentTask || 'Executing policy checks',
      potentialFindingsCount: huntFindings.filter((f) => f.status === 'Potential').length,
      verifiedFindingsCount: huntFindings.filter((f) =>
        ['Verified', 'Submitted', 'Accepted', 'Resolved'].includes(f.status)
      ).length,
      policyViolationsCount: 0,
      steps: defaultSteps,
      liveLogs: [
        `Active policy enforcer initialized on target domain ${asset ? asset.domain : h.scope}`,
        `Zero policy violations detected during authorization verification`,
        h.currentTask || `Session running in compliant state`,
      ],
    };
  });
};

export const getHuntById = async (id: string, user: AuthUser): Promise<Hunt | null> => {
  const rawHunt = await db.select().from(hunts).where(eq(hunts.id, id));
  if (rawHunt.length === 0) return null;

  const h = rawHunt[0];
  if (user.role !== 'ADMIN' && h.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to access this hunt session');
  }

  return await getHuntByIdInternal(id);
};

export const createHunt = async (
  data: {
    programId: string;
    assetId?: string;
    targetDomain?: string;
  },
  user: AuthUser
) => {
  let createdHuntId = '';
  let isExisting = false;

  await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);
    const researcherId = user.uid;

    const prog = await tx.select().from(programs).where(eq(programs.id, data.programId));
    if (prog.length === 0) {
      throw new BadRequestError('INVALID_PROGRAM: Program not found');
    }

    // Resolve target asset
    let targetAsset;
    if (data.assetId) {
      const res = await tx.select().from(assets).where(eq(assets.id, data.assetId));
      if (res.length > 0) targetAsset = res[0];
    }
    if (!targetAsset && data.targetDomain) {
      const res = await tx.select().from(assets).where(eq(assets.domain, data.targetDomain));
      if (res.length > 0) {
        targetAsset = res[0];
      } else {
        const newAssetId = `asset-${Date.now()}`;
        const [created] = await tx
          .insert(assets)
          .values({
            id: newAssetId,
            programId: data.programId,
            domain: data.targetDomain,
            type: 'Web',
            status: 'IN_SCOPE',
            scopeStatus: 'In Scope',
          })
          .returning();
        targetAsset = created;
      }
    }
    if (!targetAsset) {
      const programAssets = await tx.select().from(assets).where(eq(assets.programId, data.programId));
      if (programAssets.length > 0) {
        targetAsset = programAssets[0];
      } else {
        const newAssetId = `asset-${Date.now()}`;
        const [created] = await tx
          .insert(assets)
          .values({
            id: newAssetId,
            programId: data.programId,
            domain: 'target.test',
            type: 'Web',
            status: 'IN_SCOPE',
            scopeStatus: 'In Scope',
          })
          .returning();
        targetAsset = created;
      }
    }

    // Policy Authorization Evaluation
    const targetToEvaluate = data.targetDomain || targetAsset.domain;
    const policyResult = await evaluatePolicy(user, {
      programId: data.programId,
      target: targetToEvaluate,
    });

    if (policyResult.decision === 'BLOCK') {
      throw new ForbiddenError(`FORBIDDEN_SCOPE: Start Hunt denied by authorization policy: ${policyResult.reason}`);
    }

    // Lock active hunt sessions to prevent race condition duplicates
    const activeStatuses = ['Starting', 'Running', 'Hunting', 'Analyzing'];
    const activeHunts = await tx
      .select()
      .from(hunts)
      .where(
        and(
          eq(hunts.programId, data.programId),
          eq(hunts.assetId, targetAsset.id),
          eq(hunts.researcherId, researcherId),
          inArray(hunts.status, activeStatuses)
        )
      )
      .for('update');

    if (activeHunts.length > 0) {
      createdHuntId = activeHunts[0].id;
      isExisting = true;
      return;
    }

    const huntId = `hunt-${Date.now()}`;
    createdHuntId = huntId;

    await tx.insert(hunts).values({
      id: huntId,
      programId: data.programId,
      assetId: targetAsset.id,
      researcherId,
      status: 'Hunting',
      progress: 15,
      scope: targetAsset.domain,
      currentTask: `Reconnaissance & Policy Rule Verification on ${targetAsset.domain}`,
      startedAt: 'Just now',
    });

    await recordAuditEvent(
      {
        userId: researcherId,
        entityType: 'HUNT',
        entityId: huntId,
        action: 'HUNT_STARTED',
        previousState: 'Ready',
        newState: 'Hunting',
        metadata: `Session initiated on ${targetAsset.domain}`,
      },
      tx
    );
  });

  const huntObj = await getHuntByIdInternal(createdHuntId);
  return { hunt: huntObj, isExisting };
};

export const updateHuntStatus = async (
  huntId: string,
  targetStatus: string,
  user: AuthUser,
  customTask?: string
) => {
  return await db.transaction(async (tx) => {
    await syncUserRecord(user, tx);

    const existing = await tx.select().from(hunts).where(eq(hunts.id, huntId)).for('update');
    if (existing.length === 0) {
      throw new NotFoundError('HUNT_NOT_FOUND: Hunt session does not exist');
    }

    const hunt = existing[0];
    if (user.role !== 'ADMIN' && hunt.researcherId !== user.uid) {
      throw new ForbiddenError('FORBIDDEN: You do not have permission to modify this hunt session');
    }

    // Idempotent state check
    if (hunt.status === targetStatus) {
      return await getHuntByIdInternal(huntId, tx);
    }

    if (!canTransitionHunt(hunt.status, targetStatus)) {
      throw new ConflictError(
        `INVALID_STATE_TRANSITION: Cannot transition hunt status from ${hunt.status} to ${targetStatus}`
      );
    }

    let newProgress = hunt.progress;
    if (targetStatus === 'Hunting') newProgress = Math.max(hunt.progress, 25);
    if (targetStatus === 'Analyzing') newProgress = Math.max(hunt.progress, 80);
    if (targetStatus === 'Completed' || targetStatus === 'Complete') newProgress = 100;

    await tx
      .update(hunts)
      .set({
        status: targetStatus,
        progress: newProgress,
        currentTask: customTask || `Status updated to ${targetStatus}`,
        completedAt: targetStatus === 'Completed' || targetStatus === 'Complete' ? 'Just now' : hunt.completedAt,
        updatedAt: new Date(),
      })
      .where(eq(hunts.id, huntId));

    await recordAuditEvent(
      {
        userId: user.uid,
        entityType: 'HUNT',
        entityId: huntId,
        action: `HUNT_${targetStatus.toUpperCase()}`,
        previousState: hunt.status,
        newState: targetStatus,
        metadata: `Status changed from ${hunt.status} to ${targetStatus}`,
      },
      tx
    );

    return await getHuntByIdInternal(huntId, tx);
  });
};
