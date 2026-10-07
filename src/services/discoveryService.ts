import { db } from '../db/index.ts';
import { discoverySessions, assets, programs, programScopes, users } from '../db/schema.ts';
import { eq, and, inArray } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';
import { evaluatePolicy, parseTarget, matchScopeRule } from './policyEngine.ts';
import { recordAuditEvent } from './auditService.ts';
import { DiscoveryAdapter, FixtureDiscoveryAdapter } from './discoveryAdapter.ts';
import { logger } from '../utils/logger.ts';

export interface StartDiscoveryParams {
  programId: string;
  target: string;
  operation?: string;
  adapter?: DiscoveryAdapter;
  requestId?: string;
}

export async function startDiscovery(
  user: AuthUser | null | undefined,
  params: StartDiscoveryParams
) {
  const { programId, target, requestId } = params;
  const operationToEvaluate = params.operation || 'ASSET_ENUMERATION';
  const adapter = params.adapter || new FixtureDiscoveryAdapter();

  // 1. Authenticate using existing authenticated user context
  if (!user || !user.uid) {
    await recordAuditEvent({
      userId: 'unauthenticated',
      entityType: 'DISCOVERY' as any,
      entityId: programId || 'unknown',
      action: 'DISCOVERY_BLOCKED',
      success: false,
      requestId,
      metadata: { reason: 'UNAUTHENTICATED: User authentication is required', target },
    });
    throw new Error('UNAUTHENTICATED: User authentication is required');
  }

  // 2. Verify Researcher authorization
  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'DISCOVERY' as any,
      entityId: programId || 'unknown',
      action: 'DISCOVERY_BLOCKED',
      success: false,
      requestId,
      metadata: { reason: 'UNAUTHORIZED_RESEARCHER: Researcher is not registered in authorization directory', target },
    });
    throw new Error('UNAUTHORIZED_RESEARCHER: Researcher is not registered in authorization directory');
  }

  // 3. Verify Program & Active Status
  if (!programId || typeof programId !== 'string') {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'DISCOVERY' as any,
      entityId: 'unknown',
      action: 'DISCOVERY_BLOCKED',
      success: false,
      requestId,
      metadata: { reason: 'PROGRAM_NOT_FOUND: Program ID is required', target },
    });
    throw new Error('PROGRAM_NOT_FOUND: Program ID is required');
  }

  const programRows = await db.select().from(programs).where(eq(programs.id, programId));
  if (programRows.length === 0) {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'DISCOVERY' as any,
      entityId: programId,
      action: 'DISCOVERY_BLOCKED',
      success: false,
      requestId,
      metadata: { reason: 'PROGRAM_NOT_FOUND: Program does not exist', target },
    });
    throw new Error('PROGRAM_NOT_FOUND: Program does not exist');
  }

  const program = programRows[0];
  if (program.status !== 'ACTIVE' && program.status !== 'Active') {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'DISCOVERY' as any,
      entityId: programId,
      action: 'DISCOVERY_BLOCKED',
      success: false,
      requestId,
      metadata: { reason: `INACTIVE_PROGRAM: Program '${program.name}' is inactive (Status: ${program.status})`, target },
    });
    throw new Error(`INACTIVE_PROGRAM: Program '${program.name}' is inactive (Status: ${program.status})`);
  }

  // 4. Resolve Target Scope & Call Existing Policy Engine for ASSET_ENUMERATION
  const policyResult = await evaluatePolicy(
    user,
    { programId, target, operation: operationToEvaluate },
    requestId
  );

  if (policyResult.decision !== 'ALLOW') {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'DISCOVERY' as any,
      entityId: programId,
      action: 'DISCOVERY_BLOCKED',
      success: false,
      requestId,
      metadata: {
        target,
        operation: operationToEvaluate,
        decision: policyResult.decision,
        reason: policyResult.reason,
      },
    });
    throw new Error(`DISCOVERY_POLICY_BLOCKED: ${policyResult.reason}`);
  }

  // 5. Prevent Duplicate Active Discovery Sessions
  const activeSessions = await db
    .select()
    .from(discoverySessions)
    .where(
      and(
        eq(discoverySessions.programId, programId),
        eq(discoverySessions.target, target),
        inArray(discoverySessions.status, ['READY', 'STARTING', 'DISCOVERING', 'ANALYZING'])
      )
    );

  if (activeSessions.length > 0) {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'DISCOVERY' as any,
      entityId: programId,
      action: 'DISCOVERY_BLOCKED',
      success: false,
      requestId,
      metadata: { reason: 'ACTIVE_SESSION_EXISTS: An active discovery session already exists for this target', target },
    });
    throw new Error('ACTIVE_SESSION_EXISTS: An active discovery session already exists for this program and target');
  }

  // Resolve matching program scope ID
  const dbScopes = await db.select().from(programScopes).where(eq(programScopes.programId, programId));
  const parsedRootTarget = parseTarget(target);
  const matchedTargetScope = dbScopes.find((s) =>
    matchScopeRule(parsedRootTarget, {
      id: s.id,
      programId: s.programId,
      targetPattern: s.targetPattern,
      scopeType: s.scopeType as any,
      scopeStatus: s.scopeStatus as any,
    })
  );

  // 6. Create Discovery Session & Transition State Machine
  const sessionId = `disc-sess-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const [session] = await db
    .insert(discoverySessions)
    .values({
      id: sessionId,
      programId,
      initiatedBy: user.uid,
      targetScopeId: matchedTargetScope?.id || null,
      target,
      operation: operationToEvaluate,
      status: 'READY',
      startedAt: new Date(),
      requestId: requestId || null,
    })
    .returning();

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'DISCOVERY' as any,
    entityId: sessionId,
    action: 'DISCOVERY_STARTED',
    newState: 'READY',
    requestId,
    metadata: { programId, target, operation: operationToEvaluate },
  });

  // State Transition: READY -> STARTING -> DISCOVERING
  await db
    .update(discoverySessions)
    .set({ status: 'DISCOVERING', updatedAt: new Date() })
    .where(eq(discoverySessions.id, sessionId));

  // 7. Process Fixture Candidates via Adapter
  const candidates = await adapter.discoverCandidates(target);

  // State Transition: DISCOVERING -> ANALYZING
  await db
    .update(discoverySessions)
    .set({ status: 'ANALYZING', updatedAt: new Date() })
    .where(eq(discoverySessions.id, sessionId));

  // 8. Normalize & Evaluate Candidates Against Scope Engine
  for (const candidate of candidates) {
    const parsedCandidate = parseTarget(candidate.rawTarget);
    if (!parsedCandidate.isValid) {
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'DISCOVERY' as any,
        entityId: candidate.rawTarget,
        action: 'ASSET_SCOPE_BLOCKED',
        success: false,
        requestId,
        metadata: {
          programId,
          rawTarget: candidate.rawTarget,
          reason: 'Malformed target format',
          status: 'OUT_OF_SCOPE',
        },
      });
      continue;
    }

    const candidateHostname = parsedCandidate.hostname || candidate.hostname || '';
    const candidatePath = candidate.path || parsedCandidate.path || '/';
    const candidateMethod = candidate.httpMethod || (candidatePath !== '/' ? 'POST' : 'GET');
    const candidateUrl = candidate.url || parsedCandidate.fullUrl || `https://${candidate.rawTarget}`;
    const candidateType = candidate.type || (candidatePath !== '/' ? 'API_ENDPOINT' : 'SUBDOMAIN');

    // Evaluate Candidate with Scope/Policy Engine
    const candidatePolicy = await evaluatePolicy(
      user,
      { programId, target: candidate.rawTarget, operation: operationToEvaluate },
      requestId
    );

    // Query existing asset in database
    const existingAssets = await db
      .select()
      .from(assets)
      .where(
        and(
          eq(assets.programId, programId),
          eq(assets.domain, candidateHostname),
          eq(assets.path, candidatePath)
        )
      );

    if (candidatePolicy.decision === 'ALLOW') {
      if (existingAssets.length > 0) {
        const existing = existingAssets[0];
        // CRITICAL REQUIREMENT: Never turn UNKNOWN or OUT_OF_SCOPE into AUTHORIZED
        if (existing.status === 'OUT_OF_SCOPE' || existing.status === 'DISABLED' || existing.status === 'UNKNOWN') {
          await recordAuditEvent({
            userId: user.uid,
            entityType: 'DISCOVERY' as any,
            entityId: existing.id,
            action: 'ASSET_SCOPE_BLOCKED',
            success: false,
            requestId,
            metadata: {
              programId,
              rawTarget: candidate.rawTarget,
              reason: `Preserved existing status '${existing.status}' on asset; refused elevation to AUTHORIZED`,
              status: existing.status,
            },
          });
        } else {
          // Update lastSeenAt on existing authorized asset (prevent duplicates)
          await db
            .update(assets)
            .set({ lastSeenAt: new Date(), updatedAt: new Date() })
            .where(eq(assets.id, existing.id));

          await recordAuditEvent({
            userId: user.uid,
            entityType: 'DISCOVERY' as any,
            entityId: existing.id,
            action: 'ASSET_DISCOVERED',
            newState: 'AUTHORIZED',
            requestId,
            metadata: {
              programId,
              rawTarget: candidate.rawTarget,
              domain: candidateHostname,
              path: candidatePath,
              type: candidateType,
              status: 'AUTHORIZED',
            },
          });
        }
      } else {
        // Find scope ID for this candidate
        const matchedCandidateScope = dbScopes.find((s) =>
          matchScopeRule(parsedCandidate, {
            id: s.id,
            programId: s.programId,
            targetPattern: s.targetPattern,
            scopeType: s.scopeType as any,
            scopeStatus: s.scopeStatus as any,
          })
        );

        // Find parent asset ID if applicable
        const rootDomain = candidateHostname.split('.').slice(-2).join('.');
        const parentAssetRows = await db
          .select()
          .from(assets)
          .where(and(eq(assets.programId, programId), eq(assets.domain, rootDomain)));

        const newAssetId = `ast-disc-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        await db.insert(assets).values({
          id: newAssetId,
          programId,
          scopeId: matchedCandidateScope?.id || null,
          parentAssetId: parentAssetRows.length > 0 ? parentAssetRows[0].id : null,
          domain: candidateHostname,
          hostname: candidateHostname,
          type: candidateType,
          url: candidateUrl,
          path: candidatePath,
          httpMethod: candidateMethod,
          status: 'AUTHORIZED',
          scopeStatus: 'In Scope',
          technology: candidate.rawTarget.includes('token')
            ? 'JWT Authentication Endpoint'
            : 'Discovered Infrastructure',
          endpointCount: 1,
          discoverySource: 'AUTHORIZED_DISCOVERY',
          confidence: 100,
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        });

        await recordAuditEvent({
          userId: user.uid,
          entityType: 'DISCOVERY' as any,
          entityId: newAssetId,
          action: 'ASSET_DISCOVERED',
          newState: 'AUTHORIZED',
          requestId,
          metadata: {
            programId,
            rawTarget: candidate.rawTarget,
            domain: candidateHostname,
            path: candidatePath,
            type: candidateType,
            status: 'AUTHORIZED',
          },
        });
      }
    } else {
      // Candidate is OUT_OF_SCOPE or BLOCKED
      // Ensure candidate in database remains/is marked OUT_OF_SCOPE
      if (existingAssets.length > 0) {
        const existing = existingAssets[0];
        if (existing.status !== 'OUT_OF_SCOPE') {
          await db
            .update(assets)
            .set({ status: 'OUT_OF_SCOPE', scopeStatus: 'Out of Scope', updatedAt: new Date() })
            .where(eq(assets.id, existing.id));
        }
      }

      await recordAuditEvent({
        userId: user.uid,
        entityType: 'DISCOVERY' as any,
        entityId: candidate.rawTarget,
        action: 'ASSET_SCOPE_BLOCKED',
        success: false,
        requestId,
        metadata: {
          programId,
          rawTarget: candidate.rawTarget,
          reason: candidatePolicy.reason,
          status: 'OUT_OF_SCOPE',
        },
      });
    }
  }

  // 9. Transition Session State: ANALYZING -> COMPLETED
  const [completedSession] = await db
    .update(discoverySessions)
    .set({
      status: 'COMPLETED',
      completedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(discoverySessions.id, sessionId))
    .returning();

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'DISCOVERY' as any,
    entityId: sessionId,
    action: 'DISCOVERY_COMPLETED',
    previousState: 'ANALYZING',
    newState: 'COMPLETED',
    requestId,
    metadata: { programId, target, candidateCount: candidates.length },
  });

  return completedSession;
}

export async function getDiscoverySession(user: AuthUser, sessionId: string) {
  if (!user || !user.uid) {
    throw new Error('UNAUTHENTICATED: User authentication is required');
  }

  const sessionRows = await db
    .select()
    .from(discoverySessions)
    .where(eq(discoverySessions.id, sessionId));

  if (sessionRows.length === 0) {
    throw new Error('SESSION_NOT_FOUND: Discovery session not found');
  }

  const session = sessionRows[0];

  if (user.role !== 'ADMIN' && session.initiatedBy !== user.uid) {
    throw new Error('FORBIDDEN: You do not have permission to access this discovery session');
  }

  return session;
}

export async function stopDiscovery(user: AuthUser, sessionId: string, requestId?: string) {
  if (!user || !user.uid) {
    throw new Error('UNAUTHENTICATED: User authentication is required');
  }

  const sessionRows = await db
    .select()
    .from(discoverySessions)
    .where(eq(discoverySessions.id, sessionId));

  if (sessionRows.length === 0) {
    throw new Error('SESSION_NOT_FOUND: Discovery session not found');
  }

  const session = sessionRows[0];

  if (user.role !== 'ADMIN' && session.initiatedBy !== user.uid) {
    throw new Error('FORBIDDEN: You do not have permission to stop this discovery session');
  }

  const activeStatuses = ['READY', 'STARTING', 'DISCOVERING', 'ANALYZING'];
  if (!activeStatuses.includes(session.status)) {
    throw new Error(`INVALID_STATE_TRANSITION: Cannot stop discovery session in status '${session.status}'`);
  }

  const previousState = session.status;
  const [updatedSession] = await db
    .update(discoverySessions)
    .set({
      status: 'STOPPED',
      completedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(discoverySessions.id, sessionId))
    .returning();

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'DISCOVERY' as any,
    entityId: sessionId,
    action: 'DISCOVERY_STOPPED',
    previousState,
    newState: 'STOPPED',
    requestId,
    metadata: { programId: session.programId, target: session.target },
  });

  return updatedSession;
}

export interface AssetFilterParams {
  programId?: string;
  discoverySessionId?: string;
  type?: string;
  status?: string;
  scopeId?: string;
}

export async function getAssets(user: AuthUser, filters: AssetFilterParams) {
  if (!user || !user.uid) {
    throw new Error('UNAUTHENTICATED: User authentication is required');
  }

  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new Error('UNAUTHORIZED_RESEARCHER: Researcher is not registered in authorization directory');
  }

  let effectiveProgramId = filters.programId;
  let effectiveScopeId = filters.scopeId;

  if (filters.discoverySessionId) {
    const sessionRows = await db
      .select()
      .from(discoverySessions)
      .where(eq(discoverySessions.id, filters.discoverySessionId));

    if (sessionRows.length === 0) {
      return [];
    }

    const session = sessionRows[0];
    if (user.role !== 'ADMIN' && session.initiatedBy !== user.uid) {
      throw new Error('FORBIDDEN: You do not have permission to access assets for this discovery session');
    }

    if (!effectiveProgramId) {
      effectiveProgramId = session.programId;
    }
    if (!effectiveScopeId && session.targetScopeId) {
      effectiveScopeId = session.targetScopeId;
    }
  }

  const conditions = [];

  if (effectiveProgramId) {
    conditions.push(eq(assets.programId, effectiveProgramId));
  }
  if (effectiveScopeId) {
    conditions.push(eq(assets.scopeId, effectiveScopeId));
  }
  if (filters.type) {
    conditions.push(eq(assets.type, filters.type));
  }
  if (filters.status) {
    conditions.push(eq(assets.status, filters.status));
  }

  if (conditions.length > 0) {
    return await db.select().from(assets).where(and(...conditions));
  }

  return await db.select().from(assets);
}
