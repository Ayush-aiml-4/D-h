import crypto from 'crypto';
import { db } from '../db/index.ts';
import { programs, assets, users } from '../db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';
import {
  ExecutionRequest,
  ExecutionResult,
  ExecutionContext,
  ExecutionObservation,
  ExecutionStatus,
} from './execution/types.ts';
import { resolveExecutionPolicy, evaluateExecutionApproval } from './execution/executionPolicy.ts';
import { resolveExecutionAdapter } from './execution/adapterRegistry.ts';
import { SafeControlledHttpClient } from './execution/httpClient.ts';
import './execution/adapters/index.ts'; // ensure adapters are registered
import { evaluatePolicy } from './policyEngine.ts';
import { getCapability } from './capabilityService.ts';
import { getResearchCaseById } from './caseService.ts';
import { recordAuditEvent } from './auditService.ts';
import { redactSecrets } from '../utils/logger.ts';
import { computeEvidenceHash } from './evidenceService.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  UnauthorizedError,
  BadRequestError,
} from '../utils/errors.ts';

export const CANONICAL_EXECUTION_TRANSITIONS: Record<ExecutionStatus, ExecutionStatus[]> = {
  REQUESTED: ['AUTHORIZED', 'BLOCKED', 'FAILED', 'CANCELLED'],
  AUTHORIZED: ['APPROVED', 'BLOCKED', 'FAILED', 'CANCELLED'],
  APPROVED: ['RUNNING', 'CANCELLED', 'FAILED'],
  RUNNING: ['COMPLETED', 'FAILED', 'CANCELLED'],
  COMPLETED: [],
  CANCELLED: [],
  FAILED: [],
  BLOCKED: [],
};

export function canTransitionExecution(from: ExecutionStatus, to: ExecutionStatus): boolean {
  if (from === to) return true;
  return CANONICAL_EXECUTION_TRANSITIONS[from]?.includes(to) ?? false;
}

export function isTerminalExecutionStatus(status: ExecutionStatus): boolean {
  return status === 'COMPLETED' || status === 'CANCELLED' || status === 'FAILED' || status === 'BLOCKED';
}

const executionsStore: Map<string, ExecutionResult> = new Map();

export function clearExecutionsStore(): void {
  executionsStore.clear();
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

/**
 * Executes a registered security research capability through the governed execution pipeline.
 */
export async function executeCapability(
  user: AuthUser,
  request: ExecutionRequest,
  requestId: string = 'no-request-id'
): Promise<ExecutionResult> {
  const startTime = Date.now();

  // 1. Authenticate researcher identity (strictly server-side)
  await verifyResearcherAccess(user);

  // 2. Validate input parameters
  if (!request.caseId || typeof request.caseId !== 'string') {
    throw new BadRequestError('CASE_ID_REQUIRED: Research Case ID is required');
  }
  if (!request.capabilityId || typeof request.capabilityId !== 'string') {
    throw new BadRequestError('CAPABILITY_ID_REQUIRED: Capability ID is required');
  }
  if (!request.assetId || typeof request.assetId !== 'string') {
    throw new BadRequestError('ASSET_ID_REQUIRED: Asset ID is required');
  }

  // 3. Verify research case ownership & status
  const caseItem = await getResearchCaseById(request.caseId, user);
  if (!caseItem) {
    throw new NotFoundError(`CASE_NOT_FOUND: Research case '${request.caseId}' not found`);
  }
  if (caseItem.status === 'CLOSED' || caseItem.status === 'ARCHIVED') {
    throw new ConflictError(`CASE_INACTIVE: Research case is ${caseItem.status} and cannot accept executions`);
  }

  // 4. Verify program authorization
  const programRows = await db.select().from(programs).where(eq(programs.id, caseItem.programId));
  if (programRows.length === 0) {
    throw new NotFoundError(`PROGRAM_NOT_FOUND: Program '${caseItem.programId}' not found`);
  }
  const program = programRows[0];
  if (program.status !== 'Active' && program.status !== 'ACTIVE') {
    throw new ForbiddenError(`PROGRAM_INACTIVE: Program '${program.name}' is inactive`);
  }

  // 5. Verify asset authorization
  const assetRows = await db
    .select()
    .from(assets)
    .where(and(eq(assets.id, request.assetId), eq(assets.programId, program.id)));
  if (assetRows.length === 0) {
    throw new NotFoundError(`ASSET_NOT_FOUND: Asset '${request.assetId}' not found in program '${program.name}'`);
  }
  const asset = assetRows[0];

  // Resolve target string
  const resolvedTarget = request.target || asset.domain || asset.url || 'unknown-target';

  // 6. Resolve capability definition and adapter
  const capability = getCapability(request.capabilityId);
  const capName = capability?.name || request.capabilityId;

  // Resolve execution policy & approval requirement
  const executionPolicy = resolveExecutionPolicy(request.capabilityId);
  const approval = evaluateExecutionApproval(user, executionPolicy, request.confirmApproval);

  // Resolve adapter from registry (fails fast if unregistered or disabled)
  const adapter = resolveExecutionAdapter(request.capabilityId);

  // Generate execution identifier
  const executionId = `exec-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const nowStr = new Date().toISOString();

  // 7. Policy evaluation (server-authoritative)
  const policyResult = await evaluatePolicy(
    user,
    {
      programId: program.id,
      target: resolvedTarget,
      operation: capName,
    },
    requestId
  );

  if (policyResult.decision === 'BLOCK' || policyResult.decision === 'REVIEW_REQUIRED') {
    const blockedResult: ExecutionResult = {
      executionId,
      caseId: caseItem.id,
      programId: program.id,
      programName: program.name,
      assetId: asset.id,
      capabilityId: request.capabilityId,
      capabilityName: capName,
      target: resolvedTarget,
      researcherId: user.uid,
      researcherName: user.name || user.email || 'Researcher',
      status: 'BLOCKED',
      authorizationLevel: executionPolicy.authorizationLevel,
      policyDecision: policyResult.decision,
      approval,
      observations: [],
      durationMs: Date.now() - startTime,
      createdAt: nowStr,
      completedAt: new Date().toISOString(),
      error: `Policy decision: ${policyResult.decision}. ${policyResult.reason || 'Operation not permitted by program scope'}`,
      requestId,
    };

    executionsStore.set(executionId, blockedResult);

    await recordAuditEvent({
      userId: user.uid,
      entityType: 'EXECUTION',
      entityId: executionId,
      action: 'EXECUTION_BLOCKED',
      newState: 'BLOCKED',
      requestId,
      metadata: {
        caseId: caseItem.id,
        capabilityId: request.capabilityId,
        reason: blockedResult.error,
      },
    });

    return blockedResult;
  }

  // 8. Construct Execution Context
  const context: ExecutionContext = {
    executionId,
    user,
    programId: program.id,
    programName: program.name,
    assetId: asset.id,
    target: resolvedTarget,
    caseId: caseItem.id,
    capabilityId: request.capabilityId,
    capabilityName: capName,
    authorizationLevel: executionPolicy.authorizationLevel,
    policyDecision: policyResult.decision,
    approval,
    requestId,
    timeoutMs: executionPolicy.maxTimeoutMs,
    rateLimitBudget: 10,
    parameters: request.parameters,
  };

  // 9. Instantiate Safe Controlled HTTP Client
  const httpClient = new SafeControlledHttpClient(context);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'EXECUTION',
    entityId: executionId,
    action: 'EXECUTION_STARTED',
    newState: 'RUNNING',
    requestId,
    metadata: {
      caseId: caseItem.id,
      capabilityId: request.capabilityId,
      target: resolvedTarget,
    },
  });

  // 10. Execute Adapter
  let rawObservations: ExecutionObservation[] = [];
  try {
    rawObservations = await adapter.execute(context, httpClient);
  } catch (err: any) {
    const failedResult: ExecutionResult = {
      executionId,
      caseId: caseItem.id,
      programId: program.id,
      programName: program.name,
      assetId: asset.id,
      capabilityId: request.capabilityId,
      capabilityName: capName,
      target: resolvedTarget,
      researcherId: user.uid,
      researcherName: user.name || user.email || 'Researcher',
      status: 'FAILED',
      authorizationLevel: executionPolicy.authorizationLevel,
      policyDecision: policyResult.decision,
      approval,
      observations: [],
      durationMs: Date.now() - startTime,
      createdAt: nowStr,
      startedAt: nowStr,
      completedAt: new Date().toISOString(),
      error: err.message || 'Execution adapter error',
      requestId,
    };

    executionsStore.set(executionId, failedResult);

    await recordAuditEvent({
      userId: user.uid,
      entityType: 'EXECUTION',
      entityId: executionId,
      action: 'EXECUTION_FAILED',
      newState: 'FAILED',
      requestId,
      metadata: { error: failedResult.error },
    });

    return failedResult;
  }

  // 11. Sanitize Observations & Calculate Evidence Integrity Hash
  const sanitizedObservations: ExecutionObservation[] = rawObservations.map((obs) => {
    const cleanData = redactSecrets(obs.sanitizedData);
    const evHash = computeEvidenceHash(cleanData, obs.capabilityId, obs.assetId);
    return {
      ...obs,
      sanitizedData: cleanData,
      evidenceHash: evHash,
    };
  });

  const primaryEvidenceHash = sanitizedObservations[0]?.evidenceHash;
  const evidenceId = `ev-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

  const completedResult: ExecutionResult = {
    executionId,
    caseId: caseItem.id,
    programId: program.id,
    programName: program.name,
    assetId: asset.id,
    capabilityId: request.capabilityId,
    capabilityName: capName,
    target: resolvedTarget,
    researcherId: user.uid,
    researcherName: user.name || user.email || 'Researcher',
    status: 'COMPLETED',
    authorizationLevel: executionPolicy.authorizationLevel,
    policyDecision: policyResult.decision,
    approval,
    observations: sanitizedObservations,
    evidenceId,
    evidenceHash: primaryEvidenceHash,
    durationMs: Date.now() - startTime,
    createdAt: nowStr,
    startedAt: nowStr,
    completedAt: new Date().toISOString(),
    requestId,
  };

  executionsStore.set(executionId, completedResult);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'EXECUTION',
    entityId: executionId,
    action: 'EXECUTION_COMPLETED',
    newState: 'COMPLETED',
    requestId,
    metadata: {
      caseId: caseItem.id,
      capabilityId: request.capabilityId,
      evidenceId,
      evidenceHash: primaryEvidenceHash,
      observationsCount: sanitizedObservations.length,
    },
  });

  return completedResult;
}

/**
 * Retrieve execution record with ownership verification
 */
export async function getExecutionById(
  executionId: string,
  user: AuthUser
): Promise<ExecutionResult> {
  await verifyResearcherAccess(user);

  const exec = executionsStore.get(executionId);
  if (!exec) {
    throw new NotFoundError(`EXECUTION_NOT_FOUND: Execution '${executionId}' not found`);
  }

  if (user.role !== 'ADMIN' && exec.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to view this execution');
  }

  return exec;
}

/**
 * List executions with filtering
 */
export async function listExecutions(
  user: AuthUser,
  filters?: { caseId?: string; programId?: string; status?: ExecutionStatus }
): Promise<ExecutionResult[]> {
  await verifyResearcherAccess(user);

  const results: ExecutionResult[] = [];
  for (const exec of executionsStore.values()) {
    if (user.role !== 'ADMIN' && exec.researcherId !== user.uid) {
      continue;
    }
    if (filters?.caseId && exec.caseId !== filters.caseId) {
      continue;
    }
    if (filters?.programId && exec.programId !== filters.programId) {
      continue;
    }
    if (filters?.status && exec.status !== filters.status) {
      continue;
    }
    results.push(exec);
  }

  return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

/**
 * Cancel an execution that is not in a terminal state
 */
export async function cancelExecution(
  executionId: string,
  user: AuthUser,
  requestId: string = 'no-request-id'
): Promise<ExecutionResult> {
  await verifyResearcherAccess(user);

  const exec = executionsStore.get(executionId);
  if (!exec) {
    throw new NotFoundError(`EXECUTION_NOT_FOUND: Execution '${executionId}' not found`);
  }

  if (user.role !== 'ADMIN' && exec.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to cancel this execution');
  }

  if (isTerminalExecutionStatus(exec.status)) {
    throw new ConflictError(
      `CANNOT_CANCEL_TERMINAL_EXECUTION: Execution is in terminal state '${exec.status}' and cannot be cancelled`
    );
  }

  const cancelledExec: ExecutionResult = {
    ...exec,
    status: 'CANCELLED',
    completedAt: new Date().toISOString(),
  };

  executionsStore.set(executionId, cancelledExec);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'EXECUTION',
    entityId: executionId,
    action: 'EXECUTION_CANCELLED',
    previousState: exec.status,
    newState: 'CANCELLED',
    requestId,
  });

  return cancelledExec;
}
