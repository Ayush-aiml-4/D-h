import crypto from 'crypto';
import { db } from '../../../db/index.ts';
import { programs, assets } from '../../../db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { AuthUser } from '../../../middleware/auth.ts';
import {
  ActiveExecutionRequest,
  ActiveExecutionResult,
  ActiveExecutionContext,
  ActiveExecutionObservation,
  ActiveExecutionStatus,
  RequestBudget,
} from './activeTestingTypes.ts';
import {
  resolveActiveCapability,
  resolveActiveAdapter,
  CANONICAL_ACTIVE_CAPABILITIES,
} from './activeCapabilityRegistry.ts';
import { evaluateActiveTestingPolicy } from './activePolicyEngine.ts';
import {
  createApprovalRequirement,
  validateAndConsumeApproval,
} from './approvalService.ts';
import { BudgetEngine } from './budgetEngine.ts';
import { ControlledRequestBuilder } from './requestBuilder.ts';
import { SafeControlledHttpClient } from '../httpClient.ts';
import { verifyResearcherAccess } from '../../researchExecutionService.ts';
import { getResearchCaseById } from '../../caseService.ts';
import { recordAuditEvent } from '../../auditService.ts';
import { redactSecrets } from '../../../utils/logger.ts';
import { computeEvidenceHash } from '../../evidenceService.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  BadRequestError,
} from '../../../utils/errors.ts';

import './adapters/index.ts'; // ensure adapters are loaded

export const ACTIVE_EXECUTION_TRANSITIONS: Record<ActiveExecutionStatus, ActiveExecutionStatus[]> = {
  QUEUED: ['AUTHORIZED', 'BLOCKED', 'FAILED', 'CANCELLED'],
  AUTHORIZED: ['APPROVED', 'BLOCKED', 'FAILED', 'CANCELLED'],
  APPROVED: ['RUNNING', 'CANCELLED', 'FAILED'],
  RUNNING: ['COMPLETED', 'FAILED', 'CANCELLED'],
  COMPLETED: [],
  CANCELLED: [],
  FAILED: [],
  BLOCKED: [],
};

export function canTransitionActiveExecution(from: ActiveExecutionStatus, to: ActiveExecutionStatus): boolean {
  if (from === to) return true;
  return ACTIVE_EXECUTION_TRANSITIONS[from]?.includes(to) ?? false;
}

export function isTerminalActiveExecutionStatus(status: ActiveExecutionStatus): boolean {
  return status === 'COMPLETED' || status === 'CANCELLED' || status === 'FAILED' || status === 'BLOCKED';
}

const activeExecutionsStore: Map<string, ActiveExecutionResult> = new Map();
const activeContextsStore: Map<string, ActiveExecutionContext> = new Map();

export function clearActiveExecutionsStore(): void {
  activeExecutionsStore.clear();
  activeContextsStore.clear();
}

/**
 * Execute an active security research capability through the governed active testing pipeline.
 */
export async function executeActiveCapability(
  user: AuthUser,
  request: ActiveExecutionRequest,
  requestId: string = 'no-request-id'
): Promise<ActiveExecutionResult> {
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
    throw new ConflictError(`CASE_INACTIVE: Research case is ${caseItem.status} and cannot accept active executions`);
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

  const resolvedTarget = request.target || asset.domain || asset.url || 'unknown-target';

  // 6. Resolve Active Capability Definition & Adapter
  const capabilityDef = resolveActiveCapability(request.capabilityId);
  const adapter = resolveActiveAdapter(request.capabilityId);

  const executionId = `act-exec-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const nowStr = new Date().toISOString();

  // 7. Audit event: ACTIVE_EXECUTION_REQUESTED
  await recordAuditEvent({
    userId: user.uid,
    entityType: 'ACTIVE_EXECUTION',
    entityId: executionId,
    action: 'ACTIVE_EXECUTION_REQUESTED',
    newState: 'QUEUED',
    requestId,
    metadata: {
      caseId: caseItem.id,
      capabilityId: capabilityDef.capabilityId,
      programId: program.id,
      assetId: asset.id,
      target: resolvedTarget,
      tier: capabilityDef.authorizationTier,
    },
  });

  // 8. Server-Authoritative Active Policy Evaluation
  const policyResult = await evaluateActiveTestingPolicy(
    user,
    program.id,
    asset.id,
    capabilityDef,
    resolvedTarget,
    requestId
  );

  if (policyResult.decision === 'BLOCK') {
    const blockedResult: ActiveExecutionResult = {
      executionId,
      caseId: caseItem.id,
      programId: program.id,
      programName: program.name,
      assetId: asset.id,
      capabilityId: capabilityDef.capabilityId,
      capabilityName: capabilityDef.canonicalName,
      target: resolvedTarget,
      researcherId: user.uid,
      researcherName: user.name || user.email || 'Researcher',
      status: 'BLOCKED',
      authorizationTier: capabilityDef.authorizationTier,
      policyDecision: policyResult.decision,
      observations: [],
      requestsExecuted: 0,
      durationMs: Date.now() - startTime,
      createdAt: nowStr,
      completedAt: new Date().toISOString(),
      error: `Policy decision: BLOCK. ${policyResult.reason}`,
      requestId,
    };

    activeExecutionsStore.set(executionId, blockedResult);

    await recordAuditEvent({
      userId: user.uid,
      entityType: 'ACTIVE_EXECUTION',
      entityId: executionId,
      action: 'ACTIVE_EXECUTION_BLOCKED',
      newState: 'BLOCKED',
      requestId,
      metadata: {
        caseId: caseItem.id,
        capabilityId: capabilityDef.capabilityId,
        reason: blockedResult.error,
      },
    });

    return blockedResult;
  }

  // 9. Explicit Approval Workflow for APPROVAL_REQUIRED
  let consumedApprovalId: string | undefined = undefined;

  if (capabilityDef.approvalRequired || capabilityDef.authorizationTier === 'APPROVAL_REQUIRED') {
    if (!request.approvalId && !request.confirmApproval) {
      // Generate a new pending approval requirement and return REVIEW_REQUIRED
      const approvalReq = await createApprovalRequirement(
        user,
        program.id,
        asset.id,
        capabilityDef,
        resolvedTarget,
        requestId
      );

      const reviewRequiredResult: ActiveExecutionResult = {
        executionId,
        caseId: caseItem.id,
        programId: program.id,
        programName: program.name,
        assetId: asset.id,
        capabilityId: capabilityDef.capabilityId,
        capabilityName: capabilityDef.canonicalName,
        target: resolvedTarget,
        researcherId: user.uid,
        researcherName: user.name || user.email || 'Researcher',
        status: 'AUTHORIZED',
        authorizationTier: capabilityDef.authorizationTier,
        policyDecision: 'REVIEW_REQUIRED',
        approvalId: approvalReq.approvalId,
        observations: [],
        requestsExecuted: 0,
        durationMs: Date.now() - startTime,
        createdAt: nowStr,
        error: `EXPLICIT_APPROVAL_REQUIRED: Please confirm approval '${approvalReq.approvalId}' to execute`,
        requestId,
      };

      activeExecutionsStore.set(executionId, reviewRequiredResult);
      return reviewRequiredResult;
    }

    // Validate and single-use consume the confirmed approval
    const consumedApproval = await validateAndConsumeApproval(
      user,
      request.approvalId,
      capabilityDef,
      program.id,
      asset.id,
      resolvedTarget,
      requestId
    );
    consumedApprovalId = consumedApproval.approvalId;
  }

  // 10. Construct Budget and Execution Context
  const budget: RequestBudget = {
    maxTotalRequests: capabilityDef.maximumRequestBudget,
    maxRequestsPerSecond: 5,
    maxConcurrency: capabilityDef.maximumConcurrency,
    maxExecutionDurationMs: capabilityDef.timeout,
    maxResponseBytes: capabilityDef.maximumResponseSize,
    totalRequestsExecuted: 0,
    startedAt: Date.now(),
  };

  const budgetEngine = new BudgetEngine(budget);

  const context: ActiveExecutionContext = {
    executionId,
    researcherId: user.uid,
    researcherName: user.name || user.email || 'Researcher',
    user,
    programId: program.id,
    programName: program.name,
    caseId: caseItem.id,
    assetId: asset.id,
    target: resolvedTarget,
    capabilityId: capabilityDef.capabilityId,
    capabilityName: capabilityDef.canonicalName,
    authorizationTier: capabilityDef.authorizationTier,
    approvalId: consumedApprovalId,
    policyDecision: policyResult.decision,
    requestBudget: budget,
    concurrencyBudget: capabilityDef.maximumConcurrency,
    timeout: capabilityDef.timeout,
    startedAt: nowStr,
    cancellationState: {
      isCancelled: false,
    },
    requestId,
    parameters: request.parameters,
  };

  activeContextsStore.set(executionId, context);

  // 11. Instantiate Safe Controlled Client & Controlled Request Builder
  const baseClient = new SafeControlledHttpClient({
    executionId,
    user,
    programId: program.id,
    programName: program.name,
    assetId: asset.id,
    target: resolvedTarget,
    caseId: caseItem.id,
    capabilityId: capabilityDef.capabilityId,
    capabilityName: capabilityDef.canonicalName,
    authorizationLevel: capabilityDef.authorizationTier as any,
    policyDecision: policyResult.decision,
    requestId,
    timeoutMs: capabilityDef.timeout,
    rateLimitBudget: capabilityDef.maximumRequestBudget,
    parameters: request.parameters,
  });

  const requestBuilder = new ControlledRequestBuilder(context, baseClient, budgetEngine);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'ACTIVE_EXECUTION',
    entityId: executionId,
    action: 'ACTIVE_EXECUTION_STARTED',
    newState: 'RUNNING',
    requestId,
    metadata: {
      caseId: caseItem.id,
      capabilityId: capabilityDef.capabilityId,
      target: resolvedTarget,
      approvalId: consumedApprovalId,
      budget: {
        maxTotalRequests: budget.maxTotalRequests,
        timeout: budget.maxExecutionDurationMs,
      },
    },
  });

  // 12. Execute Active Adapter
  let rawObservations: ActiveExecutionObservation[] = [];
  try {
    rawObservations = await adapter.execute(context, requestBuilder);
  } catch (err: any) {
    const isCancelled = context.cancellationState.isCancelled;
    const finalStatus: ActiveExecutionStatus = isCancelled ? 'CANCELLED' : 'FAILED';

    const failedResult: ActiveExecutionResult = {
      executionId,
      caseId: caseItem.id,
      programId: program.id,
      programName: program.name,
      assetId: asset.id,
      capabilityId: capabilityDef.capabilityId,
      capabilityName: capabilityDef.canonicalName,
      target: resolvedTarget,
      researcherId: user.uid,
      researcherName: user.name || user.email || 'Researcher',
      status: finalStatus,
      authorizationTier: capabilityDef.authorizationTier,
      policyDecision: policyResult.decision,
      approvalId: consumedApprovalId,
      observations: [],
      requestsExecuted: requestBuilder.getExecutedCount(),
      durationMs: Date.now() - startTime,
      createdAt: nowStr,
      startedAt: nowStr,
      completedAt: new Date().toISOString(),
      error: err.message || 'Active execution error',
      requestId,
    };

    activeExecutionsStore.set(executionId, failedResult);

    await recordAuditEvent({
      userId: user.uid,
      entityType: 'ACTIVE_EXECUTION',
      entityId: executionId,
      action: isCancelled ? 'ACTIVE_EXECUTION_CANCELLED' : 'ACTIVE_EXECUTION_FAILED',
      newState: finalStatus,
      requestId,
      metadata: { error: failedResult.error },
    });

    return failedResult;
  }

  // 13. Sanitize Observations & Calculate Evidence Integrity Hash
  const sanitizedObservations: ActiveExecutionObservation[] = rawObservations.map((obs) => {
    const cleanData = redactSecrets(obs.sanitizedData);
    const evHash = computeEvidenceHash(cleanData, obs.capabilityId, obs.assetId);
    return {
      ...obs,
      sanitizedData: cleanData,
      evidenceHash: evHash,
    };
  });

  const primaryEvidenceHash = sanitizedObservations[0]?.evidenceHash;
  const evidenceId = `ev-act-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

  const completedResult: ActiveExecutionResult = {
    executionId,
    caseId: caseItem.id,
    programId: program.id,
    programName: program.name,
    assetId: asset.id,
    capabilityId: capabilityDef.capabilityId,
    capabilityName: capabilityDef.canonicalName,
    target: resolvedTarget,
    researcherId: user.uid,
    researcherName: user.name || user.email || 'Researcher',
    status: 'COMPLETED',
    authorizationTier: capabilityDef.authorizationTier,
    policyDecision: policyResult.decision,
    approvalId: consumedApprovalId,
    observations: sanitizedObservations,
    evidenceId,
    evidenceHash: primaryEvidenceHash,
    requestsExecuted: requestBuilder.getExecutedCount(),
    durationMs: Date.now() - startTime,
    createdAt: nowStr,
    startedAt: nowStr,
    completedAt: new Date().toISOString(),
    requestId,
  };

  activeExecutionsStore.set(executionId, completedResult);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'ACTIVE_EXECUTION',
    entityId: executionId,
    action: 'ACTIVE_EXECUTION_COMPLETED',
    newState: 'COMPLETED',
    requestId,
    metadata: {
      caseId: caseItem.id,
      capabilityId: capabilityDef.capabilityId,
      evidenceId,
      evidenceHash: primaryEvidenceHash,
      requestsExecuted: completedResult.requestsExecuted,
      observationsCount: sanitizedObservations.length,
    },
  });

  return completedResult;
}

/**
 * Deterministically cancel an active execution
 */
export async function cancelActiveExecution(
  executionId: string,
  user: AuthUser,
  reason: string = 'Cancelled by researcher',
  requestId: string = 'no-request-id'
): Promise<ActiveExecutionResult> {
  await verifyResearcherAccess(user);

  const exec = activeExecutionsStore.get(executionId);
  if (!exec) {
    throw new NotFoundError(`EXECUTION_NOT_FOUND: Active execution '${executionId}' not found`);
  }

  if (user.role !== 'ADMIN' && exec.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to cancel this active execution');
  }

  if (isTerminalActiveExecutionStatus(exec.status)) {
    throw new ConflictError(
      `CANNOT_CANCEL_TERMINAL_EXECUTION: Active execution is in terminal state '${exec.status}' and cannot be cancelled`
    );
  }

  // Update context cancellation state
  const ctx = activeContextsStore.get(executionId);
  if (ctx) {
    ctx.cancellationState.isCancelled = true;
    ctx.cancellationState.reason = reason;
  }

  const cancelledExec: ActiveExecutionResult = {
    ...exec,
    status: 'CANCELLED',
    completedAt: new Date().toISOString(),
    error: `Cancelled: ${reason}`,
  };

  activeExecutionsStore.set(executionId, cancelledExec);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'ACTIVE_EXECUTION',
    entityId: executionId,
    action: 'ACTIVE_EXECUTION_CANCELLED',
    previousState: exec.status,
    newState: 'CANCELLED',
    requestId,
    metadata: { reason },
  });

  return cancelledExec;
}

export async function getActiveExecutionById(
  executionId: string,
  user: AuthUser
): Promise<ActiveExecutionResult> {
  await verifyResearcherAccess(user);

  const exec = activeExecutionsStore.get(executionId);
  if (!exec) {
    throw new NotFoundError(`EXECUTION_NOT_FOUND: Active execution '${executionId}' not found`);
  }

  if (user.role !== 'ADMIN' && exec.researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to view this active execution');
  }

  return exec;
}

export async function listActiveExecutions(
  user: AuthUser,
  filters?: { caseId?: string; programId?: string; status?: ActiveExecutionStatus }
): Promise<ActiveExecutionResult[]> {
  await verifyResearcherAccess(user);

  const results: ActiveExecutionResult[] = [];
  for (const exec of activeExecutionsStore.values()) {
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

export function listAllActiveCapabilityDefinitions() {
  return Object.values(CANONICAL_ACTIVE_CAPABILITIES);
}
