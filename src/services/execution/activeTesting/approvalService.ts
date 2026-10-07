import crypto from 'crypto';
import { AuthUser } from '../../../middleware/auth.ts';
import {
  ActiveApprovalRequirement,
  ActiveCapabilityDefinition,
  ActiveExecutionRequest,
} from './activeTestingTypes.ts';
import { recordAuditEvent } from '../../auditService.ts';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  BadRequestError,
} from '../../../utils/errors.ts';

const APPROVAL_EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes validity

const activeApprovalsStore: Map<string, ActiveApprovalRequirement> = new Map();

export function computeExecutionFingerprint(
  researcherId: string,
  programId: string,
  assetId: string,
  capabilityId: string,
  target: string
): string {
  return crypto
    .createHash('sha256')
    .update(`${researcherId}:${programId}:${assetId}:${capabilityId}:${target.toLowerCase()}`)
    .digest('hex');
}

export function clearApprovalsStore(): void {
  activeApprovalsStore.clear();
}

/**
 * Creates a server-side, time-bounded approval requirement for an APPROVAL_REQUIRED capability.
 */
export async function createApprovalRequirement(
  user: AuthUser,
  programId: string,
  assetId: string,
  capability: ActiveCapabilityDefinition,
  target: string,
  requestId: string = 'no-request-id'
): Promise<ActiveApprovalRequirement> {
  if (!user || !user.uid) {
    throw new ForbiddenError('UNAUTHENTICATED: Valid researcher authentication required');
  }

  const now = Date.now();
  const approvalId = `appr-${now}-${crypto.randomBytes(6).toString('hex')}`;
  const fingerprint = computeExecutionFingerprint(
    user.uid,
    programId,
    assetId,
    capability.capabilityId,
    target
  );

  const approvalReq: ActiveApprovalRequirement = {
    approvalId,
    researcherId: user.uid,
    researcherName: user.name || user.email || 'Researcher',
    programId,
    assetId,
    capabilityId: capability.capabilityId,
    target,
    authorizationTier: capability.authorizationTier,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + APPROVAL_EXPIRATION_MS).toISOString(),
    status: 'PENDING',
    executionFingerprint: fingerprint,
  };

  activeApprovalsStore.set(approvalId, approvalReq);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'ACTIVE_EXECUTION',
    entityId: approvalId,
    action: 'ACTIVE_EXECUTION_APPROVAL_REQUIRED',
    newState: 'PENDING',
    requestId,
    metadata: {
      approvalId,
      capabilityId: capability.capabilityId,
      programId,
      assetId,
      target,
      tier: capability.authorizationTier,
      expiresAt: approvalReq.expiresAt,
    },
  });

  return approvalReq;
}

/**
 * Explicitly confirms a pending approval requirement by the authenticated researcher.
 */
export async function confirmApprovalRequirement(
  user: AuthUser,
  approvalId: string,
  requestId: string = 'no-request-id'
): Promise<ActiveApprovalRequirement> {
  if (!user || !user.uid) {
    throw new ForbiddenError('UNAUTHENTICATED: Valid researcher authentication required');
  }
  if (!approvalId || typeof approvalId !== 'string') {
    throw new BadRequestError('APPROVAL_ID_REQUIRED: Approval ID is required');
  }

  const approval = activeApprovalsStore.get(approvalId);
  if (!approval) {
    throw new NotFoundError(`APPROVAL_NOT_FOUND: Approval requirement '${approvalId}' not found`);
  }

  // 1. Enforce researcher ownership (cannot confirm someone else's approval)
  if (approval.researcherId !== user.uid && user.role !== 'ADMIN') {
    throw new ForbiddenError('FORBIDDEN_RESEARCHER_MISMATCH: Cannot confirm approval for another researcher');
  }

  // 2. Enforce expiration
  if (Date.now() > new Date(approval.expiresAt).getTime()) {
    approval.status = 'EXPIRED';
    throw new ConflictError('APPROVAL_EXPIRED: The approval window has expired. Please re-request approval.');
  }

  // 3. Enforce valid transition from PENDING
  if (approval.status !== 'PENDING') {
    throw new ConflictError(
      `INVALID_APPROVAL_STATE: Approval is in status '${approval.status}' and cannot be confirmed`
    );
  }

  approval.status = 'CONFIRMED';
  approval.confirmedAt = new Date().toISOString();
  activeApprovalsStore.set(approvalId, approval);

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'ACTIVE_EXECUTION',
    entityId: approvalId,
    action: 'ACTIVE_EXECUTION_APPROVED',
    previousState: 'PENDING',
    newState: 'CONFIRMED',
    requestId,
    metadata: {
      approvalId,
      capabilityId: approval.capabilityId,
      target: approval.target,
    },
  });

  return approval;
}

/**
 * Validates and single-use consumes an approval before execution starts.
 */
export async function validateAndConsumeApproval(
  user: AuthUser,
  approvalId: string | undefined,
  capability: ActiveCapabilityDefinition,
  programId: string,
  assetId: string,
  target: string,
  requestId: string = 'no-request-id'
): Promise<ActiveApprovalRequirement> {
  if (!capability.approvalRequired && capability.authorizationTier !== 'APPROVAL_REQUIRED') {
    // Capability does not require explicit approval
    const syntheticId = `auto-appr-${Date.now()}`;
    return {
      approvalId: syntheticId,
      researcherId: user.uid,
      researcherName: user.name || user.email || 'Researcher',
      programId,
      assetId,
      capabilityId: capability.capabilityId,
      target,
      authorizationTier: capability.authorizationTier,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + APPROVAL_EXPIRATION_MS).toISOString(),
      status: 'CONSUMED',
      executionFingerprint: 'auto-authorized',
      confirmedAt: new Date().toISOString(),
      consumedAt: new Date().toISOString(),
    };
  }

  if (!approvalId) {
    throw new ForbiddenError(
      `APPROVAL_REQUIRED: Capability '${capability.canonicalName}' requires explicit researcher approval before execution`
    );
  }

  const approval = activeApprovalsStore.get(approvalId);
  if (!approval) {
    throw new NotFoundError(
      `APPROVAL_NOT_FOUND: Approval requirement '${approvalId}' does not exist or was rejected`
    );
  }

  // Enforce caller match
  if (approval.researcherId !== user.uid && user.role !== 'ADMIN') {
    throw new ForbiddenError(
      'FORBIDDEN_RESEARCHER_MISMATCH: Approval belongs to a different researcher identity'
    );
  }

  // Enforce capability match
  if (approval.capabilityId.toLowerCase() !== capability.capabilityId.toLowerCase()) {
    throw new ForbiddenError(
      `APPROVAL_CAPABILITY_MISMATCH: Approval '${approvalId}' was generated for capability '${approval.capabilityId}', not '${capability.capabilityId}'`
    );
  }

  // Enforce program and asset match
  if (approval.programId !== programId || approval.assetId !== assetId) {
    throw new ForbiddenError(
      'APPROVAL_SCOPE_MISMATCH: Approval parameters do not match requested program or asset target'
    );
  }

  // Enforce expiration
  if (Date.now() > new Date(approval.expiresAt).getTime()) {
    approval.status = 'EXPIRED';
    throw new ConflictError('APPROVAL_EXPIRED: The approval window has expired. Re-request authorization.');
  }

  // Enforce CONFIRMED status (must not be PENDING, CONSUMED, EXPIRED, or REVOKED)
  if (approval.status !== 'CONFIRMED') {
    throw new ForbiddenError(
      `APPROVAL_NOT_CONFIRMED: Approval requirement status is '${approval.status}'. Must be CONFIRMED before execution.`
    );
  }

  // Single-use consumption
  approval.status = 'CONSUMED';
  approval.consumedAt = new Date().toISOString();
  activeApprovalsStore.set(approvalId, approval);

  return approval;
}

export function getApprovalById(approvalId: string): ActiveApprovalRequirement | undefined {
  return activeApprovalsStore.get(approvalId);
}
