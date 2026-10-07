import { AuthUser } from '../../../middleware/auth.ts';
import { ActiveCapabilityDefinition, ActiveTestingTier } from './activeTestingTypes.ts';
import { evaluatePolicy } from '../../policyEngine.ts';
import { db } from '../../../db/index.ts';
import { programs, assets } from '../../../db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { ForbiddenError, NotFoundError } from '../../../utils/errors.ts';

export interface ActivePolicyEvaluationResult {
  decision: 'ALLOW' | 'REVIEW_REQUIRED' | 'BLOCK';
  reason: string;
  tier: ActiveTestingTier;
  approvalRequired: boolean;
  programId: string;
  assetId: string;
  target: string;
  capabilityId: string;
  matchedRules: string[];
}

export async function evaluateActiveTestingPolicy(
  user: AuthUser,
  programId: string,
  assetId: string,
  capability: ActiveCapabilityDefinition,
  target?: string,
  requestId: string = 'no-request-id'
): Promise<ActivePolicyEvaluationResult> {
  const matchedRules: string[] = [];

  // 1. Verify user identity
  if (!user || !user.uid) {
    return {
      decision: 'BLOCK',
      reason: 'UNAUTHENTICATED: Valid researcher identity is required',
      tier: capability.authorizationTier,
      approvalRequired: capability.approvalRequired,
      programId,
      assetId,
      target: target || 'unknown',
      capabilityId: capability.capabilityId,
      matchedRules: ['AUTH_AUTHENTICATION_REQUIRED'],
    };
  }

  // 2. Reject restricted capabilities immediately
  if (capability.authorizationTier === 'RESTRICTED' || !capability.enabled) {
    return {
      decision: 'BLOCK',
      reason: 'CAPABILITY_RESTRICTED: Destructive testing, unrestricted fuzzing, and credential guessing are strictly prohibited by DevilHunt policy',
      tier: 'RESTRICTED',
      approvalRequired: false,
      programId,
      assetId,
      target: target || 'unknown',
      capabilityId: capability.capabilityId,
      matchedRules: ['POLICY_RESTRICTED_CAPABILITY_PROHIBITED'],
    };
  }

  // 3. Verify program
  const programRows = await db.select().from(programs).where(eq(programs.id, programId));
  if (programRows.length === 0) {
    throw new NotFoundError(`PROGRAM_NOT_FOUND: Program '${programId}' not found`);
  }
  const program = programRows[0];
  if (program.status !== 'Active' && program.status !== 'ACTIVE') {
    return {
      decision: 'BLOCK',
      reason: `PROGRAM_INACTIVE: Program '${program.name}' is inactive and does not permit security testing`,
      tier: capability.authorizationTier,
      approvalRequired: capability.approvalRequired,
      programId,
      assetId,
      target: target || 'unknown',
      capabilityId: capability.capabilityId,
      matchedRules: ['POLICY_PROGRAM_INACTIVE_BLOCK'],
    };
  }
  matchedRules.push('PROGRAM_ACTIVE_CONFIRMED');

  // 4. Verify asset
  const assetRows = await db
    .select()
    .from(assets)
    .where(and(eq(assets.id, assetId), eq(assets.programId, program.id)));
  if (assetRows.length === 0) {
    throw new NotFoundError(`ASSET_NOT_FOUND: Asset '${assetId}' not found in program '${program.name}'`);
  }
  const asset = assetRows[0];
  const resolvedTarget = target || asset.domain || asset.url || 'unknown';

  // 5. Evaluate target against program scope
  const basePolicyResult = await evaluatePolicy(
    user,
    {
      programId: program.id,
      target: resolvedTarget,
      operation: capability.canonicalName,
    },
    requestId
  );

  if (basePolicyResult.decision === 'BLOCK') {
    return {
      decision: 'BLOCK',
      reason: basePolicyResult.reason || 'Target is out of scope for the selected program',
      tier: capability.authorizationTier,
      approvalRequired: capability.approvalRequired,
      programId,
      assetId,
      target: resolvedTarget,
      capabilityId: capability.capabilityId,
      matchedRules: [...matchedRules, 'SCOPE_OUT_OF_BOUNDS_BLOCK'],
    };
  }

  // 6. Check program rules / active testing permissions
  const programDescription = (program.description || '').toLowerCase();
  if (
    programDescription.includes('no active') ||
    programDescription.includes('passive only') ||
    programDescription.includes('prohibit automated') ||
    programDescription.includes('no automated')
  ) {
    return {
      decision: 'BLOCK',
      reason: `PROGRAM_RESTRICTION: Program policy explicitly restricts active security testing on this asset`,
      tier: capability.authorizationTier,
      approvalRequired: capability.approvalRequired,
      programId,
      assetId,
      target: resolvedTarget,
      capabilityId: capability.capabilityId,
      matchedRules: [...matchedRules, 'PROGRAM_POLICY_ACTIVE_PROHIBITED'],
    };
  }
  matchedRules.push('PROGRAM_POLICY_ACTIVE_PERMITTED');

  // 7. Tier evaluation
  if (capability.authorizationTier === 'APPROVAL_REQUIRED' || capability.approvalRequired) {
    matchedRules.push('EXPLICIT_APPROVAL_MANDATE');
    return {
      decision: 'REVIEW_REQUIRED',
      reason: `EXPLICIT_APPROVAL_REQUIRED: Capability '${capability.canonicalName}' requires explicit researcher approval before execution`,
      tier: capability.authorizationTier,
      approvalRequired: true,
      programId,
      assetId,
      target: resolvedTarget,
      capabilityId: capability.capabilityId,
      matchedRules,
    };
  }

  matchedRules.push('LOW_RISK_ACTIVE_PERMITTED');
  return {
    decision: 'ALLOW',
    reason: `Operation permitted under ${capability.authorizationTier} policy`,
    tier: capability.authorizationTier,
    approvalRequired: false,
    programId,
    assetId,
    target: resolvedTarget,
    capabilityId: capability.capabilityId,
    matchedRules,
  };
}
