import crypto from 'crypto';
import { db } from '../../db/index.ts';
import { findings, hunts, assets, programs, users } from '../../db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { AuthUser } from '../../middleware/auth.ts';
import { evaluatePolicy } from '../policyEngine.ts';
import { updateFindingStatus, normalizeFindingState } from '../findingService.ts';
import { recordAuditEvent } from '../auditService.ts';
import { sanitizeAndRedact } from '../capabilities/utils.ts';
import { getControlledValidator } from './index.ts';
import {
  ValidationRequest,
  ValidationResult,
  ValidationEvidence,
  ValidationContext,
  ValidationResultStatus,
} from './types.ts';
import {
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  BadRequestError,
} from '../../utils/errors.ts';
import { Asset, Finding } from '../../types.ts';

export async function validateFinding(
  user: AuthUser,
  request: ValidationRequest,
  requestId: string
): Promise<ValidationResult> {
  // 1. Authenticate user identity
  if (!user || !user.uid) {
    throw new UnauthorizedError('UNAUTHENTICATED: User authentication is required');
  }

  // 2. Verify researcher registration
  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new ForbiddenError(
      'UNAUTHORIZED_RESEARCHER: Researcher identity not registered in authorization directory'
    );
  }

  const { findingId, validationId, observationOverride } = request;
  if (!findingId || typeof findingId !== 'string') {
    throw new BadRequestError('INVALID_INPUT: findingId is required');
  }

  // 3. Retrieve finding & verify existence
  const rawFindings = await db.select().from(findings).where(eq(findings.id, findingId));
  if (rawFindings.length === 0) {
    throw new NotFoundError(`FINDING_NOT_FOUND: Finding '${findingId}' does not exist`);
  }
  const f = rawFindings[0];

  // 4. Verify researcher ownership or ADMIN role
  const parentHunt = await db.select().from(hunts).where(eq(hunts.id, f.huntId));
  if (parentHunt.length === 0) {
    throw new NotFoundError(`HUNT_NOT_FOUND: Parent hunt '${f.huntId}' not found`);
  }

  if (user.role !== 'ADMIN' && parentHunt[0].researcherId !== user.uid) {
    throw new ForbiddenError('FORBIDDEN: You do not have permission to validate this finding');
  }

  // 5. Resolve associated asset & program
  const assetRows = await db.select().from(assets).where(eq(assets.id, f.assetId));
  if (assetRows.length === 0) {
    throw new NotFoundError(`ASSET_NOT_FOUND: Associated asset '${f.assetId}' not found`);
  }
  const rawAsset = assetRows[0];
  const targetDomain = rawAsset.domain;

  const resolvedAsset: Asset = {
    id: rawAsset.id,
    programId: rawAsset.programId,
    domain: rawAsset.domain,
    hostname: rawAsset.domain,
    type: (rawAsset as any).type || 'SUBDOMAIN',
    status: rawAsset.status,
  };

  // 6. Resolve validator
  const targetValidatorKey = validationId || f.category || f.title;
  const validator = getControlledValidator(targetValidatorKey);

  if (!validator) {
    throw new NotFoundError(
      `VALIDATOR_NOT_FOUND: Controlled validator for '${targetValidatorKey}' is not registered`
    );
  }

  // 7. Evaluate policy Engine
  const policyResult = await evaluatePolicy(
    user,
    {
      programId: f.programId,
      target: targetDomain,
      operation: validator.validationType,
    },
    requestId
  );

  // Deterministic Correlation Key
  const normObs = JSON.stringify(observationOverride || f.evidence || {});
  const correlationKey = crypto
    .createHash('md5')
    .update(`${f.id}:${validator.validationId}:${normObs}`)
    .digest('hex');

  const nowIso = new Date().toISOString();

  // If BLOCK or REVIEW_REQUIRED, stop execution & return policy decision
  if (policyResult.decision !== 'ALLOW') {
    const blockedStatus: ValidationResultStatus =
      policyResult.decision === 'BLOCK' ? 'BLOCKED' : 'REVIEW_REQUIRED';

    await recordAuditEvent({
      userId: user.uid,
      entityType: 'VALIDATION',
      entityId: findingId,
      action: `VALIDATION_${policyResult.decision}`,
      requestId,
      metadata: `Validation execution halted due to policy decision: ${policyResult.decision}`,
    });

    const emptyEvidence: ValidationEvidence = {
      evidenceId: `ev-val-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      validationId: validator.validationId,
      findingId: f.id,
      assetId: resolvedAsset.id,
      capabilityId: validator.supportedCapability,
      observedAt: nowIso,
      result: blockedStatus,
      confidence: 0,
      sanitizedObservation: { policyDecision: policyResult.decision, reason: policyResult.reason },
      evidenceHash: crypto.createHash('sha256').update(nowIso).digest('hex'),
      requestId,
    };

    return {
      validationId: validator.validationId,
      validationType: validator.validationType,
      findingId: f.id,
      assetId: resolvedAsset.id,
      capabilityId: validator.supportedCapability,
      safetyLevel: validator.safetyLevel,
      executed: false,
      result: blockedStatus,
      confidence: 0,
      policyDecision: policyResult.decision,
      reason: policyResult.reason || 'Policy execution blocked or requires review',
      summary: `Validation execution stopped: ${policyResult.decision}`,
      evidence: emptyEvidence,
      correlationKey,
      validatedAt: nowIso,
      requestId,
    };
  }

  // 8. Execute controlled validator
  const fullFinding: Finding = {
    id: f.id,
    huntId: f.huntId,
    programName: f.programId,
    title: f.title,
    category: f.category,
    severity: f.severity as any,
    confidence: f.confidence,
    target: targetDomain,
    status: f.status as any,
    whatWeFound: f.description,
    whyItMatters: '',
    affectedTarget: targetDomain,
    evidence: {
      requestMethod: 'GET',
      requestUrl: `https://${targetDomain}`,
      requestHeaders: {},
      responseStatus: 200,
      responseHeaders: {},
      responseBodySnippet: f.evidence || '',
      timestamp: nowIso,
      validationStatus: f.status,
      proofHash: '',
    },
    policyCheck: { inScope: true, testPermitted: true, validationCompleted: true, noRestrictedAction: true },
    recommendedFix: '',
    createdAt: f.discoveredAt || nowIso,
  };

  const validationContext: ValidationContext = {
    finding: fullFinding,
    asset: resolvedAsset,
    programId: f.programId,
    user,
    requestId,
    observationData: observationOverride,
  };

  const rawResult = await validator.validate(validationContext);

  // 9. Sanitize and redact evidence
  const { sanitized, redactedSecrets } = sanitizeAndRedact(rawResult.sanitizedObservation);

  const proofString = JSON.stringify(sanitized);
  const evidenceHash = crypto.createHash('sha256').update(proofString).digest('hex');

  const evidence: ValidationEvidence = {
    evidenceId: `ev-val-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    validationId: validator.validationId,
    findingId: f.id,
    assetId: resolvedAsset.id,
    capabilityId: validator.supportedCapability,
    observedAt: nowIso,
    result: rawResult.result,
    confidence: rawResult.confidence,
    sanitizedObservation: sanitized,
    evidenceHash,
    requestId,
  };

  // 10. Progress finding status through state machine if VALIDATED
  let updatedFindingStatus = f.status;
  if (rawResult.result === 'VALIDATED') {
    const currentCanonical = normalizeFindingState(f.status);
    if (currentCanonical === 'POTENTIAL') {
      await updateFindingStatus(f.id, 'Under review', user, requestId);
    }
    const updatedFinding = await updateFindingStatus(f.id, 'Validated', user, requestId);
    if (updatedFinding) {
      updatedFindingStatus = updatedFinding.status;
    }
  }

  // 11. Record audit event
  await recordAuditEvent({
    userId: user.uid,
    entityType: 'VALIDATION',
    entityId: findingId,
    action: `VALIDATION_COMPLETED`,
    requestId,
    previousState: f.status,
    newState: updatedFindingStatus,
    metadata: `Validation completed with status ${rawResult.result} (confidence: ${rawResult.confidence}%)`,
  });

  return {
    validationId: validator.validationId,
    validationType: validator.validationType,
    findingId: f.id,
    assetId: resolvedAsset.id,
    capabilityId: validator.supportedCapability,
    safetyLevel: validator.safetyLevel,
    executed: true,
    result: rawResult.result,
    confidence: rawResult.confidence,
    policyDecision: 'ALLOW',
    summary: rawResult.summary,
    evidence,
    correlationKey,
    validatedAt: nowIso,
    requestId,
  };
}
