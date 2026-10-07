import { db } from '../db/index.ts';
import { assets, users } from '../db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';
import { CAPABILITIES } from '../constants/capabilities.ts';
import {
  Asset,
  CapabilityDefinition,
  CapabilityEvaluationParams,
  CapabilityEvaluationResult,
  CapabilityImplementationStatus,
} from '../types.ts';
import { evaluatePolicy } from './policyEngine.ts';
import { getCapabilityAnalyzer } from './capabilities/index.ts';
import { PassiveAnalysisResult } from './capabilities/types.ts';
import {
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  BadRequestError,
} from '../utils/errors.ts';

export function listCapabilities(filter?: {
  category?: string;
  status?: CapabilityImplementationStatus | string;
}): CapabilityDefinition[] {
  let results = [...CAPABILITIES];

  if (filter?.category) {
    const catLower = filter.category.toLowerCase().trim();
    results = results.filter((c) => c.category.toLowerCase() === catLower);
  }

  if (filter?.status) {
    const statusUpper = filter.status.toUpperCase().trim();
    results = results.filter((c) => c.implementationStatus === statusUpper);
  }

  return results;
}

export function getCapability(id: string): CapabilityDefinition | null {
  if (!id || typeof id !== 'string') return null;
  const targetId = id.trim().toLowerCase();
  return (
    CAPABILITIES.find(
      (c) =>
        c.id.toLowerCase() === targetId ||
        c.name.toLowerCase() === targetId ||
        c.name.toLowerCase().includes(targetId)
    ) || null
  );
}

/**
 * Capability evaluation preview.
 * Authenticates user, verifies asset access, resolves capability context,
 * and calls server-side evaluatePolicy().
 * 
 * MUST NEVER:
 * - execute network scanning
 * - launch vulnerability exploits
 * - mutate target resources
 */
export async function evaluateResearchCapability(
  user: AuthUser,
  params: CapabilityEvaluationParams
): Promise<CapabilityEvaluationResult> {
  const { programId, target, capabilityId, assetId, requestId } = params;

  // 1. Authenticate user identity
  if (!user || !user.uid) {
    throw new UnauthorizedError('UNAUTHENTICATED: User authentication is required');
  }

  // 2. Verify researcher registration in directory
  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new ForbiddenError(
      'UNAUTHORIZED_RESEARCHER: Researcher identity not registered in authorization directory'
    );
  }

  // 3. Resolve capability definition
  const capability = getCapability(capabilityId);
  if (!capability) {
    throw new NotFoundError(
      `CAPABILITY_NOT_FOUND: Capability '${capabilityId}' is not registered in authoritative capability index`
    );
  }

  // 4. Verify program ID
  if (!programId || typeof programId !== 'string') {
    throw new BadRequestError('PROGRAM_NOT_FOUND: Program ID is required');
  }

  // 5. Verify asset access if assetId is provided
  if (assetId) {
    const assetRows = await db
      .select()
      .from(assets)
      .where(and(eq(assets.id, assetId), eq(assets.programId, programId)));

    if (assetRows.length === 0) {
      throw new NotFoundError(
        `ASSET_NOT_FOUND: Specified asset '${assetId}' does not exist or does not belong to program '${programId}'`
      );
    }
  }

  // 6. Evaluate authorization policy via server-side policy engine
  const policyResult = await evaluatePolicy(
    user,
    {
      programId,
      target,
      operation: capability.name || capability.id,
    },
    requestId
  );

  return {
    isAuthorizationEvaluationOnly: true,
    decision: policyResult.decision,
    programId,
    target,
    capability,
    reason: policyResult.reason || 'Capability policy preview complete',
    evaluatedAt: new Date().toISOString(),
  };
}

/**
 * Passive Research Capability Execution Service.
 * Evaluates authorization policy first.
 * If ALLOW, executes registered passive research capability analyzer with fixture/controlled input.
 * If BLOCK or REVIEW_REQUIRED, returns policy decision without executing research adapter.
 */
export async function analyzeResearchCapabilityService(
  user: AuthUser,
  params: {
    programId: string;
    target: string;
    capabilityId?: string;
    capability?: string;
    assetId?: string;
    observationData?: Record<string, any>;
    requestId?: string;
  }
): Promise<PassiveAnalysisResult> {
  const { programId, target, assetId, observationData, requestId } = params;
  const capId = params.capabilityId || params.capability || 'cap-http-header-analysis';

  // 1. Authenticate user identity
  if (!user || !user.uid) {
    throw new UnauthorizedError('UNAUTHENTICATED: User authentication is required');
  }

  // 2. Verify researcher registration in directory
  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new ForbiddenError(
      'UNAUTHORIZED_RESEARCHER: Researcher identity not registered in authorization directory'
    );
  }

  // 3. Resolve capability analyzer
  const analyzer = getCapabilityAnalyzer(capId);
  const capabilityDef: CapabilityDefinition = getCapability(capId) || {
    id: analyzer?.capabilityId || capId,
    name: analyzer?.name || capId,
    category: 'CONFIGURATION_AUDIT',
    implementationStatus: 'SUPPORTED',
    automationLevel: 'AUTOMATED',
    description: analyzer?.description || 'Passive research capability',
    authenticationRequirement: 'OPTIONAL',
    policyRequirement: 'POLICY_CHECK_REQUIRED',
    humanValidationRequirement: 'RECOMMENDED',
    evidenceSupport: 'JSON_EVIDENCE',
    reproductionSupport: 'CURL_COMMAND',
    reportingSupport: 'AUTOMATED_REPORT',
  };

  if (!analyzer) {
    throw new NotFoundError(
      `CAPABILITY_NOT_FOUND: Capability analyzer '${capId}' is not registered`
    );
  }

  // 4. Verify program ID
  if (!programId || typeof programId !== 'string') {
    throw new BadRequestError('PROGRAM_NOT_FOUND: Program ID is required');
  }

  // 5. Verify asset access if assetId provided or resolve asset
  let resolvedAsset: Asset;
  if (assetId) {
    const assetRows = await db
      .select()
      .from(assets)
      .where(and(eq(assets.id, assetId), eq(assets.programId, programId)));

    if (assetRows.length === 0) {
      throw new NotFoundError(
        `ASSET_NOT_FOUND: Specified asset '${assetId}' does not exist or does not belong to program '${programId}'`
      );
    }
    const a = assetRows[0];
    resolvedAsset = {
      id: a.id,
      programId: a.programId,
      domain: a.domain,
      hostname: a.domain,
      type: (a as any).type || 'SUBDOMAIN',
      status: a.status,
    };
  } else {
    const assetRows = await db
      .select()
      .from(assets)
      .where(and(eq(assets.domain, target), eq(assets.programId, programId)));

    if (assetRows.length > 0) {
      const a = assetRows[0];
      resolvedAsset = {
        id: a.id,
        programId: a.programId,
        domain: a.domain,
        hostname: a.domain,
        type: (a as any).type || 'SUBDOMAIN',
        status: a.status,
      };
    } else {
      resolvedAsset = {
        id: `asset-${target}`,
        programId,
        domain: target,
        hostname: target,
        type: 'SUBDOMAIN',
        status: 'IN_SCOPE',
      };
    }
  }

  // 6. Evaluate policy engine
  const policyResult = await evaluatePolicy(
    user,
    {
      programId,
      target,
      operation: capabilityDef.name || capabilityDef.id,
    },
    requestId
  );

  if (policyResult.decision !== 'ALLOW') {
    return {
      capabilityId: analyzer.capabilityId,
      capabilityName: analyzer.name,
      assetId: resolvedAsset.id,
      observedAt: new Date().toISOString(),
      observations: [],
      findingCandidates: [],
      evidence: [],
      executed: false,
      policyDecision: policyResult.decision,
      reason: policyResult.reason || 'Execution blocked or review required by authorization policy',
    };
  }

  // 7. Execute controlled passive analyzer
  const analysisResult = await analyzer.analyze({
    asset: resolvedAsset,
    capability: capabilityDef,
    observationData: observationData || { target },
    programId,
    user,
    requestId,
  });

  return {
    ...analysisResult,
    policyDecision: 'ALLOW',
  };
}

