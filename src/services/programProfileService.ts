import { AuthUser } from '../middleware/auth.ts';
import {
  ProgramProfile,
  ScopeResolutionResult,
  FindingEligibilityEvaluationResult,
  DryRunExecutionParams,
  DryRunExecutionResult,
  InScopeAsset,
  OutOfScopeAsset,
} from '../types/programProfile.ts';
import { MEESHO_PROGRAM_PROFILE } from '../profiles/meesho.profile.ts';
import { parseTarget, TargetParseResult } from './policyEngine.ts';
import { recordAuditEvent } from './auditService.ts';
import { logger } from '../utils/logger.ts';

// In-Memory Profile Registry
const programProfileRegistry: Map<string, ProgramProfile> = new Map();

// Initialize registry with built-in profiles
export function initializeProgramProfiles(): void {
  registerProgramProfile(MEESHO_PROGRAM_PROFILE);
}

// Auto-register default profiles upon module load
initializeProgramProfiles();

export function registerProgramProfile(profile: ProgramProfile): void {
  programProfileRegistry.set(profile.id.toLowerCase(), profile);
  if (profile.handle) {
    programProfileRegistry.set(profile.handle.toLowerCase(), profile);
  }
}

export function getProgramProfile(idOrHandle: string): ProgramProfile | null {
  if (!idOrHandle || typeof idOrHandle !== 'string') return null;
  return programProfileRegistry.get(idOrHandle.toLowerCase().trim()) || null;
}

export function listProgramProfiles(): ProgramProfile[] {
  const unique = new Map<string, ProgramProfile>();
  for (const profile of programProfileRegistry.values()) {
    unique.set(profile.id, profile);
  }
  return Array.from(unique.values());
}

/**
 * Checks if a parsed target or raw target string matches a pattern.
 * Strictly enforces boundary checks:
 * - Prevents prefix lookalikes (evil-valmo.in)
 * - Prevents suffix lookalikes (www.valmo.in.attacker.com)
 */
export function matchesTargetPattern(
  rawTarget: string,
  parsedTarget: TargetParseResult,
  pattern: string,
  assetType: string
): boolean {
  const normalizedRaw = rawTarget.trim().toLowerCase();
  const normalizedPattern = pattern.trim().toLowerCase();

  // 1. Mobile App iOS Numeric App Store ID (e.g. 1457958492)
  if (assetType === 'MOBILE_APP_IOS' || /^\d+$/.test(normalizedPattern)) {
    if (normalizedRaw === normalizedPattern) return true;
    if (normalizedRaw === `id${normalizedPattern}`) return true;
    if (normalizedRaw.includes(`id${normalizedPattern}`) || normalizedRaw.includes(`/app/id${normalizedPattern}`)) {
      return true;
    }
    // Strict exact equality or standard App Store URI match
    const segments = normalizedRaw.split(/[\/\:\?\#\.\-]/);
    return segments.includes(normalizedPattern);
  }

  // 2. Mobile App Android Package Matching (e.g. com.meesho.supply, com.valmo.valmo)
  if (
    assetType === 'MOBILE_APP_ANDROID' ||
    normalizedPattern.startsWith('com.')
  ) {
    if (normalizedRaw === normalizedPattern) return true;
    if (normalizedRaw.startsWith(normalizedPattern + '/') || normalizedRaw.startsWith(normalizedPattern + ':')) return true;
    const parts = normalizedRaw.split(/[\/\:\?\#]/);
    return parts.includes(normalizedPattern);
  }

  // 3. Other Non-Hostname Assets (e.g. "Rider App", "Other Asset")
  if (assetType === 'OTHER') {
    return normalizedRaw === normalizedPattern;
  }

  // If parsed target is not valid and not a mobile identifier, fail closed
  if (!parsedTarget.isValid) {
    return false;
  }

  const hostname = parsedTarget.hostname.toLowerCase();

  // 4. Wildcard Pattern: "*.example.com"
  if (normalizedPattern.startsWith('*.')) {
    const baseDomain = normalizedPattern.slice(2);
    if (hostname === baseDomain) return true;
    if (hostname.endsWith('.' + baseDomain)) return true;
    return false;
  }

  // 5. Exact Domain / Subdomain / API_ENDPOINT Pattern
  if (
    assetType === 'DOMAIN' ||
    assetType === 'SUBDOMAIN' ||
    assetType === 'API_ENDPOINT'
  ) {
    const cleanPattern = normalizedPattern.replace(/^https?:\/\//, '').split('/')[0];
    return hostname === cleanPattern;
  }

  // 6. URL or Sub-path Pattern
  if (assetType === 'URL') {
    if (parsedTarget.fullUrl) {
      const fullUrlLower = parsedTarget.fullUrl.toLowerCase();
      if (fullUrlLower === normalizedPattern) return true;
      if (fullUrlLower.startsWith(normalizedPattern.endsWith('/') ? normalizedPattern : normalizedPattern + '/')) return true;
    }
    if (normalizedRaw.startsWith(normalizedPattern)) return true;
    return false;
  }

  // Default exact hostname match
  return hostname === normalizedPattern;
}

/**
 * Resolves a given target against a Program Profile.
 * Evaluates in-scope assets, out-of-scope assets, and operational constraints.
 * Fails closed if no active in-scope asset is matched.
 * Respects that broad wildcards are explicitly ineligible and must NOT grant ALLOW.
 */
export function resolveTargetScope(
  profileId: string,
  target: string
): ScopeResolutionResult {
  const evaluatedAt = new Date().toISOString();

  if (!profileId || typeof profileId !== 'string') {
    return {
      decision: 'DENY',
      target: target || 'unknown',
      programId: 'unknown',
      isBountyEligible: false,
      operationalWarnings: [],
      reason: 'Program profile ID is missing or invalid',
      evaluatedAt,
    };
  }

  const profile = getProgramProfile(profileId);
  if (!profile) {
    return {
      decision: 'DENY',
      target: target || 'unknown',
      programId: profileId,
      isBountyEligible: false,
      operationalWarnings: [],
      reason: `Program profile '${profileId}' not found`,
      evaluatedAt,
    };
  }

  if (profile.status !== 'ACTIVE') {
    return {
      decision: 'DENY',
      target,
      programId: profile.id,
      isBountyEligible: false,
      operationalWarnings: [],
      reason: `Program profile '${profile.name}' is inactive (Status: ${profile.status})`,
      evaluatedAt,
    };
  }

  if (!target || typeof target !== 'string' || target.trim().length === 0) {
    return {
      decision: 'DENY',
      target: target || '',
      programId: profile.id,
      isBountyEligible: false,
      operationalWarnings: [],
      reason: 'Target is empty or invalid',
      evaluatedAt,
    };
  }

  const trimmedTarget = target.trim();
  const parsedTarget = parseTarget(trimmedTarget);

  const isMobileTarget =
    /^com\.[a-zA-Z0-9_\.]+$/.test(trimmedTarget) ||
    /^\d{5,15}$/.test(trimmedTarget) ||
    trimmedTarget === 'Rider App' ||
    trimmedTarget === 'Other Asset';

  if (!parsedTarget.isValid && !isMobileTarget) {
    return {
      decision: 'DENY',
      target: trimmedTarget,
      programId: profile.id,
      isBountyEligible: false,
      operationalWarnings: [],
      reason: 'Malformed target or invalid hostname format',
      evaluatedAt,
    };
  }

  // 1. Check Explicit In-Scope Exact Assets First
  let matchedInScope: InScopeAsset | null = null;
  for (const inScopeAsset of profile.inScopeAssets) {
    if (matchesTargetPattern(trimmedTarget, parsedTarget, inScopeAsset.targetPattern, inScopeAsset.assetType)) {
      matchedInScope = inScopeAsset;
      break;
    }
  }

  // 2. Check Explicit Out-of-Scope Named Assets (e.g. warehouse.meesho.com, console.valmo.in)
  for (const oosAsset of profile.outOfScopeAssets) {
    if (!oosAsset.isWildcardIneligible) {
      if (matchesTargetPattern(trimmedTarget, parsedTarget, oosAsset.targetPattern, oosAsset.assetType)) {
        return {
          decision: 'DENY',
          target: trimmedTarget,
          programId: profile.id,
          matchedAsset: oosAsset,
          isBountyEligible: false,
          operationalWarnings: [],
          reason: `Target explicitly matches out-of-scope asset '${oosAsset.targetPattern}': ${oosAsset.reason}`,
          evaluatedAt,
        };
      }
    }
  }

  // 3. If matched an explicit in-scope asset and not an explicit named out-of-scope asset, ALLOW
  if (matchedInScope) {
    const warnings: string[] = [];
    for (const constraint of profile.operationalConstraints) {
      if (
        constraint.targetPattern === '*' ||
        matchesTargetPattern(trimmedTarget, parsedTarget, constraint.targetPattern, 'DOMAIN')
      ) {
        warnings.push(constraint.mandatoryWarning);
      }
    }

    return {
      decision: 'ALLOW',
      target: trimmedTarget,
      programId: profile.id,
      matchedAsset: matchedInScope,
      isBountyEligible: matchedInScope.bountyEligible,
      maxSeverity: matchedInScope.maxSeverity,
      operationalWarnings: warnings,
      reason: `Target is authorized under explicit in-scope asset '${matchedInScope.targetPattern}' (Max Severity: ${matchedInScope.maxSeverity})`,
      evaluatedAt,
    };
  }

  // 4. Check Explicitly Ineligible Wildcards (e.g. *.meesho.com, *.valmo.in)
  for (const oosAsset of profile.outOfScopeAssets) {
    if (oosAsset.isWildcardIneligible) {
      if (matchesTargetPattern(trimmedTarget, parsedTarget, oosAsset.targetPattern, oosAsset.assetType)) {
        return {
          decision: 'DENY',
          target: trimmedTarget,
          programId: profile.id,
          matchedAsset: oosAsset,
          isBountyEligible: false,
          operationalWarnings: [],
          reason: `Target matches ineligible wildcard scope '${oosAsset.targetPattern}'. The program explicitly marks wildcard entries as ineligible; only specifically listed in-scope assets are acceptable.`,
          evaluatedAt,
        };
      }
    }
  }

  // 5. Default: Fail-Closed for any unlisted/unknown asset
  return {
    decision: 'DENY',
    target: trimmedTarget,
    programId: profile.id,
    isBountyEligible: false,
    operationalWarnings: [],
    reason: 'Target is unlisted / not present in explicitly authorized in-scope assets (fail-closed)',
    evaluatedAt,
  };
}

/**
 * Evaluates finding eligibility independently of target scope.
 * Evaluates whether a vulnerability category qualifies for bounty reward,
 * is an impact-dependent finding, or is a standard HackerOne / program exclusion.
 */
export function evaluateFindingEligibility(
  profileId: string,
  vulnerabilityCategory: string,
  findingDetails?: { title?: string; cwe?: string; description?: string }
): FindingEligibilityEvaluationResult {
  const evaluatedAt = new Date().toISOString();
  const profile = getProgramProfile(profileId);

  if (!profile) {
    return {
      programId: profileId,
      vulnerabilityTitle: findingDetails?.title || vulnerabilityCategory,
      category: vulnerabilityCategory,
      classification: 'HACKERONE_CORE_INELIGIBLE',
      isEligible: false,
      disqualificationReason: `Program profile '${profileId}' not found`,
      evaluatedAt,
    };
  }

  const searchTerms = [
    vulnerabilityCategory.toLowerCase(),
    (findingDetails?.title || '').toLowerCase(),
    (findingDetails?.cwe || '').toLowerCase(),
  ].filter(Boolean);

  // 1. Check Core Ineligible Rules First
  for (const rule of profile.findingEligibilityRules) {
    if (!rule.eligible) {
      const ruleCategoryLower = rule.vulnerabilityCategory.toLowerCase();
      const ruleCweLower = (rule.cwe || '').toLowerCase();

      const isMatch = searchTerms.some(
        (term) =>
          term.includes(ruleCategoryLower) ||
          ruleCategoryLower.includes(term) ||
          (ruleCweLower && term.includes(ruleCweLower))
      );

      if (isMatch) {
        return {
          programId: profile.id,
          vulnerabilityTitle: findingDetails?.title || vulnerabilityCategory,
          category: vulnerabilityCategory,
          classification: rule.classification,
          isEligible: false,
          matchedRule: rule,
          disqualificationReason: rule.reason,
          impactRequirement: rule.impactRequirement,
          evaluatedAt,
        };
      }
    }
  }

  // 2. Check Explicit Qualifying & Impact-Dependent Rules
  for (const rule of profile.findingEligibilityRules) {
    if (rule.eligible) {
      const ruleCategoryLower = rule.vulnerabilityCategory.toLowerCase();
      const ruleCweLower = (rule.cwe || '').toLowerCase();

      const isMatch = searchTerms.some(
        (term) =>
          term.includes(ruleCategoryLower) ||
          ruleCategoryLower.includes(term) ||
          (ruleCweLower && term.includes(ruleCweLower))
      );

      if (isMatch) {
        return {
          programId: profile.id,
          vulnerabilityTitle: findingDetails?.title || vulnerabilityCategory,
          category: vulnerabilityCategory,
          classification: rule.classification,
          isEligible: true,
          matchedRule: rule,
          impactRequirement: rule.impactRequirement,
          evaluatedAt,
        };
      }
    }
  }

  // Default: Qualifying if not matching an explicit ineligible rule
  return {
    programId: profile.id,
    vulnerabilityTitle: findingDetails?.title || vulnerabilityCategory,
    category: vulnerabilityCategory,
    classification: 'QUALIFYING',
    isEligible: true,
    evaluatedAt,
  };
}

/**
 * Full Server-Side Program Profile Policy Evaluator.
 * Verifies researcher identity, evaluates scope, prohibited operations, hazardous operations, and logs audit events.
 */
export async function evaluateProgramProfilePolicy(
  user: AuthUser | null,
  request: {
    programId: string;
    target: string;
    operation?: string;
  },
  requestId?: string
): Promise<{
  decision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  programId: string;
  target: string;
  isBountyEligible: boolean;
  maxSeverity?: string;
  operationalWarnings: string[];
  reason: string;
}> {
  const { programId, target, operation } = request;

  // 1. Unauthenticated Check
  if (!user || !user.uid) {
    logger.warn('PROGRAM_PROFILE_UNAUTHENTICATED', { programId, target, requestId });
    return {
      decision: 'BLOCK',
      programId: programId || 'unknown',
      target: target || 'unknown',
      isBountyEligible: false,
      operationalWarnings: [],
      reason: 'Authentication required for program profile policy evaluation',
    };
  }

  // 2. Validate Profile Existence
  const profile = getProgramProfile(programId);
  if (!profile) {
    const reason = `Program profile '${programId}' does not exist`;
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId || 'unknown',
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, reason },
    });
    return {
      decision: 'BLOCK',
      programId: programId || 'unknown',
      target: target || 'unknown',
      isBountyEligible: false,
      operationalWarnings: [],
      reason,
    };
  }

  // 3. Strictly Prohibited Operations Check (DoS, Phishing, Social Engineering, Data Destruction)
  if (operation) {
    const opUpper = operation.toUpperCase().trim();
    const prohibitedList = profile.prohibitedOperations || [];
    if (prohibitedList.includes(opUpper)) {
      const reason = `Operation '${operation}' is explicitly prohibited by ${profile.name} policy`;
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'POLICY',
        entityId: profile.id,
        action: 'POLICY_EVALUATE_BLOCK',
        success: false,
        requestId,
        metadata: { target, operation, reason },
      });
      return {
        decision: 'BLOCK',
        programId: profile.id,
        target,
        isBountyEligible: false,
        operationalWarnings: [],
        reason,
      };
    }
  }

  // 4. Hazardous Operations Check (Requires Explicit Authorization / REVIEW_REQUIRED)
  if (operation) {
    const opUpper = operation.toUpperCase().trim();
    const hazardousList = profile.hazardousOperationsRequireAuthorization || [];
    if (hazardousList.includes(opUpper)) {
      const reason = `Hazardous testing operation '${operation}' requires explicit authorization/review under ${profile.name} policy to prevent availability impact`;
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'POLICY',
        entityId: profile.id,
        action: 'POLICY_EVALUATE_REVIEW_REQUIRED',
        success: true,
        requestId,
        metadata: { target, operation, reason },
      });
      return {
        decision: 'REVIEW_REQUIRED',
        programId: profile.id,
        target,
        isBountyEligible: false,
        operationalWarnings: [],
        reason,
      };
    }
  }

  // 5. Resolve Scope
  const scopeResolution = resolveTargetScope(profile.id, target);
  if (scopeResolution.decision === 'DENY') {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: profile.id,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, reason: scopeResolution.reason },
    });
    return {
      decision: 'BLOCK',
      programId: profile.id,
      target,
      isBountyEligible: false,
      operationalWarnings: [],
      reason: scopeResolution.reason,
    };
  }

  // 6. Sensitive Operations Check (REVIEW_REQUIRED)
  if (operation) {
    const opUpper = operation.toUpperCase().trim();
    const sensitiveList = profile.sensitiveOperations || [];
    if (sensitiveList.includes(opUpper)) {
      const reason = `Operation '${operation}' requires manual authorization review under ${profile.name} rules`;
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'POLICY',
        entityId: profile.id,
        action: 'POLICY_EVALUATE_REVIEW_REQUIRED',
        success: true,
        requestId,
        metadata: { target, operation, reason },
      });
      return {
        decision: 'REVIEW_REQUIRED',
        programId: profile.id,
        target,
        isBountyEligible: scopeResolution.isBountyEligible,
        maxSeverity: scopeResolution.maxSeverity,
        operationalWarnings: scopeResolution.operationalWarnings,
        reason,
      };
    }
  }

  // 7. Authorized ALLOW
  await recordAuditEvent({
    userId: user.uid,
    entityType: 'POLICY',
    entityId: profile.id,
    action: 'POLICY_EVALUATE_ALLOW',
    success: true,
    requestId,
    metadata: {
      target,
      operation: operation || 'GENERAL_TESTING',
      matchedPattern: scopeResolution.matchedAsset?.targetPattern,
      warningsCount: scopeResolution.operationalWarnings.length,
    },
  });

  return {
    decision: 'ALLOW',
    programId: profile.id,
    target,
    isBountyEligible: scopeResolution.isBountyEligible,
    maxSeverity: scopeResolution.maxSeverity,
    operationalWarnings: scopeResolution.operationalWarnings,
    reason: scopeResolution.reason,
  };
}

/**
 * Dry-Run Capability Execution Evaluator.
 * Simulates policy authorization and research capability execution with ZERO network traffic.
 */
export async function executeDryRunCapability(
  user: AuthUser,
  params: DryRunExecutionParams,
  requestId?: string
): Promise<DryRunExecutionResult> {
  const evaluatedAt = new Date().toISOString();
  const { programId, target, capabilityId, operation } = params;

  const policyResult = await evaluateProgramProfilePolicy(
    user,
    {
      programId,
      target,
      operation,
    },
    requestId
  );

  const scopeResolution = resolveTargetScope(programId, target);

  const simulatedSteps = [
    `[DRY-RUN] Initialized capability '${capabilityId}' on target '${target}'`,
    `[DRY-RUN] Evaluated program profile authorization: ${policyResult.decision}`,
    `[DRY-RUN] Scope resolution matched: ${scopeResolution.matchedAsset?.targetPattern || 'NONE'} (Bounty Eligible: ${scopeResolution.isBountyEligible})`,
    `[DRY-RUN] Zero network packets sent across container interface (Network isolated)`,
    `[DRY-RUN] Simulated execution completed successfully with decision: ${policyResult.decision}`,
  ];

  await recordAuditEvent({
    userId: user.uid,
    entityType: 'POLICY',
    entityId: programId,
    action: 'PROGRAM_PROFILE_DRY_RUN_EVALUATED',
    success: policyResult.decision !== 'BLOCK',
    requestId,
    metadata: {
      capabilityId,
      target,
      decision: policyResult.decision,
      dryRun: true,
    },
  });

  return {
    dryRun: true,
    target,
    capabilityId,
    programId,
    scopeResolution,
    policyDecision: policyResult.decision,
    simulatedNetworkTraffic: false,
    reproductionStepsSimulated: simulatedSteps,
    warnings: scopeResolution.operationalWarnings,
    auditLogged: true,
    evaluatedAt,
  };
}
