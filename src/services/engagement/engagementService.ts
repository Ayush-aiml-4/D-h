/**
 * DEVILHUNT — Program-Agnostic Engagement Layer & Controlled Onboarding Workflow
 *
 * Implements:
 * 1. Clean distinction between Generic DevilHunt Policy and Program-Specific Policy.
 * 2. Strict controlled onboarding workflow:
 *    PROGRAM_DRAFT -> POLICY_IMPORTED -> SCOPE_VALIDATED -> RULES_VALIDATED -> RESEARCHER_REVIEW -> HUMAN_APPROVAL -> READY_FOR_PASSIVE_TESTING
 * 3. Never automatically transitions into active testing. Active testing requires explicit subsequent approval.
 */

import {
  EngagementOnboardingStage,
  EngagementProgramProfile,
  GenericDevilHuntPolicy,
  ProgramSpecificPolicy,
  EngagementAsset,
  EngagementExcludedAsset,
} from '../../types/engagement.ts';
import { BadRequestError, ForbiddenError } from '../../utils/errors.ts';
import { recordEngagementAudit } from './passiveResearchService.ts';

// Standard Invariant Generic DevilHunt Policy
export const DEFAULT_GENERIC_DEVILHUNT_POLICY: GenericDevilHuntPolicy = {
  version: '2.0.0-HARDENED',
  strictLocalFirst: true,
  zeroLiveTrafficDefault: true,
  failClosedScopeEnforced: true,
  symbolicCredentialsOnly: true,
  rawSecretStorageForbidden: true,
  humanApprovalMandatoryForActive: true,
  evidenceIntegrityMandatory: true,
  prohibitedGlobalAttacks: [
    'DENIAL_OF_SERVICE_OR_STRESS_TESTING',
    'SOCIAL_ENGINEERING_AND_PHISHING',
    'PHYSICAL_FACILITY_ACCESS',
    'UNAUTHORIZED_THIRD_PARTY_INFRASTRUCTURE_ATTACKS',
    'MASS_AUTOMATED_SCANNING_SPAM',
  ],
};

// Lifecycle transition sequence
export const ONBOARDING_WORKFLOW_SEQUENCE: EngagementOnboardingStage[] = [
  'PROGRAM_DRAFT',
  'POLICY_IMPORTED',
  'SCOPE_VALIDATED',
  'RULES_VALIDATED',
  'RESEARCHER_REVIEW',
  'HUMAN_APPROVAL',
  'READY_FOR_PASSIVE_TESTING',
];

// In-Memory Engagement Profiles Registry
const engagementProfilesRegistry = new Map<string, EngagementProgramProfile>();

/**
 * Initializes a new program draft in the controlled onboarding lifecycle.
 */
export function createProgramDraft(params: {
  id: string;
  name: string;
  handle: string;
  platform: EngagementProgramProfile['platform'];
  policyUrl: string;
  bountyStatus?: 'BOUNTY' | 'VDP';
  rewardCeiling?: string;
  contactChannel?: string;
  creator: string;
}): EngagementProgramProfile {
  if (!params.id || !params.name || !params.handle) {
    throw new BadRequestError('MISSING_PROGRAM_IDENTITY: id, name, and handle are required');
  }

  const cleanId = params.id.toLowerCase().trim();
  if (engagementProfilesRegistry.has(cleanId)) {
    throw new BadRequestError(`PROGRAM_ALREADY_EXISTS: Program '${cleanId}' is already registered`);
  }

  const profile: EngagementProgramProfile = {
    id: cleanId,
    name: params.name.trim(),
    handle: params.handle.trim(),
    platform: params.platform,
    policyUrl: params.policyUrl.trim(),
    bountyStatus: params.bountyStatus || 'BOUNTY',
    rewardCeiling: params.rewardCeiling || 'TBD',
    contactChannel: params.contactChannel || 'security@target.com',
    genericPolicy: { ...DEFAULT_GENERIC_DEVILHUNT_POLICY },
    programPolicy: {
      allowedVulnerabilityClasses: [],
      prohibitedTesting: [...DEFAULT_GENERIC_DEVILHUNT_POLICY.prohibitedGlobalAttacks],
      severityRestrictions: {
        maxSeverity: 'CRITICAL',
        inScopeOnly: true,
      },
      requestLimits: {
        numericLimitSpecified: false,
        rateLimitPerSecond: 5,
        maxConcurrentRequests: 2,
        totalSessionBudget: 50,
        burstTolerance: 5,
      },
      testingWindows: {
        continuousAllowed: true,
      },
      accountRequirements: {
        accountTiers: ['STANDARD_USER'],
        researcherAccountReferences: ['ACCOUNT_A'],
        credentialTypeAllowed: 'SYMBOLIC_REFERENCE_ONLY',
        forbiddenCredentialPatterns: ['*password*', '*jwt*', '*bearer*', '*cookie*'],
      },
      financialStateChangingRestrictions: {
        stateChangingOperationsForbidden: false,
        zeroValueOrdersOnly: true,
        immediateCancellationRequired: true,
        walletOrPaymentTestingForbidden: true,
      },
      requiredHumanApprovals: {
        requireApprovalForActiveTesting: true,
        requireApprovalForHighSeverity: true,
        requireApprovalForStateChanging: true,
        requireApprovalForReportSubmission: true,
      },
      disclosureRequirements: {
        platformCoordinationOnly: true,
        publicDisclosureForbidden: true,
        minimumSafeHarborStatement: 'Testing performed in accordance with program policy and DevilHunt fail-closed governance.',
      },
    },
    inScopeAssets: [],
    outOfScopeAssets: [],
    onboardingStage: 'PROGRAM_DRAFT',
    onboardingHistory: [
      {
        stage: 'PROGRAM_DRAFT',
        completedAt: new Date().toISOString(),
        completedBy: params.creator,
        notes: 'Initial program draft initialized',
      },
    ],
  };

  engagementProfilesRegistry.set(cleanId, profile);
  return profile;
}

/**
 * Imports program-specific policy and advances stage to POLICY_IMPORTED.
 */
export function importProgramPolicy(
  programId: string,
  policy: Partial<ProgramSpecificPolicy>,
  operator: string
): EngagementProgramProfile {
  const profile = getEngagementProfile(programId);
  if (!profile) {
    throw new BadRequestError(`PROGRAM_NOT_FOUND: ${programId}`);
  }

  if (profile.onboardingStage !== 'PROGRAM_DRAFT' && profile.onboardingStage !== 'POLICY_IMPORTED') {
    throw new BadRequestError(
      `INVALID_WORKFLOW_TRANSITION: Cannot import policy at stage '${profile.onboardingStage}'. Current stage must be PROGRAM_DRAFT.`
    );
  }

  // Update policy
  profile.programPolicy = {
    ...profile.programPolicy,
    ...policy,
    // Always preserve baseline non-negotiable prohibitions
    prohibitedTesting: Array.from(
      new Set([...(policy.prohibitedTesting || []), ...DEFAULT_GENERIC_DEVILHUNT_POLICY.prohibitedGlobalAttacks])
    ),
  };

  profile.onboardingStage = 'POLICY_IMPORTED';
  profile.onboardingHistory.push({
    stage: 'POLICY_IMPORTED',
    completedAt: new Date().toISOString(),
    completedBy: operator,
    notes: 'Program policy imported and merged with DevilHunt generic policy',
  });

  return profile;
}

/**
 * Imports scope assets and advances to SCOPE_VALIDATED.
 */
export function setProgramScopeAssets(
  programId: string,
  inScope: EngagementAsset[],
  outOfScope: EngagementExcludedAsset[],
  operator: string
): EngagementProgramProfile {
  const profile = getEngagementProfile(programId);
  if (!profile) {
    throw new BadRequestError(`PROGRAM_NOT_FOUND: ${programId}`);
  }

  if (profile.onboardingStage !== 'POLICY_IMPORTED' && profile.onboardingStage !== 'SCOPE_VALIDATED') {
    throw new BadRequestError(
      `INVALID_WORKFLOW_TRANSITION: Cannot validate scope at stage '${profile.onboardingStage}'. Current stage must be POLICY_IMPORTED.`
    );
  }

  if (inScope.length === 0) {
    throw new BadRequestError('SCOPE_VALIDATION_FAILED: Program must have at least one valid in-scope asset');
  }

  profile.inScopeAssets = inScope;
  profile.outOfScopeAssets = outOfScope;
  profile.onboardingStage = 'SCOPE_VALIDATED';
  profile.onboardingHistory.push({
    stage: 'SCOPE_VALIDATED',
    completedAt: new Date().toISOString(),
    completedBy: operator,
    notes: `Scope validated: ${inScope.length} in-scope, ${outOfScope.length} out-of-scope assets`,
  });

  return profile;
}

/**
 * Validates program rules and advances to RULES_VALIDATED.
 */
export function validateProgramRules(programId: string, operator: string): EngagementProgramProfile {
  const profile = getEngagementProfile(programId);
  if (!profile) {
    throw new BadRequestError(`PROGRAM_NOT_FOUND: ${programId}`);
  }

  if (profile.onboardingStage !== 'SCOPE_VALIDATED' && profile.onboardingStage !== 'RULES_VALIDATED') {
    throw new BadRequestError(
      `INVALID_WORKFLOW_TRANSITION: Current stage is '${profile.onboardingStage}', expected SCOPE_VALIDATED.`
    );
  }

  // Ensure policy has allowed vulnerability classes defined
  if (profile.programPolicy.allowedVulnerabilityClasses.length === 0) {
    throw new BadRequestError('RULES_VALIDATION_FAILED: Allowed vulnerability classes must be specified');
  }

  profile.onboardingStage = 'RULES_VALIDATED';
  profile.onboardingHistory.push({
    stage: 'RULES_VALIDATED',
    completedAt: new Date().toISOString(),
    completedBy: operator,
    notes: 'Program rules and vulnerability eligibility verified against DevilHunt invariants',
  });

  return profile;
}

/**
 * Records researcher review and advances to RESEARCHER_REVIEW.
 */
export function submitResearcherReview(
  programId: string,
  operator: string,
  reviewNotes: string
): EngagementProgramProfile {
  const profile = getEngagementProfile(programId);
  if (!profile) {
    throw new BadRequestError(`PROGRAM_NOT_FOUND: ${programId}`);
  }

  if (profile.onboardingStage !== 'RULES_VALIDATED') {
    throw new BadRequestError(
      `INVALID_WORKFLOW_TRANSITION: Current stage is '${profile.onboardingStage}', expected RULES_VALIDATED.`
    );
  }

  if (!reviewNotes || reviewNotes.trim().length < 10) {
    throw new BadRequestError('REVIEW_NOTES_REQUIRED: Detailed researcher review notes are mandatory before approval');
  }

  profile.onboardingStage = 'RESEARCHER_REVIEW';
  profile.onboardingHistory.push({
    stage: 'RESEARCHER_REVIEW',
    completedAt: new Date().toISOString(),
    completedBy: operator,
    notes: reviewNotes.trim(),
  });

  return profile;
}

/**
 * Executes human approval gate and advances to READY_FOR_PASSIVE_TESTING.
 * Enforces that no stage automatically transitions to active testing.
 */
export function grantHumanOnboardingApproval(
  programId: string,
  approverRole: 'SECURITY_LEAD' | 'ENGAGEMENT_ADMIN' | 'HUMAN_OPERATOR',
  approverToken: string,
  approvalConfirmation: boolean
): EngagementProgramProfile {
  const profile = getEngagementProfile(programId);
  if (!profile) {
    throw new BadRequestError(`PROGRAM_NOT_FOUND: ${programId}`);
  }

  if (profile.onboardingStage !== 'RESEARCHER_REVIEW') {
    throw new BadRequestError(
      `APPROVAL_GATE_BLOCKED: Cannot approve program at stage '${profile.onboardingStage}'. Must complete RESEARCHER_REVIEW first.`
    );
  }

  if (!approvalConfirmation) {
    throw new ForbiddenError('APPROVAL_DENIED: Explicit confirmation checkbox must be checked');
  }

  if (!approverToken || approverToken.trim().length < 6) {
    throw new ForbiddenError('APPROVAL_DENIED: Valid human operator approval token is required');
  }

  // First record the HUMAN_APPROVAL stage
  profile.onboardingHistory.push({
    stage: 'HUMAN_APPROVAL',
    completedAt: new Date().toISOString(),
    completedBy: `${approverRole} (${approverToken.slice(0, 4)}...)`,
    notes: 'Human operator validated all policies, scope limits, and symbolic credentials',
  });

  // Advance strictly to READY_FOR_PASSIVE_TESTING (NEVER directly to ACTIVE)
  profile.onboardingStage = 'READY_FOR_PASSIVE_TESTING';
  profile.onboardingHistory.push({
    stage: 'READY_FOR_PASSIVE_TESTING',
    completedAt: new Date().toISOString(),
    completedBy: approverRole,
    notes: 'Program is now certified for passive-first research. Active testing remains locked.',
  });

  recordEngagementAudit({
    programId: profile.id,
    targetAsset: profile.policyUrl,
    researchMode: 'PASSIVE',
    policyEvaluationResult: 'ALLOW',
    humanApprovalReference: approverToken,
    executionId: `onboard-${profile.id}`,
    proxyCorrelationId: 'none',
    evidenceHash: 'none',
    action: 'PROGRAM_ONBOARDING_APPROVED_FOR_PASSIVE_TESTING',
    details: { approverRole, stage: 'READY_FOR_PASSIVE_TESTING' },
  });

  return profile;
}

/**
 * Authorizes active testing under separate, explicit human-in-the-loop approval.
 */
export function grantActiveTestingAuthorization(
  programId: string,
  approverToken: string,
  reason: string
): EngagementProgramProfile {
  const profile = getEngagementProfile(programId);
  if (!profile) {
    throw new BadRequestError(`PROGRAM_NOT_FOUND: ${programId}`);
  }

  if (profile.onboardingStage !== 'READY_FOR_PASSIVE_TESTING') {
    throw new ForbiddenError(
      `ACTIVE_TESTING_GATED: Program must be in 'READY_FOR_PASSIVE_TESTING' state before active authorization. Current: ${profile.onboardingStage}`
    );
  }

  if (!approverToken || approverToken.trim().length < 6) {
    throw new ForbiddenError('ACTIVE_TESTING_GATED: Valid human operator token required to authorize active capabilities');
  }

  profile.onboardingStage = 'ACTIVE_TESTING_AUTHORIZED';
  profile.onboardingHistory.push({
    stage: 'ACTIVE_TESTING_AUTHORIZED',
    completedAt: new Date().toISOString(),
    completedBy: `Operator (${approverToken.slice(0, 4)}...)`,
    notes: `Active testing authorized: ${reason}`,
  });

  recordEngagementAudit({
    programId: profile.id,
    targetAsset: profile.policyUrl,
    researchMode: 'ACTIVE',
    policyEvaluationResult: 'ALLOW',
    humanApprovalReference: approverToken,
    executionId: `active-auth-${Date.now()}`,
    proxyCorrelationId: 'none',
    evidenceHash: 'none',
    action: 'ACTIVE_TESTING_EXPLICITLY_AUTHORIZED',
    details: { reason },
  });

  return profile;
}

export function getEngagementProfile(idOrHandle: string): EngagementProgramProfile | null {
  if (!idOrHandle) return null;
  return engagementProfilesRegistry.get(idOrHandle.toLowerCase().trim()) || null;
}

export function listEngagementProfiles(): EngagementProgramProfile[] {
  return Array.from(engagementProfilesRegistry.values());
}

export function registerEngagementProfile(profile: EngagementProgramProfile): void {
  engagementProfilesRegistry.set(profile.id.toLowerCase().trim(), profile);
  if (profile.handle) {
    engagementProfilesRegistry.set(profile.handle.toLowerCase().trim(), profile);
  }
}
