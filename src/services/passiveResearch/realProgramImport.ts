/**
 * Mission #0018 — Real Program Import
 * Never fabricate authorization, scope, credentials, or proxy config.
 * Operator must supply all required fields; incomplete imports FAIL CLOSED.
 */

import {
  RealProgramProfile,
  AuthorizationStatus,
  ProgramPlatform,
  registerProgramProfile,
  advanceOnboarding,
  getProgramProfile,
  getOnboardingState,
} from './programProfileModel.ts';
import { registerScopeProfile } from '../passiveIntelligence/scopeGuard.ts';
import { appendTimelineEvent } from '../passiveIntelligence/researchTimeline.ts';

export interface ProgramImportInput {
  programId: string;
  programName: string;
  platform: ProgramPlatform;
  authorizationStatus: AuthorizationStatus;
  authorizationReference: string | null;
  policyVersion: string;
  scopeVersion: string;
  allowedAssets: string[];
  excludedAssets: string[];
  allowedMethods?: Array<'GET' | 'HEAD' | 'OPTIONS'>;
  prohibitedActions?: string[];
  vulnerabilityClasses?: string[];
  requestBudget: number;
  burstLimit?: number;
  testingWindow?: { start: string; end: string } | null;
  researcherAccountReferences: string[];
  proxyRequirement: boolean;
  proxyEndpoint?: string | null;
  evidencePolicy?: string;
  reportingPolicy?: string;
}

export interface ImportResult {
  ok: boolean;
  profile?: RealProgramProfile;
  errors: string[];
  warnings: string[];
}

const REQUIRED_STRING = (v: unknown, name: string, errors: string[]) => {
  if (typeof v !== 'string' || !v.trim()) errors.push(`MISSING_OR_EMPTY:${name}`);
};

/**
 * Import an operator-supplied program. Does not invent missing fields.
 */
export function importRealProgram(input: ProgramImportInput): ImportResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  REQUIRED_STRING(input.programId, 'programId', errors);
  REQUIRED_STRING(input.programName, 'programName', errors);
  REQUIRED_STRING(input.platform, 'platform', errors);
  REQUIRED_STRING(input.policyVersion, 'policyVersion', errors);
  REQUIRED_STRING(input.scopeVersion, 'scopeVersion', errors);

  if (!input.authorizationStatus) {
    errors.push('MISSING:authorizationStatus');
  }

  // Never invent AUTHORIZED — operator must set it
  if (input.authorizationStatus === 'AUTHORIZED') {
    if (!input.authorizationReference || !String(input.authorizationReference).trim()) {
      errors.push('AUTHORIZED_REQUIRES_authorizationReference');
    }
  }

  if (!Array.isArray(input.allowedAssets) || input.allowedAssets.length === 0) {
    errors.push('MISSING_OR_EMPTY:allowedAssets');
  } else {
    for (const a of input.allowedAssets) {
      if (typeof a !== 'string' || !a.trim() || /\s/.test(a) || a.includes('://')) {
        errors.push(`INVALID_ASSET_HOST:${a}`);
      }
      // Reject obvious fabrications in automated contexts is N/A — operator supplied
    }
  }

  if (!Array.isArray(input.excludedAssets)) {
    errors.push('MISSING:excludedAssets (may be empty array)');
  }

  if (typeof input.requestBudget !== 'number' || input.requestBudget < 1 || input.requestBudget > 500) {
    errors.push('INVALID:requestBudget (must be 1–500)');
  }

  if (!Array.isArray(input.researcherAccountReferences) || input.researcherAccountReferences.length === 0) {
    errors.push('MISSING_OR_EMPTY:researcherAccountReferences');
  } else {
    for (const r of input.researcherAccountReferences) {
      if (/eyJ[A-Za-z0-9_-]+\.|password\s*=|Bearer\s+[A-Za-z0-9\-._]{20,}/i.test(r)) {
        errors.push('RAW_CREDENTIAL_IN_RESEARCHER_REFERENCE');
      }
    }
  }

  if (input.proxyRequirement) {
    if (!input.proxyEndpoint || !String(input.proxyEndpoint).trim()) {
      errors.push('PROXY_REQUIRED_BUT_proxyEndpoint_MISSING');
    }
  }

  // Program may *list* additional methods in policy text; DevilHunt still only *executes* passive methods.
  // Do not reject the import solely because the program documents POST/etc. — those stay LOCKED at execution.
  const methods = input.allowedMethods || ['GET', 'HEAD', 'OPTIONS'];
  const passiveOnly = methods.filter((m) => ['GET', 'HEAD', 'OPTIONS'].includes(m));
  if (passiveOnly.length === 0) {
    errors.push('NO_PASSIVE_METHODS_IN_PROGRAM_POLICY');
  }
  // Store full list for compatibility reporting; execution layer ignores non-passive
  const methodsToStore = methods.length ? methods : (['GET', 'HEAD', 'OPTIONS'] as Array<'GET' | 'HEAD' | 'OPTIONS'>);

  if (errors.length) {
    return { ok: false, errors, warnings };
  }

  const now = new Date().toISOString();
  const profile: RealProgramProfile = {
    programId: input.programId.trim(),
    programName: input.programName.trim(),
    platform: input.platform,
    authorizationStatus: input.authorizationStatus,
    authorizationReference: input.authorizationReference,
    policyVersion: input.policyVersion.trim(),
    scopeVersion: input.scopeVersion.trim(),
    allowedAssets: input.allowedAssets.map((a) => a.trim().toLowerCase()),
    excludedAssets: (input.excludedAssets || []).map((a) => a.trim().toLowerCase()),
    allowedMethods: (passiveOnly.length ? passiveOnly : ['GET', 'HEAD', 'OPTIONS']) as Array<'GET' | 'HEAD' | 'OPTIONS'>,
    prohibitedActions: input.prohibitedActions || [
      'DOS',
      'BRUTE_FORCE',
      'CREDENTIAL_ATTACK',
      'STATE_CHANGE',
      'ACTIVE_EXPLOITATION',
    ],
    vulnerabilityClasses: input.vulnerabilityClasses || [],
    requestBudget: input.requestBudget,
    burstLimit: input.burstLimit ?? 2,
    testingWindow: input.testingWindow ?? null,
    researcherAccountReferences: input.researcherAccountReferences,
    proxyRequirement: input.proxyRequirement,
    proxyEndpoint: input.proxyEndpoint ?? null,
    evidencePolicy: input.evidencePolicy || 'SHA256_REQUIRED_REDACT_SECRETS',
    reportingPolicy: input.reportingPolicy || 'HUMAN_REVIEW_MANDATORY',
    createdAt: now,
    updatedAt: now,
  };

  if (profile.authorizationStatus !== 'AUTHORIZED') {
    warnings.push(`authorizationStatus is ${profile.authorizationStatus} — passive research will remain blocked`);
  }
  const locked = methods.filter((m) => !['GET', 'HEAD', 'OPTIONS'].includes(m));
  if (locked.length) {
    warnings.push(`ACTIVE_OR_STATE_CHANGING_METHOD_AVAILABLE_BUT_LOCKED:${locked.join(',')}`);
  }

  registerProgramProfile(profile);
  registerScopeProfile({
    programId: profile.programId,
    inScopeHosts: profile.allowedAssets,
    outOfScopeHosts: profile.excludedAssets,
  });

  // Advance through import stages (not past human approval)
  try {
    advanceOnboarding(profile.programId, 'POLICY_IMPORTED');
    advanceOnboarding(profile.programId, 'SCOPE_VALIDATED');
    advanceOnboarding(profile.programId, 'RULES_VALIDATED');
    advanceOnboarding(profile.programId, 'RESEARCHER_REVIEW');
  } catch (e) {
    warnings.push(`onboarding_partial:${e instanceof Error ? e.message : String(e)}`);
  }

  appendTimelineEvent({
    type: 'PROGRAM_CREATED',
    programId: profile.programId,
    researchCaseId: 'import',
    details: {
      programName: profile.programName,
      platform: profile.platform,
      authorizationStatus: profile.authorizationStatus,
      assetCount: profile.allowedAssets.length,
    },
  });

  return { ok: true, profile, errors: [], warnings };
}

export function getImportedProgram(programId: string): RealProgramProfile | null {
  return getProgramProfile(programId);
}

export function getImportOnboardingStage(programId: string): string | null {
  return getOnboardingState(programId)?.stage ?? null;
}
