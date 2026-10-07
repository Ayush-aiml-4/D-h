/**
 * Mission #0016 — Production-ready authorized program profile model.
 * Never assume authorization. Fail closed.
 */

export type AuthorizationStatus =
  | 'AUTHORIZED'
  | 'NOT_AUTHORIZED'
  | 'EXPIRED'
  | 'SUSPENDED'
  | 'UNKNOWN';

export type ProgramPlatform =
  | 'HackerOne'
  | 'Bugcrowd'
  | 'Intigriti'
  | 'YesWeHack'
  | 'Synack'
  | 'Direct'
  | 'Self-Hosted';

export interface RealProgramProfile {
  programId: string;
  programName: string;
  platform: ProgramPlatform;
  authorizationStatus: AuthorizationStatus;
  authorizationReference: string | null;
  policyVersion: string;
  scopeVersion: string;
  allowedAssets: string[];
  excludedAssets: string[];
  allowedMethods: Array<'GET' | 'HEAD' | 'OPTIONS'>;
  prohibitedActions: string[];
  vulnerabilityClasses: string[];
  requestBudget: number;
  burstLimit: number;
  testingWindow: { start: string; end: string } | null;
  researcherAccountReferences: string[];
  proxyRequirement: boolean;
  proxyEndpoint: string | null;
  evidencePolicy: string;
  reportingPolicy: string;
  createdAt: string;
  updatedAt: string;
}

export type OnboardingStage =
  | 'PROGRAM_DRAFT'
  | 'POLICY_IMPORTED'
  | 'SCOPE_VALIDATED'
  | 'RULES_VALIDATED'
  | 'RESEARCHER_REVIEW'
  | 'HUMAN_APPROVAL'
  | 'READY_FOR_PASSIVE_TESTING'
  | 'PASSIVE_SESSION_ACTIVE'
  | 'PASSIVE_SESSION_COMPLETED';

const STAGE_ORDER: OnboardingStage[] = [
  'PROGRAM_DRAFT',
  'POLICY_IMPORTED',
  'SCOPE_VALIDATED',
  'RULES_VALIDATED',
  'RESEARCHER_REVIEW',
  'HUMAN_APPROVAL',
  'READY_FOR_PASSIVE_TESTING',
  'PASSIVE_SESSION_ACTIVE',
  'PASSIVE_SESSION_COMPLETED',
];

export interface ProgramOnboardingState {
  programId: string;
  stage: OnboardingStage;
  humanApprovalReference: string | null;
  humanApprovalGrantedAt: string | null;
  blockers: string[];
  updatedAt: string;
}

const profiles = new Map<string, RealProgramProfile>();
const onboarding = new Map<string, ProgramOnboardingState>();

export function clearProgramRegistry(): void {
  profiles.clear();
  onboarding.clear();
}

export function registerProgramProfile(profile: RealProgramProfile): void {
  profiles.set(profile.programId, { ...profile, allowedAssets: [...profile.allowedAssets], excludedAssets: [...profile.excludedAssets] });
  if (!onboarding.has(profile.programId)) {
    onboarding.set(profile.programId, {
      programId: profile.programId,
      stage: 'PROGRAM_DRAFT',
      humanApprovalReference: null,
      humanApprovalGrantedAt: null,
      blockers: [],
      updatedAt: new Date().toISOString(),
    });
  }
}

export function getProgramProfile(programId: string): RealProgramProfile | null {
  return profiles.get(programId) || null;
}

export function listProgramProfiles(): RealProgramProfile[] {
  return [...profiles.values()];
}

export function getOnboardingState(programId: string): ProgramOnboardingState | null {
  return onboarding.get(programId) || null;
}

function canAdvance(from: OnboardingStage, to: OnboardingStage): boolean {
  const fi = STAGE_ORDER.indexOf(from);
  const ti = STAGE_ORDER.indexOf(to);
  // Allow same stage (idempotent) or next stage only — no skip except no reverse past COMPLETED
  return ti === fi || ti === fi + 1;
}

export function advanceOnboarding(
  programId: string,
  to: OnboardingStage,
  opts?: { humanApprovalReference?: string }
): ProgramOnboardingState {
  const state = onboarding.get(programId);
  if (!state) throw new Error(`PROGRAM_NOT_FOUND:${programId}`);
  if (!canAdvance(state.stage, to)) {
    throw new Error(`INVALID_STAGE_TRANSITION:${state.stage}->${to}`);
  }

  // Authorization hard gate before READY_FOR_PASSIVE_TESTING
  if (to === 'READY_FOR_PASSIVE_TESTING' || to === 'PASSIVE_SESSION_ACTIVE') {
    const profile = profiles.get(programId);
    if (!profile || profile.authorizationStatus !== 'AUTHORIZED') {
      throw new Error('PROGRAM_NOT_AUTHORIZED');
    }
  }

  if (to === 'HUMAN_APPROVAL' || to === 'READY_FOR_PASSIVE_TESTING') {
    if (to === 'READY_FOR_PASSIVE_TESTING' && !state.humanApprovalReference && !opts?.humanApprovalReference) {
      throw new Error('APPROVAL_REQUIRED');
    }
  }

  if (opts?.humanApprovalReference) {
    state.humanApprovalReference = opts.humanApprovalReference;
    state.humanApprovalGrantedAt = new Date().toISOString();
  }

  // PASSIVE_SESSION_ACTIVE requires prior HUMAN_APPROVAL with reference
  if (to === 'PASSIVE_SESSION_ACTIVE') {
    if (!state.humanApprovalReference) throw new Error('APPROVAL_REQUIRED');
    if (state.stage !== 'READY_FOR_PASSIVE_TESTING' && state.stage !== 'PASSIVE_SESSION_ACTIVE') {
      throw new Error(`INVALID_STAGE_TRANSITION:${state.stage}->${to}`);
    }
  }

  // Never auto-transition to active testing — that stage does not exist here
  state.stage = to;
  state.updatedAt = new Date().toISOString();
  onboarding.set(programId, state);
  return { ...state, blockers: [...state.blockers] };
}

export function isAuthorizedForPassive(programId: string): { ok: boolean; reason: string } {
  const profile = profiles.get(programId);
  if (!profile) return { ok: false, reason: 'PROGRAM_NOT_FOUND' };
  if (profile.authorizationStatus === 'EXPIRED') return { ok: false, reason: 'AUTHORIZATION_EXPIRED' };
  if (profile.authorizationStatus === 'SUSPENDED') return { ok: false, reason: 'AUTHORIZATION_SUSPENDED' };
  if (profile.authorizationStatus === 'NOT_AUTHORIZED') return { ok: false, reason: 'NOT_AUTHORIZED' };
  if (profile.authorizationStatus === 'UNKNOWN') return { ok: false, reason: 'AUTHORIZATION_UNKNOWN' };
  if (profile.authorizationStatus !== 'AUTHORIZED') return { ok: false, reason: 'PROGRAM_NOT_AUTHORIZED' };

  if (profile.testingWindow) {
    const now = Date.now();
    const start = Date.parse(profile.testingWindow.start);
    const end = Date.parse(profile.testingWindow.end);
    if (!Number.isNaN(start) && now < start) return { ok: false, reason: 'TESTING_WINDOW_NOT_STARTED' };
    if (!Number.isNaN(end) && now > end) return { ok: false, reason: 'TESTING_WINDOW_EXPIRED' };
  }

  const state = onboarding.get(programId);
  if (!state) return { ok: false, reason: 'ONBOARDING_MISSING' };
  if (!state.humanApprovalReference) return { ok: false, reason: 'APPROVAL_REQUIRED' };
  if (
    state.stage !== 'READY_FOR_PASSIVE_TESTING' &&
    state.stage !== 'PASSIVE_SESSION_ACTIVE' &&
    state.stage !== 'PASSIVE_SESSION_COMPLETED'
  ) {
    return { ok: false, reason: `STAGE_NOT_READY:${state.stage}` };
  }

  return { ok: true, reason: 'AUTHORIZED' };
}

/** Factory for test/demo profiles — clearly synthetic, never claims real HackerOne program */
export function createSyntheticAuthorizedProfile(overrides?: Partial<RealProgramProfile>): RealProgramProfile {
  const now = new Date().toISOString();
  return {
    programId: overrides?.programId || 'synth-authorized-001',
    programName: overrides?.programName || 'DevilHunt Synthetic Authorized Program',
    platform: overrides?.platform || 'Self-Hosted',
    authorizationStatus: overrides?.authorizationStatus ?? 'AUTHORIZED',
    authorizationReference: overrides?.authorizationReference ?? 'AUTH-REF-SYNTH-001',
    policyVersion: overrides?.policyVersion || '1.0.0',
    scopeVersion: overrides?.scopeVersion || '1.0.0',
    allowedAssets: overrides?.allowedAssets || [
      'app.synthetic-bounty.local',
      'api.synthetic-bounty.local',
      'static.synthetic-bounty.local',
    ],
    excludedAssets: overrides?.excludedAssets || [
      'admin.synthetic-bounty.local',
      'internal.synthetic-bounty.local',
    ],
    allowedMethods: overrides?.allowedMethods || ['GET', 'HEAD', 'OPTIONS'],
    prohibitedActions: overrides?.prohibitedActions || [
      'DOS',
      'BRUTE_FORCE',
      'CREDENTIAL_ATTACK',
      'STATE_CHANGE',
      'ACTIVE_EXPLOITATION',
    ],
    vulnerabilityClasses: overrides?.vulnerabilityClasses || ['INFORMATION_DISCLOSURE', 'SECURITY_MISCONFIGURATION'],
    requestBudget: overrides?.requestBudget ?? 20,
    burstLimit: overrides?.burstLimit ?? 2,
    testingWindow: overrides?.testingWindow ?? {
      start: new Date(Date.now() - 86400000).toISOString(),
      end: new Date(Date.now() + 86400000 * 30).toISOString(),
    },
    researcherAccountReferences: overrides?.researcherAccountReferences || ['researcher-ref-synth'],
    proxyRequirement: overrides?.proxyRequirement ?? false,
    proxyEndpoint: overrides?.proxyEndpoint ?? null,
    evidencePolicy: overrides?.evidencePolicy || 'SHA256_REQUIRED_REDACT_SECRETS',
    reportingPolicy: overrides?.reportingPolicy || 'HUMAN_REVIEW_MANDATORY',
    createdAt: overrides?.createdAt || now,
    updatedAt: overrides?.updatedAt || now,
  };
}
