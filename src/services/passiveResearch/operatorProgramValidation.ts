/**
 * Mission #0021 — Operator-supplied real program profile validation.
 * NEVER invents program ID, scope, authorization, policy, proxy, or rate limits.
 * Missing required fields → MISSING + BLOCK.
 */

import { importRealProgram, type ProgramImportInput, type ImportResult } from './realProgramImport.ts';
import { checkTargetScope, checkMethodAllowed, PASSIVE_METHODS } from './scopeEnforcement.ts';
import { runPassivePreflight } from './preflight.ts';
import { submitDualConfirmation, clearConfirmations } from './dualConfirmation.ts';
import {
  startSupervisedCollection,
  supervisedPassiveRequest,
  emergencyStop,
} from './supervisedCollection.ts';
import { clearProgramRegistry, getProgramProfile, getOnboardingState } from './programProfileModel.ts';
import { clearSessions, isActiveTestingLocked } from './passiveSessionController.ts';
import {
  persistProgram,
  persistConfirmation,
  persistSessionSnapshot,
  getScopeVersions,
  appendAudit,
  clearPersistenceStore,
} from './persistenceStore.ts';
import { registerScopeProfile } from '../passiveIntelligence/scopeGuard.ts';

export type FieldStatus = 'VALID' | 'MISSING' | 'BLOCKED' | 'UNSPECIFIED' | 'LOCKED';

export type PolicyCompatibility = 'COMPATIBLE' | 'INCOMPATIBLE' | 'REQUIRES_OPERATOR_REVIEW';

export interface OperatorProfileFieldReport {
  field: string;
  status: FieldStatus;
  valuePreview?: string;
  note?: string;
}

export interface MethodCompatibilityRow {
  method: string;
  programAllows: boolean;
  devilHuntPassiveAllows: boolean;
  executionStatus: 'ALLOWED_PASSIVE' | 'ACTIVE_OR_STATE_CHANGING_METHOD_AVAILABLE_BUT_LOCKED' | 'DENIED';
}

export interface OperatorValidationReport {
  classification:
    | 'REAL_PROGRAM_PROFILE_VALIDATED'
    | 'REAL_PROGRAM_PROFILE_BLOCKED'
    | 'REAL_PROGRAM_PROFILE_PENDING_OPERATOR_DATA';
  fields: OperatorProfileFieldReport[];
  importOk: boolean;
  importErrors: string[];
  scopeChecks: Array<{ target: string; decision: string; allowed: boolean }>;
  policyCompatibility: PolicyCompatibility;
  policyNotes: string[];
  authorizationStatus: FieldStatus;
  authorizationNotes: string[];
  methodRows: MethodCompatibilityRow[];
  rateLimit: { programLimit: string; devilHuntSafetyBudget: number | null };
  proxyStatus: FieldStatus;
  proxyNotes: string[];
  dualConfirmationStatus: FieldStatus;
  preflightStatus: 'READY' | 'BLOCKED' | 'SKIPPED';
  preflightReasons: string[];
  fixtureSession: {
    attempted: boolean;
    ok: boolean;
    liveNetwork: boolean;
    sessionId?: string;
    observations?: number;
    evidenceHint?: string;
    cancelOk?: boolean;
  };
  totalLivePackets: number;
  activeTestingLocked: boolean;
  blockers: string[];
}

const DEVILHUNT_PASSIVE = ['GET', 'HEAD', 'OPTIONS'] as const;

function preview(v: unknown): string | undefined {
  if (v === null || v === undefined) return undefined;
  if (typeof v === 'string') return v.slice(0, 80) || undefined;
  if (typeof v === 'number') return String(v);
  if (Array.isArray(v)) return v.slice(0, 5).join(', ');
  return undefined;
}

/**
 * Validate an operator-supplied profile. Pass null/undefined to signal no data provided.
 */
export async function validateOperatorSuppliedProgram(
  input: ProgramImportInput | null | undefined,
  opts?: {
    primaryApprover?: string;
    secondaryApprover?: string;
    supervisedLiveEnabled?: boolean;
    runFixtureSession?: boolean;
  }
): Promise<OperatorValidationReport> {
  clearProgramRegistry();
  clearConfirmations();
  clearSessions();
  clearPersistenceStore();

  const blockers: string[] = [];
  const fields: OperatorProfileFieldReport[] = [];

  if (!input) {
    return {
      classification: 'REAL_PROGRAM_PROFILE_PENDING_OPERATOR_DATA',
      fields: [
        { field: 'programId', status: 'MISSING', note: 'No operator profile supplied in this session' },
        { field: 'programName', status: 'MISSING' },
        { field: 'authorizationReference', status: 'MISSING' },
        { field: 'allowedAssets', status: 'MISSING' },
        { field: 'policyVersion', status: 'MISSING' },
        { field: 'scopeVersion', status: 'MISSING' },
      ],
      importOk: false,
      importErrors: ['NO_OPERATOR_PROFILE_SUPPLIED'],
      scopeChecks: [],
      policyCompatibility: 'REQUIRES_OPERATOR_REVIEW',
      policyNotes: ['Cannot evaluate policy without operator-supplied program rules'],
      authorizationStatus: 'MISSING',
      authorizationNotes: ['No authorizationReference provided by operator'],
      methodRows: DEVILHUNT_PASSIVE.map((m) => ({
        method: m,
        programAllows: false,
        devilHuntPassiveAllows: true,
        executionStatus: 'DENIED' as const,
      })),
      rateLimit: { programLimit: 'UNSPECIFIED', devilHuntSafetyBudget: null },
      proxyStatus: 'UNSPECIFIED',
      proxyNotes: ['No proxy configuration supplied'],
      dualConfirmationStatus: 'MISSING',
      preflightStatus: 'SKIPPED',
      preflightReasons: ['No program to preflight'],
      fixtureSession: { attempted: false, ok: false, liveNetwork: false },
      totalLivePackets: 0,
      activeTestingLocked: isActiveTestingLocked(),
      blockers: ['NO_OPERATOR_PROFILE_SUPPLIED — refuse to invent HackerOne/program data'],
    };
  }

  // Field inventory (no silent defaults for identity/scope/auth)
  const requiredPairs: Array<[string, unknown]> = [
    ['programId', input.programId],
    ['programName', input.programName],
    ['platform', input.platform],
    ['policyVersion', input.policyVersion],
    ['scopeVersion', input.scopeVersion],
    ['authorizationReference', input.authorizationReference],
    ['allowedAssets', input.allowedAssets],
    ['requestBudget', input.requestBudget],
    ['researcherAccountReferences', input.researcherAccountReferences],
  ];
  for (const [name, val] of requiredPairs) {
    const missing =
      val === null ||
      val === undefined ||
      (typeof val === 'string' && !val.trim()) ||
      (Array.isArray(val) && val.length === 0) ||
      (name === 'requestBudget' && (typeof val !== 'number' || val < 1));
    fields.push({
      field: name,
      status: missing ? 'MISSING' : 'VALID',
      valuePreview: missing ? undefined : preview(val),
    });
    if (missing) blockers.push(`MISSING:${name}`);
  }

  fields.push({
    field: 'excludedAssets',
    status: Array.isArray(input.excludedAssets) ? 'VALID' : 'MISSING',
    valuePreview: preview(input.excludedAssets),
  });
  fields.push({
    field: 'proxyRequirement',
    status: 'VALID',
    valuePreview: String(!!input.proxyRequirement),
  });
  if (input.proxyRequirement) {
    const pe = input.proxyEndpoint;
    fields.push({
      field: 'proxyEndpoint',
      status: pe && String(pe).trim() ? 'VALID' : 'MISSING',
      valuePreview: preview(pe),
    });
    if (!pe || !String(pe).trim()) blockers.push('MISSING:proxyEndpoint');
  }

  // Rate limit: never invent
  const rateLimit = {
    programLimit: 'UNSPECIFIED' as string,
    devilHuntSafetyBudget: typeof input.requestBudget === 'number' ? input.requestBudget : null,
  };

  const importResult: ImportResult = importRealProgram(input);
  if (!importResult.ok) {
    blockers.push(...importResult.errors);
  }

  const profile = importResult.profile || getProgramProfile(input.programId || '');
  const scopeChecks: OperatorValidationReport['scopeChecks'] = [];

  if (profile) {
    registerScopeProfile({
      programId: profile.programId,
      inScopeHosts: profile.allowedAssets,
      outOfScopeHosts: profile.excludedAssets,
    });
    persistProgram(profile, getOnboardingState(profile.programId) || {
      programId: profile.programId,
      stage: 'RESEARCHER_REVIEW',
      humanApprovalReference: null,
      humanApprovalGrantedAt: null,
      blockers: [],
      updatedAt: new Date().toISOString(),
    });

    for (const asset of profile.allowedAssets) {
      const r = checkTargetScope(profile.programId, `https://${asset}/`);
      scopeChecks.push({ target: `https://${asset}/`, decision: r.code, allowed: r.allowed });
    }
    for (const ex of profile.excludedAssets) {
      const r = checkTargetScope(profile.programId, `https://${ex}/`);
      scopeChecks.push({ target: `https://${ex}/`, decision: r.code, allowed: r.allowed });
    }
    // Negative probes
    for (const t of [
      'https://evil-unlisted.example/',
      `https://${profile.allowedAssets[0] || 'x'}.attacker.local/`,
      'https://user:pass@spoof.test/',
      'not a url',
    ]) {
      const r = checkTargetScope(profile.programId, t);
      scopeChecks.push({ target: t, decision: r.code, allowed: r.allowed });
    }
  }

  // Policy compatibility: program methods vs DevilHunt passive
  const programMethods = (input.allowedMethods || ['GET', 'HEAD', 'OPTIONS']).map((m) => m.toUpperCase());
  const methodRows: MethodCompatibilityRow[] = [];
  const allMethods = new Set([...programMethods, ...DEVILHUNT_PASSIVE, 'POST', 'PUT', 'PATCH', 'DELETE']);
  for (const method of allMethods) {
    const programAllows = programMethods.includes(method);
    const devilHuntPassiveAllows = (DEVILHUNT_PASSIVE as readonly string[]).includes(method);
    let executionStatus: MethodCompatibilityRow['executionStatus'] = 'DENIED';
    if (programAllows && devilHuntPassiveAllows) executionStatus = 'ALLOWED_PASSIVE';
    else if (programAllows && !devilHuntPassiveAllows) {
      executionStatus = 'ACTIVE_OR_STATE_CHANGING_METHOD_AVAILABLE_BUT_LOCKED';
    }
    methodRows.push({ method, programAllows, devilHuntPassiveAllows, executionStatus });
  }

  let policyCompatibility: PolicyCompatibility = 'COMPATIBLE';
  const policyNotes: string[] = [];
  if (programMethods.some((m) => !DEVILHUNT_PASSIVE.includes(m as any))) {
    policyNotes.push(
      'Program lists methods beyond GET/HEAD/OPTIONS — remaining locked by DevilHunt passive policy'
    );
    policyCompatibility = 'REQUIRES_OPERATOR_REVIEW';
  }
  if (input.authorizationStatus && input.authorizationStatus !== 'AUTHORIZED') {
    policyNotes.push(`authorizationStatus=${input.authorizationStatus}`);
    policyCompatibility = 'INCOMPATIBLE';
    blockers.push('NOT_AUTHORIZED');
  }

  const authorizationStatus: FieldStatus =
    input.authorizationStatus === 'AUTHORIZED' && input.authorizationReference
      ? 'VALID'
      : !input.authorizationReference
        ? 'MISSING'
        : 'BLOCKED';
  const authorizationNotes: string[] = [];
  if (!input.authorizationReference) authorizationNotes.push('authorizationReference missing');
  if (input.authorizationStatus === 'EXPIRED') {
    authorizationNotes.push('EXPIRED');
    blockers.push('AUTHORIZATION_EXPIRED');
  }

  let proxyStatus: FieldStatus = 'VALID';
  const proxyNotes: string[] = [];
  if (input.proxyRequirement) {
    if (!input.proxyEndpoint) {
      proxyStatus = 'BLOCKED';
      proxyNotes.push('Proxy required but endpoint not supplied');
      blockers.push('PROXY_REQUIRED_UNAVAILABLE');
    } else {
      proxyNotes.push('Proxy endpoint reference present (not fabricated)');
    }
  } else {
    proxyNotes.push('Proxy not required by supplied profile');
  }

  // Dual confirmation (only if import succeeded enough)
  let dualConfirmationStatus: FieldStatus = 'MISSING';
  let preflightStatus: OperatorValidationReport['preflightStatus'] = 'SKIPPED';
  let preflightReasons: string[] = [];
  let confirmationId: string | undefined;
  const targets =
    profile?.allowedAssets.map((a) => `https://${a}/`) ||
    (input.allowedAssets || []).map((a) => (a.startsWith('http') ? a : `https://${a}/`));

  if (importResult.ok && profile && blockers.filter((b) => b.startsWith('MISSING:')).length === 0) {
    const primary = opts?.primaryApprover || '';
    const secondary = opts?.secondaryApprover || '';
    if (!primary || !secondary) {
      dualConfirmationStatus = 'MISSING';
      blockers.push('DUAL_CONFIRMATION_NOT_PROVIDED');
    } else if (primary.trim() === secondary.trim()) {
      dualConfirmationStatus = 'BLOCKED';
      blockers.push('APPROVERS_MUST_BE_DISTINCT');
    } else {
      const conf = submitDualConfirmation({
        programId: profile.programId,
        targets,
        primaryApproverRef: primary,
        secondaryApproverRef: secondary,
        supervisedLiveEnabled: opts?.supervisedLiveEnabled === true,
        proxyAvailable: !input.proxyRequirement || !!input.proxyEndpoint,
      });
      if (conf.ok) {
        dualConfirmationStatus = 'VALID';
        confirmationId = conf.confirmation.confirmationId;
        persistConfirmation(conf.confirmation);
      } else {
        dualConfirmationStatus = 'BLOCKED';
        blockers.push(...conf.errors);
      }
    }

    const pf = runPassivePreflight({
      programId: profile.programId,
      targets,
      proxyAvailable: !input.proxyRequirement || !!input.proxyEndpoint,
    });
    preflightStatus = pf.status;
    preflightReasons = pf.reasons;
    if (pf.status === 'BLOCKED') blockers.push(...pf.reasons.map((r) => `PREFLIGHT:${r}`));
  }

  // Fixture-only session
  const fixtureSession: OperatorValidationReport['fixtureSession'] = {
    attempted: false,
    ok: false,
    liveNetwork: false,
  };

  if (
    opts?.runFixtureSession &&
    importResult.ok &&
    profile &&
    confirmationId &&
    preflightStatus === 'READY' &&
    dualConfirmationStatus === 'VALID'
  ) {
    fixtureSession.attempted = true;
    const started = startSupervisedCollection({
      confirmationId,
      programId: profile.programId,
      targets,
      proxyAvailable: !input.proxyRequirement || !!input.proxyEndpoint,
    });
    if (started.ok) {
      fixtureSession.sessionId = started.session.sessionId;
      persistSessionSnapshot({
        sessionId: started.session.sessionId,
        programId: profile.programId,
        researchCaseId: started.session.researchCaseId,
        state: started.session.state,
        budgetMax: started.session.budgetMax,
        budgetUsed: 0,
        scopeVersion: profile.scopeVersion,
        mode: 'FIXTURE',
        cancelled: false,
        createdAt: started.session.createdAt,
        updatedAt: started.session.updatedAt,
        requiresReauthorization: false,
      });
      const req = await supervisedPassiveRequest({
        sessionId: started.session.sessionId,
        confirmationId,
        target: targets[0],
        method: 'GET',
        mode: 'FIXTURE',
        fixtureResponse: {
          status: 200,
          headers: { 'content-type': 'text/plain', 'x-devilhunt-mode': 'fixture' },
          body: 'OPERATOR_PROFILE_FIXTURE_NO_LIVE_TRAFFIC',
        },
      });
      fixtureSession.ok = req.ok;
      fixtureSession.liveNetwork = req.liveNetwork === true;
      fixtureSession.observations = req.observations?.length || 0;
      fixtureSession.evidenceHint = req.evidenceId;
      const stopped = emergencyStop(started.session.sessionId, '0021_FIXTURE_COMPLETE');
      fixtureSession.cancelOk = stopped?.state === 'CANCELLED';
      if (req.liveNetwork) blockers.push('UNEXPECTED_LIVE_TRAFFIC');
    } else {
      blockers.push(...started.errors);
    }
  }

  const classification: OperatorValidationReport['classification'] =
    blockers.length === 0 && importResult.ok && preflightStatus === 'READY'
      ? 'REAL_PROGRAM_PROFILE_VALIDATED'
      : importResult.ok
        ? 'REAL_PROGRAM_PROFILE_BLOCKED'
        : blockers.includes('NO_OPERATOR_PROFILE_SUPPLIED')
          ? 'REAL_PROGRAM_PROFILE_PENDING_OPERATOR_DATA'
          : 'REAL_PROGRAM_PROFILE_BLOCKED';

  appendAudit({
    type: 'PROGRAM_IMPORTED',
    programId: input.programId || 'unknown',
    details: { classification, blockerCount: blockers.length },
  });

  return {
    classification,
    fields,
    importOk: importResult.ok,
    importErrors: importResult.errors,
    scopeChecks,
    policyCompatibility,
    policyNotes,
    authorizationStatus,
    authorizationNotes,
    methodRows,
    rateLimit,
    proxyStatus,
    proxyNotes,
    dualConfirmationStatus,
    preflightStatus,
    preflightReasons,
    fixtureSession,
    totalLivePackets: 0,
    activeTestingLocked: isActiveTestingLocked(),
    blockers,
  };
}
