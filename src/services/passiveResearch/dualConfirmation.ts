/**
 * Mission #0018 — Dual human confirmation before supervised passive collection.
 * Two distinct approval references required. No automatic approval.
 */

import crypto from 'crypto';
import { getProgramProfile, advanceOnboarding, getOnboardingState } from './programProfileModel.ts';
import { runPassivePreflight, PreflightResult } from './preflight.ts';
import { appendTimelineEvent } from '../passiveIntelligence/researchTimeline.ts';

export interface ConfirmationManifest {
  programId: string;
  programName: string;
  authorizationReference: string;
  allowedAssets: string[];
  allowedMethods: string[];
  requestBudget: number;
  testingWindow: { start: string; end: string } | null;
  proxyRequirement: boolean;
  proxyEndpoint: string | null;
  explicitStatement: string;
  targets: string[];
}

export interface DualConfirmationRecord {
  confirmationId: string;
  programId: string;
  manifest: ConfirmationManifest;
  primaryApproverRef: string;
  secondaryApproverRef: string;
  primaryConfirmedAt: string;
  secondaryConfirmedAt: string;
  preflight: PreflightResult;
  supervisedLiveEnabled: boolean;
  createdAt: string;
}

const confirmations = new Map<string, DualConfirmationRecord>();

export function clearConfirmations(): void {
  confirmations.clear();
}

export function getConfirmation(confirmationId: string): DualConfirmationRecord | null {
  return confirmations.get(confirmationId) || null;
}

export function listConfirmations(programId?: string): DualConfirmationRecord[] {
  const all = [...confirmations.values()];
  return programId ? all.filter((c) => c.programId === programId) : all;
}

export function buildConfirmationManifest(params: {
  programId: string;
  targets: string[];
}): { ok: true; manifest: ConfirmationManifest } | { ok: false; errors: string[] } {
  const profile = getProgramProfile(params.programId);
  if (!profile) return { ok: false, errors: ['PROGRAM_NOT_FOUND'] };
  if (profile.authorizationStatus !== 'AUTHORIZED') {
    return { ok: false, errors: [`NOT_AUTHORIZED:${profile.authorizationStatus}`] };
  }
  if (!profile.authorizationReference) {
    return { ok: false, errors: ['MISSING_AUTHORIZATION_REFERENCE'] };
  }
  if (!params.targets.length) return { ok: false, errors: ['NO_TARGETS'] };

  return {
    ok: true,
    manifest: {
      programId: profile.programId,
      programName: profile.programName,
      authorizationReference: profile.authorizationReference,
      allowedAssets: [...profile.allowedAssets],
      allowedMethods: [...profile.allowedMethods],
      requestBudget: profile.requestBudget,
      testingWindow: profile.testingWindow,
      proxyRequirement: profile.proxyRequirement,
      proxyEndpoint: profile.proxyEndpoint,
      targets: [...params.targets],
      explicitStatement:
        'I confirm this is a PASSIVE-ONLY session (GET/HEAD/OPTIONS). No active testing, exploitation, state-changing methods, or credential attacks will be performed.',
    },
  };
}

/**
 * Record dual human confirmation. primary and secondary refs must differ.
 * supervisedLiveEnabled defaults false — live network requires explicit true from both context and env policy.
 */
export function submitDualConfirmation(params: {
  programId: string;
  targets: string[];
  primaryApproverRef: string;
  secondaryApproverRef: string;
  supervisedLiveEnabled?: boolean;
  proxyAvailable?: boolean;
}): { ok: true; confirmation: DualConfirmationRecord } | { ok: false; errors: string[] } {
  const errors: string[] = [];

  if (!params.primaryApproverRef?.trim()) errors.push('PRIMARY_APPROVER_REQUIRED');
  if (!params.secondaryApproverRef?.trim()) errors.push('SECONDARY_APPROVER_REQUIRED');
  if (
    params.primaryApproverRef &&
    params.secondaryApproverRef &&
    params.primaryApproverRef.trim() === params.secondaryApproverRef.trim()
  ) {
    errors.push('APPROVERS_MUST_BE_DISTINCT');
  }

  const built = buildConfirmationManifest({ programId: params.programId, targets: params.targets });
  if (!built.ok) return { ok: false, errors: [...errors, ...built.errors] };
  if (errors.length) return { ok: false, errors };

  // Grant dual human approval BEFORE preflight (preflight requires approval)
  const approvalRef = `${params.primaryApproverRef.trim()}+${params.secondaryApproverRef.trim()}`;
  try {
    const state = getOnboardingState(params.programId);
    if (!state) return { ok: false, errors: ['ONBOARDING_MISSING'] };

    if (state.stage === 'RESEARCHER_REVIEW') {
      advanceOnboarding(params.programId, 'HUMAN_APPROVAL', { humanApprovalReference: approvalRef });
    }
    let st = getOnboardingState(params.programId)!;
    if (st.stage === 'HUMAN_APPROVAL') {
      advanceOnboarding(params.programId, 'READY_FOR_PASSIVE_TESTING', { humanApprovalReference: approvalRef });
    } else if (st.stage === 'RESEARCHER_REVIEW') {
      advanceOnboarding(params.programId, 'HUMAN_APPROVAL', { humanApprovalReference: approvalRef });
      advanceOnboarding(params.programId, 'READY_FOR_PASSIVE_TESTING', { humanApprovalReference: approvalRef });
    } else if (!st.humanApprovalReference) {
      // Already at READY or beyond without ref — cannot inject
      return { ok: false, errors: [`ONBOARDING_STATE:${st.stage}:MISSING_APPROVAL_REF`] };
    }
  } catch (e) {
    return {
      ok: false,
      errors: [`ONBOARDING_ERROR:${e instanceof Error ? e.message : String(e)}`],
    };
  }

  const preflight = runPassivePreflight({
    programId: params.programId,
    targets: params.targets,
    proxyAvailable: params.proxyAvailable ?? true,
    evidenceStorageAvailable: true,
    auditStorageAvailable: true,
  });

  if (preflight.status === 'BLOCKED') {
    return { ok: false, errors: ['PREFLIGHT_BLOCKED', ...preflight.reasons] };
  }

  const now = new Date().toISOString();
  const confirmation: DualConfirmationRecord = {
    confirmationId: `dconf-${crypto.randomBytes(6).toString('hex')}`,
    programId: params.programId,
    manifest: built.manifest,
    primaryApproverRef: params.primaryApproverRef.trim(),
    secondaryApproverRef: params.secondaryApproverRef.trim(),
    primaryConfirmedAt: now,
    secondaryConfirmedAt: now,
    preflight,
    supervisedLiveEnabled: params.supervisedLiveEnabled === true,
    createdAt: now,
  };

  confirmations.set(confirmation.confirmationId, confirmation);

  appendTimelineEvent({
    type: 'HUMAN_APPROVAL',
    programId: params.programId,
    researchCaseId: 'dual-confirmation',
    details: {
      confirmationId: confirmation.confirmationId,
      primary: params.primaryApproverRef.trim(),
      secondary: params.secondaryApproverRef.trim(),
      supervisedLive: confirmation.supervisedLiveEnabled,
    },
  });

  return { ok: true, confirmation };
}

export function isConfirmationValidForSession(confirmationId: string, programId: string): boolean {
  const c = confirmations.get(confirmationId);
  if (!c) return false;
  if (c.programId !== programId) return false;
  if (c.preflight.status !== 'READY') return false;
  return true;
}
