/**
 * Mission #0026 — Operator authorization intake model.
 * Every field is CONFIGURED | MISSING | INVALID | PENDING | FIXTURE_ONLY.
 * Never invents values. FIXTURE_* never counts as real CONFIGURED.
 */

import { isFixtureValue } from './meeshoAuthorizationValidator.ts';

export type FieldState = 'CONFIGURED' | 'MISSING' | 'INVALID' | 'PENDING' | 'FIXTURE_ONLY';

export interface OperatorAuthorizationInput {
  programId?: string | null;
  authorizationReference?: string | null;
  policyVersion?: string | null;
  researcherIdentity?: string | null;
  hackeroneUsername?: string | null;
  primaryApprover?: string | null;
  primaryApprovalReference?: string | null;
  secondaryApprover?: string | null;
  secondaryApprovalReference?: string | null;
  authorizationExpiresAt?: string | null;
  separateLiveMissionApproval?: string | boolean | null;
}

export interface FieldReport {
  field: string;
  state: FieldState;
  /** Safe preview only — never secrets */
  preview: string | null;
}

function classifyField(value: string | null | undefined, allowEmptyAsMissing = true): FieldState {
  if (value === null || value === undefined || (allowEmptyAsMissing && !String(value).trim())) {
    return 'MISSING';
  }
  const v = String(value).trim();
  if (isFixtureValue(v)) return 'FIXTURE_ONLY';
  if (v.length < 2) return 'INVALID';
  return 'CONFIGURED';
}

export function inspectAuthorizationInput(input: OperatorAuthorizationInput = {}): {
  fields: FieldReport[];
  hasAnyRealConfigured: boolean;
  hasAnyFixture: boolean;
  allRequiredRealConfigured: boolean;
} {
  const map: Array<[string, string | null | undefined]> = [
    ['programId', input.programId],
    ['authorizationReference', input.authorizationReference],
    ['policyVersion', input.policyVersion],
    ['researcherIdentity', input.researcherIdentity],
    ['hackeroneUsername', input.hackeroneUsername],
    ['primaryApprover', input.primaryApprover],
    ['primaryApprovalReference', input.primaryApprovalReference],
    ['secondaryApprover', input.secondaryApprover],
    ['secondaryApprovalReference', input.secondaryApprovalReference],
    ['authorizationExpiresAt', input.authorizationExpiresAt],
  ];

  const fields: FieldReport[] = map.map(([field, value]) => {
    const state = classifyField(value);
    let preview: string | null = null;
    if (state === 'CONFIGURED' || state === 'FIXTURE_ONLY') {
      const v = String(value).trim();
      preview = v.length > 24 ? v.slice(0, 12) + '…' : v;
    }
    return { field, state, preview };
  });

  // separateLiveMissionApproval
  let liveState: FieldState = 'MISSING';
  if (input.separateLiveMissionApproval === true || input.separateLiveMissionApproval === 'true') {
    liveState = 'CONFIGURED';
  } else if (
    typeof input.separateLiveMissionApproval === 'string' &&
    input.separateLiveMissionApproval.trim()
  ) {
    liveState = isFixtureValue(input.separateLiveMissionApproval) ? 'FIXTURE_ONLY' : 'CONFIGURED';
  }
  fields.push({
    field: 'separateLiveMissionApproval',
    state: liveState,
    preview: liveState === 'CONFIGURED' ? 'true' : null,
  });

  const required = [
    'programId',
    'authorizationReference',
    'policyVersion',
    'researcherIdentity',
    'hackeroneUsername',
    'primaryApprover',
    'primaryApprovalReference',
    'secondaryApprover',
    'secondaryApprovalReference',
  ];

  const hasAnyRealConfigured = fields.some(
    (f) => required.includes(f.field) && f.state === 'CONFIGURED'
  );
  const hasAnyFixture = fields.some((f) => f.state === 'FIXTURE_ONLY');
  const allRequiredRealConfigured = required.every(
    (name) => fields.find((f) => f.field === name)?.state === 'CONFIGURED'
  );

  return { fields, hasAnyRealConfigured, hasAnyFixture, allRequiredRealConfigured };
}

export function toBindingInput(input: OperatorAuthorizationInput): Record<string, string | null | boolean> {
  return {
    programId: input.programId?.trim() || null,
    authorizationReference: input.authorizationReference?.trim() || null,
    policyVersion: input.policyVersion?.trim() || null,
    researcherIdentity: input.researcherIdentity?.trim() || null,
    hackeroneUsername: input.hackeroneUsername?.trim() || null,
    primaryApprover: input.primaryApprover?.trim() || null,
    primaryApprovalReference: input.primaryApprovalReference?.trim() || null,
    secondaryApprover: input.secondaryApprover?.trim() || null,
    secondaryApprovalReference: input.secondaryApprovalReference?.trim() || null,
    separateLiveMissionApproved:
      input.separateLiveMissionApproval === true ||
      input.separateLiveMissionApproval === 'true' ||
      (typeof input.separateLiveMissionApproval === 'string' &&
        !!input.separateLiveMissionApproval.trim() &&
        !isFixtureValue(input.separateLiveMissionApproval)),
  };
}
