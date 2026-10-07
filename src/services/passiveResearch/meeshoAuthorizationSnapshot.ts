/**
 * Mission #0023 — Immutable authorization snapshot (operator-supplied only).
 * Separate from policy snapshot. No secrets. Mutation fails deterministically.
 */

export interface MeeshoAuthorizationData {
  programId: string | null;
  authorizationReference: string | null;
  policyVersion: string | null;
  researcherIdentity: string | null;
  hackeroneUsername: string | null;
  primaryApprover: string | null;
  primaryApprovalReference: string | null;
  secondaryApprover: string | null;
  secondaryApprovalReference: string | null;
  /** Explicit operator flag only — never auto-set */
  separateLiveMissionApproved: boolean;
}

export class ImmutableMeeshoAuthorizationSnapshot {
  private readonly data: MeeshoAuthorizationData;
  private readonly frozen: boolean;

  constructor(data: MeeshoAuthorizationData) {
    this.data = {
      programId: data.programId?.trim() || null,
      authorizationReference: data.authorizationReference?.trim() || null,
      policyVersion: data.policyVersion?.trim() || null,
      researcherIdentity: data.researcherIdentity?.trim() || null,
      hackeroneUsername: data.hackeroneUsername?.trim() || null,
      primaryApprover: data.primaryApprover?.trim() || null,
      primaryApprovalReference: data.primaryApprovalReference?.trim() || null,
      secondaryApprover: data.secondaryApprover?.trim() || null,
      secondaryApprovalReference: data.secondaryApprovalReference?.trim() || null,
      separateLiveMissionApproved: data.separateLiveMissionApproved === true,
    };
    Object.freeze(this.data);
    this.frozen = true;
  }

  get isImmutable(): boolean {
    return this.frozen;
  }

  view(): Readonly<MeeshoAuthorizationData> {
    return this.data;
  }

  attemptMutation(_k: string, _v: unknown): never {
    throw new Error('AUTHORIZATION_SNAPSHOT_IMMUTABLE: mutation rejected');
  }
}

export function createAuthorizationSnapshot(
  input: Partial<MeeshoAuthorizationData> = {}
): ImmutableMeeshoAuthorizationSnapshot {
  return new ImmutableMeeshoAuthorizationSnapshot({
    programId: input.programId ?? null,
    authorizationReference: input.authorizationReference ?? null,
    policyVersion: input.policyVersion ?? null,
    researcherIdentity: input.researcherIdentity ?? null,
    hackeroneUsername: input.hackeroneUsername ?? null,
    primaryApprover: input.primaryApprover ?? null,
    primaryApprovalReference: input.primaryApprovalReference ?? null,
    secondaryApprover: input.secondaryApprover ?? null,
    secondaryApprovalReference: input.secondaryApprovalReference ?? null,
    separateLiveMissionApproved: input.separateLiveMissionApproved === true,
  });
}

/** Clearly marked synthetic fixture — NOT real Meesho authorization */
export const FIXTURE_AUTH_VECTOR: MeeshoAuthorizationData = {
  programId: 'FIXTURE_PROGRAM_ID',
  authorizationReference: 'FIXTURE_AUTHORIZATION_REFERENCE',
  policyVersion: 'FIXTURE_POLICY_VERSION',
  researcherIdentity: 'FIXTURE_RESEARCHER_IDENTITY',
  hackeroneUsername: 'FIXTURE_HACKERONE_IDENTITY',
  primaryApprover: 'FIXTURE_PRIMARY_APPROVER',
  primaryApprovalReference: 'FIXTURE_PRIMARY_APPROVAL_REF',
  secondaryApprover: 'FIXTURE_SECONDARY_APPROVER',
  secondaryApprovalReference: 'FIXTURE_SECONDARY_APPROVAL_REF',
  separateLiveMissionApproved: false,
};
