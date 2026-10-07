/**
 * Validate operator authorization data — never invent, never expand scope.
 */

import type { MeeshoAuthorizationData } from './meeshoAuthorizationSnapshot.ts';
import { assertNoSecretsInPayload } from './meeshoCredentialPolicy.ts';
import { classifyMeeshoAsset } from './meeshoScopePolicy.ts';

export type AuthFieldStatus = 'PASS' | 'PENDING' | 'BLOCKED' | 'FAIL';

export interface AuthValidationResult {
  fields: Record<string, AuthFieldStatus>;
  /** Real operator authorization only — never true for FIXTURE_* values */
  authorizationValidated: boolean;
  /** Fixture-only structural validation — never unlocks live */
  fixtureAuthorizationValidated: boolean;
  isFixtureVector: boolean;
  reasons: string[];
  scopeExpansionAttempted: boolean;
  scopeExpansionBlocked: boolean;
}

/** Detect clearly marked fixture values — these never satisfy real auth gate */
export function isFixtureValue(v: string | null | undefined): boolean {
  if (!v) return false;
  return /^FIXTURE[_-]/i.test(String(v).trim());
}

export function isFixtureAuthorizationVector(auth: {
  programId?: string | null;
  authorizationReference?: string | null;
  researcherIdentity?: string | null;
  hackeroneUsername?: string | null;
}): boolean {
  const keys = [auth.programId, auth.authorizationReference, auth.researcherIdentity, auth.hackeroneUsername];
  return keys.some((k) => isFixtureValue(k));
}

export function validateAuthorizationData(
  auth: MeeshoAuthorizationData,
  policyVersionFromSnapshot: string | null
): AuthValidationResult {
  const fields: Record<string, AuthFieldStatus> = {};
  const reasons: string[] = [];

  const present = (v: string | null | undefined) => !!(v && String(v).trim());

  fields.PROGRAM_ID = present(auth.programId) ? 'PASS' : 'PENDING';
  fields.AUTHORIZATION_REFERENCE = present(auth.authorizationReference) ? 'PASS' : 'PENDING';
  fields.POLICY_VERSION = present(auth.policyVersion) ? 'PASS' : 'PENDING';
  fields.RESEARCHER_IDENTITY = present(auth.researcherIdentity) ? 'PASS' : 'PENDING';
  fields.HACKERONE_IDENTITY = present(auth.hackeroneUsername) ? 'PASS' : 'PENDING';
  fields.PRIMARY_APPROVER = present(auth.primaryApprover) ? 'PASS' : 'PENDING';
  fields.PRIMARY_APPROVAL_REFERENCE = present(auth.primaryApprovalReference) ? 'PASS' : 'PENDING';
  fields.SECONDARY_APPROVER = present(auth.secondaryApprover) ? 'PASS' : 'PENDING';
  fields.SECONDARY_APPROVAL_REFERENCE = present(auth.secondaryApprovalReference) ? 'PASS' : 'PENDING';

  // Dual approval
  if (!present(auth.primaryApprovalReference) || !present(auth.secondaryApprovalReference)) {
    fields.DUAL_APPROVAL = 'PENDING';
    reasons.push('Dual approval incomplete');
  } else if (
    auth.primaryApprover &&
    auth.secondaryApprover &&
    auth.primaryApprover === auth.secondaryApprover
  ) {
    fields.DUAL_APPROVAL = 'BLOCKED';
    fields.DUAL_APPROVERS_DISTINCT = 'BLOCKED';
    reasons.push('Approver identities must be distinct');
  } else if (auth.primaryApprovalReference === auth.secondaryApprovalReference) {
    fields.DUAL_APPROVAL = 'BLOCKED';
    fields.DUAL_APPROVAL_REFS_DISTINCT = 'BLOCKED';
    reasons.push('Approval references must be distinct');
  } else if (
    present(auth.primaryApprover) &&
    present(auth.secondaryApprover) &&
    auth.primaryApprover !== auth.secondaryApprover
  ) {
    fields.DUAL_APPROVAL = 'PASS';
    fields.DUAL_APPROVERS_DISTINCT = 'PASS';
    fields.DUAL_APPROVAL_REFS_DISTINCT = 'PASS';
  } else {
    fields.DUAL_APPROVAL = 'PENDING';
    reasons.push('Approver identities incomplete');
  }

  // Policy version match
  if (!present(auth.policyVersion)) {
    fields.POLICY_AUTHORIZATION_VERSION_MATCH = 'PENDING';
  } else if (policyVersionFromSnapshot && auth.policyVersion !== policyVersionFromSnapshot) {
    fields.POLICY_AUTHORIZATION_VERSION_MATCH = 'BLOCKED';
    reasons.push('POLICY_AUTHORIZATION_VERSION_MISMATCH');
  } else if (!policyVersionFromSnapshot && present(auth.policyVersion)) {
    // Auth has version; policy snapshot may still have null — require both when binding complete
    fields.POLICY_AUTHORIZATION_VERSION_MATCH = 'PENDING';
    reasons.push('Policy snapshot version still MISSING');
  } else {
    fields.POLICY_AUTHORIZATION_VERSION_MATCH = 'PASS';
  }

  // Secrets
  try {
    assertNoSecretsInPayload({
      programId: auth.programId,
      authorizationReference: auth.authorizationReference,
      hackeroneUsername: auth.hackeroneUsername,
      researcherIdentity: auth.researcherIdentity,
    });
    fields.NO_SECRETS_IN_AUTH = 'PASS';
  } catch {
    fields.NO_SECRETS_IN_AUTH = 'FAIL';
    reasons.push('Secret-like material in authorization object');
  }

  // Scope expansion probes (authorization must not expand)
  const expandHosts = ['www.meesho.com', 'api.meesho.com', '*.meesho.com'];
  let expansionBlocked = true;
  for (const h of expandHosts) {
    const r = classifyMeeshoAsset(h.startsWith('*') ? 'https://evil.meesho.com/' : `https://${h}/`);
    if (r.allowedForPassiveHttp) expansionBlocked = false;
  }
  fields.AUTHORIZATION_CANNOT_EXPAND_SCOPE = expansionBlocked ? 'PASS' : 'FAIL';

  const requiredPass = [
    fields.PROGRAM_ID,
    fields.AUTHORIZATION_REFERENCE,
    fields.POLICY_VERSION,
    fields.RESEARCHER_IDENTITY,
    fields.HACKERONE_IDENTITY,
    fields.DUAL_APPROVAL,
    fields.NO_SECRETS_IN_AUTH,
  ];

  const structurallyComplete =
    requiredPass.every((s) => s === 'PASS') &&
    fields.POLICY_AUTHORIZATION_VERSION_MATCH === 'PASS' &&
    fields.AUTHORIZATION_CANNOT_EXPAND_SCOPE === 'PASS';

  const fixtureVector = isFixtureAuthorizationVector(auth);
  fields.FIXTURE_VECTOR = fixtureVector ? 'PASS' : 'PENDING';
  // Real authorization never true for fixture vectors
  const authorizationValidated = structurallyComplete && !fixtureVector;
  const fixtureAuthorizationValidated = structurallyComplete && fixtureVector;

  if (fixtureVector) {
    reasons.push('FIXTURE_VECTOR_CANNOT_SATISFY_REAL_AUTHORIZATION_GATE');
  }

  return {
    fields,
    authorizationValidated,
    fixtureAuthorizationValidated,
    isFixtureVector: fixtureVector,
    reasons,
    scopeExpansionAttempted: true,
    scopeExpansionBlocked: expansionBlocked,
  };
}
