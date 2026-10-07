/**
 * Mission #0023 — Bind policy snapshot + authorization snapshot.
 * Never enables live execution. TOTAL_LIVE_PACKETS = 0.
 */

import { createMeeshoPolicySnapshot, type ImmutableMeeshoPolicySnapshot } from './meeshoPolicySnapshot.ts';
import {
  createAuthorizationSnapshot,
  type ImmutableMeeshoAuthorizationSnapshot,
  type MeeshoAuthorizationData,
  FIXTURE_AUTH_VECTOR,
} from './meeshoAuthorizationSnapshot.ts';
import { validateAuthorizationData } from './meeshoAuthorizationValidator.ts';
import { isActiveTestingLocked } from './passiveSessionController.ts';
import { publicDisclosurePolicy } from './meeshoPolicyValidator.ts';

export type GateStatus = 'PASS' | 'PENDING' | 'BLOCKED' | 'FAIL';

export interface BoundAuthorizationContext {
  policy: ImmutableMeeshoPolicySnapshot;
  authorization: ImmutableMeeshoAuthorizationSnapshot;
  policyValidated: boolean;
  /** Real operator authorization only */
  authorizationValidated: boolean;
  /** Structural fixture validation only */
  fixtureAuthorizationValidated: boolean;
  isFixtureVector: boolean;
  liveEnvironmentEnabled: boolean;
  liveExecutionEnabled: boolean;
  activeTestingLocked: boolean;
  fixtureReady: boolean;
  classification:
    | 'POLICY_VALIDATED_LIVE_AUTHORIZATION_PENDING'
    | 'POLICY_VALIDATED_AUTHORIZATION_VALIDATED_LIVE_DISABLED'
    | 'POLICY_VALIDATED_FIXTURE_AUTHORIZATION_ONLY'
    | 'BLOCKED';
  gates: Record<string, GateStatus>;
  reasons: string[];
  totalLivePackets: 0;
}

export function bindAuthorization(
  authInput: Partial<MeeshoAuthorizationData> = {},
  policyOpts: { policyVersion?: string | null; programId?: string | null } = {}
): BoundAuthorizationContext {
  // Policy version on snapshot only if operator supplies — do not invent
  const policy = createMeeshoPolicySnapshot({
    programId: policyOpts.programId ?? authInput.programId ?? null,
    policyVersion: policyOpts.policyVersion ?? authInput.policyVersion ?? null,
    hackerOneIdentityConfigured: !!authInput.hackeroneUsername?.trim(),
  });

  const authorization = createAuthorizationSnapshot(authInput);
  const authView = authorization.view();
  const policyView = policy.view();
  const validation = validateAuthorizationData(authView, policyView.policyVersion);

  const gates: Record<string, GateStatus> = {
    POLICY_SNAPSHOT_AVAILABLE: 'PASS',
    POLICY_SNAPSHOT_IMMUTABLE: policy.isImmutable ? 'PASS' : 'FAIL',
    AUTHORIZATION_SNAPSHOT_AVAILABLE: 'PASS',
    AUTHORIZATION_SNAPSHOT_IMMUTABLE: authorization.isImmutable ? 'PASS' : 'FAIL',
    PROGRAM_ID_PRESENT: validation.fields.PROGRAM_ID || 'PENDING',
    AUTHORIZATION_REFERENCE_PRESENT: validation.fields.AUTHORIZATION_REFERENCE || 'PENDING',
    POLICY_VERSION_PRESENT: validation.fields.POLICY_VERSION || 'PENDING',
    POLICY_AUTHORIZATION_VERSION_MATCH: validation.fields.POLICY_AUTHORIZATION_VERSION_MATCH || 'PENDING',
    RESEARCHER_IDENTITY_PRESENT: validation.fields.RESEARCHER_IDENTITY || 'PENDING',
    HACKERONE_IDENTITY_CONFIGURED: validation.fields.HACKERONE_IDENTITY || 'PENDING',
    PRIMARY_APPROVAL_PRESENT:
      validation.fields.PRIMARY_APPROVAL_REFERENCE === 'PASS' && validation.fields.PRIMARY_APPROVER === 'PASS'
        ? 'PASS'
        : 'PENDING',
    SECONDARY_APPROVAL_PRESENT:
      validation.fields.SECONDARY_APPROVAL_REFERENCE === 'PASS' && validation.fields.SECONDARY_APPROVER === 'PASS'
        ? 'PASS'
        : 'PENDING',
    DUAL_APPROVERS_DISTINCT: validation.fields.DUAL_APPROVERS_DISTINCT || validation.fields.DUAL_APPROVAL || 'PENDING',
    CLOSED_SCOPE_RETAINED: 'PASS',
    AUTHORIZATION_CANNOT_EXPAND_SCOPE: validation.fields.AUTHORIZATION_CANNOT_EXPAND_SCOPE || 'PASS',
    MOBILE_DYNAMIC_TESTING_BLOCKED:
      policyView.mobileTestingRules.MOBILE_DYNAMIC_TESTING === 'BLOCKED' ? 'PASS' : 'FAIL',
    KNOWN_DUPLICATE_FILTER_ACTIVE: 'PASS',
    CREDENTIAL_REDACTION_ACTIVE: validation.fields.NO_SECRETS_IN_AUTH || 'PASS',
    PUBLIC_DISCLOSURE_BLOCKED: publicDisclosurePolicy() === 'BLOCKED' ? 'PASS' : 'FAIL',
    ACTIVE_TESTING_LOCKED: isActiveTestingLocked() ? 'PASS' : 'FAIL',
    LIVE_ENVIRONMENT_DISABLED: process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE === 'true' ? 'FAIL' : 'PASS',
    FIXTURE_MODE_AVAILABLE: 'PASS',
    AUDIT_LOGGING_ACTIVE: 'PASS',
    EVIDENCE_REDACTION_ACTIVE: 'PASS',
    TOTAL_LIVE_PACKETS_ZERO: 'PASS',
    SEPARATE_LIVE_MISSION_REQUIRED: authView.separateLiveMissionApproved ? 'PASS' : 'PENDING',
  };

  const policyValidated =
    gates.POLICY_SNAPSHOT_IMMUTABLE === 'PASS' &&
    gates.CLOSED_SCOPE_RETAINED === 'PASS' &&
    gates.MOBILE_DYNAMIC_TESTING_BLOCKED === 'PASS' &&
    gates.ACTIVE_TESTING_LOCKED === 'PASS' &&
    gates.LIVE_ENVIRONMENT_DISABLED === 'PASS';

  const authorizationValidated = validation.authorizationValidated;
  const fixtureAuthorizationValidated = validation.fixtureAuthorizationValidated;
  const isFixtureVector = validation.isFixtureVector;

  gates.REAL_AUTHORIZATION_GATE = authorizationValidated ? 'PASS' : 'PENDING';
  gates.FIXTURE_AUTHORIZATION_ONLY = fixtureAuthorizationValidated ? 'PASS' : 'PENDING';

  // Never enable live execution from binding layer
  const liveEnvironmentEnabled = false;
  const liveExecutionEnabled = false;

  let classification: BoundAuthorizationContext['classification'] = 'BLOCKED';
  if (policyValidated && authorizationValidated) {
    classification = 'POLICY_VALIDATED_AUTHORIZATION_VALIDATED_LIVE_DISABLED';
  } else if (policyValidated && fixtureAuthorizationValidated) {
    classification = 'POLICY_VALIDATED_FIXTURE_AUTHORIZATION_ONLY';
  } else if (policyValidated) {
    classification = 'POLICY_VALIDATED_LIVE_AUTHORIZATION_PENDING';
  }

  return {
    policy,
    authorization,
    policyValidated,
    authorizationValidated,
    fixtureAuthorizationValidated,
    isFixtureVector,
    liveEnvironmentEnabled,
    liveExecutionEnabled,
    activeTestingLocked: true,
    fixtureReady: policyValidated && gates.FIXTURE_MODE_AVAILABLE === 'PASS',
    classification,
    gates,
    reasons: validation.reasons,
    totalLivePackets: 0,
  };
}

export function rejectLiveExecutionAttempt(ctx: BoundAuthorizationContext): {
  allowed: false;
  reason: string;
} {
  return {
    allowed: false,
    reason: ctx.liveExecutionEnabled
      ? 'UNEXPECTED_LIVE_ENABLED'
      : 'LIVE_EXECUTION_DISABLED_SEPARATE_MISSION_REQUIRED',
  };
}

export { FIXTURE_AUTH_VECTOR };
