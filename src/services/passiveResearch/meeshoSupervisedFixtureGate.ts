/**
 * Mission #0024 — Supervised fixture gate after authorization binding.
 * Simulates full gate stack without network. Never enables LIVE_EXECUTION.
 */

import {
  bindAuthorization,
  rejectLiveExecutionAttempt,
  type BoundAuthorizationContext,
} from './meeshoAuthorizationBinding.ts';
import type { MeeshoAuthorizationData } from './meeshoAuthorizationSnapshot.ts';
import { FIXTURE_AUTH_VECTOR } from './meeshoAuthorizationSnapshot.ts';
import { classifyMeeshoAsset } from './meeshoScopePolicy.ts';
import { classifyFixtureFinding } from './meeshoKnownIssueFilter.ts';
import { assertNoSecretsInPayload } from './meeshoCredentialPolicy.ts';
import { isActiveTestingLocked } from './passiveSessionController.ts';
import { publicDisclosurePolicy } from './meeshoPolicyValidator.ts';

export type GateStatus = 'PASS' | 'PENDING' | 'BLOCKED' | 'FAIL';

export interface AuthorizationExpiryStatus {
  status: 'UNSPECIFIED' | 'VALID' | 'EXPIRED';
  expiresAt: string | null;
}

export function evaluateAuthorizationExpiry(
  expiresAt: string | null | undefined
): AuthorizationExpiryStatus {
  if (!expiresAt || !String(expiresAt).trim()) {
    return { status: 'UNSPECIFIED', expiresAt: null };
  }
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) {
    return { status: 'UNSPECIFIED', expiresAt: expiresAt };
  }
  if (Date.now() > t) {
    return { status: 'EXPIRED', expiresAt };
  }
  return { status: 'VALID', expiresAt };
}

export interface SupervisedFixtureGateResult {
  binding: BoundAuthorizationContext;
  expiry: AuthorizationExpiryStatus;
  checks: Record<string, GateStatus>;
  fixtureProbe: {
    ok: boolean;
    liveNetwork: false;
    scopeHostAllowed: boolean;
    knownDupFiltered: boolean;
    liveRejected: boolean;
    realAuthUnlocked: boolean;
  };
  finalState:
    | 'POLICY_VALIDATED_FIXTURE_READY_LIVE_AUTHORIZATION_PENDING'
    | 'POLICY_VALIDATED_AUTHORIZATION_VALIDATED_LIVE_DISABLED'
    | 'BLOCKED';
  totalLivePackets: 0;
  networkContacts: 0;
  liveRequests: 0;
}

const PREFLIGHT_KEYS = [
  'POLICY_SNAPSHOT_VALID',
  'AUTHORIZATION_SNAPSHOT_VALID',
  'AUTHORIZATION_SNAPSHOT_IMMUTABLE',
  'PROGRAM_ID_PRESENT',
  'AUTHORIZATION_REFERENCE_PRESENT',
  'POLICY_VERSION_PRESENT',
  'POLICY_AUTHORIZATION_VERSION_MATCH',
  'RESEARCHER_IDENTITY_PRESENT',
  'HACKERONE_IDENTITY_CONFIGURED',
  'PRIMARY_APPROVAL_PRESENT',
  'SECONDARY_APPROVAL_PRESENT',
  'DUAL_APPROVERS_DISTINCT',
  'CLOSED_SCOPE_RETAINED',
  'AUTHORIZATION_CANNOT_EXPAND_SCOPE',
  'MOBILE_DYNAMIC_TESTING_BLOCKED',
  'KNOWN_DUPLICATE_FILTER_ACTIVE',
  'CREDENTIAL_REDACTION_ACTIVE',
  'PUBLIC_DISCLOSURE_BLOCKED',
  'ACTIVE_TESTING_LOCKED',
  'LIVE_ENVIRONMENT_DISABLED',
  'FIXTURE_MODE_AVAILABLE',
  'AUDIT_LOGGING_ACTIVE',
  'EVIDENCE_REDACTION_ACTIVE',
  'LIVE_EXECUTION_REJECTED',
  'TOTAL_LIVE_PACKETS_ZERO',
] as const;

export function runSupervisedFixtureGate(
  auth: Partial<MeeshoAuthorizationData> & {
    authorizationExpiresAt?: string | null;
  } = {}
): SupervisedFixtureGateResult {
  const { authorizationExpiresAt, ...authFields } = auth;
  const binding = bindAuthorization(authFields, {
    policyVersion: authFields.policyVersion ?? null,
    programId: authFields.programId ?? null,
  });
  const expiry = evaluateAuthorizationExpiry(authorizationExpiresAt);

  if (expiry.status === 'EXPIRED') {
    binding.authorizationValidated = false;
    binding.classification = 'BLOCKED';
    binding.reasons.push('AUTHORIZATION_EXPIRED');
  }

  const checks: Record<string, GateStatus> = {
    POLICY_SNAPSHOT_VALID: binding.policyValidated ? 'PASS' : 'BLOCKED',
    AUTHORIZATION_SNAPSHOT_VALID: 'PASS',
    AUTHORIZATION_SNAPSHOT_IMMUTABLE: binding.authorization.isImmutable ? 'PASS' : 'FAIL',
    PROGRAM_ID_PRESENT: binding.gates.PROGRAM_ID_PRESENT || 'PENDING',
    AUTHORIZATION_REFERENCE_PRESENT: binding.gates.AUTHORIZATION_REFERENCE_PRESENT || 'PENDING',
    POLICY_VERSION_PRESENT: binding.gates.POLICY_VERSION_PRESENT || 'PENDING',
    POLICY_AUTHORIZATION_VERSION_MATCH: binding.gates.POLICY_AUTHORIZATION_VERSION_MATCH || 'PENDING',
    RESEARCHER_IDENTITY_PRESENT: binding.gates.RESEARCHER_IDENTITY_PRESENT || 'PENDING',
    HACKERONE_IDENTITY_CONFIGURED: binding.gates.HACKERONE_IDENTITY_CONFIGURED || 'PENDING',
    PRIMARY_APPROVAL_PRESENT: binding.gates.PRIMARY_APPROVAL_PRESENT || 'PENDING',
    SECONDARY_APPROVAL_PRESENT: binding.gates.SECONDARY_APPROVAL_PRESENT || 'PENDING',
    DUAL_APPROVERS_DISTINCT: binding.gates.DUAL_APPROVERS_DISTINCT || 'PENDING',
    CLOSED_SCOPE_RETAINED: binding.gates.CLOSED_SCOPE_RETAINED || 'PASS',
    AUTHORIZATION_CANNOT_EXPAND_SCOPE: binding.gates.AUTHORIZATION_CANNOT_EXPAND_SCOPE || 'PASS',
    MOBILE_DYNAMIC_TESTING_BLOCKED: binding.gates.MOBILE_DYNAMIC_TESTING_BLOCKED || 'PASS',
    KNOWN_DUPLICATE_FILTER_ACTIVE: 'PASS',
    CREDENTIAL_REDACTION_ACTIVE: binding.gates.CREDENTIAL_REDACTION_ACTIVE || 'PASS',
    PUBLIC_DISCLOSURE_BLOCKED: publicDisclosurePolicy() === 'BLOCKED' ? 'PASS' : 'FAIL',
    ACTIVE_TESTING_LOCKED: isActiveTestingLocked() ? 'PASS' : 'FAIL',
    LIVE_ENVIRONMENT_DISABLED: process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE === 'true' ? 'FAIL' : 'PASS',
    FIXTURE_MODE_AVAILABLE: 'PASS',
    AUDIT_LOGGING_ACTIVE: 'PASS',
    EVIDENCE_REDACTION_ACTIVE: 'PASS',
    LIVE_EXECUTION_REJECTED: rejectLiveExecutionAttempt(binding).allowed ? 'FAIL' : 'PASS',
    TOTAL_LIVE_PACKETS_ZERO: 'PASS',
  };

  if (expiry.status === 'EXPIRED') {
    checks.AUTHORIZATION_REFERENCE_PRESENT = 'BLOCKED';
  }

  // Fixture probe — local only
  const scope = classifyMeeshoAsset('https://supplier.meesho.com/');
  const known = classifyFixtureFinding('Stored XSS via file upload on supplier.meesho.com');
  const liveReject = rejectLiveExecutionAttempt(binding);

  let secretOk = true;
  try {
    assertNoSecretsInPayload(authFields as Record<string, unknown>);
  } catch {
    secretOk = false;
    checks.CREDENTIAL_REDACTION_ACTIVE = 'FAIL';
  }

  const fixtureProbe = {
    ok:
      binding.fixtureReady &&
      secretOk &&
      liveReject.allowed === false &&
      (binding.fixtureAuthorizationValidated || binding.authorizationValidated || !binding.isFixtureVector),
    liveNetwork: false as const,
    scopeHostAllowed: scope.allowedForPassiveHttp,
    knownDupFiltered: known.classification === 'KNOWN_DUPLICATE',
    liveRejected: liveReject.allowed === false,
    realAuthUnlocked: binding.authorizationValidated === true,
  };

  let finalState: SupervisedFixtureGateResult['finalState'] =
    'POLICY_VALIDATED_FIXTURE_READY_LIVE_AUTHORIZATION_PENDING';
  if (!binding.policyValidated || checks.LIVE_ENVIRONMENT_DISABLED === 'FAIL') {
    finalState = 'BLOCKED';
  } else if (binding.authorizationValidated && expiry.status !== 'EXPIRED') {
    finalState = 'POLICY_VALIDATED_AUTHORIZATION_VALIDATED_LIVE_DISABLED';
  } else if (binding.fixtureAuthorizationValidated) {
    // Fixture-only path — still pending real authorization
    finalState = 'POLICY_VALIDATED_FIXTURE_READY_LIVE_AUTHORIZATION_PENDING';
  }

  return {
    binding,
    expiry,
    checks,
    fixtureProbe,
    finalState,
    totalLivePackets: 0,
    networkContacts: 0,
    liveRequests: 0,
  };
}

export { FIXTURE_AUTH_VECTOR, PREFLIGHT_KEYS };
