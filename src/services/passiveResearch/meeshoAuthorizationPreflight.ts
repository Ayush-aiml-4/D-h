/**
 * Mission #0023 authorization preflight — 25 checks, never auto-enables live.
 */

import { bindAuthorization, type GateStatus } from './meeshoAuthorizationBinding.ts';
import type { MeeshoAuthorizationData } from './meeshoAuthorizationSnapshot.ts';

export const AUTH_PREFLIGHT_CHECKS = [
  'POLICY_SNAPSHOT_AVAILABLE',
  'POLICY_SNAPSHOT_IMMUTABLE',
  'AUTHORIZATION_SNAPSHOT_AVAILABLE',
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
  'TOTAL_LIVE_PACKETS_ZERO',
] as const;

export interface AuthPreflightReport {
  checks: Record<string, GateStatus>;
  policyValidated: boolean;
  authorizationValidated: boolean;
  liveExecutionEnabled: false;
  classification: string;
  totalLivePackets: 0;
  reasons: string[];
}

export function runAuthorizationPreflight(
  auth: Partial<MeeshoAuthorizationData> = {}
): AuthPreflightReport {
  const ctx = bindAuthorization(auth);
  const checks: Record<string, GateStatus> = {};
  for (const k of AUTH_PREFLIGHT_CHECKS) {
    checks[k] = ctx.gates[k] || 'PENDING';
  }
  return {
    checks,
    policyValidated: ctx.policyValidated,
    authorizationValidated: ctx.authorizationValidated,
    liveExecutionEnabled: false,
    classification: ctx.classification,
    totalLivePackets: 0,
    reasons: ctx.reasons,
  };
}
