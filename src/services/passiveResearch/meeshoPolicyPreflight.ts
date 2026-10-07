/**
 * Mission #0022 preflight — re-export binding gates as explicit 20-check report.
 */

import { bindMeeshoPolicy, type OperatorAuthBinding, type GateStatus } from './meeshoPolicyBinding.ts';

export interface MeeshoPolicyPreflightReport {
  checks: Record<string, GateStatus>;
  policyValidated: boolean;
  fixtureReady: boolean;
  liveAuthorizationStatus: 'PENDING' | 'BLOCKED' | 'VALIDATED';
  classification: string;
  liveMode: 'DISABLED';
  totalLivePackets: 0;
  reasons: string[];
}

const CHECK_ORDER = [
  'MEESHO_POLICY_PRESENT',
  'POLICY_VERSION_PRESENT',
  'POLICY_SNAPSHOT_IMMUTABLE',
  'SCOPE_EXPLICIT',
  'CLOSED_SCOPE_ENFORCED',
  'UNKNOWN_ASSET_BLOCKED',
  'THIRD_PARTY_ASSET_BLOCKED',
  'MOBILE_DYNAMIC_TESTING_BLOCKED',
  'KNOWN_DUPLICATE_FILTER_ACTIVE',
  'CREDENTIAL_REDACTION_ACTIVE',
  'HACKERONE_HEADER_IDENTITY_CONFIGURED',
  'AUTHORIZATION_REFERENCE_PRESENT',
  'DUAL_APPROVAL_PRESENT',
  'DUAL_APPROVERS_DISTINCT',
  'ACTIVE_TESTING_LOCKED',
  'LIVE_ENVIRONMENT_DISABLED',
  'FIXTURE_MODE_AVAILABLE',
  'PUBLIC_DISCLOSURE_BLOCKED',
  'AUDIT_LOGGING_ACTIVE',
  'EVIDENCE_REDACTION_ACTIVE',
] as const;

export function runMeeshoPolicyPreflight(auth: OperatorAuthBinding = {}): MeeshoPolicyPreflightReport {
  const binding = bindMeeshoPolicy(auth);
  const checks: Record<string, GateStatus> = {};
  for (const k of CHECK_ORDER) {
    checks[k] = binding.gates[k] || 'PENDING';
  }
  return {
    checks,
    policyValidated: binding.policyValidated,
    fixtureReady: binding.fixtureReady,
    liveAuthorizationStatus: binding.liveAuthorizationStatus,
    classification: binding.classification,
    liveMode: 'DISABLED',
    totalLivePackets: 0,
    reasons: binding.reasons,
  };
}

export { CHECK_ORDER };
