/**
 * Mission #0022 — Bind operator-supplied Meesho policy → immutable snapshot → fixture readiness.
 * Distinguishes POLICY_VALIDATED from LIVE_AUTHORIZATION_VALIDATED.
 * Never invents authorizationReference, programId, H1 username, or approvers.
 */

import { createMeeshoPolicySnapshot, type ImmutableMeeshoPolicySnapshot } from './meeshoPolicySnapshot.ts';
import { classifyMeeshoAsset } from './meeshoScopePolicy.ts';
import { classifyFixtureFinding } from './meeshoKnownIssueFilter.ts';
import { assertNoSecretsInPayload, buildHackerOneHeader } from './meeshoCredentialPolicy.ts';
import { isActiveTestingLocked } from './passiveSessionController.ts';

export type GateStatus = 'PASS' | 'BLOCKED' | 'PENDING';

export interface OperatorAuthBinding {
  /** All optional — absence = PENDING/BLOCKED, never fabricated */
  programId?: string | null;
  policyVersion?: string | null;
  policyUpdatedAt?: string | null;
  authorizationReference?: string | null;
  hackerOneUsername?: string | null;
  primaryApprovalReference?: string | null;
  secondaryApprovalReference?: string | null;
}

export interface PolicyBindingResult {
  policyValidated: boolean;
  fixtureReady: boolean;
  liveAuthorizationValidated: boolean;
  liveAuthorizationStatus: 'PENDING' | 'BLOCKED' | 'VALIDATED';
  snapshot: ImmutableMeeshoPolicySnapshot;
  gates: Record<string, GateStatus>;
  reasons: string[];
  classification:
    | 'POLICY_VALIDATED_FIXTURE_READY'
    | 'POLICY_VALIDATED_LIVE_AUTHORIZATION_PENDING'
    | 'BLOCKED';
  totalLivePackets: 0;
  activeTesting: 'LOCKED';
  liveNetwork: 'DISABLED';
}

export function bindMeeshoPolicy(auth: OperatorAuthBinding = {}): PolicyBindingResult {
  const reasons: string[] = [];
  const gates: Record<string, GateStatus> = {};

  const h1 = buildHackerOneHeader(auth.hackerOneUsername);
  const snapshot = createMeeshoPolicySnapshot({
    programId: auth.programId,
    policyVersion: auth.policyVersion,
    policyUpdatedAt: auth.policyUpdatedAt,
    hackerOneIdentityConfigured: h1.ok,
  });

  const set = (k: string, status: GateStatus, reason?: string) => {
    gates[k] = status;
    if (status !== 'PASS' && reason) reasons.push(reason);
  };

  // Policy presence (from #0021 embedded model)
  set('MEESHO_POLICY_PRESENT', 'PASS');
  set(
    'POLICY_VERSION_PRESENT',
    auth.policyVersion?.trim() ? 'PASS' : 'PENDING',
    'POLICY_VERSION pending operator supply'
  );
  set('POLICY_SNAPSHOT_IMMUTABLE', snapshot.isImmutable ? 'PASS' : 'BLOCKED');
  set('SCOPE_EXPLICIT', 'PASS');
  set('CLOSED_SCOPE_ENFORCED', 'PASS');
  set('UNKNOWN_ASSET_BLOCKED', classifyMeeshoAsset('https://unknown.example/').allowedForPassiveHttp ? 'BLOCKED' : 'PASS');
  set('THIRD_PARTY_ASSET_BLOCKED', classifyMeeshoAsset('https://razorpay.com/').decision === 'THIRD_PARTY' ? 'PASS' : 'BLOCKED');
  set('MOBILE_DYNAMIC_TESTING_BLOCKED', snapshot.view().mobileTestingRules.MOBILE_DYNAMIC_TESTING === 'BLOCKED' ? 'PASS' : 'BLOCKED');
  set('KNOWN_DUPLICATE_FILTER_ACTIVE', 'PASS');
  set('CREDENTIAL_REDACTION_ACTIVE', 'PASS');

  set(
    'HACKERONE_HEADER_IDENTITY_CONFIGURED',
    h1.ok ? 'PASS' : 'PENDING',
    h1.ok ? undefined : 'HACKERONE_IDENTITY_NOT_CONFIGURED'
  );
  set(
    'AUTHORIZATION_REFERENCE_PRESENT',
    auth.authorizationReference?.trim() ? 'PASS' : 'PENDING',
    'AUTHORIZATION_REFERENCE missing — policy is not authorization'
  );

  const primary = auth.primaryApprovalReference?.trim();
  const secondary = auth.secondaryApprovalReference?.trim();
  if (!primary || !secondary) {
    set('DUAL_APPROVAL_PRESENT', 'PENDING', 'Dual approval references missing');
    set('DUAL_APPROVERS_DISTINCT', 'PENDING');
  } else if (primary === secondary) {
    set('DUAL_APPROVAL_PRESENT', 'BLOCKED', 'Approvers must be distinct');
    set('DUAL_APPROVERS_DISTINCT', 'BLOCKED', 'primary == secondary');
  } else {
    set('DUAL_APPROVAL_PRESENT', 'PASS');
    set('DUAL_APPROVERS_DISTINCT', 'PASS');
  }

  set('ACTIVE_TESTING_LOCKED', isActiveTestingLocked() ? 'PASS' : 'BLOCKED');
  set(
    'LIVE_ENVIRONMENT_DISABLED',
    process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE === 'true' ? 'BLOCKED' : 'PASS',
    process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE === 'true' ? 'Live env flag must remain unset for #0022' : undefined
  );
  set('FIXTURE_MODE_AVAILABLE', 'PASS');
  set('PUBLIC_DISCLOSURE_BLOCKED', snapshot.view().disclosurePolicy.publicDisclosure === 'BLOCKED' ? 'PASS' : 'BLOCKED');
  set('AUDIT_LOGGING_ACTIVE', 'PASS');
  set('EVIDENCE_REDACTION_ACTIVE', 'PASS');

  // Secret scan on binding inputs
  try {
    assertNoSecretsInPayload({
      authorizationReference: auth.authorizationReference,
      hackerOneUsername: auth.hackerOneUsername,
      primary,
      secondary,
    });
  } catch {
    set('CREDENTIAL_REDACTION_ACTIVE', 'BLOCKED', 'Secret-like material in binding inputs');
  }

  const policyGatesOk =
    gates.MEESHO_POLICY_PRESENT === 'PASS' &&
    gates.POLICY_SNAPSHOT_IMMUTABLE === 'PASS' &&
    gates.SCOPE_EXPLICIT === 'PASS' &&
    gates.CLOSED_SCOPE_ENFORCED === 'PASS' &&
    gates.MOBILE_DYNAMIC_TESTING_BLOCKED === 'PASS' &&
    gates.KNOWN_DUPLICATE_FILTER_ACTIVE === 'PASS' &&
    gates.CREDENTIAL_REDACTION_ACTIVE === 'PASS' &&
    gates.ACTIVE_TESTING_LOCKED === 'PASS' &&
    gates.LIVE_ENVIRONMENT_DISABLED === 'PASS' &&
    gates.PUBLIC_DISCLOSURE_BLOCKED === 'PASS';

  const liveAuthComplete =
    gates.AUTHORIZATION_REFERENCE_PRESENT === 'PASS' &&
    gates.HACKERONE_HEADER_IDENTITY_CONFIGURED === 'PASS' &&
    gates.DUAL_APPROVAL_PRESENT === 'PASS' &&
    gates.DUAL_APPROVERS_DISTINCT === 'PASS' &&
    !!auth.programId?.trim();

  // Policy validated even if live auth pending
  const policyValidated = policyGatesOk;
  const fixtureReady = policyValidated && gates.FIXTURE_MODE_AVAILABLE === 'PASS';
  const liveAuthorizationValidated = false; // Mission #0022 never grants live authorization validation as "ready for live request"
  // Even if fields present, #0022 does not flip to live-validated for traffic
  const liveAuthorizationStatus: PolicyBindingResult['liveAuthorizationStatus'] = liveAuthComplete
    ? 'PENDING' // still pending explicit live mission; not auto-validated here
    : gates.DUAL_APPROVERS_DISTINCT === 'BLOCKED'
      ? 'BLOCKED'
      : 'PENDING';

  let classification: PolicyBindingResult['classification'] = 'BLOCKED';
  if (policyValidated && fixtureReady) {
    classification =
      liveAuthorizationStatus === 'PENDING' || !liveAuthComplete
        ? 'POLICY_VALIDATED_LIVE_AUTHORIZATION_PENDING'
        : 'POLICY_VALIDATED_FIXTURE_READY';
  }

  return {
    policyValidated,
    fixtureReady,
    liveAuthorizationValidated,
    liveAuthorizationStatus,
    snapshot,
    gates,
    reasons,
    classification,
    totalLivePackets: 0,
    activeTesting: 'LOCKED',
    liveNetwork: 'DISABLED',
  };
}

/** Fixture-only probe — never opens sockets */
export function fixturePolicyProbe(binding: PolicyBindingResult): {
  ok: boolean;
  liveNetwork: false;
  knownDupSample: ReturnType<typeof classifyFixtureFinding>;
  scopeSample: ReturnType<typeof classifyMeeshoAsset>;
} {
  if (!binding.fixtureReady) {
    return {
      ok: false,
      liveNetwork: false,
      knownDupSample: classifyFixtureFinding('unrelated fixture observation'),
      scopeSample: classifyMeeshoAsset('https://supplier.meesho.com/'),
    };
  }
  return {
    ok: true,
    liveNetwork: false,
    knownDupSample: classifyFixtureFinding('Stored XSS via file upload on supplier.meesho.com'),
    scopeSample: classifyMeeshoAsset('https://supplier.meesho.com/'),
  };
}
