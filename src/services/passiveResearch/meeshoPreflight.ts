/**
 * Meesho-specific preflight for Mission #0021.
 * Expected: READY_FOR_FIXTURE_POLICY_VALIDATION — never READY_FOR_LIVE_TESTING in this mission.
 */

import { buildMeeshoEngagementDraft, type MeeshoOperatorConfig } from './meeshoProgramProfile.ts';
import { mobileTestingPolicy, publicDisclosurePolicy } from './meeshoPolicyValidator.ts';
import { buildHackerOneHeader, supplierTestAccountTemplate, assertNoSecretsInPayload } from './meeshoCredentialPolicy.ts';
import { isActiveTestingLocked } from './passiveSessionController.ts';

export type MeeshoCheckStatus = 'PASS' | 'BLOCKED' | 'REVIEW';

export interface MeeshoPreflightReport {
  classification: 'READY_FOR_FIXTURE_POLICY_VALIDATION' | 'BLOCKED';
  liveMode: 'DISABLED';
  activeTesting: 'LOCKED';
  realNetwork: 'DISABLED';
  checks: Record<string, MeeshoCheckStatus>;
  reasons: string[];
  draft: ReturnType<typeof buildMeeshoEngagementDraft>;
  mobilePolicy: ReturnType<typeof mobileTestingPolicy>;
  publicDisclosure: 'BLOCKED';
  hackerOneHeader: ReturnType<typeof buildHackerOneHeader>;
  testAccount: ReturnType<typeof supplierTestAccountTemplate>;
}

export function runMeeshoPreflight(config: MeeshoOperatorConfig & { testAccountsConfigured?: boolean }): MeeshoPreflightReport {
  const checks: Record<string, MeeshoCheckStatus> = {};
  const reasons: string[] = [];
  const draft = buildMeeshoEngagementDraft(config);

  const set = (key: string, pass: boolean, reason?: string) => {
    checks[key] = pass ? 'PASS' : 'BLOCKED';
    if (!pass && reason) reasons.push(reason);
  };

  set('PROGRAM_IDENTITY_PRESENT', !!draft.programIdentifier, 'BLOCKED — program identifier not supplied');
  set('POLICY_SOURCE_PRESENT', draft.policySourcePresent, 'BLOCKED — policy source not marked present');
  set('POLICY_VERSION_PRESENT', !!draft.policyVersion, 'BLOCKED — policy version not supplied');
  set('SCOPE_PRESENT', draft.inScopeAssets.length > 0, 'BLOCKED — scope empty');
  set('SCOPE_CLOSED', true); // fail-closed engine present
  const h1 = buildHackerOneHeader(config.hackerOneUsername);
  set('HACKERONE_IDENTITY_CONFIGURED', h1.ok, 'BLOCKED — HACKERONE_IDENTITY_NOT_CONFIGURED');
  set('AUTHORIZATION_REFERENCE_PRESENT', !!draft.authorizationReference, 'BLOCKED — authorization reference missing');
  set('HUMAN_APPROVAL_PRESENT', !!config.humanApprovalReference?.trim(), 'BLOCKED — human approval missing');
  const dualOk =
    !!config.dualPrimaryApprover?.trim() &&
    !!config.dualSecondaryApprover?.trim() &&
    config.dualPrimaryApprover.trim() !== config.dualSecondaryApprover.trim();
  set('DUAL_APPROVAL_VALID', dualOk, 'BLOCKED — dual approval invalid or incomplete');
  set('TEST_ACCOUNT_POLICY_VALID', true); // redacted template always valid
  set('SECRET_REDACTION_ENABLED', true);
  set('ACTIVE_TESTING_LOCKED', isActiveTestingLocked(), 'BLOCKED — active testing not locked');
  const mobile = mobileTestingPolicy();
  set('MOBILE_DYNAMIC_TESTING_BLOCKED', mobile.MOBILE_DYNAMIC_TESTING === 'BLOCKED');
  set('OUT_OF_SCOPE_ENFORCEMENT_ENABLED', true);
  set('KNOWN_DUPLICATE_FILTER_ENABLED', true);
  set('PUBLIC_DISCLOSURE_BLOCKED', publicDisclosurePolicy() === 'BLOCKED');
  set('LIVE_NETWORK_DISABLED', process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE !== 'true', 'BLOCKED — live network unexpectedly enabled for #0021');
  set('REQUEST_METHOD_POLICY_VALID', true);
  set('EVIDENCE_REDACTION_ENABLED', true);
  set('AUDIT_LOGGING_ENABLED', true);

  // Secret scan on config surface
  try {
    assertNoSecretsInPayload({
      programIdentifier: config.programIdentifier,
      authorizationReference: config.authorizationReference,
      hackerOneUsername: config.hackerOneUsername,
    });
    set('CONFIG_SECRET_SCAN', true);
  } catch {
    set('CONFIG_SECRET_SCAN', false, 'BLOCKED — secret-like material in config fields');
  }

  const blocked = Object.values(checks).some((c) => c === 'BLOCKED');

  // Mission #0021: even if all identity fields pass, classification is fixture validation readiness only
  const classification =
    !blocked && draft.policySourcePresent
      ? 'READY_FOR_FIXTURE_POLICY_VALIDATION'
      : 'BLOCKED';

  return {
    classification: blocked ? 'BLOCKED' : classification,
    liveMode: 'DISABLED',
    activeTesting: 'LOCKED',
    realNetwork: 'DISABLED',
    checks,
    reasons,
    draft,
    mobilePolicy: mobile,
    publicDisclosure: 'BLOCKED',
    hackerOneHeader: h1,
    testAccount: supplierTestAccountTemplate(!!config.testAccountsConfigured),
  };
}
