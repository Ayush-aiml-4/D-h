/**
 * Living Program Configuration Model (Operational Spec v1)
 * PENDING fields must never coerce to YES/authorized.
 */

export type RewardModel = 'PENDING' | 'A_PAID' | 'B_VDP' | 'C_SELECTED' | 'D_NOT_DECIDED';
export type SpecialAuthClass =
  | 'admin'
  | 'staging'
  | 'mobile_dynamic'
  | 'api_fuzzing'
  | 'high_volume'
  | 'partner'
  | 'internal'
  | 'physical';
export type SpecialAuthDecision = 'PENDING' | 'IN_SCOPE' | 'PRIOR_WRITTEN_AUTH' | 'OUT_OF_SCOPE';

export interface AllowlistEntry {
  id: string;
  type: 'domain' | 'wildcard' | 'api' | 'mobile' | 'ip' | 'cidr' | 'repo';
  /** Exact host, wildcard pattern (e.g. *.example.test), package id, CIDR, or repo slug */
  value: string;
  /** Optional path prefix constraint */
  pathPrefix?: string;
}

export interface ProgramConfig {
  // Identity
  Q1_programName: string | null; // PENDING if null
  Q2_legalEntity: string | null;
  Q3_publicDescription: string | null;

  // Scope
  Q4_authorizedAssets: AllowlistEntry[];
  /** EMPTY | PARTIAL | COMPLETE — complete only when full HackerOne In-Scope register is verified */
  Q4_registerStatus: 'EMPTY' | 'PARTIAL' | 'COMPLETE';
  Q5_allowlistOnly: true; // confirmed
  Q6_intentionalThirdPartyInScope: AllowlistEntry[] | null; // null = unresolved

  // Special auth matrix
  Q7_Q14_specialAuth: Record<SpecialAuthClass, SpecialAuthDecision>;

  // Auth (detail pending)
  Q15_selfRegistration: 'PENDING' | 'YES' | 'NO';
  Q16_programTestAccounts: 'PENDING' | 'YES' | 'NO';
  Q17_multiAccount: 'PENDING' | 'YES' | 'NO';
  Q18_privEscOwnAccounts: 'PENDING' | 'YES' | 'NO';
  Q19_mfaTesting: 'PENDING' | 'YES' | 'NO';
  Q20_ssoTesting: 'PENDING' | 'YES' | 'NO' | 'APP_INTEGRATION_ONLY';

  // Testing
  Q21_reasonableScanningInScopeOnly: true; // confirmed
  Q22_numericRateLimits: null; // none confirmed
  Q23_authenticatedScanners: 'PENDING' | 'YES' | 'NO';
  Q24_passwordResetTesting: 'PENDING' | 'YES' | 'NO';
  Q25_emailSmsTesting: 'PENDING' | 'YES' | 'NO';
  Q26_webhookTesting: 'PENDING' | 'YES' | 'NO';

  // Researcher ID
  Q27_customHeaderRequired: boolean;
  /** e.g. X-Hackerone — value is researcher HackerOne username, never stored as secret */
  Q27_headerName: string | null;
  Q27_headerValueTemplate: string | null; // e.g. <h1-username>
  Q28_userAgentRequired: boolean;
  Q29_otherIdRequired: boolean;

  // Rewards
  Q30_rewardModel: RewardModel;
  /** Informational displayed ranges only — not guaranteed payouts */
  Q31_bountyStructure: Record<string, unknown> | null;
  Q32_discretionaryBonuses: 'PENDING' | 'YES' | 'NO';
  Q33_exceptionalBonuses: 'PENDING' | 'YES' | 'NO';

  // Safe harbor / optional
  Q34_safeHarbor: 'A_STANDARD_GOOD_FAITH';
  Q35_aiResearchSafeHarbor: 'NOT_DECIDED';
  Q36_leakedCredentialsExemplary: 'NOT_DECIDED';

  // Disclosure
  Q37_postRemediationDisclosure: 'PENDING' | 'A' | 'B' | 'C' | 'D';
  Q38_disclosureTimeline: null;
  Q39_thirdPartyCoordBeforePublic: true;

  // Governance
  Q40_policyOwner: string | null;
  Q41_securityContact: string | null;
  Q42_policyVersion: string | null;
  Q43_effectiveDate: string | null;
  Q44_reviewFrequency: string | null;

  /** Non-authorizing evidence notes (metrics, features, registration guidance) */
  programNotes: {
    platform?: string;
    websiteShown?: string;
    programLaunchShown?: string;
    closedScope?: boolean;
    features?: string[];
    mobileTestingNote?: string;
    accountRegistrationGuidance?: string;
    displayedMetrics?: Record<string, string>;
    q4CategoryNotes?: string[];
    testAccountsAvailable?: boolean;
    testAccountStorage?: string;
  };
}

export const DEFAULT_SPECIAL_AUTH: Record<SpecialAuthClass, SpecialAuthDecision> = {
  admin: 'PENDING',
  staging: 'PENDING',
  mobile_dynamic: 'PENDING',
  api_fuzzing: 'PENDING',
  high_volume: 'PENDING',
  partner: 'PENDING',
  internal: 'PENDING',
  physical: 'PENDING',
};

/** Canonical living config — confirmed values fixed; rest PENDING */
export function createDefaultProgramConfig(): ProgramConfig {
  return {
    Q1_programName: null,
    Q2_legalEntity: null,
    Q3_publicDescription: null,
    Q4_authorizedAssets: [],
    Q4_registerStatus: 'EMPTY',
    Q5_allowlistOnly: true,
    Q6_intentionalThirdPartyInScope: null,
    Q7_Q14_specialAuth: { ...DEFAULT_SPECIAL_AUTH },
    Q15_selfRegistration: 'PENDING',
    Q16_programTestAccounts: 'PENDING',
    Q17_multiAccount: 'PENDING',
    Q18_privEscOwnAccounts: 'PENDING',
    Q19_mfaTesting: 'PENDING',
    Q20_ssoTesting: 'PENDING',
    Q21_reasonableScanningInScopeOnly: true,
    Q22_numericRateLimits: null,
    Q23_authenticatedScanners: 'PENDING',
    Q24_passwordResetTesting: 'PENDING',
    Q25_emailSmsTesting: 'PENDING',
    Q26_webhookTesting: 'PENDING',
    Q27_customHeaderRequired: false,
    Q27_headerName: null,
    Q27_headerValueTemplate: null,
    Q28_userAgentRequired: false,
    Q29_otherIdRequired: false,
    Q30_rewardModel: 'D_NOT_DECIDED',
    Q31_bountyStructure: null,
    Q32_discretionaryBonuses: 'PENDING',
    Q33_exceptionalBonuses: 'PENDING',
    Q34_safeHarbor: 'A_STANDARD_GOOD_FAITH',
    Q35_aiResearchSafeHarbor: 'NOT_DECIDED',
    Q36_leakedCredentialsExemplary: 'NOT_DECIDED',
    Q37_postRemediationDisclosure: 'PENDING',
    Q38_disclosureTimeline: null,
    Q39_thirdPartyCoordBeforePublic: true,
    Q40_policyOwner: null,
    Q41_securityContact: null,
    Q42_policyVersion: null,
    Q43_effectiveDate: null,
    Q44_reviewFrequency: null,
    programNotes: {},
  };
}

export const BOUNTY_STATUS_DEFERRED = 'DEFERRED — PROGRAM REWARD MODEL NOT CONFIGURED';
export const BOUNTY_STATUS_CONFIGURED_PAID = 'CONFIGURED — PAID BUG BOUNTY';

export type FieldCategory = 'CONFIRMED' | 'PENDING_OWNER_INPUT' | 'DERIVED' | 'OPTIONAL_NOT_ENABLED';

export function categorizeField(key: keyof ProgramConfig, cfg: ProgramConfig): FieldCategory {
  const confirmedKeys: (keyof ProgramConfig)[] = [
    'Q5_allowlistOnly',
    'Q21_reasonableScanningInScopeOnly',
    'Q27_customHeaderRequired',
    'Q28_userAgentRequired',
    'Q29_otherIdRequired',
    'Q34_safeHarbor',
    'Q39_thirdPartyCoordBeforePublic',
  ];
  if (confirmedKeys.includes(key)) return 'CONFIRMED';
  if (key === 'Q35_aiResearchSafeHarbor' || key === 'Q36_leakedCredentialsExemplary') {
    return 'OPTIONAL_NOT_ENABLED';
  }
  if (key === 'Q30_rewardModel' && cfg.Q30_rewardModel === 'D_NOT_DECIDED') return 'PENDING_OWNER_INPUT';
  const v = cfg[key];
  if (key === 'Q4_authorizedAssets') {
    if (!cfg.Q4_authorizedAssets.length) return 'PENDING_OWNER_INPUT';
    if (cfg.Q4_registerStatus === 'PARTIAL') return 'PENDING_OWNER_INPUT'; // partial register
    if (cfg.Q4_registerStatus === 'COMPLETE') return 'CONFIRMED';
  }
  if (key === 'Q4_registerStatus' && cfg.Q4_registerStatus === 'PARTIAL') return 'PENDING_OWNER_INPUT';
  if (v === null || v === 'PENDING') {
    /* fall through */
  }
  if (v === null || v === 'PENDING' || v === 'D_NOT_DECIDED' || v === 'NOT_DECIDED') return 'PENDING_OWNER_INPUT';
  if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
    const allPending = Object.values(v as Record<string, string>).every((x) => x === 'PENDING');
    if (allPending) return 'PENDING_OWNER_INPUT';
  }
  return 'CONFIRMED';
}
