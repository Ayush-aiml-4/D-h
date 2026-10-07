/**
 * Mission #0021 — Meesho HackerOne program profile (operator-supplied policy only).
 * Does NOT invent domains, auth refs, HackerOne usernames, or credentials.
 * Concrete host from supplied policy: supplier.meesho.com
 * "Meesho Web" / mobile apps are labeled assets; exact web hosts require operator clarification if not listed.
 */

export const MEESHO_PROGRAM_NAME = 'Meesho Bug Bounty Program';
export const MEESHO_PLATFORM = 'HackerOne' as const;

/** Policy metadata preserved from operator-supplied document */
export const MEESHO_POLICY_META = {
  bountyUpdateEffective: '19 Aug 2026',
  severityModel: 'CVSS',
  finalBountyAuthority: 'Meesho Security team',
  publicDisclosure: 'BLOCKED' as const,
  coordinatedDisclosureChannel: 'HackerOne',
};

export type MeeshoAssetKind = 'WEB_LABEL' | 'MOBILE_APP' | 'WEB_HOST';

export interface MeeshoScopedAsset {
  id: string;
  label: string;
  kind: MeeshoAssetKind;
  /** Only set when the policy names a concrete host */
  host?: string;
  notes?: string;
}

/**
 * IN-SCOPE as listed by the operator-supplied policy.
 * No assumption that every Meesho-owned domain is in scope.
 */
export const MEESHO_IN_SCOPE_ASSETS: MeeshoScopedAsset[] = [
  {
    id: 'meesho-web',
    label: 'Meesho Web',
    kind: 'WEB_LABEL',
    notes: 'Policy lists "Meesho Web" without enumerating every hostname — exact hosts REQUIRE_OPERATOR_CLARIFICATION before live HTTP',
  },
  {
    id: 'meesho-android',
    label: 'Meesho Android App',
    kind: 'MOBILE_APP',
    notes: 'Mobile: STATIC ANALYSIS only per policy',
  },
  {
    id: 'meesho-ios',
    label: 'Meesho iOS App',
    kind: 'MOBILE_APP',
    notes: 'Mobile: STATIC ANALYSIS only per policy',
  },
  {
    id: 'valmo-mobile',
    label: 'Valmo Mobile App',
    kind: 'MOBILE_APP',
    notes: 'Mobile: STATIC ANALYSIS only per policy',
  },
  {
    id: 'supplier-meesho',
    label: 'supplier.meesho.com',
    kind: 'WEB_HOST',
    host: 'supplier.meesho.com',
  },
];

/** Explicit concrete hosts derivable without invention */
export const MEESHO_EXPLICIT_HOSTS: string[] = ['supplier.meesho.com'];

export interface MeeshoBountyBand {
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  minUsd: number;
  maxUsd: number;
}

export const MEESHO_BOUNTY_MOBILE: MeeshoBountyBand[] = [
  { severity: 'Low', minUsd: 100, maxUsd: 500 },
  { severity: 'Medium', minUsd: 500, maxUsd: 1000 },
  { severity: 'High', minUsd: 1000, maxUsd: 2500 },
  { severity: 'Critical', minUsd: 2500, maxUsd: 3500 },
];

export const MEESHO_BOUNTY_WEB_PLATFORM: MeeshoBountyBand[] = [
  { severity: 'Low', minUsd: 100, maxUsd: 500 },
  { severity: 'Medium', minUsd: 500, maxUsd: 1000 },
  { severity: 'High', minUsd: 1000, maxUsd: 2000 },
  { severity: 'Critical', minUsd: 2500, maxUsd: 3000 },
];

export interface MeeshoOperatorConfig {
  /** Operator must supply — never invent */
  programIdentifier?: string | null;
  authorizationReference?: string | null;
  policySourcePresent: boolean;
  policyVersion?: string | null;
  hackerOneUsername?: string | null;
  humanApprovalReference?: string | null;
  dualPrimaryApprover?: string | null;
  dualSecondaryApprover?: string | null;
}

export interface MeeshoTestAccountRef {
  credentialType: string;
  accountPurpose: string;
  asset: string;
  username: 'REDACTED';
  password: 'SECRET_REF';
  status: 'OPERATOR_PROVIDED' | 'NOT_CONFIGURED';
  secretReference: string;
}

/**
 * Represent test accounts without storing secrets.
 * status NOT_CONFIGURED unless operator marks presence without values.
 */
export function createRedactedTestAccountRef(params: {
  credentialType: string;
  accountPurpose: string;
  asset: string;
  configured: boolean;
}): MeeshoTestAccountRef {
  return {
    credentialType: params.credentialType,
    accountPurpose: params.accountPurpose,
    asset: params.asset,
    username: 'REDACTED',
    password: 'SECRET_REF',
    status: params.configured ? 'OPERATOR_PROVIDED' : 'NOT_CONFIGURED',
    secretReference: `secret-ref:${params.credentialType}:${params.asset}`,
  };
}

export function buildMeeshoEngagementDraft(config: MeeshoOperatorConfig): {
  programName: string;
  platform: typeof MEESHO_PLATFORM;
  programIdentifier: string | null;
  authorizationReference: string | null;
  policyVersion: string | null;
  policySourcePresent: boolean;
  inScopeAssets: MeeshoScopedAsset[];
  explicitHosts: string[];
  bountyMobile: MeeshoBountyBand[];
  bountyWeb: MeeshoBountyBand[];
  policyMeta: typeof MEESHO_POLICY_META;
  missingFields: string[];
} {
  const missing: string[] = [];
  if (!config.programIdentifier?.trim()) missing.push('programIdentifier');
  if (!config.authorizationReference?.trim()) missing.push('authorizationReference');
  if (!config.policySourcePresent) missing.push('policySource');
  if (!config.policyVersion?.trim()) missing.push('policyVersion');
  if (!config.hackerOneUsername?.trim()) missing.push('hackerOneUsername');

  return {
    programName: MEESHO_PROGRAM_NAME,
    platform: MEESHO_PLATFORM,
    programIdentifier: config.programIdentifier?.trim() || null,
    authorizationReference: config.authorizationReference?.trim() || null,
    policyVersion: config.policyVersion?.trim() || null,
    policySourcePresent: config.policySourcePresent,
    inScopeAssets: MEESHO_IN_SCOPE_ASSETS.map((a) => ({ ...a })),
    explicitHosts: [...MEESHO_EXPLICIT_HOSTS],
    bountyMobile: MEESHO_BOUNTY_MOBILE.map((b) => ({ ...b })),
    bountyWeb: MEESHO_BOUNTY_WEB_PLATFORM.map((b) => ({ ...b })),
    policyMeta: { ...MEESHO_POLICY_META },
    missingFields: missing,
  };
}
