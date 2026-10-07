/**
 * Mission #0022 — Immutable Meesho policy snapshot.
 * Mutation after freeze fails deterministically. No invented auth/program IDs.
 */

import {
  MEESHO_PROGRAM_NAME,
  MEESHO_PLATFORM,
  MEESHO_IN_SCOPE_ASSETS,
  MEESHO_EXPLICIT_HOSTS,
  MEESHO_BOUNTY_MOBILE,
  MEESHO_BOUNTY_WEB_PLATFORM,
  MEESHO_POLICY_META,
  type MeeshoScopedAsset,
  type MeeshoBountyBand,
} from './meeshoProgramProfile.ts';
import {
  MEESHO_EXPLICIT_EXCLUSIONS,
  MEESHO_SUPPLIER_CONSTRAINTS,
  MEESHO_KNOWN_DUPLICATES,
  MEESHO_TESTING_RESTRICTIONS,
  mobileTestingPolicy,
  publicDisclosurePolicy,
  type PolicyConstraint,
} from './meeshoPolicyValidator.ts';

export interface MeeshoPolicySnapshotData {
  programName: string;
  platform: 'HackerOne';
  /** MISSING unless operator configures — never invented */
  programId: string | null;
  policyVersion: string | null;
  policyUpdatedAt: string | null;
  bountyUpdatedAt: string;
  scopePolicy: {
    labeledAssets: MeeshoScopedAsset[];
    explicitHosts: string[];
    closedScope: true;
    noWildcardInference: true;
  };
  excludedAssets: string[];
  excludedFindings: PolicyConstraint[];
  knownIssues: PolicyConstraint[];
  testingRestrictions: PolicyConstraint[];
  disclosurePolicy: { publicDisclosure: 'BLOCKED'; channel: string };
  safeHarbor: {
    note: string;
    outsideScopeNeverAuthorized: true;
  };
  mobileTestingRules: {
    MOBILE_STATIC_ANALYSIS: 'POLICY_ALLOWED';
    MOBILE_DYNAMIC_TESTING: 'BLOCKED';
  };
  supplierPanelRules: PolicyConstraint[];
  credentialPolicy: {
    usernameRepresentation: 'REDACTED';
    passwordRepresentation: 'SECRET_REF';
    neverPersistRawSecrets: true;
  };
  requestHeaderRequirements: {
    headerName: 'X-Hackerone';
    identityRequired: true;
    identityConfigured: boolean;
  };
  bountyRanges: {
    mobile: MeeshoBountyBand[];
    webPlatform: MeeshoBountyBand[];
    notGuaranteedPayment: true;
  };
  communicationRequirements: {
    channel: 'HackerOne';
    publicDisclosureBlocked: true;
  };
  liveNetwork: 'DISABLED';
  fixtureMode: 'ENABLED';
  activeTesting: 'LOCKED';
}

export class ImmutableMeeshoPolicySnapshot {
  private readonly data: MeeshoPolicySnapshotData;
  private frozen = false;

  constructor(data: MeeshoPolicySnapshotData) {
    this.data = structuredClone(data);
    Object.freeze(this.data);
    Object.freeze(this.data.scopePolicy);
    Object.freeze(this.data.scopePolicy.labeledAssets);
    Object.freeze(this.data.scopePolicy.explicitHosts);
    Object.freeze(this.data.excludedFindings);
    Object.freeze(this.data.knownIssues);
    Object.freeze(this.data.testingRestrictions);
    Object.freeze(this.data.supplierPanelRules);
    Object.freeze(this.data.mobileTestingRules);
    Object.freeze(this.data.credentialPolicy);
    Object.freeze(this.data.requestHeaderRequirements);
    Object.freeze(this.data.bountyRanges);
    Object.freeze(this.data.disclosurePolicy);
    Object.freeze(this.data.safeHarbor);
    Object.freeze(this.data.communicationRequirements);
    this.frozen = true;
  }

  get isImmutable(): boolean {
    return this.frozen;
  }

  /** Read-only view */
  view(): Readonly<MeeshoPolicySnapshotData> {
    return this.data;
  }

  /**
   * Any mutation attempt fails deterministically.
   */
  attemptMutation(_key: string, _value: unknown): never {
    throw new Error('POLICY_SNAPSHOT_IMMUTABLE: mutation rejected');
  }
}

export interface SnapshotBuildInput {
  programId?: string | null;
  policyVersion?: string | null;
  policyUpdatedAt?: string | null;
  hackerOneIdentityConfigured?: boolean;
}

export function createMeeshoPolicySnapshot(input: SnapshotBuildInput = {}): ImmutableMeeshoPolicySnapshot {
  const mobile = mobileTestingPolicy();
  const data: MeeshoPolicySnapshotData = {
    programName: MEESHO_PROGRAM_NAME,
    platform: MEESHO_PLATFORM,
    programId: input.programId?.trim() || null,
    policyVersion: input.policyVersion?.trim() || null,
    policyUpdatedAt: input.policyUpdatedAt?.trim() || null,
    bountyUpdatedAt: MEESHO_POLICY_META.bountyUpdateEffective,
    scopePolicy: {
      labeledAssets: MEESHO_IN_SCOPE_ASSETS.map((a) => ({ ...a })),
      explicitHosts: [...MEESHO_EXPLICIT_HOSTS],
      closedScope: true,
      noWildcardInference: true,
    },
    excludedAssets: [
      'third-party/vendor systems',
      'payment providers',
      'analytics providers',
      'customer-support platforms',
      'internal systems',
      'employee-only tools',
      'staging/development (unless explicitly in scope)',
      'subsidiaries/parents/affiliates (unless explicitly stated)',
      'unlisted Meesho hosts (no *.meesho.com inference)',
    ],
    excludedFindings: [...MEESHO_EXPLICIT_EXCLUSIONS],
    knownIssues: [...MEESHO_KNOWN_DUPLICATES],
    testingRestrictions: [...MEESHO_TESTING_RESTRICTIONS],
    disclosurePolicy: {
      publicDisclosure: publicDisclosurePolicy(),
      channel: MEESHO_POLICY_META.coordinatedDisclosureChannel,
    },
    safeHarbor: {
      note: 'Safe harbor never authorizes out-of-scope assets; unclear actions → REQUIRES_OPERATOR_CLARIFICATION',
      outsideScopeNeverAuthorized: true,
    },
    mobileTestingRules: {
      MOBILE_STATIC_ANALYSIS: mobile.MOBILE_STATIC_ANALYSIS,
      MOBILE_DYNAMIC_TESTING: mobile.MOBILE_DYNAMIC_TESTING,
    },
    supplierPanelRules: [...MEESHO_SUPPLIER_CONSTRAINTS],
    credentialPolicy: {
      usernameRepresentation: 'REDACTED',
      passwordRepresentation: 'SECRET_REF',
      neverPersistRawSecrets: true,
    },
    requestHeaderRequirements: {
      headerName: 'X-Hackerone',
      identityRequired: true,
      identityConfigured: input.hackerOneIdentityConfigured === true,
    },
    bountyRanges: {
      mobile: MEESHO_BOUNTY_MOBILE.map((b) => ({ ...b })),
      webPlatform: MEESHO_BOUNTY_WEB_PLATFORM.map((b) => ({ ...b })),
      notGuaranteedPayment: true,
    },
    communicationRequirements: {
      channel: 'HackerOne',
      publicDisclosureBlocked: true,
    },
    liveNetwork: 'DISABLED',
    fixtureMode: 'ENABLED',
    activeTesting: 'LOCKED',
  };

  return new ImmutableMeeshoPolicySnapshot(data);
}
