/**
 * DEVILHUNT — Program-Agnostic Engagement Layer Types
 * Supports clean abstraction between Generic DevilHunt Policy and Program-Specific Policy,
 * First-Program Onboarding Workflow, Fail-Closed Scope, Proxy Boundary, and Research Accounts.
 */

export type EngagementOnboardingStage =
  | 'PROGRAM_DRAFT'
  | 'POLICY_IMPORTED'
  | 'SCOPE_VALIDATED'
  | 'RULES_VALIDATED'
  | 'RESEARCHER_REVIEW'
  | 'HUMAN_APPROVAL'
  | 'READY_FOR_PASSIVE_TESTING'
  | 'ACTIVE_TESTING_AUTHORIZED';

export type ReadinessDimensionState =
  | 'READY'
  | 'BLOCKED'
  | 'MISSING'
  | 'REVIEW_REQUIRED'
  | 'NOT_CONFIGURED'
  | 'AWAITING_APPROVAL';

export type OverallReadinessStatus =
  | 'READY_FOR_PASSIVE_TESTING'
  | 'READY_WITH_RESTRICTIONS'
  | 'BLOCKED'
  | 'REVIEW_REQUIRED'
  | 'NOT_CONFIGURED';

export type EngagementPlatform =
  | 'HackerOne'
  | 'Bugcrowd'
  | 'Intigriti'
  | 'Direct'
  | 'YesWeHack'
  | 'Synack'
  | 'Self-Hosted';

export type EngagementAssetType =
  | 'DOMAIN'
  | 'SUBDOMAIN'
  | 'WILDCARD'
  | 'URL'
  | 'API_ENDPOINT'
  | 'MOBILE_APP_ANDROID'
  | 'MOBILE_APP_IOS'
  | 'SERVICE'
  | 'OTHER';

export type EngagementSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export interface GenericDevilHuntPolicy {
  version: string;
  strictLocalFirst: boolean;
  zeroLiveTrafficDefault: boolean;
  failClosedScopeEnforced: boolean;
  symbolicCredentialsOnly: boolean;
  rawSecretStorageForbidden: boolean;
  humanApprovalMandatoryForActive: boolean;
  evidenceIntegrityMandatory: boolean;
  prohibitedGlobalAttacks: string[];
}

export interface ProgramSpecificPolicy {
  allowedVulnerabilityClasses: string[];
  prohibitedTesting: string[];
  severityRestrictions: {
    maxSeverity: EngagementSeverity;
    inScopeOnly: boolean;
  };
  requestLimits: {
    numericLimitSpecified: boolean;
    rateLimitPerSecond: number;
    maxConcurrentRequests: number;
    totalSessionBudget: number;
    burstTolerance: number;
  };
  testingWindows: {
    continuousAllowed: boolean;
    allowedWindowsUtc?: Array<{
      dayOfWeek?: string;
      startHourUtc: number;
      endHourUtc: number;
    }>;
    blackoutPeriods?: Array<{
      startUtc: string;
      endUtc: string;
      reason: string;
    }>;
  };
  accountRequirements: {
    accountTiers: string[];
    researcherAccountReferences: string[];
    credentialTypeAllowed: 'SYMBOLIC_REFERENCE_ONLY';
    forbiddenCredentialPatterns: string[];
  };
  geographicRestrictions?: {
    allowedSourceRegions?: string[];
    vpnRequirement?: boolean;
    proxyRequirement: boolean;
  };
  financialStateChangingRestrictions: {
    stateChangingOperationsForbidden: boolean;
    zeroValueOrdersOnly: boolean;
    immediateCancellationRequired: boolean;
    walletOrPaymentTestingForbidden: boolean;
  };
  requiredHumanApprovals: {
    requireApprovalForActiveTesting: boolean;
    requireApprovalForHighSeverity: boolean;
    requireApprovalForStateChanging: boolean;
    requireApprovalForReportSubmission: boolean;
  };
  disclosureRequirements: {
    platformCoordinationOnly: boolean;
    publicDisclosureForbidden: boolean;
    minimumSafeHarborStatement: string;
    disclosureWindowDays?: number;
  };
}

export interface EngagementAsset {
  id: string;
  targetPattern: string;
  assetType: EngagementAssetType;
  bountyEligible: boolean;
  maxSeverity: EngagementSeverity;
  description?: string;
  allowWildcardSubdomains?: boolean;
}

export interface EngagementExcludedAsset {
  id: string;
  targetPattern: string;
  assetType: EngagementAssetType;
  reason: string;
}

export interface EngagementProgramProfile {
  id: string;
  name: string;
  handle: string;
  platform: EngagementPlatform;
  policyUrl: string;
  bountyStatus: 'BOUNTY' | 'VDP';
  rewardCeiling: string;
  contactChannel: string;
  genericPolicy: GenericDevilHuntPolicy;
  programPolicy: ProgramSpecificPolicy;
  inScopeAssets: EngagementAsset[];
  outOfScopeAssets: EngagementExcludedAsset[];
  onboardingStage: EngagementOnboardingStage;
  onboardingHistory: Array<{
    stage: EngagementOnboardingStage;
    completedAt: string;
    completedBy: string;
    notes?: string;
  }>;
}

export type ProxyConnectionStatus =
  | 'CONFIGURED'
  | 'NOT_CONFIGURED'
  | 'BURP_CONFIGURATION_NOT_AVAILABLE'
  | 'CONNECTED'
  | 'DISCONNECTED'
  | 'ERROR';

export interface ProxyBoundaryConfig {
  proxyHost?: string;
  proxyPort?: number;
  proxyProtocol?: 'http' | 'https' | 'socks5';
  caCertificateRef?: string;
  upstreamHeaders?: Record<string, string>;
  enabled: boolean;
  status: ProxyConnectionStatus;
  lastHealthCheck?: {
    timestamp: string;
    healthy: boolean;
    latencyMs?: number;
    errorMessage?: string;
  };
}

export interface ResearchAccount {
  id: string;
  symbolicIdentifier: string;
  tier: string;
  programId: string;
  label: string;
  createdAt: string;
  credentialSafetyVerified: boolean;
}

export interface ScopeValidationDecision {
  allowed: boolean;
  decision: 'ALLOW' | 'DENY' | 'REVIEW_REQUIRED' | 'BLOCK';
  target: string;
  canonicalHostname: string;
  matchedAsset?: EngagementAsset | EngagementExcludedAsset;
  reason: string;
  lookalikeDetected: boolean;
  malformedDetected: boolean;
  outOfScopeDetected: boolean;
  evaluatedAt: string;
}

export interface EngagementAuditEntry {
  id: string;
  timestamp: string;
  programId: string;
  targetAsset: string;
  researchMode: 'PASSIVE' | 'ACTIVE';
  policyEvaluationResult: 'ALLOW' | 'DENY' | 'REVIEW_REQUIRED' | 'BLOCK';
  humanApprovalReference: string | null;
  executionId: string;
  proxyCorrelationId: string;
  evidenceHash: string;
  action: string;
  details?: Record<string, any>;
}

export interface PassiveEvidenceRecord {
  id: string;
  timestamp: string;
  executionId: string;
  proxyCorrelationId: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  url: string;
  responseStatus: number;
  headers: Record<string, string>;
  bodySnippet: string;
  evidenceHash: string;
}

export interface EngagementReadinessEvaluation {
  programId: string;
  programName: string;
  scopeStatus: ReadinessDimensionState;
  policyStatus: ReadinessDimensionState;
  accountStatus: ReadinessDimensionState;
  proxyStatus: ReadinessDimensionState;
  requestBudgetStatus: ReadinessDimensionState;
  approvalStatus: ReadinessDimensionState;
  passiveModeStatus: ReadinessDimensionState;
  activeModeStatus: ReadinessDimensionState;
  evidenceSystemStatus: ReadinessDimensionState;
  reportingSystemStatus: ReadinessDimensionState;
  overallReadiness: OverallReadinessStatus;
  dimensions: Record<
    string,
    {
      status: ReadinessDimensionState;
      name: string;
      reason: string;
      details?: string[];
      recommendations?: string[];
    }
  >;
  evaluatedAt: string;
}
