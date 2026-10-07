export type AssetType =
  | 'DOMAIN'
  | 'SUBDOMAIN'
  | 'WILDCARD'
  | 'URL'
  | 'API_ENDPOINT'
  | 'MOBILE_APP_ANDROID'
  | 'MOBILE_APP_IOS'
  | 'SERVICE'
  | 'OTHER';

export type MaximumSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export type AuthorizationDecision =
  | 'ALLOW'
  | 'DENY'
  | 'REVIEW_REQUIRED'
  | 'BLOCK';

export interface InScopeAsset {
  id: string;
  targetPattern: string;
  assetType: AssetType;
  bountyEligible: boolean;
  maxSeverity: MaximumSeverity;
  description?: string;
  specialInstructions?: string;
  operationalConstraints?: string[];
}

export interface OutOfScopeAsset {
  id: string;
  targetPattern: string;
  assetType: AssetType;
  reason: string;
  isWildcardIneligible?: boolean;
}

export interface OperationalConstraint {
  id: string;
  targetPattern: string;
  constraintType:
    | 'LOCATION_RESTRICTION'
    | 'CANCELLATION_WINDOW'
    | 'RATE_LIMIT_POLICY'
    | 'SPECIAL_CREDENTIALS'
    | 'GENERAL';
  name: string;
  description: string;
  mandatoryWarning: string;
}

export type FindingEligibilityClassification =
  | 'HACKERONE_CORE_INELIGIBLE'
  | 'MEESHO_EXCLUSION'
  | 'IMPACT_DEPENDENT'
  | 'QUALIFYING';

export interface FindingEligibilityRule {
  id: string;
  vulnerabilityCategory: string;
  cwe?: string;
  classification: FindingEligibilityClassification;
  eligible: boolean;
  reason: string;
  impactRequirement?: string;
  conditions?: string[];
}

export interface ProgramProfile {
  id: string;
  handle: string;
  name: string;
  platform: 'HackerOne' | 'Bugcrowd' | 'Intigriti' | 'Direct' | 'Self-Hosted';
  policyUrl: string;
  rewardCeiling: string;
  status: 'ACTIVE' | 'PAUSED' | 'ARCHIVED';
  description?: string;
  inScopeAssets: InScopeAsset[];
  outOfScopeAssets: OutOfScopeAsset[];
  operationalConstraints: OperationalConstraint[];
  findingEligibilityRules: FindingEligibilityRule[];
  rateLimitPolicy: {
    numericLimitSpecified: false;
    description: string;
  };
  hazardousOperationsRequireAuthorization?: string[];
  prohibitedOperations?: string[];
  sensitiveOperations?: string[];
}

export interface ScopeResolutionResult {
  decision: AuthorizationDecision;
  target: string;
  programId: string;
  matchedAsset?: InScopeAsset | OutOfScopeAsset;
  isBountyEligible: boolean;
  maxSeverity?: MaximumSeverity;
  operationalWarnings: string[];
  reason: string;
  evaluatedAt: string;
}

export interface FindingEligibilityEvaluationResult {
  programId: string;
  vulnerabilityTitle: string;
  category: string;
  classification: FindingEligibilityClassification;
  isEligible: boolean;
  matchedRule?: FindingEligibilityRule;
  disqualificationReason?: string;
  impactRequirement?: string;
  evaluatedAt: string;
}

export interface DryRunExecutionParams {
  programId: string;
  target: string;
  capabilityId: string;
  operation?: string;
  simulatedPayload?: string;
}

export interface DryRunExecutionResult {
  dryRun: true;
  target: string;
  capabilityId: string;
  programId: string;
  scopeResolution: ScopeResolutionResult;
  policyDecision: AuthorizationDecision;
  simulatedNetworkTraffic: false;
  reproductionStepsSimulated: string[];
  warnings: string[];
  auditLogged: boolean;
  evaluatedAt: string;
}
