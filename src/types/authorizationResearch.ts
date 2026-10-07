import { SeverityLevel } from '../types.ts';

export type AuthContextLabel =
  | 'ACCOUNT_A'
  | 'ACCOUNT_B'
  | 'STANDARD_USER'
  | 'PRIVILEGED_USER'
  | 'ADMIN_USER'
  | 'SELLER'
  | 'SUPPLIER'
  | 'GUEST'
  | 'UNAUTHENTICATED'
  | string;

export type AccountRole =
  | 'STANDARD_USER'
  | 'ADMIN_USER'
  | 'SELLER'
  | 'SUPPLIER'
  | 'GUEST'
  | 'UNAUTHENTICATED'
  | string;

export type AuthState = 'AUTHENTICATED' | 'UNAUTHENTICATED' | 'EXPIRED' | 'INVALID';

export interface AuthContext {
  contextId: string;
  contextLabel: AuthContextLabel;
  researcherId: string;
  programId: string;
  caseId: string;
  accountIdentifier: string;
  accountRole: AccountRole;
  authState: AuthState;
  credentialReference: string; // E.g. "cred-ref-user-a-01" (NEVER plaintext token or password)
  sessionReference: string;    // E.g. "sess-ref-user-a-01"
  authorizationScopes: string[];
  expiresAt?: string;
  metadata?: Record<string, any>;
}

export type ResourceSensitivity =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'CONFIDENTIAL'
  | 'RESTRICTED_PII'
  | 'FINANCIAL';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export interface ResourceModel {
  resourceType: string; // e.g. 'order', 'invoice', 'profile', 'payment_method', 'admin_settings'
  resourceId: string;   // e.g. 'order-1001', 'user-2002'
  ownerAccount: string; // e.g. 'acc-user-a'
  roleRequired?: AccountRole;
  endpointPath: string; // e.g. '/api/v1/orders/{orderId}'
  httpMethod: HttpMethod;
  expectedAuthorization: Record<string, 'ALLOW' | 'DENY'>; // e.g. { ACCOUNT_A: 'ALLOW', ACCOUNT_B: 'DENY', UNAUTHENTICATED: 'DENY' }
  sensitivity: ResourceSensitivity;
  parentResourceType?: string;
  parentResourceId?: string;
  parameters?: Record<string, any>;
  headers?: Record<string, string>;
  body?: Record<string, any>;
}

export type ResearchClass =
  | 'BOLA_IDOR'
  | 'HORIZONTAL_AUTH'
  | 'VERTICAL_ESCALATION'
  | 'UNAUTHENTICATED_ACCESS'
  | 'API_METHOD_INCONSISTENCY'
  | 'PARAMETER_OWNERSHIP';

export interface AuthorizationHypothesis {
  hypothesisId: string;
  researchClass: ResearchClass;
  title: string;
  description: string;
  targetAsset: string;
  endpoint: string;
  httpMethod: HttpMethod;
  baselineContext: AuthContext;
  comparisonContext: AuthContext;
  targetResource: ResourceModel;
  mutatedParameters?: Record<string, any>;
  expectedBaselineAuth: 'ALLOW' | 'DENY';
  expectedComparisonAuth: 'ALLOW' | 'DENY';
}

export interface DifferentialExecutionSnapshot {
  statusCode: number;
  contentType: string;
  responseHeaders: Record<string, string>;
  responseBody: any;
  responseTimeMs: number;
  observedAuth: 'ALLOW' | 'DENY';
  errorDetected: boolean;
  errorMessage?: string;
}

export type ConfidenceRating = 'LOW_CONFIDENCE' | 'MEDIUM_CONFIDENCE' | 'HIGH_CONFIDENCE';

export interface DifferentialDifferences {
  statusDiffers: boolean;
  bodyDiffers: boolean;
  sensitiveFieldsExposed: string[];
  resourceOwnershipExposed: boolean;
  privilegeBoundaryViolated: boolean;
  stateChanged: boolean;
  unauthorizedDataAccess: boolean;
}

export interface ImpactAssessment {
  confidentialityImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  integrityImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  privilegeImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  overallImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reasoning: string;
}

export interface DifferentialAnalysisResult {
  hypothesisId: string;
  researchClass: ResearchClass;
  targetAsset: string;
  endpoint: string;
  httpMethod: HttpMethod;
  resourceId: string;
  baselineContextLabel: string;
  comparisonContextLabel: string;
  baselineResult: DifferentialExecutionSnapshot;
  comparisonResult: DifferentialExecutionSnapshot;
  differences: DifferentialDifferences;
  confidence: ConfidenceRating;
  isVulnerabilityCandidate: boolean;
  vulnerabilityType?: string;
  cwe?: string;
  owasp?: string;
  explanation: string;
  impactAssessment: ImpactAssessment;
  evidenceHash?: string;
}

export interface FindingCandidate {
  candidateId: string;
  caseId: string;
  programId: string;
  targetAsset: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  confidence: number;
  cwe: string;
  owasp: string;
  whatWeFound: string;
  whyItMatters: string;
  reproductionSteps: string[];
  evidenceHash: string;
  sanitizedEvidence: Record<string, any>;
  impact: string;
  recommendedFix: string;
  createdAt: string;
}

export interface AuthorizationProvenance {
  executionId: string;
  requestId: string;
  programId: string;
  caseId: string;
  targetAsset: string;
  researchClass: string;
  baselineContextId: string;
  comparisonContextId: string;
  resourceId: string;
  timestamp: string;
  evidenceHash: string;
}

export interface AuthorizationResearchExecutionParams {
  programId: string;
  caseId: string;
  target: string;
  assetId?: string;
  researchClass: ResearchClass;
  hypotheses: AuthorizationHypothesis[];
  requestBudget?: number;
  dryRun?: boolean;
  allowLocalFixtureTarget?: boolean;
  approvalId?: string;
  cancellationToken?: { isCancelled: boolean; reason?: string };
}

export interface AuthorizationResearchExecutionResult {
  executionId: string;
  programId: string;
  programName: string;
  caseId: string;
  target: string;
  researchClass: ResearchClass;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED' | 'DENY';
  status: 'COMPLETED' | 'CANCELLED' | 'BLOCKED' | 'FAILED';
  totalRequestsExecuted: number;
  requestBudget: number;
  hypothesesEvaluated: number;
  differentialResults: DifferentialAnalysisResult[];
  findingCandidates: FindingCandidate[];
  evidenceRecords: any[];
  auditEventsRecorded: number;
  dryRun: boolean;
  executedAt: string;
  durationMs: number;
  cancellationReason?: string;
  error?: string;
}
