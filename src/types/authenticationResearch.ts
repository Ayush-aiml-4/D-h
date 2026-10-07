import { SeverityLevel } from '../types.ts';
import { AuthContext, HttpMethod } from './authorizationResearch.ts';

export type AuthenticationState =
  | 'UNAUTHENTICATED'
  | 'AUTHENTICATED_STANDARD'
  | 'AUTHENTICATED_PRIVILEGED'
  | 'SESSION_EXPIRED'
  | 'SESSION_INVALIDATED'
  | 'SESSION_REVOKED';

export type SessionState = 'ACTIVE' | 'EXPIRED' | 'INVALIDATED' | 'REVOKED';

export interface SessionModel {
  sessionId: string;
  sessionReference: string; // e.g. "sess-ref-user-a-01" (NEVER raw token)
  accountIdentifier: string;
  accountRole: string;
  state: SessionState;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  invalidatedAt?: string;
  credentialReference: string; // e.g. "cred-ref-user-a-01" (NEVER raw password/token)
  metadata?: Record<string, any>;
}

export type AuthenticationResearchClass =
  | 'AUTHENTICATION_BOUNDARY'
  | 'SESSION_ISOLATION'
  | 'SESSION_INVALIDATION'
  | 'PRIVILEGE_STATE_TRANSITION'
  | 'INPUT_XSS'
  | 'INPUT_INJECTION'
  | 'INPUT_PATH_TRAVERSAL'
  | 'INPUT_VALIDATION_DIFFERENTIAL';

export type InputParameterType = 'QUERY' | 'PATH' | 'JSON_BODY' | 'FORM' | 'HEADER';

export type PayloadSafetyClass =
  | 'PASSIVE_MARKER'
  | 'REFLECTION_MARKER'
  | 'CONTEXT_TEST'
  | 'ENCODING_TEST'
  | 'BOUNDARY_TEST'
  | 'CONTROLLED_XSS_TEST'
  | 'CONTROLLED_INJECTION_TEST'
  | 'PATH_CANONICALIZATION_TEST';

export type PayloadRiskTier = 'LOW_RISK_ACTIVE' | 'APPROVAL_REQUIRED' | 'RESTRICTED';

export type SecurityContextType =
  | 'HTML_BODY'
  | 'HTML_ATTRIBUTE'
  | 'JAVASCRIPT'
  | 'JSON'
  | 'URL'
  | 'SQL_CLAUSE'
  | 'SHELL_ARGUMENT'
  | 'FILE_PATH';

export interface SafePayload {
  payloadId: string;
  category: PayloadSafetyClass;
  name: string;
  payloadString: string;
  purpose: string;
  expectedObservation: string;
  riskTier: PayloadRiskTier;
  approvalRequired: boolean;
  contexts: SecurityContextType[];
}

export type ConfidenceRating =
  | 'NO_FINDING'
  | 'OBSERVATION'
  | 'LOW_CONFIDENCE'
  | 'MEDIUM_CONFIDENCE'
  | 'HIGH_CONFIDENCE';

export type XssClassification =
  | 'NO_REFLECTION'
  | 'REFLECTED_ONLY'
  | 'SAFE_ENCODED'
  | 'POTENTIAL_XSS'
  | 'HIGH_CONFIDENCE_XSS';

export type InjectionClassification =
  | 'NO_DIFFERENTIAL'
  | 'SAFE_ENCODED'
  | 'ERROR_ONLY_SUPPRESSED'
  | 'BOOLEAN_DIFFERENTIAL'
  | 'STRUCTURED_INJECTION_EVIDENCE';

export type PathTraversalClassification =
  | 'CONFINED_TO_ROOT'
  | 'SAFE_NORMALIZED'
  | 'CANONICALIZATION_BLOCKED'
  | 'ESCAPED_ROOT_TRAVERSAL';

export interface ControlledParameter {
  parameterName: string;
  parameterType: InputParameterType;
  baseValue: any;
  securityContext: SecurityContextType;
  testPayloads: SafePayload[];
  isSensitive?: boolean;
}

export interface AuthenticationHypothesis {
  hypothesisId: string;
  researchClass: AuthenticationResearchClass;
  title: string;
  description: string;
  targetAsset: string;
  endpoint: string;
  httpMethod: HttpMethod;
  requiredAuthState?: AuthenticationState;
  testedAuthState?: AuthenticationState;
  authContext?: AuthContext;
  sessionModel?: SessionModel;
  controlledParameter?: ControlledParameter;
  expectedBehavior: 'ALLOW' | 'DENY' | 'SAFE_ENCODED' | 'CONFINED';
  expectedStatusCode?: number;
  sensitivity?: string;
}

export interface ExecutionSnapshot {
  statusCode: number;
  contentType: string;
  responseHeaders: Record<string, string>;
  responseBody: any;
  responseTimeMs: number;
  observedBehavior: 'ALLOW' | 'DENY' | 'REFLECTED' | 'ENCODED' | 'ERROR';
  errorDetected: boolean;
  errorMessage?: string;
}

export interface AuthDifferentialDifferences {
  statusDiffers: boolean;
  bodyDiffers: boolean;
  sensitiveFieldsExposed: string[];
  sessionBoundaryViolated: boolean;
  privilegeBoundaryViolated: boolean;
  authenticationBypassed: boolean;
  reflectionObserved: boolean;
  unsafeContextInterpretation: boolean;
  booleanDifferentialObserved: boolean;
  pathTraversedOutsideRoot: boolean;
  unauthorizedStateChange: boolean;
}

export interface ImpactAssessment {
  confidentialityImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  integrityImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  privilegeImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  overallImpact: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reasoning: string;
}

export interface AuthResearchDifferentialResult {
  hypothesisId: string;
  researchClass: AuthenticationResearchClass;
  targetAsset: string;
  endpoint: string;
  httpMethod: HttpMethod;
  testedParameter?: string;
  testedPayload?: string;
  testedAuthState?: AuthenticationState;
  testedSessionState?: SessionState;
  baselineResult?: ExecutionSnapshot;
  comparisonResult: ExecutionSnapshot;
  differences: AuthDifferentialDifferences;
  classification:
    | XssClassification
    | InjectionClassification
    | PathTraversalClassification
    | 'AUTH_BYPASS'
    | 'SESSION_VIOLATION'
    | 'PRIVILEGE_VIOLATION'
    | 'SAFE_ENFORCED'
    | 'NO_VULNERABILITY';
  confidence: ConfidenceRating;
  confidenceReasoning: string;
  isVulnerabilityCandidate: boolean;
  vulnerabilityType?: string;
  cwe?: string;
  owasp?: string;
  explanation: string;
  impactAssessment: ImpactAssessment;
  evidenceHash?: string;
  sanitizedEvidence?: Record<string, any>;
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
  confidenceRating: ConfidenceRating;
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

export interface AuthenticationResearchExecutionParams {
  programId: string;
  caseId: string;
  target: string;
  assetId?: string;
  researchClass: AuthenticationResearchClass;
  hypotheses: AuthenticationHypothesis[];
  requestBudget?: number;
  dryRun?: boolean;
  allowLocalFixtureTarget?: boolean;
  approvalId?: string;
  cancellationToken?: { isCancelled: boolean; reason?: string };
}

export interface AuthenticationResearchExecutionResult {
  executionId: string;
  programId: string;
  programName: string;
  caseId: string;
  target: string;
  researchClass: AuthenticationResearchClass;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED' | 'DENY';
  status: 'COMPLETED' | 'CANCELLED' | 'BLOCKED' | 'FAILED';
  totalRequestsExecuted: number;
  requestBudget: number;
  hypothesesEvaluated: number;
  differentialResults: AuthResearchDifferentialResult[];
  findingCandidates: FindingCandidate[];
  evidenceRecords: any[];
  auditEventsRecorded: number;
  dryRun: boolean;
  executedAt: string;
  durationMs: number;
  cancellationReason?: string;
  error?: string;
}
