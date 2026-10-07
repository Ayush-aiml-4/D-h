export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export type ProgramStatus = 'Active' | 'Paused' | 'Archived' | 'Reviewing';

export type HuntStatus = 'Ready' | 'Starting' | 'Hunting' | 'Running' | 'Analyzing' | 'Completed' | 'Stopped' | 'Blocked' | 'Paused' | 'Findings Found' | 'Complete';

export type FindingStatus = 'Potential' | 'Under review' | 'Needs review' | 'Validated' | 'Verified' | 'Submitted' | 'Accepted' | 'Rejected' | 'Duplicate' | 'Resolved' | 'Dismissed';

export type ReportStatus = 'Draft' | 'Ready' | 'Submitted' | 'Accepted' | 'Rejected' | 'Duplicate' | 'Resolved';

export type PolicyStatus = 'LOADED' | 'ENFORCED' | 'WARNING' | 'BLOCKED' | 'UNKNOWN';

export interface Program {
  id: string;
  name: string;
  organization: string;
  targetCount: number;
  scopeStatus: string;
  rulesLoaded: boolean;
  rewardMax: string;
  lastHunt: string;
  status: 'Active' | 'Paused' | 'Reviewing';
  targets: string[];
  rulesAllowed: string[];
  rulesBlocked: string[];
  description?: string;
}

export interface HuntStep {
  id: string;
  name: string;
  status: 'done' | 'active' | 'pending';
  progress?: number;
}

export interface Hunt {
  id: string;
  programId: string;
  programName: string;
  targetDomain: string;
  scopeCount: number;
  status: HuntStatus;
  startedAt: string;
  progressPercent: number;
  currentTask: string;
  potentialFindingsCount: number;
  verifiedFindingsCount: number;
  policyViolationsCount: number;
  steps: HuntStep[];
  liveLogs: string[];
}

export interface EvidenceData {
  requestMethod: string;
  requestUrl: string;
  requestHeaders: Record<string, string>;
  requestBody?: string;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseBodySnippet: string;
  timestamp: string;
  validationStatus: string;
  proofHash: string;
}

export interface PolicyCheckResult {
  inScope: boolean;
  testPermitted: boolean;
  validationCompleted: boolean;
  noRestrictedAction: boolean;
}

export interface Finding {
  id: string;
  huntId: string;
  programName: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  confidence: number;
  target: string;
  status: FindingStatus;
  whatWeFound: string;
  whyItMatters: string;
  affectedTarget: string;
  evidence: EvidenceData;
  policyCheck: PolicyCheckResult;
  recommendedFix: string;
  createdAt: string;
}

export interface Report {
  id: string;
  findingId: string;
  programName: string;
  title: string;
  severity: SeverityLevel;
  researcher: string;
  target: string;
  status: ReportStatus;
  summary: string;
  impact: string;
  technicalDetails: string;
  evidenceSnippet: string;
  reproductionSteps: string[];
  recommendedFix: string;
  testingPolicy: string;
  timeline: { date: string; action: string }[];
  createdAt: string;
  recipientContact: string;
}

export type ResearchPriorityLabel = 'HIGH PRIORITY' | 'MEDIUM PRIORITY' | 'LOW PRIORITY';

export interface AttackSurfaceNode {
  id: string;
  name: string;
  domain: string;
  type: 'root' | 'subdomain' | 'api' | 'auth' | 'admin' | 'static' | 'microservice' | string;
  assetStatus: 'AUTHORIZED' | 'DISCOVERED' | 'OUT_OF_SCOPE' | 'UNKNOWN' | 'DISABLED' | string;
  scopeStatus: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNDER_REVIEW' | 'UNKNOWN' | string;
  policyDecision: 'ALLOW' | 'REVIEW_REQUIRED' | 'BLOCK' | string;
  priorityLabel: ResearchPriorityLabel;
  priorityReason: string;
  endpointsCount: number;
  techStack: string[];
  children?: AttackSurfaceNode[];
  endpoints?: string[];
  programId?: string;
  scopeId?: string | null;
  discoverySessionId?: string | null;
  researcherOwnership?: 'OWNED' | 'OTHER' | 'SYSTEM';
  lastSeenAt?: string;
}

export interface AssetNode {
  id: string;
  name: string;
  domain: string;
  type: 'root' | 'subdomain' | 'api' | 'auth' | 'admin' | 'static' | 'microservice' | string;
  status: string;
  endpointsCount: number;
  techStack: string[];
  children?: AssetNode[];
  endpoints?: string[];
  priorityLabel?: ResearchPriorityLabel;
  priorityReason?: string;
  assetStatus?: string;
  scopeStatus?: string;
  policyDecision?: string;
  programId?: string;
  scopeId?: string | null;
  discoverySessionId?: string | null;
  researcherOwnership?: 'OWNED' | 'OTHER' | 'SYSTEM';
  lastSeenAt?: string;
}

export interface HistorySession {
  id: string;
  huntId: string;
  programName: string;
  target: string;
  date: string;
  duration: string;
  potentialFindings: number;
  verifiedFindings: number;
  reportStatus: ReportStatus;
  bountyEarned: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  entityId: string;
  entityType: 'HUNT' | 'FINDING' | 'REPORT' | 'PROGRAM';
  previousState: string;
  newState: string;
  researcher: string;
  action: string;
}

export interface UserProfile {
  name: string;
  role: string;
  bountyTotal: string;
  paidBounty: string;
  pendingBounty: string;
  potentialBounty: string;
  activeHunts: number;
  verifiedBugs: number;
  submittedReports: number;
  isDemoMode?: boolean;
}

export interface ProgramScope {
  id: string;
  programId: string;
  targetPattern: string;
  scopeType: 'EXACT_DOMAIN' | 'SUBDOMAIN' | 'URL' | 'API_ENDPOINT';
  scopeStatus: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'REVIEW_REQUIRED' | 'DISABLED';
  description?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface Asset {
  id: string;
  programId: string;
  scopeId?: string | null;
  parentAssetId?: string | null;
  domain: string;
  type: string; // DOMAIN | SUBDOMAIN | URL | API_ENDPOINT | SERVICE | Web | API | Infrastructure | Mobile
  hostname?: string | null;
  url?: string | null;
  path?: string | null;
  httpMethod?: string | null;
  status: string; // AUTHORIZED | DISCOVERED | OUT_OF_SCOPE | UNKNOWN | DISABLED | IN_SCOPE
  scopeStatus?: string;
  technology?: string | null;
  endpointCount?: number;
  discoverySource?: string | null;
  confidence?: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface DiscoverySession {
  id: string;
  programId: string;
  initiatedBy: string;
  targetScopeId?: string | null;
  target: string;
  operation: string;
  status: 'READY' | 'STARTING' | 'DISCOVERING' | 'ANALYZING' | 'COMPLETED' | 'STOPPED' | 'BLOCKED' | 'FAILED';
  startedAt?: string | null;
  completedAt?: string | null;
  requestId?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface PolicyEvaluationRequest {
  programId: string;
  target: string;
  operation?: string;
}

export interface PolicyEvaluationResult {
  decision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  programId: string;
  target: string;
  scopeType?: string;
  scopeStatus?: string;
  matchedPattern?: string;
  reason: string;
}

export type CapabilityImplementationStatus = 'SUPPORTED' | 'PARTIAL' | 'MANUAL' | 'PLANNED';
export type CapabilityAutomationLevel = 'AUTOMATED' | 'SEMI_AUTOMATED' | 'MANUAL';
export type CapabilityAuthenticationRequirement = 'NONE' | 'OPTIONAL' | 'REQUIRED';
export type CapabilityPolicyRequirement = 'POLICY_CHECK_REQUIRED' | 'EXPLICIT_SCOPE_PERMITTED';
export type CapabilityHumanValidationRequirement = 'REQUIRED' | 'RECOMMENDED' | 'OPTIONAL' | 'NONE';
export type CapabilityEvidenceSupport = 'JSON_EVIDENCE' | 'HTTP_PROOFS' | 'DOM_SNAPSHOTS' | 'HEURISTIC_TRACE';
export type CapabilityReproductionSupport = 'CURL_COMMAND' | 'HTTP_HAR' | 'REPRODUCTION_STEPS' | 'NONE';
export type CapabilityReportingSupport = 'AUTOMATED_REPORT' | 'MANUAL_REVIEW_DRAFT' | 'FINDING_ONLY';

export interface CapabilityDefinition {
  id: string;
  name: string;
  description: string;
  category: string;
  owaspMapping?: string;
  cweMapping?: string;
  implementationStatus: CapabilityImplementationStatus;
  automationLevel: CapabilityAutomationLevel;
  authenticationRequirement: CapabilityAuthenticationRequirement;
  policyRequirement: CapabilityPolicyRequirement;
  humanValidationRequirement: CapabilityHumanValidationRequirement;
  evidenceSupport: CapabilityEvidenceSupport;
  reproductionSupport: CapabilityReproductionSupport;
  reportingSupport: CapabilityReportingSupport;
}

export interface CapabilityEvaluationParams {
  programId: string;
  target: string;
  capabilityId: string;
  assetId?: string;
  requestId?: string;
}

export interface CapabilityEvaluationResult {
  isAuthorizationEvaluationOnly: boolean;
  decision: 'ALLOW' | 'REVIEW_REQUIRED' | 'BLOCK';
  programId: string;
  target: string;
  capability: CapabilityDefinition;
  reason: string;
  evaluatedAt: string;
}

export type CanonicalCaseStatus =
  | 'DRAFT'
  | 'ACTIVE'
  | 'PAUSED'
  | 'UNDER_REVIEW'
  | 'CLOSED'
  | 'ARCHIVED';

export interface ResearchCaseMetrics {
  discoverySessionCount: number;
  assetCount: number;
  activityCount: number;
  findingCount: number;
  evidenceCount: number;
  reportCount: number;
}

export interface ResearchCase {
  id: string;
  programId: string;
  programName: string;
  title: string;
  objective: string;
  researcherId: string;
  researcherName: string;
  status: CanonicalCaseStatus;
  scopeSummary: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
  metrics: ResearchCaseMetrics;
}

export interface ResearchActivity {
  id: string;
  caseId: string;
  programId: string;
  capabilityId: string;
  assetId: string;
  target: string;
  action: string;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  status: 'PLANNED' | 'EXECUTING' | 'COMPLETED' | 'BLOCKED';
  executedBy: string;
  timestamp: string;
  requestId: string;
  metadata?: Record<string, any>;
}

export type CanonicalDisclosureStatus =
  | 'DRAFT'
  | 'UNDER_REVIEW'
  | 'READY_FOR_APPROVAL'
  | 'APPROVED'
  | 'SUBMISSION_READY'
  | 'SUBMITTED'
  | 'REJECTED'
  | 'WITHDRAWN';

export interface QualityGateResult {
  passed: boolean;
  gateId: string;
  name: string;
  description: string;
  failureReason?: string;
}

export interface DisclosureQualitySummary {
  overallPassed: boolean;
  passedCount: number;
  totalCount: number;
  gates: QualityGateResult[];
}

export interface PossibleDuplicateSummary {
  findingId: string;
  title: string;
  severity?: string | null;
  correlationHash?: string;
  matchReason: string;
}

export interface DisclosureEvidenceReference {
  evidenceId: string;
  description: string;
  integrityHash: string;
  validationStatus: string;
  timestamp: string;
}

export interface DisclosurePackage {
  id: string;
  findingId: string;
  reportId?: string;
  caseId?: string;
  programId: string;
  assetId: string;

  // Identity & Governance
  researcherId: string;
  researcherName: string;
  status: CanonicalDisclosureStatus;
  createdAt: string;
  updatedAt: string;
  approvedAt?: string;
  approvedBy?: string;
  submittedAt?: string;

  // Research Content (Whitelisted / Sanitized)
  title: string;
  executiveSummary: string;
  technicalDescription: string;
  impact?: string;
  affectedComponent: string;
  affectedAsset: string;
  vulnerabilityClassification?: string;
  cwe?: string;
  owasp?: string;

  // Reproduction & Proof
  prerequisites: string;
  reproductionSteps: string[];
  expectedBehavior: string;
  observedBehavior: string;
  sanitizedProofOfConcept: string;

  // Evidence & Provenance References
  evidenceReferences: DisclosureEvidenceReference[];

  // Remediation & Scope Metadata
  recommendedRemediation?: string;
  programName: string;
  authorizedScopeRule: string;
  scopeVerificationStatus: 'VERIFIED_IN_SCOPE' | 'REQUIRES_REVIEW' | 'OUT_OF_SCOPE';

  // Quality & Duplicate Intelligence
  qualitySummary: DisclosureQualitySummary;
  possibleDuplicates: PossibleDuplicateSummary[];
}

export type DisclosureExportFormat = 'markdown' | 'html' | 'text' | 'json';

export type ExecutionStatus =
  | 'REQUESTED'
  | 'AUTHORIZED'
  | 'APPROVED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'CANCELLED'
  | 'FAILED'
  | 'BLOCKED';

export type AuthorizationLevel =
  | 'PASSIVE'
  | 'LOW_RISK'
  | 'REQUIRES_APPROVAL'
  | 'RESTRICTED';

export interface ExecutionApproval {
  approved: boolean;
  approvedBy: string;
  approvedAt: string;
  approvalType: 'AUTOMATIC_LOW_RISK' | 'EXPLICIT_RESEARCHER_CONFIRMATION' | 'ADMIN_AUTHORIZATION';
  reason?: string;
}

export interface ExecutionObservation {
  observationId: string;
  executionId: string;
  capabilityId: string;
  assetId: string;
  timestamp: string;
  observationType: string;
  target: string;
  sanitizedData: Record<string, any>;
  evidenceHash?: string;
  correlationHash?: string;
  requestId: string;
}

export interface ExecutionResult {
  executionId: string;
  caseId: string;
  programId: string;
  programName: string;
  assetId: string;
  capabilityId: string;
  capabilityName: string;
  target: string;
  researcherId: string;
  researcherName: string;
  status: ExecutionStatus;
  authorizationLevel: AuthorizationLevel;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  approval?: ExecutionApproval;
  observations: ExecutionObservation[];
  evidenceId?: string;
  evidenceHash?: string;
  durationMs: number;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  error?: string;
  requestId: string;
}


