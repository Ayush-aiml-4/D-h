/**
 * DEVILHUNT Mission #0014 / #0015 — Passive Research Intelligence Types
 * All analysis is observation-only. No autonomous exploitation.
 */

export type DiscoveryType =
  | 'DISCOVERED_ENDPOINT'
  | 'DISCOVERED_RESOURCE'
  | 'DISCOVERED_CONFIGURATION'
  | 'DISCOVERED_REFERENCE';

export type SignalStrength = 'INFO' | 'LOW_SIGNAL' | 'MEDIUM_SIGNAL' | 'HIGH_SIGNAL';

export type ReviewPriority = 'REVIEW_NOW' | 'REVIEW' | 'LOW_PRIORITY' | 'INFORMATIONAL';

export type ObservationKind =
  | 'SECURITY_HEADER'
  | 'CORS_OBSERVATION'
  | 'INFORMATION_DISCLOSURE'
  | 'TECHNOLOGY_FINGERPRINT'
  | 'ENDPOINT_INTEREST'
  | 'SOURCE_MAP'
  | 'VERBOSE_ERROR'
  | 'INTERNAL_HOSTNAME'
  | 'CONFIGURATION_EXPOSURE'
  | 'FALSE_POSITIVE_CANDIDATE';

export type FindingCandidateStatus =
  | 'OPEN'
  | 'NEEDS_REVIEW'
  | 'CONFIRMED'
  | 'REJECTED_FALSE_POSITIVE'
  | 'PROMOTED_TO_FINDING'
  | 'QUALITY_GATE_FAILED';

export type TimelineEventType =
  | 'SESSION_STARTED'
  | 'TARGET_DISCOVERED'
  | 'REQUEST_EXECUTED'
  | 'RESPONSE_CAPTURED'
  | 'ENDPOINT_DISCOVERED'
  | 'OBSERVATION_CREATED'
  | 'EVIDENCE_CREATED'
  | 'CORRELATION_CREATED'
  | 'FINDING_CANDIDATE_CREATED'
  | 'RESEARCHER_REVIEWED'
  | 'QUALITY_GATE'
  | 'REPORT_DRAFT_GENERATED'
  | 'PROGRAM_CREATED'
  | 'POLICY_IMPORTED'
  | 'SCOPE_VALIDATED'
  | 'RULES_VALIDATED'
  | 'HUMAN_APPROVAL'
  | 'TARGET_QUEUED'
  | 'SESSION_CANCELLED'
  | 'BUDGET_EXHAUSTED'
  | 'SCOPE_BLOCKED';

export type ConfidenceLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export type EndpointInventoryStatus = 'DISCOVERED_ONLY' | 'PASSIVE_OBSERVED' | 'OUT_OF_SCOPE' | 'BLOCKED';

export interface NormalizedPassiveResponse {
  url: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  status: number;
  headers: Record<string, string>;
  body: string;
  contentType: string;
  programId: string;
  researchCaseId: string;
  executionId: string;
  requestId: string;
  target: string;
  timestamp: string;
}

export interface DiscoveryRecord {
  id: string;
  discoveryType: DiscoveryType;
  sourceUrl: string;
  extractedValue: string;
  methodHint?: string;
  confidence: ConfidenceLevel;
  evidenceRef: string;
  scopeAllowed: boolean;
  scopeReason: string;
  programId: string;
  researchCaseId: string;
  timestamp: string;
}

export interface EndpointInventoryEntry {
  id: string;
  endpoint: string;
  method: string;
  source: string;
  scopeDecision: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNKNOWN';
  authenticationIndicator: boolean;
  contentType?: string;
  firstDiscovered: string;
  lastObserved: string;
  evidenceCount: number;
  status: EndpointInventoryStatus;
  programId: string;
}

export interface SecurityObservation {
  id: string;
  kind: ObservationKind;
  signal: SignalStrength;
  title: string;
  observedBehavior: string;
  expectedBehavior: string;
  securityRelevance: string;
  confidence: ConfidenceLevel;
  evidenceRef: string;
  sourceUrl: string;
  programId: string;
  researchCaseId: string;
  requestId: string;
  timestamp: string;
  redacted: boolean;
}

export interface TechnologyFingerprint {
  id: string;
  technology: string;
  category: 'framework' | 'backend' | 'frontend' | 'api' | 'cdn' | 'server' | 'cloud' | 'other';
  confidence: ConfidenceLevel;
  evidenceRef: string;
  sourceUrl: string;
  indicators: string[];
}

export interface GraphNode {
  id: string;
  type: 'TARGET' | 'PAGE' | 'RESOURCE' | 'ENDPOINT' | 'OBSERVATION' | 'EVIDENCE' | 'FINDING_CANDIDATE' | 'REPORT';
  label: string;
  metadata: Record<string, string>;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  relation: string;
}

export interface RelationshipGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CorrelationResult {
  id: string;
  title: string;
  observationIds: string[];
  rationale: string[];
  reviewPriority: ReviewPriority;
  candidateClass: string;
  confidence: ConfidenceLevel;
  programId: string;
  researchCaseId: string;
  timestamp: string;
}

export interface FindingCandidate {
  id: string;
  title: string;
  status: FindingCandidateStatus;
  reviewPriority: ReviewPriority;
  vulnerabilityClass: string;
  cwe?: string;
  affectedAsset: string;
  observedBehavior: string;
  expectedBehavior: string;
  securityImpact: string;
  confidence: ConfidenceLevel;
  observationIds: string[];
  evidenceIds: string[];
  correlationId?: string;
  programId: string;
  researchCaseId: string;
  scopeConfirmed: boolean;
  qualityGateNotes: string[];
  createdAt: string;
  reviewedAt?: string;
  reviewerAction?: 'CONFIRM' | 'REJECT_FALSE_POSITIVE';
  synthetic: boolean;
}

export interface EvidenceArtifact {
  id: string;
  researchCaseId: string;
  executionId: string;
  requestId: string;
  target: string;
  observationId?: string;
  findingCandidateId?: string;
  timestamp: string;
  sha256: string;
  method: string;
  url: string;
  status: number;
  headersRedacted: Record<string, string>;
  bodySnippetRedacted: string;
  integrityValid: boolean;
}

export interface TimelineEvent {
  id: string;
  type: TimelineEventType;
  programId: string;
  researchCaseId: string;
  executionId?: string;
  requestId?: string;
  target?: string;
  timestamp: string;
  details: Record<string, string | number | boolean>;
}

export interface ReportDraft {
  id: string;
  findingCandidateId: string;
  title: string;
  summary: string;
  affectedAsset: string;
  vulnerabilityClass: string;
  cwe: string;
  technicalDescription: string;
  observedBehavior: string;
  expectedBehavior: string;
  securityImpact: string;
  reproductionSteps: string[];
  evidence: string[];
  suggestedRemediation: string;
  scopeConfirmation: string;
  confidence: ConfidenceLevel;
  missingSections: string[];
  synthetic: boolean;
  createdAt: string;
}

export interface SessionMetrics {
  targetsEvaluated: number;
  targetsBlocked: number;
  requestsExecuted: number;
  requestsBlocked: number;
  requestsRemaining: number;
  observationsGenerated: number;
  falsePositives: number;
  findingCandidates: number;
  confirmedFindings: number;
  rejectedFindings: number;
  evidenceArtifacts: number;
  reportsGenerated: number;
  qualityGateFailures: number;
  securityControlViolations: number;
  liveNetworkRequests: number;
}

export interface SecurityControlDashboard {
  scopeEnforcement: 'PASS' | 'FAIL';
  budgetEnforcement: 'PASS' | 'FAIL';
  methodEnforcement: 'PASS' | 'FAIL';
  credentialProtection: 'PASS' | 'FAIL';
  secretRedaction: 'PASS' | 'FAIL';
  evidenceIntegrity: 'PASS' | 'FAIL';
  humanApproval: 'PASS' | 'FAIL';
  activeTestingIsolation: 'PASS' | 'FAIL';
  auditTrail: 'PASS' | 'FAIL';
  reportQualityGate: 'PASS' | 'FAIL';
}

export interface SyntheticScenario {
  id: string;
  name: string;
  path: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  status: number;
  headers: Record<string, string>;
  body: string;
  expectedObservations: ObservationKind[];
}
