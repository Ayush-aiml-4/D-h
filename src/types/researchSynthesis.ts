import { SeverityLevel } from '../types.ts';
import { AuthorizationDecision } from './programProfile.ts';

export type ObservationType =
  | 'AUTHZ_BOUNDARY_WEAKNESS'
  | 'AUTHN_BYPASS'
  | 'FORBIDDEN_WORKFLOW_TRANSITION'
  | 'BUSINESS_INVARIANT_VIOLATION'
  | 'OUTBOUND_SSRF_INTERACTION'
  | 'BLIND_INTERACTION_RECEIVED'
  | 'SESSION_BOUNDARY_VIOLATION'
  | 'PARAMETER_REFLECTION'
  | 'CROSS_ACCOUNT_ACCESS'
  | 'PRIVILEGE_ESCALATION'
  | 'UNAUTHENTICATED_ACCESS'
  | 'REPLAY_VIOLATION'
  | 'RACE_CONDITION_ANOMALY'
  | 'METADATA_ACCESS_ATTEMPT'
  | 'UNEXPECTED_STATE_TRANSITION'
  | 'SQL_INJECTION_DIFFERENTIAL'
  | 'PATH_TRAVERSAL_READ'
  | 'XSS_HTML_EXECUTION'
  | 'CUSTOM_OBSERVATION';

export type SynthesisEngineProvenance =
  | 'AUTHORIZATION_0004'
  | 'AUTHENTICATION_0005'
  | 'WORKFLOW_0006'
  | 'SERVER_INTERACTION_0007'
  | 'SYNTHESIS_0008'
  | 'MANUAL';

export type ConfidenceRating =
  | 'HIGH_CONFIDENCE'
  | 'MEDIUM_CONFIDENCE'
  | 'LOW_CONFIDENCE'
  | 'NO_FINDING';

export interface ActorContext {
  researcherId: string;
  accountIdentifier?: string;
  accountRole?: string;
  indirectCredentialRef?: string;
  sessionIdentifier?: string;
  [key: string]: any;
}

export interface ResearchObservation {
  observationId: string;
  researchCaseId: string;
  executionId: string;
  requestId: string;
  programId: string;
  target: string;
  asset: string;
  capability: string;
  actorContext: ActorContext;
  timestamp: string;
  observationType: ObservationType;
  expectedBehavior: string;
  observedBehavior: string;
  impactIndicators: string[];
  evidenceReferences: string[];
  confidence: ConfidenceRating;
  provenance: {
    engine: SynthesisEngineProvenance;
    fixtureId?: string;
    stepNumber?: number;
    hypothesisId?: string;
  };
  resourceIdentifier?: string;
  workflowId?: string;
  metadata?: Record<string, any>;
}

export type EvidenceGraphNodeType =
  | 'OBSERVATION'
  | 'EVIDENCE'
  | 'RESOURCE'
  | 'ACTOR'
  | 'STATE'
  | 'ACTION'
  | 'IMPACT';

export type EvidenceGraphEdgeType =
  | 'DERIVED_FROM'
  | 'PRECEDES'
  | 'AFFECTS'
  | 'AUTHORIZES'
  | 'VIOLATES'
  | 'TRANSITIONS_TO'
  | 'CORRELATES_WITH'
  | 'SUPPORTS'
  | 'CONTRADICTS';

export interface EvidenceGraphNode {
  id: string;
  type: EvidenceGraphNodeType;
  label: string;
  properties: Record<string, any>;
  evidenceHash?: string;
}

export interface EvidenceGraphEdge {
  id: string;
  source: string;
  target: string;
  type: EvidenceGraphEdgeType;
  reason?: string;
  weight?: number;
}

export interface EvidenceGraph {
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
}

export type CorrelationReason =
  | 'SAME_CASE'
  | 'SHARED_RESOURCE'
  | 'SHARED_ACTOR'
  | 'SHARED_WORKFLOW'
  | 'LINEAGE'
  | 'STATE_TRANSITION'
  | 'EVIDENCE_PROVENANCE'
  | 'CROSS_ENGINE_CHAIN';

export type ObservationClusterGroupType =
  | 'SINGLE_FINDING'
  | 'RELATED_FINDINGS'
  | 'INDEPENDENT_FINDINGS'
  | 'INSUFFICIENT_EVIDENCE';

export interface ObservationCluster {
  clusterId: string;
  groupType: ObservationClusterGroupType;
  primaryObservationId: string;
  observationIds: string[];
  reasons: CorrelationReason[];
  rationale: string;
  sharedIdentifiers: {
    caseId?: string;
    resource?: string;
    actor?: string;
    target?: string;
    workflowId?: string;
  };
}

export interface AttackChainStep {
  stepOrder: number;
  actor: string;
  action: string;
  resource: string;
  initialState?: string;
  resultingState?: string;
  authorizationContext?: string;
  evidenceRef?: string;
  description: string;
}

export interface AttackChain {
  chainId: string;
  steps: AttackChainStep[];
  summary: string;
  entryPoint: string;
  terminalImpact: string;
}

export type ImpactDimension =
  | 'CONFIDENTIALITY'
  | 'INTEGRITY'
  | 'AUTHORIZATION'
  | 'ACCOUNT_BOUNDARY'
  | 'RESOURCE_OWNERSHIP'
  | 'FINANCIAL'
  | 'WORKFLOW_CONTROL'
  | 'SERVER_SIDE_INTERACTION'
  | 'SENSITIVE_DATA';

export interface ImpactAnalysisResult {
  dimensions: ImpactDimension[];
  summary: string;
  technicalSeverity: SeverityLevel;
  hasSufficientEvidence: boolean;
}

export interface QualityGateStatus {
  gateId: string;
  gateName: string;
  passed: boolean;
  reason?: string;
}

export interface ReportReadinessResult {
  isReady: boolean;
  qualityScore: number;
  passedGates: string[];
  missingGates: string[];
  gateDetails: QualityGateStatus[];
}

export interface SynthesizedFindingCandidate {
  findingId: string;
  programId: string;
  target: string;
  title: string;
  vulnerabilityClass: string;
  cweId: string;
  severity: SeverityLevel;
  rootCause: string;
  attackChain: AttackChain;
  preconditions: string[];
  reproductionSteps: string[];
  expectedBehavior: string;
  observedBehavior: string;
  impact: ImpactAnalysisResult;
  confidence: ConfidenceRating;
  evidenceReferences: string[];
  evidenceHash: string;
  affectedAsset: string;
  scopeDecision: AuthorizationDecision;
  policyDecision: 'AUTHORIZED' | 'UNAUTHORIZED' | 'APPROVAL_REQUIRED' | 'BLOCK';
  programEligibility: 'BOUNTY_ELIGIBLE' | 'INELIGIBLE' | 'REVIEW_REQUIRED';
  duplicateGroupId?: string;
  reportReadiness: ReportReadinessResult;
  createdAt: string;
}

export interface ReportDraft {
  draftId: string;
  findingId: string;
  title: string;
  summary: string;
  affectedAsset: string;
  preconditions: string[];
  stepsToReproduce: string[];
  expectedResult: string;
  actualResult: string;
  securityImpact: string;
  evidence: string[];
  evidenceHash: string;
  rootCause: string;
  remediation: string;
  testingNotes: string;
  sanitizationStatus: 'CLEAN' | 'SECRETS_DETECTED' | 'REDACTED';
  readinessStatus: 'REPORT_READY' | 'NOT_READY';
  missingGates: string[];
  generatedAt: string;
}

export interface SynthesisRequest {
  caseId: string;
  observations: ResearchObservation[];
  programId?: string;
  target?: string;
  dryRun?: boolean;
}

export interface SynthesisResult {
  caseId: string;
  evidenceGraph: EvidenceGraph;
  clusters: ObservationCluster[];
  candidates: SynthesizedFindingCandidate[];
  reportDrafts: ReportDraft[];
  totalObservations: number;
  totalCandidates: number;
  readyReportsCount: number;
  auditEvidenceHashes: string[];
  executionTimeMs: number;
}
