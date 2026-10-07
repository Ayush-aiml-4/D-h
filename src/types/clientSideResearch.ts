import { SeverityLevel } from '../types.ts';
import { ConfidenceRating, ResearchObservation } from './researchSynthesis.ts';

export type { ConfidenceRating };

export type ClientSideContextType =
  | 'HTML_TEXT'
  | 'HTML_ATTRIBUTE'
  | 'HTML_ATTRIBUTE_URL'
  | 'JAVASCRIPT_STRING'
  | 'JAVASCRIPT_CODE'
  | 'URL'
  | 'CSS'
  | 'UNKNOWN';

export type ClientSideSourceType =
  | 'QUERY_PARAMETER'
  | 'PATH_PARAMETER'
  | 'FORM_INPUT'
  | 'STORED_DATABASE_VALUE'
  | 'URL_FRAGMENT'
  | 'POST_MESSAGE'
  | 'LOCAL_STORAGE'
  | 'SESSION_STORAGE'
  | 'URL_COMPONENT';

export type ClientSideSinkType =
  | 'INNER_HTML'
  | 'OUTER_HTML'
  | 'INSERT_ADJACENT_HTML'
  | 'DOCUMENT_WRITE'
  | 'EVAL'
  | 'FUNCTION_CONSTRUCTOR'
  | 'SET_TIMEOUT_STRING'
  | 'SET_INTERVAL_STRING'
  | 'DANGEROUS_URL_ASSIGNMENT'
  | 'SAFE_TEXT_CONTENT'
  | 'SAFE_ATTRIBUTE_SETTER'
  | 'SAFE_FRAMEWORK_BINDING'
  | 'SAFE_SINK'
  | 'POTENTIALLY_DANGEROUS_SINK';

export type TransformationType =
  | 'HTML_ENCODING'
  | 'ATTRIBUTE_ENCODING'
  | 'JAVASCRIPT_ESCAPING'
  | 'URL_ENCODING'
  | 'SANITIZATION'
  | 'DECODING'
  | 'NORMALIZATION'
  | 'NONE';

export type EncodingClassification =
  | 'NO_ENCODING'
  | 'CORRECT_ENCODING'
  | 'WRONG_CONTEXT_ENCODING'
  | 'DOUBLE_ENCODING'
  | 'DECODE_AFTER_ENCODING';

export type SanitizerStatus =
  | 'SANITIZED'
  | 'PARTIALLY_SANITIZED'
  | 'BYPASSABLE_FIXTURE'
  | 'NOT_SANITIZED';

export type StoredXssImpactScope =
  | 'SELF_ONLY'
  | 'SAME_USER'
  | 'CROSS_USER'
  | 'PRIVILEGED_USER_CONTEXT';

export type ClientSideImpactDimension =
  | 'CODE_EXECUTION'
  | 'SESSION_IMPACT'
  | 'ACCOUNT_IMPACT'
  | 'DATA_INTEGRITY'
  | 'CONTENT_INTEGRITY'
  | 'CROSS_USER_IMPACT';

export type SymbolicPayloadMarker =
  | 'HTML_CONTEXT_MARKER'
  | 'ATTRIBUTE_CONTEXT_MARKER'
  | 'JS_STRING_MARKER'
  | 'URL_CONTEXT_MARKER'
  | 'SAFE_TEXT_MARKER';

export interface SourceDefinition {
  sourceId: string;
  sourceType: ClientSideSourceType;
  name: string;
  value: string;
  isResearcherControlled: boolean;
  taintMarker?: string;
  actorIdentifier?: string;
}

export interface SinkDefinition {
  sinkId: string;
  sinkType: ClientSideSinkType;
  apiName: string;
  isDangerous: boolean;
  context: ClientSideContextType;
  targetProperty?: string;
}

export interface TransformationStep {
  stepOrder: number;
  transformationType: TransformationType;
  description: string;
  inputSnippet: string;
  outputSnippet: string;
  neutralizesContext: boolean;
}

export interface DataFlowTrace {
  traceId: string;
  source: SourceDefinition;
  transformations: TransformationStep[];
  sink: SinkDefinition;
  isTaintPathValid: boolean;
  isNeutralized: boolean;
  finalRenderedContext: ClientSideContextType;
  renderedOutput: string;
}

export interface BrowserExecutionEvidence {
  evidenceId: string;
  fixtureId: string;
  correlationId: string;
  sourceMarker: string;
  sink: ClientSideSinkType;
  executionMarker: string;
  executedContext: ClientSideContextType;
  evidenceHash: string;
  timestamp: string;
  isSimulatedExecution: boolean;
  executionLog: string[];
}

export interface ClientSideImpactAnalysis {
  dimensions: ClientSideImpactDimension[];
  storedScope?: StoredXssImpactScope;
  severity: SeverityLevel;
  summary: string;
  hasSufficientEvidence: boolean;
}

export type XssVulnerabilityType =
  | 'REFLECTED_XSS'
  | 'STORED_XSS'
  | 'DOM_XSS'
  | 'BENIGN_REFLECTION'
  | 'SAFE_TRANSFORMATION'
  | 'SUPPRESSED_FALSE_POSITIVE';

export interface ClientSideResearchEvaluation {
  evaluationId: string;
  researchCaseId: string;
  programId: string;
  target: string;
  asset: string;
  vulnerabilityType: XssVulnerabilityType;
  isVulnerable: boolean;
  context: ClientSideContextType;
  source: SourceDefinition;
  sink: SinkDefinition;
  dataFlow: DataFlowTrace;
  encodingClassification: EncodingClassification;
  sanitizerStatus: SanitizerStatus;
  evidence?: BrowserExecutionEvidence;
  impact: ClientSideImpactAnalysis;
  confidence: ConfidenceRating;
  confidenceReasoning: string;
  rootCause: string;
  cweId: string;
  remediation: string;
  observation?: ResearchObservation;
}

export interface StoredXssWorkflowStep {
  stepNumber: number;
  stage: 'INPUT_CREATED' | 'STORED' | 'RETRIEVED' | 'RENDERED' | 'EXECUTION';
  actorId: string;
  role: string;
  action: string;
  state: string;
  evidenceRef?: string;
  payloadSnapshot?: string;
}

export interface StoredXssWorkflowEvaluation {
  workflowId: string;
  researchCaseId: string;
  steps: StoredXssWorkflowStep[];
  isVulnerable: boolean;
  impactScope: StoredXssImpactScope;
  attackerActor: string;
  victimActor: string;
  rootCause: string;
  confidence: ConfidenceRating;
  evidence: BrowserExecutionEvidence;
}
