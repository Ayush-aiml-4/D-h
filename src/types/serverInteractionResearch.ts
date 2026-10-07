import { SeverityLevel } from '../types.ts';

export interface CancellationToken {
  isCancelled: boolean;
}

export type DestinationClass =
  | 'PUBLIC_EXTERNAL'
  | 'PRIVATE_RFC1918'
  | 'LOOPBACK'
  | 'LINK_LOCAL'
  | 'METADATA'
  | 'UNSPECIFIED'
  | 'INVALID'
  | 'CONTROLLED_FIXTURE';

export type PortPolicy = 'PORT_ALLOWED' | 'PORT_FORBIDDEN' | 'PORT_UNSPECIFIED';

export type ResolutionStatus = 'RESOLVED' | 'FAILED' | 'BLOCKED';

export interface ResolutionResult {
  hostname: string;
  ipAddress: string;
  ipVersion: 'IPv4' | 'IPv6';
  destinationClass: DestinationClass;
  status: ResolutionStatus;
  dnsRebindingStep?: number;
  resolvedAt: string;
}

export interface ParsedUrl {
  rawUrl: string;
  canonicalUrl: string;
  scheme: string;
  isValidScheme: boolean;
  hostname: string;
  canonicalHostname: string;
  port: number;
  explicitPort: boolean;
  pathname: string;
  search: string;
  hash: string;
  username?: string;
  password?: string;
  hasUserInfo: boolean;
  isValid: boolean;
  validationError?: string;
}

export interface Destination {
  parsedUrl: ParsedUrl;
  initialResolution?: ResolutionResult;
  destinationClass: DestinationClass;
}

export interface RedirectHop {
  hopIndex: number;
  sourceUrl: string;
  targetUrl: string;
  targetParsedUrl: ParsedUrl;
  resolution: ResolutionResult;
  destinationClass: DestinationClass;
  policyDecision: 'ALLOW' | 'DENY' | 'REVIEW_REQUIRED';
  statusCode: number;
}

export interface DestinationPolicyDecision {
  decision: 'ALLOW' | 'DENY' | 'REVIEW_REQUIRED' | 'BLOCK';
  reason: string;
  destinationClass: DestinationClass;
  isRestricted: boolean;
  violatedRule?: string;
}

export interface InteractionObservation {
  interactionId: string;
  correlationToken: string;
  timestamp: string;
  fixtureId: string;
  destinationClass: DestinationClass;
  requestedUrl: string;
  method: string;
  headers: Record<string, string>;
  bodySnippet?: string;
  sourceIp?: string;
  isCorrelated: boolean;
}

export interface ServerSideRequest {
  requestId: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  followRedirects?: boolean;
  maxRedirects?: number;
  timeoutMs?: number;
  correlationToken?: string;
}

export interface SSRFHypothesis {
  hypothesisId: string;
  targetEndpoint: string;
  inputParameter: string;
  testUrl: string;
  intendedDestinationClass: DestinationClass;
  expectedBehavior: 'ACCEPT' | 'REJECT' | 'SUPPRESS';
  requiresCorrelation?: boolean;
  correlationToken?: string;
  dnsRebindingSimulation?: boolean;
}

export type SSRFImpact =
  | 'SERVER_SIDE_REQUEST_ONLY'
  | 'INTERNAL_RESOURCE_ACCESS'
  | 'SENSITIVE_SERVICE_ACCESS'
  | 'CREDENTIAL_ACCESS_INDICATOR'
  | 'NETWORK_BOUNDARY_CROSSING'
  | 'NONE';

export type SSRFConfidence =
  | 'NO_FINDING'
  | 'OBSERVATION'
  | 'LOW_CONFIDENCE'
  | 'MEDIUM_CONFIDENCE'
  | 'HIGH_CONFIDENCE';

export interface ServerInteractionEvidence {
  researchCaseId: string;
  executionId: string;
  requestId: string;
  target: string;
  suppliedUrl: string;
  canonicalUrl: string;
  resolutionResult: ResolutionResult;
  destinationClass: DestinationClass;
  redirectChain: RedirectHop[];
  interactionCorrelation: {
    isCorrelated: boolean;
    correlationToken?: string;
    observationId?: string;
  };
  policyDecision: DestinationPolicyDecision;
  observedBehavior: string;
  impact: SSRFImpact;
  confidence: SSRFConfidence;
  evidenceHash: string;
  sanitizedHeaders: Record<string, string>;
  sanitizedPayload?: string;
}

export interface SSRFFindingCandidate {
  candidateId: string;
  title: string;
  target: string;
  vulnerabilityType: string;
  cweId: string;
  severity: SeverityLevel;
  confidence: SSRFConfidence;
  impact: SSRFImpact;
  destinationClass: DestinationClass;
  reproductionSteps: string[];
  remediation: string;
  evidenceSummary: Record<string, any>;
  evidenceHash: string;
  createdAt: string;
}

export interface SSRFResearchResult {
  executionId: string;
  programId: string;
  target: string;
  status: 'COMPLETED' | 'CANCELLED' | 'BLOCKED' | 'ERROR';
  totalHypotheses: number;
  evaluatedHypotheses: number;
  findings: SSRFFindingCandidate[];
  suppressedCount: number;
  networkRequestsCount: number;
  evidenceList: ServerInteractionEvidence[];
  summary: string;
  cancellationReason?: string;
}
