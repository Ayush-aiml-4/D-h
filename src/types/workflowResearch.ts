import { SeverityLevel } from '../types.ts';
import { AuthContext, AccountRole } from './authorizationResearch.ts';

export interface CancellationToken {
  isCancelled: boolean;
}

export type WorkflowStateStatus =
  | 'DRAFT'
  | 'CREATED'
  | 'PENDING'
  | 'SUBMITTED'
  | 'APPROVED'
  | 'PAID'
  | 'PROCESSING'
  | 'SHIPPED'
  | 'DELIVERED'
  | 'COMPLETED'
  | 'CANCELLED'
  | 'REFUNDED'
  | 'REJECTED'
  | 'CONSUMED'
  | 'UNUSED'
  | string;

export type WorkflowInvariantType =
  | 'OWNERSHIP_INVARIANT'
  | 'STATUS_INVARIANT'
  | 'AUTHORIZATION_INVARIANT'
  | 'QUANTITY_INVARIANT'
  | 'SEQUENCE_INVARIANT'
  | 'SINGLE_USE_INVARIANT'
  | 'STATE_INVARIANT'
  | 'BUSINESS_RULE_INVARIANT'
  | 'CONCURRENCY_INVARIANT'
  | 'TERMINAL_STATE_INVARIANT';

export type ReplayPolicy = 'REPLAY_ALLOWED' | 'REPLAY_REJECTED' | 'REPLAY_UNDEFINED';

export interface WorkflowSecurityInvariant {
  invariantId: string;
  type: WorkflowInvariantType;
  name: string;
  description: string;
  enforceAtStates?: string[];
  enforceAtActions?: string[];
  expectedResult: 'ALLOW' | 'DENY';
  ruleFn?: (context: WorkflowInvariantContext) => { valid: boolean; reason?: string; impact?: string };
}

export interface WorkflowInvariantContext {
  currentState: WorkflowStateInstance;
  targetState?: string;
  action: WorkflowAction;
  actor: WorkflowActor;
  resource: WorkflowResource;
  metadata?: Record<string, any>;
  history?: WorkflowTransitionRecord[];
}

export interface WorkflowActor {
  actorId: string;
  actorLabel: string;
  role: AccountRole;
  credentialReference: string; // Indirect safe reference only
  sessionReference?: string;
}

export interface WorkflowResource {
  resourceId: string;
  resourceType: string;
  ownerActorId: string;
  initialStatus: WorkflowStateStatus;
  currentStatus: WorkflowStateStatus;
  attributes: Record<string, any>; // e.g. amount, lineItems, couponCode, balance
}

export interface WorkflowAction {
  actionId: string;
  actionName: string;
  endpointPath?: string;
  httpMethod?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  fromStates: string[];
  toState: string;
  requiredRole?: AccountRole;
  isOwnerOnly?: boolean;
  isSingleUse?: boolean;
  replayPolicy: ReplayPolicy;
  isPrivileged?: boolean;
  parameters?: Record<string, any>;
}

export interface WorkflowTransitionRule {
  fromState: string;
  actionId: string;
  toState: string;
  allowedRoles?: AccountRole[];
  isOwnerOnly?: boolean;
  preconditions?: string[];
  postconditions?: string[];
  invariants: string[]; // Invariant IDs
}

export interface WorkflowDefinition {
  workflowId: string;
  workflowName: string;
  programId: string;
  target: string;
  initialState: string;
  terminalStates: string[];
  states: string[];
  actions: WorkflowAction[];
  transitions: WorkflowTransitionRule[];
  invariants: WorkflowSecurityInvariant[];
  sensitivity: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED_PII' | 'FINANCIAL';
  maxRequestBudget: number;
  approvalRequired?: boolean;
}

export interface WorkflowStateInstance {
  stateInstanceId: string;
  workflowId: string;
  currentState: string;
  actor: WorkflowActor;
  resource: WorkflowResource;
  isTerminal: boolean;
  stepNumber: number;
  data: Record<string, any>;
}

export interface WorkflowTransitionRecord {
  step: number;
  fromState: string;
  actionId: string;
  toState: string;
  actorId: string;
  timestamp: string;
  status: 'SUCCESS' | 'REJECTED' | 'INVALID_TRANSITION';
  responseStatus?: number;
  responsePayload?: any;
}

export interface WorkflowTransitionEvaluation {
  actionId: string;
  fromState: string;
  toState: string;
  actor: WorkflowActor;
  resource: WorkflowResource;
  isValidTransition: boolean;
  isAuthorized: boolean;
  invariantsPassed: boolean;
  violatedInvariants: {
    invariantId: string;
    type: WorkflowInvariantType;
    reason: string;
  }[];
  expectedOutcome: 'ALLOW' | 'DENY';
  observedOutcome: 'ALLOW' | 'DENY';
  status: 'CONFORMANT' | 'VIOLATION' | 'SUPPRESSED';
}

export type WorkflowImpactDimension =
  | 'CONFIDENTIALITY'
  | 'INTEGRITY'
  | 'AUTHORIZATION'
  | 'FINANCIAL'
  | 'RESOURCE_OWNERSHIP'
  | 'WORKFLOW_CONTROL'
  | 'ACCOUNT_BOUNDARY'
  | 'STATE_INTEGRITY';

export type WorkflowConfidenceLevel =
  | 'NO_FINDING'
  | 'OBSERVATION'
  | 'LOW_CONFIDENCE'
  | 'MEDIUM_CONFIDENCE'
  | 'HIGH_CONFIDENCE';

export interface WorkflowTrace {
  traceId: string;
  workflowId: string;
  scenarioName: string;
  isVulnerableExpected: boolean;
  steps: {
    stepNumber: number;
    action: WorkflowAction;
    actor: WorkflowActor;
    fromState: string;
    toState: string;
    responseStatus: number;
    responseBody: any;
    stateAfter: string;
  }[];
}

export interface WorkflowDifferentialResult {
  workflowId: string;
  scenarioName: string;
  baselineTrace: WorkflowTrace;
  evaluatedTrace: WorkflowTrace;
  hasStateDrift: boolean;
  hasUnexpectedTransition: boolean;
  hasAuthorizationBypass: boolean;
  hasInvariantBreach: boolean;
  hasReplayViolation: boolean;
  hasConcurrencyViolation: boolean;
  breachedInvariants: WorkflowSecurityInvariant[];
  explanation: string;
}

export interface WorkflowFindingCandidate {
  candidateId: string;
  researchCaseId: string;
  researchExecutionId: string;
  workflowId: string;
  target: string;
  vulnerabilityType: string;
  cweId: string;
  severity: SeverityLevel;
  confidence: WorkflowConfidenceLevel;
  impactDimensions: WorkflowImpactDimension[];
  title: string;
  description: string;
  reproductionSteps: string[];
  remediation: string;
  evidenceSummary: {
    workflowId: string;
    stepNumber: number;
    actor: string;
    fromState: string;
    action: string;
    toState: string;
    violatedInvariant: string;
    observedBehavior: string;
  };
  evidenceHash: string; // Canonical SHA-256
  createdAt: string;
}

export interface WorkflowResearchHypothesis {
  hypothesisId: string;
  workflowId: string;
  name: string;
  description: string;
  targetStateOrAction: string;
  testType:
    | 'STATE_TRANSITION'
    | 'WORKFLOW_AUTHORIZATION'
    | 'REPLAY_ATTACK'
    | 'BUSINESS_RULE'
    | 'CONCURRENCY_RACE'
    | 'TERMINAL_BYPASS'
    | 'QUANTITY_BOUNDARY';
  actors: WorkflowActor[];
  initialResource: WorkflowResource;
  actionsSequence: {
    actionId: string;
    actorId: string;
    overrideParams?: Record<string, any>;
  }[];
  expectedInvariantViolations?: WorkflowInvariantType[];
}

export interface WorkflowResearchResult {
  executionId: string;
  caseId: string;
  workflowId: string;
  programId: string;
  target: string;
  status: 'COMPLETED' | 'CANCELLED' | 'BLOCKED' | 'ERROR';
  dryRun: boolean;
  totalStepsExecuted: number;
  totalHypothesesTested: number;
  violationsDetected: number;
  candidatesGenerated: WorkflowFindingCandidate[];
  evidenceHashes: string[];
  auditEventCount: number;
  executionLogs: string[];
}
