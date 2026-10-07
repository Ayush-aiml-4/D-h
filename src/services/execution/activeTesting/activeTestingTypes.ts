import { AuthUser } from '../../../middleware/auth.ts';
import { ControlledHttpRequestOptions, ControlledHttpResponse } from '../types.ts';

export type ActiveTestingTier =
  | 'PASSIVE'
  | 'LOW_RISK_ACTIVE'
  | 'APPROVAL_REQUIRED'
  | 'RESTRICTED';

export type ActiveExecutionStatus =
  | 'QUEUED'
  | 'AUTHORIZED'
  | 'APPROVED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'CANCELLED'
  | 'BLOCKED'
  | 'FAILED';

export type MutationLevel =
  | 'NONE'
  | 'CONTROLLED_BENIGN'
  | 'PAYLOAD_PROBE'
  | 'RESTRICTED';

export type FindingPromotionPolicy =
  | 'MANUAL_REVIEW_ONLY'
  | 'OBSERVATION_ONLY';

export type ApprovalStatus =
  | 'PENDING'
  | 'CONFIRMED'
  | 'CONSUMED'
  | 'EXPIRED'
  | 'REVOKED';

export interface ActiveCapabilityDefinition {
  capabilityId: string;
  canonicalName: string;
  category: string;
  description: string;
  authorizationTier: ActiveTestingTier;
  approvalRequired: boolean;
  scopeRequired: boolean;
  policyRequirements: string[];
  maximumRequestBudget: number;
  maximumConcurrency: number;
  timeout: number; // in milliseconds
  maximumResponseSize: number; // in bytes (e.g. 1MB)
  evidenceType: string;
  findingPromotionPolicy: FindingPromotionPolicy;
  destructive: boolean;
  credentialInteraction: boolean;
  mutationLevel: MutationLevel;
  supportedProtocols: string[];
  enabled: boolean;
}

export interface RequestBudget {
  maxTotalRequests: number;
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  maxExecutionDurationMs: number;
  maxResponseBytes: number;
  totalRequestsExecuted: number;
  startedAt: number;
}

export interface ActiveApprovalRequirement {
  approvalId: string;
  researcherId: string;
  researcherName: string;
  programId: string;
  assetId: string;
  capabilityId: string;
  target: string;
  authorizationTier: ActiveTestingTier;
  createdAt: string;
  expiresAt: string;
  status: ApprovalStatus;
  executionFingerprint: string;
  confirmedAt?: string;
  consumedAt?: string;
}

export interface ActiveExecutionContext {
  executionId: string;
  researcherId: string;
  researcherName: string;
  user: AuthUser;
  programId: string;
  programName: string;
  caseId: string;
  assetId: string;
  target: string;
  capabilityId: string;
  capabilityName: string;
  authorizationTier: ActiveTestingTier;
  approvalId?: string;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  requestBudget: RequestBudget;
  concurrencyBudget: number;
  timeout: number;
  startedAt: string;
  cancellationState: {
    isCancelled: boolean;
    reason?: string;
  };
  requestId: string;
  parameters?: Record<string, string | number | boolean>;
}

export interface ActiveExecutionObservation {
  observationId: string;
  executionId: string;
  capabilityId: string;
  assetId: string;
  programId: string;
  caseId: string;
  requestId: string;
  timestamp: string;
  observationType: string;
  target: string;
  sanitizedData: Record<string, any>;
  evidenceHash?: string;
  correlationHash?: string;
}

export interface ActiveExecutionRequest {
  caseId: string;
  capabilityId: string;
  assetId: string;
  target?: string;
  approvalId?: string;
  confirmApproval?: boolean;
  parameters?: Record<string, string | number | boolean>;
}

export interface ActiveExecutionResult {
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
  status: ActiveExecutionStatus;
  authorizationTier: ActiveTestingTier;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  approvalId?: string;
  observations: ActiveExecutionObservation[];
  evidenceId?: string;
  evidenceHash?: string;
  requestsExecuted: number;
  durationMs: number;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  error?: string;
  requestId: string;
}

export interface ControlledMutationRequestOptions extends ControlledHttpRequestOptions {
  mutationTag?: string;
  mutationDescription?: string;
}

export interface ControlledRequestBuilderInterface {
  send(options: ControlledMutationRequestOptions): Promise<ControlledHttpResponse>;
  getTarget(): string;
  getHostname(): string;
  getExecutedCount(): number;
}

export interface ActiveTestingAdapter {
  capabilityId: string;
  aliases?: string[];
  name: string;
  description: string;
  authorizationTier: ActiveTestingTier;
  enabled: boolean;
  execute(
    context: ActiveExecutionContext,
    builder: ControlledRequestBuilderInterface
  ): Promise<ActiveExecutionObservation[]>;
}
