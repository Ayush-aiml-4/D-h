import { AuthUser } from '../../middleware/auth.ts';

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

export type ApprovalType =
  | 'AUTOMATIC_LOW_RISK'
  | 'EXPLICIT_RESEARCHER_CONFIRMATION'
  | 'ADMIN_AUTHORIZATION';

export interface ExecutionApproval {
  approved: boolean;
  approvedBy: string;
  approvedAt: string;
  approvalType: ApprovalType;
  reason?: string;
}

export interface ExecutionPolicy {
  authorizationLevel: AuthorizationLevel;
  requiresExplicitApproval: boolean;
  maxTimeoutMs: number;
  maxRequestsPerMinute: number;
  allowedProtocols: string[];
  allowNetworkAccess: boolean;
  description: string;
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

export interface ExecutionContext {
  executionId: string;
  user: AuthUser;
  programId: string;
  programName: string;
  assetId: string;
  target: string;
  caseId: string;
  capabilityId: string;
  capabilityName: string;
  authorizationLevel: AuthorizationLevel;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  approval?: ExecutionApproval;
  requestId: string;
  timeoutMs: number;
  rateLimitBudget: number;
  parameters?: Record<string, string | number | boolean>;
  signal?: AbortSignal;
}

export interface ExecutionRequest {
  caseId: string;
  capabilityId: string;
  assetId: string;
  target?: string;
  parameters?: Record<string, string | number | boolean>;
  confirmApproval?: boolean;
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

export interface ControlledHttpRequestOptions {
  method?: 'GET' | 'HEAD' | 'POST' | 'OPTIONS';
  path?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxRedirects?: number;
  followRedirects?: boolean;
}

export interface ControlledHttpResponse {
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  url: string;
  ip?: string;
  durationMs: number;
  redirectCount: number;
}

export interface ControlledHttpClient {
  request(options: ControlledHttpRequestOptions): Promise<ControlledHttpResponse>;
  getTarget(): string;
  getHostname(): string;
}

export interface ExecutionAdapter {
  capabilityId: string;
  aliases?: string[];
  name: string;
  description: string;
  authorizationLevel: AuthorizationLevel;
  enabled: boolean;
  execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]>;
}
