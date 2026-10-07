/**
 * DEVILHUNT — Passive-First Research Engine & Audit Provenance
 * Enforces safe, non-state-changing operations (GET/HEAD/OPTIONS only).
 * Prohibits mutations, payload injections, and state altering requests.
 * Tracks session request budgets, computes SHA-256 evidence hashes,
 * generates immutable audit records, and supports instant cancellation.
 */

import crypto from 'crypto';
import {
  EngagementAuditEntry,
  EngagementProgramProfile,
  PassiveEvidenceRecord,
} from '../../types/engagement.ts';
import { validateTargetScope } from './scopeImportService.ts';
import { getProxyBoundaryConfig } from './proxyBoundaryService.ts';
import { BadRequestError } from '../../utils/errors.ts';

// Allowed HTTP methods in passive research mode
export const SAFE_PASSIVE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export interface PassiveResearchSession {
  sessionId: string;
  programId: string;
  targetAsset: string;
  status: 'INITIALIZING' | 'RUNNING' | 'PAUSED' | 'CANCELLED' | 'COMPLETED' | 'BLOCKED';
  requestBudget: {
    maxBudget: number;
    usedRequests: number;
    rateLimitPerSec: number;
  };
  auditTrail: EngagementAuditEntry[];
  evidenceRecords: PassiveEvidenceRecord[];
  createdAt: string;
  updatedAt: string;
}

// In-Memory Active Sessions and Audit Log
const activeSessions = new Map<string, PassiveResearchSession>();
const globalAuditLog: EngagementAuditEntry[] = [];

/**
 * Calculates deterministic SHA-256 evidence hash.
 */
export function computeEvidenceSha256(data: {
  url: string;
  method: string;
  status: number;
  headers: Record<string, string>;
  bodySnippet: string;
}): string {
  const normalized = JSON.stringify({
    url: data.url.toLowerCase(),
    method: data.method.toUpperCase(),
    status: data.status,
    headers: Object.keys(data.headers)
      .sort()
      .reduce((acc, k) => ({ ...acc, [k.toLowerCase()]: data.headers[k] }), {}),
    bodySnippet: data.bodySnippet.trim(),
  });

  return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * Creates an immutable audit trail entry.
 */
export function recordEngagementAudit(entry: Omit<EngagementAuditEntry, 'id' | 'timestamp'>): EngagementAuditEntry {
  const auditRecord: EngagementAuditEntry = {
    id: `audit-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: new Date().toISOString(),
    ...entry,
  };

  globalAuditLog.push(auditRecord);
  return auditRecord;
}

/**
 * Retrieves the global audit log, optionally filtered by programId.
 */
export function getEngagementAuditLog(programId?: string): EngagementAuditEntry[] {
  if (programId) {
    const clean = programId.toLowerCase().trim();
    return globalAuditLog.filter((a) => a.programId.toLowerCase() === clean);
  }
  return [...globalAuditLog];
}

/**
 * Starts a new Passive Research Session.
 */
export function startPassiveResearchSession(params: {
  programProfile: EngagementProgramProfile;
  targetAsset: string;
  maxBudget?: number;
}): PassiveResearchSession {
  // Validate scope first
  const scopeDecision = validateTargetScope(params.targetAsset, params.programProfile);
  if (!scopeDecision.allowed) {
    recordEngagementAudit({
      programId: params.programProfile.id,
      targetAsset: params.targetAsset,
      researchMode: 'PASSIVE',
      policyEvaluationResult: 'DENY',
      humanApprovalReference: null,
      executionId: `exec-${Date.now()}`,
      proxyCorrelationId: 'none',
      evidenceHash: 'none',
      action: 'SESSION_START_REJECTED_OUT_OF_SCOPE',
      details: { reason: scopeDecision.reason },
    });
    throw new BadRequestError(`SCOPE_DENIED: Cannot start passive session on target '${params.targetAsset}': ${scopeDecision.reason}`);
  }

  const budget = params.maxBudget || params.programProfile.programPolicy.requestLimits.totalSessionBudget || 50;
  const rateLimit = params.programProfile.programPolicy.requestLimits.rateLimitPerSecond || 5;

  const sessionId = `pass-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const session: PassiveResearchSession = {
    sessionId,
    programId: params.programProfile.id,
    targetAsset: params.targetAsset,
    status: 'RUNNING',
    requestBudget: {
      maxBudget: budget,
      usedRequests: 0,
      rateLimitPerSec: rateLimit,
    },
    auditTrail: [],
    evidenceRecords: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  const auditEntry = recordEngagementAudit({
    programId: params.programProfile.id,
    targetAsset: params.targetAsset,
    researchMode: 'PASSIVE',
    policyEvaluationResult: 'ALLOW',
    humanApprovalReference: null,
    executionId: `exec-${sessionId}`,
    proxyCorrelationId: 'proxy-init',
    evidenceHash: 'none',
    action: 'PASSIVE_SESSION_INITIALIZED',
    details: { maxBudget: budget, rateLimit },
  });

  session.auditTrail.push(auditEntry);
  activeSessions.set(sessionId, session);
  return session;
}

/**
 * Executes a simulated passive research observation safely.
 * Rejects any non-safe methods (POST, PUT, DELETE, PATCH).
 * Enforces request budget limits and fail-closed stopping conditions.
 */
export function executePassiveObservation(params: {
  sessionId: string;
  profile: EngagementProgramProfile;
  method: 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  mockResponseStatus?: number;
  mockHeaders?: Record<string, string>;
  mockBodySnippet?: string;
}): {
  success: boolean;
  evidence: PassiveEvidenceRecord;
  sessionRemainingBudget: number;
} {
  const session = activeSessions.get(params.sessionId);
  if (!session) {
    throw new BadRequestError(`SESSION_NOT_FOUND: Passive session '${params.sessionId}' does not exist`);
  }

  if (session.status !== 'RUNNING') {
    throw new BadRequestError(`SESSION_NOT_RUNNING: Session '${params.sessionId}' is currently '${session.status}'`);
  }

  // 1. Enforce Safe HTTP Method
  if (!SAFE_PASSIVE_METHODS.has(params.method.toUpperCase())) {
    session.status = 'BLOCKED';
    recordEngagementAudit({
      programId: session.programId,
      targetAsset: session.targetAsset,
      researchMode: 'PASSIVE',
      policyEvaluationResult: 'BLOCK',
      humanApprovalReference: null,
      executionId: `exec-${Date.now()}`,
      proxyCorrelationId: 'blocked',
      evidenceHash: 'none',
      action: 'PASSIVE_METHOD_VIOLATION_BLOCKED',
      details: {
        attemptedMethod: params.method,
        reason: 'State-changing HTTP methods are strictly forbidden in PASSIVE_RESEARCH mode',
      },
    });
    throw new BadRequestError(
      `STATE_CHANGING_OPERATION_FORBIDDEN: Method '${params.method}' is not permitted in PASSIVE_RESEARCH mode. Only GET, HEAD, OPTIONS are allowed.`
    );
  }

  // 2. Enforce Request Budget
  if (session.requestBudget.usedRequests >= session.requestBudget.maxBudget) {
    session.status = 'COMPLETED';
    recordEngagementAudit({
      programId: session.programId,
      targetAsset: session.targetAsset,
      researchMode: 'PASSIVE',
      policyEvaluationResult: 'BLOCK',
      humanApprovalReference: null,
      executionId: `exec-${Date.now()}`,
      proxyCorrelationId: 'budget-exhausted',
      evidenceHash: 'none',
      action: 'SESSION_BUDGET_EXHAUSTED',
      details: { used: session.requestBudget.usedRequests, max: session.requestBudget.maxBudget },
    });
    throw new BadRequestError(
      `BUDGET_EXHAUSTED: Session has reached maximum authorized request limit of ${session.requestBudget.maxBudget} requests.`
    );
  }

  // Increment budget
  session.requestBudget.usedRequests += 1;
  const executionId = `exec-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const proxyBoundary = getProxyBoundaryConfig();
  const proxyCorrelationId = proxyBoundary.enabled ? `corr-${crypto.randomBytes(6).toString('hex')}` : 'direct-simulated';

  // Compute Evidence & Provenance
  const fullUrl = `${session.targetAsset.startsWith('http') ? session.targetAsset : 'https://' + session.targetAsset}${params.path}`;
  const status = params.mockResponseStatus || 200;
  const headers = params.mockHeaders || {
    'content-type': 'application/json',
    'x-content-type-options': 'nosniff',
  };
  const bodySnippet = params.mockBodySnippet || '{"status":"ok","inspected":true}';

  const evidenceHash = computeEvidenceSha256({
    url: fullUrl,
    method: params.method,
    status,
    headers,
    bodySnippet,
  });

  const evidenceRecord: PassiveEvidenceRecord = {
    id: `ev-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: new Date().toISOString(),
    executionId,
    proxyCorrelationId,
    method: params.method as 'GET' | 'HEAD' | 'OPTIONS',
    url: fullUrl,
    responseStatus: status,
    headers,
    bodySnippet,
    evidenceHash,
  };

  session.evidenceRecords.push(evidenceRecord);
  session.updatedAt = new Date().toISOString();

  // Audit
  const audit = recordEngagementAudit({
    programId: session.programId,
    targetAsset: fullUrl,
    researchMode: 'PASSIVE',
    policyEvaluationResult: 'ALLOW',
    humanApprovalReference: null,
    executionId,
    proxyCorrelationId,
    evidenceHash,
    action: 'PASSIVE_OBSERVATION_RECORDED',
    details: { method: params.method, status },
  });

  session.auditTrail.push(audit);

  return {
    success: true,
    evidence: evidenceRecord,
    sessionRemainingBudget: session.requestBudget.maxBudget - session.requestBudget.usedRequests,
  };
}

/**
 * Pauses or cancels an active passive session.
 */
export function cancelPassiveResearchSession(sessionId: string, reason: string): PassiveResearchSession {
  const session = activeSessions.get(sessionId);
  if (!session) {
    throw new BadRequestError(`SESSION_NOT_FOUND: ${sessionId}`);
  }

  session.status = 'CANCELLED';
  session.updatedAt = new Date().toISOString();

  const audit = recordEngagementAudit({
    programId: session.programId,
    targetAsset: session.targetAsset,
    researchMode: 'PASSIVE',
    policyEvaluationResult: 'ALLOW',
    humanApprovalReference: 'operator-cancel',
    executionId: `exec-cancel-${Date.now()}`,
    proxyCorrelationId: 'none',
    evidenceHash: 'none',
    action: 'PASSIVE_SESSION_CANCELLED',
    details: { reason },
  });

  session.auditTrail.push(audit);
  return session;
}

export function getPassiveSession(sessionId: string): PassiveResearchSession | null {
  return activeSessions.get(sessionId) || null;
}
