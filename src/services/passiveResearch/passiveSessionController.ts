/**
 * Mission #0016 — Passive Session Controller
 * Sole orchestration for controlled passive sessions. Active testing never enters this lifecycle.
 */

import crypto from 'crypto';
import {
  getProgramProfile,
  isAuthorizedForPassive,
  advanceOnboarding,
  getOnboardingState,
} from './programProfileModel.ts';
import { checkTargetScope, checkMethodAllowed } from './scopeEnforcement.ts';
import { analyzePassiveResponse } from '../passiveIntelligence/passiveDiscoveryEngine.ts';
import { appendTimelineEvent } from '../passiveIntelligence/researchTimeline.ts';
import { redactSecretsFromText, redactHeaders } from '../passiveIntelligence/secretRedaction.ts';
import type { NormalizedPassiveResponse, SecurityObservation, DiscoveryRecord } from '../passiveIntelligence/types.ts';
import { SafeControlledHttpClient } from '../execution/httpClient.ts';
import type { ExecutionContext, ControlledHttpResponse } from '../execution/types.ts';

export type SessionState =
  | 'CREATED'
  | 'AWAITING_APPROVAL'
  | 'READY'
  | 'RUNNING'
  | 'PAUSED'
  | 'COMPLETED'
  | 'CANCELLED'
  | 'BLOCKED'
  | 'FAILED';

export interface PassiveSession {
  sessionId: string;
  programId: string;
  researchCaseId: string;
  state: SessionState;
  budgetMax: number;
  budgetUsed: number;
  targets: string[];
  observations: SecurityObservation[];
  discoveries: DiscoveryRecord[];
  evidenceIds: string[];
  blockedRequests: Array<{ target: string; reason: string; timestamp: string }>;
  createdAt: string;
  updatedAt: string;
  cancelReason?: string;
  proxyRequired: boolean;
  proxyAvailable: boolean;
  sensitiveDataPaused: boolean;
}

export interface PolicyError {
  code:
    | 'SCOPE_DENIED'
    | 'METHOD_NOT_ALLOWED'
    | 'PROGRAM_NOT_AUTHORIZED'
    | 'APPROVAL_REQUIRED'
    | 'REQUEST_BUDGET_EXCEEDED'
    | 'PROXY_REQUIRED'
    | 'PROXY_UNAVAILABLE'
    | 'SESSION_CANCELLED'
    | 'TARGET_NOT_VERIFIED'
    | 'REDIRECT_OUT_OF_SCOPE'
    | 'RESPONSE_TOO_LARGE'
    | 'SENSITIVE_DATA_PAUSE'
    | 'SESSION_NOT_RUNNING'
    | 'ACTIVE_TESTING_LOCKED';
  message: string;
}

const sessions = new Map<string, PassiveSession>();

export const RESPONSE_LIMITS = {
  maxBodyBytes: 512 * 1024,
  maxHeaderBytes: 32 * 1024,
  maxRedirects: 3,
  defaultTimeoutMs: 10000,
};

export function clearSessions(): void {
  sessions.clear();
}

export function getSession(sessionId: string): PassiveSession | null {
  return sessions.get(sessionId) || null;
}

export function listSessions(programId?: string): PassiveSession[] {
  const all = [...sessions.values()];
  return programId ? all.filter((s) => s.programId === programId) : all;
}

export function createPassiveSession(params: {
  programId: string;
  targets: string[];
  proxyAvailable?: boolean;
}): { session?: PassiveSession; error?: PolicyError } {
  const auth = isAuthorizedForPassive(params.programId);
  if (!auth.ok) {
    return {
      error: {
        code: auth.reason.includes('APPROVAL') ? 'APPROVAL_REQUIRED' : 'PROGRAM_NOT_AUTHORIZED',
        message: auth.reason,
      },
    };
  }

  const profile = getProgramProfile(params.programId)!;
  if (profile.proxyRequirement && !params.proxyAvailable) {
    return { error: { code: 'PROXY_REQUIRED', message: 'Proxy required by program policy but unavailable' } };
  }

  // Validate all seed targets
  for (const t of params.targets) {
    const scope = checkTargetScope(params.programId, t);
    if (!scope.allowed) {
      return { error: { code: 'SCOPE_DENIED', message: `${scope.code}:${scope.reason}` } };
    }
  }

  const sessionId = `psess-${crypto.randomBytes(6).toString('hex')}`;
  const researchCaseId = `case-${crypto.randomBytes(4).toString('hex')}`;
  const session: PassiveSession = {
    sessionId,
    programId: params.programId,
    researchCaseId,
    state: 'READY',
    budgetMax: profile.requestBudget,
    budgetUsed: 0,
    targets: [...params.targets],
    observations: [],
    discoveries: [],
    evidenceIds: [],
    blockedRequests: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    proxyRequired: profile.proxyRequirement,
    proxyAvailable: !!params.proxyAvailable,
    sensitiveDataPaused: false,
  };

  sessions.set(sessionId, session);
  try {
    advanceOnboarding(params.programId, 'PASSIVE_SESSION_ACTIVE');
  } catch {
    /* already active ok */
  }

  appendTimelineEvent({
    type: 'SESSION_STARTED',
    programId: params.programId,
    researchCaseId,
    details: { sessionId, targets: params.targets.length },
  });

  return { session };
}

export function cancelSession(sessionId: string, reason: string): PassiveSession | null {
  const s = sessions.get(sessionId);
  if (!s) return null;
  s.state = 'CANCELLED';
  s.cancelReason = reason;
  s.updatedAt = new Date().toISOString();
  appendTimelineEvent({
    type: 'SESSION_CANCELLED',
    programId: s.programId,
    researchCaseId: s.researchCaseId,
    details: { sessionId, reason },
  });
  try {
    advanceOnboarding(s.programId, 'PASSIVE_SESSION_COMPLETED');
  } catch {
    /* ignore */
  }
  return s;
}

export function executePassiveRequest(params: {
  sessionId: string;
  target: string;
  method: string;
  /** When true, never use real network — fixtures only via mock handler */
  testMode?: boolean;
  fixtureResponse?: { status: number; headers: Record<string, string>; body: string };
}): {
  ok: boolean;
  error?: PolicyError;
  observations?: SecurityObservation[];
  discoveries?: DiscoveryRecord[];
  evidenceId?: string;
} {
  const s = sessions.get(params.sessionId);
  if (!s) return { ok: false, error: { code: 'SESSION_NOT_RUNNING', message: 'SESSION_NOT_FOUND' } };
  if (s.state === 'CANCELLED') return { ok: false, error: { code: 'SESSION_CANCELLED', message: s.cancelReason || 'cancelled' } };
  if (s.state === 'BLOCKED' || s.state === 'FAILED') {
    return { ok: false, error: { code: 'SESSION_NOT_RUNNING', message: s.state } };
  }
  if (s.sensitiveDataPaused) {
    return { ok: false, error: { code: 'SENSITIVE_DATA_PAUSE', message: 'Human review required for sensitive data' } };
  }

  const auth = isAuthorizedForPassive(s.programId);
  if (!auth.ok) return { ok: false, error: { code: 'PROGRAM_NOT_AUTHORIZED', message: auth.reason } };

  const methodCheck = checkMethodAllowed(params.method, s.programId);
  if (!methodCheck.allowed) {
    s.blockedRequests.push({ target: params.target, reason: methodCheck.reason, timestamp: new Date().toISOString() });
    return { ok: false, error: { code: 'METHOD_NOT_ALLOWED', message: methodCheck.reason } };
  }

  const scope = checkTargetScope(s.programId, params.target);
  if (!scope.allowed) {
    s.blockedRequests.push({ target: params.target, reason: scope.reason, timestamp: new Date().toISOString() });
    appendTimelineEvent({
      type: 'SCOPE_BLOCKED',
      programId: s.programId,
      researchCaseId: s.researchCaseId,
      target: params.target,
      details: { reason: scope.reason },
    });
    return { ok: false, error: { code: 'SCOPE_DENIED', message: scope.reason } };
  }

  if (s.budgetUsed >= s.budgetMax) {
    s.state = 'COMPLETED';
    return { ok: false, error: { code: 'REQUEST_BUDGET_EXCEEDED', message: 'Budget exhausted' } };
  }

  if (s.proxyRequired && !s.proxyAvailable) {
    return { ok: false, error: { code: 'PROXY_UNAVAILABLE', message: 'Proxy unavailable' } };
  }

  s.state = 'RUNNING';
  s.budgetUsed += 1;
  s.updatedAt = new Date().toISOString();

  const requestId = `req-${crypto.randomBytes(4).toString('hex')}`;
  const executionId = `exec-${crypto.randomBytes(4).toString('hex')}`;

  // Response acquisition: testMode / fixture ONLY — production would use SafeControlledHttpClient after all gates
  let status = 200;
  let headers: Record<string, string> = { 'content-type': 'text/html' };
  let body = '';

  if (params.fixtureResponse) {
    status = params.fixtureResponse.status;
    headers = { ...params.fixtureResponse.headers };
    body = params.fixtureResponse.body;
  } else if (params.testMode !== false) {
    // Default test mode: empty fixture — ZERO live packets
    status = 200;
    headers = { 'content-type': 'text/plain' };
    body = 'TEST_MODE_NO_LIVE_TRAFFIC';
  } else {
    // Production path: only via SafeControlledHttpClient — still requires mock unless intentionally live
    // For safety in this codebase without real program credentials, refuse live dispatch
    return {
      ok: false,
      error: {
        code: 'TARGET_NOT_VERIFIED',
        message: 'LIVE_DISPATCH_REQUIRES_EXPLICIT_PROGRAM_AND_MOCK_CLEAR — refusing accidental live traffic',
      },
    };
  }

  // Size limits
  if (Buffer.byteLength(body, 'utf8') > RESPONSE_LIMITS.maxBodyBytes) {
    s.blockedRequests.push({ target: params.target, reason: 'RESPONSE_TOO_LARGE', timestamp: new Date().toISOString() });
    return { ok: false, error: { code: 'RESPONSE_TOO_LARGE', message: 'Body exceeds limit' } };
  }

  // Secret detection pause
  const bodyCheck = redactSecretsFromText(body);
  const hdrCheck = redactHeaders(headers);
  if (bodyCheck.redacted && /eyJ|sk_live|BEGIN PRIVATE KEY|password=/i.test(body)) {
    // Strong secret patterns → pause for human review
    const strongSecret = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|sk_live_|BEGIN (?:RSA )?PRIVATE KEY|password\s*=\s*\S{6,}/i.test(body);
    if (strongSecret) {
      s.sensitiveDataPaused = true;
      s.state = 'PAUSED';
      appendTimelineEvent({
        type: 'OBSERVATION_CREATED',
        programId: s.programId,
        researchCaseId: s.researchCaseId,
        target: params.target,
        details: { sensitiveDataReview: true },
      });
      // Still analyze with redacted content
    }
  }

  const normalized: NormalizedPassiveResponse = {
    url: scope.normalizedUrl || params.target,
    method: params.method.toUpperCase() as 'GET' | 'HEAD' | 'OPTIONS',
    status,
    headers: hdrCheck.headers,
    body: bodyCheck.text,
    contentType: headers['content-type'] || 'text/plain',
    programId: s.programId,
    researchCaseId: s.researchCaseId,
    executionId,
    requestId,
    target: params.target,
    timestamp: new Date().toISOString(),
  };

  appendTimelineEvent({
    type: 'REQUEST_EXECUTED',
    programId: s.programId,
    researchCaseId: s.researchCaseId,
    executionId,
    requestId,
    target: params.target,
    details: { method: params.method, testMode: true },
  });

  const result = analyzePassiveResponse(normalized);
  s.observations.push(...result.observations);
  s.discoveries.push(...result.discoveries);
  if (result.evidenceId) s.evidenceIds.push(result.evidenceId);
  s.updatedAt = new Date().toISOString();

  return {
    ok: true,
    observations: result.observations,
    discoveries: result.discoveries,
    evidenceId: result.evidenceId,
  };
}

/** Active testing is always locked from this controller */
export function isActiveTestingLocked(): boolean {
  return true;
}
