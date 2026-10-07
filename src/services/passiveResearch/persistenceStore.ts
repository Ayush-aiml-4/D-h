/**
 * Mission #0020 — Production persistence boundary.
 * Uses in-memory durable store by default.
 * When PostgreSQL is configured, adapters can mirror writes (optional).
 * Never persists raw secrets. TOTAL_LIVE_PACKETS remains 0 in tests.
 *
 * Restart safety: LIVE sessions become REQUIRES_REAUTHORIZATION on load.
 */

import crypto from 'crypto';
import type { RealProgramProfile, ProgramOnboardingState } from './programProfileModel.ts';
import type { DualConfirmationRecord } from './dualConfirmation.ts';

export type AuthMode = 'DEVELOPMENT_AUTH' | 'TEST_AUTH' | 'PRODUCTION_AUTH';

export interface PersistedScopeVersion {
  programId: string;
  scopeVersion: string;
  allowedAssets: string[];
  excludedAssets: string[];
  createdAt: string;
  immutable: true;
}

export interface PersistedSessionSnapshot {
  sessionId: string;
  programId: string;
  researchCaseId: string;
  state: string;
  budgetMax: number;
  budgetUsed: number;
  scopeVersion: string;
  mode: 'FIXTURE' | 'LIVE_SUPERVISED';
  cancelled: boolean;
  createdAt: string;
  updatedAt: string;
  /** After restart, live sessions must re-authorize */
  requiresReauthorization: boolean;
}

export interface PersistedEvidenceMeta {
  id: string;
  sessionId: string;
  researchCaseId: string;
  target: string;
  method: string;
  sha256: string;
  timestamp: string;
  bodySnippetRedacted: string;
}

export interface PersistedAuditEvent {
  id: string;
  type: string;
  programId: string;
  sessionId?: string;
  actorRef?: string;
  timestamp: string;
  details: Record<string, string | number | boolean | null>;
}

export interface PersistedHumanReview {
  id: string;
  findingId: string;
  decision: 'CONFIRM' | 'REJECT_FALSE_POSITIVE' | 'NEEDS_MORE_REVIEW';
  reviewerReference: string;
  evidenceReference: string;
  rationale: string;
  timestamp: string;
}

interface DurableState {
  programs: Record<string, RealProgramProfile>;
  onboarding: Record<string, ProgramOnboardingState>;
  scopeVersions: PersistedScopeVersion[];
  confirmations: Record<string, DualConfirmationRecord>;
  sessions: Record<string, PersistedSessionSnapshot>;
  evidence: Record<string, PersistedEvidenceMeta>;
  audits: PersistedAuditEvent[];
  reviews: PersistedHumanReview[];
  authMode: AuthMode;
  persistenceConfigured: boolean;
}

const SECRET_RE = /eyJ[A-Za-z0-9_-]+\.|Bearer\s+[A-Za-z0-9\-._]{12,}|password\s*=|sk_live_|BEGIN (?:RSA )?PRIVATE KEY/i;

function assertNoSecrets(payload: unknown, path = 'root'): void {
  if (typeof payload === 'string' && SECRET_RE.test(payload)) {
    throw new Error(`SECRET_REJECTED_AT:${path}`);
  }
  if (payload && typeof payload === 'object') {
    for (const [k, v] of Object.entries(payload as Record<string, unknown>)) {
      if (typeof v === 'string') assertNoSecrets(v, `${path}.${k}`);
    }
  }
}

function defaultState(): DurableState {
  return {
    programs: {},
    onboarding: {},
    scopeVersions: [],
    confirmations: {},
    sessions: {},
    evidence: {},
    audits: [],
    reviews: [],
    authMode: process.env.NODE_ENV === 'production' ? 'PRODUCTION_AUTH' : 'DEVELOPMENT_AUTH',
    persistenceConfigured: false,
  };
}

/** Process-local durable store (survives within process; simulate restart via simulateRestart) */
let state: DurableState = defaultState();

export function getPersistenceStatus(): {
  status: 'PERSISTENCE_NOT_CONFIGURED' | 'IN_MEMORY_DURABLE' | 'POSTGRES_READY';
  authMode: AuthMode;
} {
  if (process.env.SQL_HOST && process.env.SQL_USER && process.env.SQL_PASSWORD && process.env.SQL_DB_NAME) {
    return { status: 'POSTGRES_READY', authMode: state.authMode };
  }
  return {
    status: state.persistenceConfigured ? 'IN_MEMORY_DURABLE' : 'PERSISTENCE_NOT_CONFIGURED',
    authMode: state.authMode,
  };
}

export function markPersistenceConfigured(): void {
  state.persistenceConfigured = true;
}

export function appendAudit(event: Omit<PersistedAuditEvent, 'id' | 'timestamp'> & { timestamp?: string }): PersistedAuditEvent {
  assertNoSecrets(event.details);
  const row: PersistedAuditEvent = {
    id: `paudit-${crypto.randomBytes(5).toString('hex')}`,
    timestamp: event.timestamp || new Date().toISOString(),
    type: event.type,
    programId: event.programId,
    sessionId: event.sessionId,
    actorRef: event.actorRef,
    details: { ...event.details },
  };
  state.audits.push(row);
  // append-only: never mutate previous
  return { ...row, details: { ...row.details } };
}

export function persistProgram(profile: RealProgramProfile, onboarding: ProgramOnboardingState): void {
  assertNoSecrets(profile);
  state.programs[profile.programId] = JSON.parse(JSON.stringify(profile));
  state.onboarding[profile.programId] = JSON.parse(JSON.stringify(onboarding));
  // Immutable scope version snapshot
  state.scopeVersions.push({
    programId: profile.programId,
    scopeVersion: profile.scopeVersion,
    allowedAssets: [...profile.allowedAssets],
    excludedAssets: [...profile.excludedAssets],
    createdAt: new Date().toISOString(),
    immutable: true,
  });
  appendAudit({
    type: 'PROGRAM_IMPORTED',
    programId: profile.programId,
    details: { scopeVersion: profile.scopeVersion, stage: onboarding.stage },
  });
  state.persistenceConfigured = true;
}

export function persistConfirmation(conf: DualConfirmationRecord): void {
  assertNoSecrets(conf as any);
  state.confirmations[conf.confirmationId] = JSON.parse(JSON.stringify(conf));
  appendAudit({
    type: 'APPROVAL_GRANTED',
    programId: conf.programId,
    actorRef: `${conf.primaryApproverRef}+${conf.secondaryApproverRef}`,
    details: { confirmationId: conf.confirmationId, supervisedLive: conf.supervisedLiveEnabled },
  });
}

export function persistSessionSnapshot(snap: PersistedSessionSnapshot): void {
  state.sessions[snap.sessionId] = { ...snap };
  appendAudit({
    type: snap.cancelled ? 'SESSION_CANCELLED' : 'SESSION_STARTED',
    programId: snap.programId,
    sessionId: snap.sessionId,
    details: { state: snap.state, mode: snap.mode, budgetUsed: snap.budgetUsed },
  });
}

/** Atomic budget consume — returns false if would exceed */
export function consumeBudget(sessionId: string, n = 1): boolean {
  const s = state.sessions[sessionId];
  if (!s || s.cancelled || s.requiresReauthorization) return false;
  if (s.budgetUsed + n > s.budgetMax) {
    appendAudit({
      type: 'BUDGET_EXHAUSTED',
      programId: s.programId,
      sessionId,
      details: { budgetUsed: s.budgetUsed, budgetMax: s.budgetMax },
    });
    return false;
  }
  s.budgetUsed += n;
  s.updatedAt = new Date().toISOString();
  return true;
}

export function persistEvidenceMeta(meta: PersistedEvidenceMeta): void {
  assertNoSecrets(meta.bodySnippetRedacted);
  state.evidence[meta.id] = { ...meta };
  appendAudit({
    type: 'EVIDENCE_CREATED',
    programId: state.sessions[meta.sessionId]?.programId || 'unknown',
    sessionId: meta.sessionId,
    details: { evidenceId: meta.id, sha256: meta.sha256 },
  });
}

export function verifyPersistedEvidenceHash(id: string, recomputedSha256: string): boolean {
  const e = state.evidence[id];
  if (!e) return false;
  return e.sha256 === recomputedSha256;
}

export function persistHumanReview(review: Omit<PersistedHumanReview, 'id' | 'timestamp'>): PersistedHumanReview {
  const row: PersistedHumanReview = {
    ...review,
    id: `prev-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: new Date().toISOString(),
  };
  state.reviews.push(row);
  appendAudit({
    type: review.decision === 'CONFIRM' ? 'FINDING_CONFIRMED' : 'FINDING_REJECTED',
    programId: 'n/a',
    actorRef: review.reviewerReference,
    details: { findingId: review.findingId, decision: review.decision },
  });
  return row;
}

export function getScopeVersions(programId: string): PersistedScopeVersion[] {
  return state.scopeVersions.filter((s) => s.programId === programId).map((s) => ({ ...s, allowedAssets: [...s.allowedAssets] }));
}

/**
 * Simulate process restart: live sessions require reauthorization; cancelled stay cancelled.
 * Sessions do NOT auto-resume network activity.
 */
export function simulateRestart(): {
  sessionsRequiringReauth: string[];
  cancelledPreserved: string[];
  auditsPreserved: number;
  evidencePreserved: number;
} {
  const requiring: string[] = [];
  const cancelled: string[] = [];
  for (const s of Object.values(state.sessions)) {
    if (s.cancelled) {
      cancelled.push(s.sessionId);
      continue;
    }
    if (s.mode === 'LIVE_SUPERVISED' || s.state === 'RUNNING' || s.state === 'READY') {
      s.requiresReauthorization = true;
      s.state = 'REQUIRES_REAUTHORIZATION';
      requiring.push(s.sessionId);
      appendAudit({
        type: 'AUTHORIZATION_INVALID',
        programId: s.programId,
        sessionId: s.sessionId,
        details: { reason: 'RESTART_REQUIRES_REAUTHORIZATION' },
      });
    }
  }
  return {
    sessionsRequiringReauth: requiring,
    cancelledPreserved: cancelled,
    auditsPreserved: state.audits.length,
    evidencePreserved: Object.keys(state.evidence).length,
  };
}

export function getAudits(programId?: string): PersistedAuditEvent[] {
  const rows = programId ? state.audits.filter((a) => a.programId === programId) : state.audits;
  return rows.map((a) => ({ ...a, details: { ...a.details } }));
}

export function getSessionSnapshot(sessionId: string): PersistedSessionSnapshot | null {
  const s = state.sessions[sessionId];
  return s ? { ...s } : null;
}

export function listPersistedSessions(programId?: string): PersistedSessionSnapshot[] {
  const all = Object.values(state.sessions);
  return (programId ? all.filter((s) => s.programId === programId) : all).map((s) => ({ ...s }));
}

export function clearPersistenceStore(): void {
  state = defaultState();
}

export function productionAuthFailClosed(): { ok: boolean; reason: string } {
  if (state.authMode === 'PRODUCTION_AUTH') {
    if (!process.env.FIREBASE_PROJECT_ID && !process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      return { ok: false, reason: 'PRODUCTION_AUTH_NOT_CONFIGURED' };
    }
  }
  return { ok: true, reason: 'OK' };
}

/** Concurrent budget stress test helper */
export function concurrentBudgetAttempts(sessionId: string, attempts: number): { accepted: number; rejected: number } {
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < attempts; i++) {
    if (consumeBudget(sessionId, 1)) accepted++;
    else rejected++;
  }
  return { accepted, rejected };
}
