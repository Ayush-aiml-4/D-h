/**
 * Mission #0018 — Supervised passive collection.
 * Live network ONLY when:
 *  1. Dual confirmation present with supervisedLiveEnabled
 *  2. process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE === 'true'
 *  3. All preflight/scope/method/budget gates pass
 *  4. SafeControlledHttpClient is used exclusively
 *
 * Automated tests MUST leave DEVILHUNT_ALLOW_LIVE_PASSIVE unset and use fixtures.
 */

import crypto from 'crypto';
import {
  createPassiveSession,
  executePassiveRequest,
  getSession,
  cancelSession,
  isActiveTestingLocked,
  type PassiveSession,
} from './passiveSessionController.ts';
import { isConfirmationValidForSession, getConfirmation } from './dualConfirmation.ts';
import { checkTargetScope, checkMethodAllowed } from './scopeEnforcement.ts';
import { isAuthorizedForPassive, getProgramProfile } from './programProfileModel.ts';
import { SafeControlledHttpClient } from '../execution/httpClient.ts';
import type { ExecutionContext } from '../execution/types.ts';
import { analyzePassiveResponse } from '../passiveIntelligence/passiveDiscoveryEngine.ts';
import { appendTimelineEvent } from '../passiveIntelligence/researchTimeline.ts';
import { redactHeaders, redactSecretsFromText } from '../passiveIntelligence/secretRedaction.ts';
import type { NormalizedPassiveResponse, SecurityObservation, DiscoveryRecord } from '../passiveIntelligence/types.ts';

export interface SupervisedCollectionPlan {
  programId: string;
  confirmationId: string;
  targets: string[];
  methods: Array<'GET' | 'HEAD' | 'OPTIONS'>;
  maxRequests: number;
}

export interface SupervisedCollectionResult {
  sessionId: string;
  mode: 'FIXTURE' | 'LIVE_SUPERVISED' | 'BLOCKED';
  liveNetworkRequests: number;
  observations: SecurityObservation[];
  discoveries: DiscoveryRecord[];
  blocked: Array<{ target: string; reason: string }>;
  errors: string[];
  activeTestingLocked: boolean;
}

function isLiveAllowedByEnv(): boolean {
  return process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE === 'true';
}

/**
 * Start supervised session after dual confirmation.
 * Default mode is FIXTURE (zero live packets).
 */
export function startSupervisedCollection(params: {
  confirmationId: string;
  programId: string;
  targets: string[];
  proxyAvailable?: boolean;
}): { ok: true; session: PassiveSession; mode: 'FIXTURE' | 'LIVE_SUPERVISED' } | { ok: false; errors: string[] } {
  if (!isConfirmationValidForSession(params.confirmationId, params.programId)) {
    return { ok: false, errors: ['INVALID_OR_MISSING_DUAL_CONFIRMATION'] };
  }

  const conf = getConfirmation(params.confirmationId)!;
  const auth = isAuthorizedForPassive(params.programId);
  if (!auth.ok) return { ok: false, errors: [auth.reason] };

  const created = createPassiveSession({
    programId: params.programId,
    targets: params.targets,
    proxyAvailable: params.proxyAvailable ?? true,
  });

  if (created.error || !created.session) {
    return { ok: false, errors: [created.error?.message || 'SESSION_CREATE_FAILED'] };
  }

  const live = conf.supervisedLiveEnabled && isLiveAllowedByEnv();
  const mode: 'FIXTURE' | 'LIVE_SUPERVISED' = live ? 'LIVE_SUPERVISED' : 'FIXTURE';

  appendTimelineEvent({
    type: 'SESSION_STARTED',
    programId: params.programId,
    researchCaseId: created.session.researchCaseId,
    details: {
      sessionId: created.session.sessionId,
      mode,
      confirmationId: params.confirmationId,
    },
  });

  return { ok: true, session: created.session, mode };
}

/**
 * Execute one supervised passive request.
 * LIVE path uses SafeControlledHttpClient only when mode is LIVE_SUPERVISED.
 * FIXTURE path never opens sockets.
 */
export async function supervisedPassiveRequest(params: {
  sessionId: string;
  confirmationId: string;
  target: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  mode: 'FIXTURE' | 'LIVE_SUPERVISED';
  fixtureResponse?: { status: number; headers: Record<string, string>; body: string };
}): Promise<{
  ok: boolean;
  liveNetwork: boolean;
  error?: string;
  observations?: SecurityObservation[];
  discoveries?: DiscoveryRecord[];
  evidenceId?: string;
}> {
  const session = getSession(params.sessionId);
  if (!session) return { ok: false, liveNetwork: false, error: 'SESSION_NOT_FOUND' };

  if (!isConfirmationValidForSession(params.confirmationId, session.programId)) {
    return { ok: false, liveNetwork: false, error: 'CONFIRMATION_INVALID' };
  }

  const methodCheck = checkMethodAllowed(params.method, session.programId);
  if (!methodCheck.allowed) {
    return { ok: false, liveNetwork: false, error: methodCheck.reason };
  }

  const scope = checkTargetScope(session.programId, params.target);
  if (!scope.allowed) {
    return { ok: false, liveNetwork: false, error: scope.reason };
  }

  // FIXTURE path — zero live packets
  if (params.mode === 'FIXTURE' || !isLiveAllowedByEnv()) {
    const result = executePassiveRequest({
      sessionId: params.sessionId,
      target: params.target,
      method: params.method,
      testMode: true,
      fixtureResponse: params.fixtureResponse || {
        status: 200,
        headers: { 'content-type': 'text/plain', 'x-devilhunt-mode': 'fixture' },
        body: 'FIXTURE_MODE_NO_LIVE_TRAFFIC',
      },
    });
    return {
      ok: result.ok,
      liveNetwork: false,
      error: result.error?.message,
      observations: result.observations,
      discoveries: result.discoveries,
      evidenceId: result.evidenceId,
    };
  }

  // LIVE_SUPERVISED path — SafeControlledHttpClient only
  if (session.budgetUsed >= session.budgetMax) {
    return { ok: false, liveNetwork: false, error: 'REQUEST_BUDGET_EXCEEDED' };
  }

  const requestId = `live-req-${crypto.randomBytes(4).toString('hex')}`;
  const executionId = `live-exec-${crypto.randomBytes(4).toString('hex')}`;

  const context: ExecutionContext = {
    executionId,
    requestId,
    programId: session.programId,
    programName: getProgramProfile(session.programId)?.programName || session.programId,
    assetId: 'supervised-asset',
    target: scope.normalizedUrl || params.target,
    caseId: session.researchCaseId,
    capabilityId: 'passive-get',
    capabilityName: 'Supervised Passive GET',
    authorizationLevel: 'PASSIVE' as any,
    policyDecision: 'ALLOW',
    user: {
      uid: 'supervised-operator',
      email: 'operator@devilhunt.local',
      name: 'Supervised Operator',
      role: 'RESEARCHER',
    },
    timeoutMs: 10000,
    rateLimitBudget: 5,
  };

  try {
    // Ensure no mock handler accidentally left from tests for intentional live —
    // callers must clear mock themselves when truly live.
    const client = new SafeControlledHttpClient(context);
    const response = await client.request({ method: params.method, path: new URL(scope.normalizedUrl || params.target).pathname });

    const hdr = redactHeaders(response.headers || {});
    const body = redactSecretsFromText(String(response.body || '').slice(0, 512 * 1024));

    const normalized: NormalizedPassiveResponse = {
      url: scope.normalizedUrl || params.target,
      method: params.method,
      status: response.status,
      headers: hdr.headers,
      body: body.text,
      contentType: (response.headers && (response.headers['content-type'] || response.headers['Content-Type'])) || 'text/plain',
      programId: session.programId,
      researchCaseId: session.researchCaseId,
      executionId,
      requestId,
      target: params.target,
      timestamp: new Date().toISOString(),
    };

    // Count budget via existing controller path using fixture injection of live result
    const injected = executePassiveRequest({
      sessionId: params.sessionId,
      target: params.target,
      method: params.method,
      testMode: true,
      fixtureResponse: {
        status: normalized.status,
        headers: normalized.headers,
        body: normalized.body,
      },
    });

    appendTimelineEvent({
      type: 'REQUEST_EXECUTED',
      programId: session.programId,
      researchCaseId: session.researchCaseId,
      executionId,
      requestId,
      target: params.target,
      details: { mode: 'LIVE_SUPERVISED', status: normalized.status },
    });

    return {
      ok: injected.ok,
      liveNetwork: true,
      observations: injected.observations,
      discoveries: injected.discoveries,
      evidenceId: injected.evidenceId,
      error: injected.error?.message,
    };
  } catch (err) {
    return {
      ok: false,
      liveNetwork: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export function emergencyStop(sessionId: string, reason: string): PassiveSession | null {
  return cancelSession(sessionId, `EMERGENCY_STOP:${reason}`);
}

export function supervisedSafetyStatus(programId: string): Record<string, 'PASS' | 'BLOCKED' | 'LOCKED' | 'SAFE' | 'ACTIVE' | 'FIXTURE'> {
  const auth = isAuthorizedForPassive(programId);
  const profile = getProgramProfile(programId);
  return {
    scope: profile && profile.allowedAssets.length ? 'PASS' : 'BLOCKED',
    authorization: auth.ok ? 'PASS' : 'BLOCKED',
    policy: profile?.policyVersion ? 'PASS' : 'BLOCKED',
    proxy: profile?.proxyRequirement ? 'BLOCKED' : 'PASS',
    budget: profile && profile.requestBudget > 0 ? 'PASS' : 'BLOCKED',
    credentials: 'SAFE',
    passiveMode: 'ACTIVE',
    activeTesting: isActiveTestingLocked() ? 'LOCKED' : 'BLOCKED',
    liveEnv: isLiveAllowedByEnv() ? 'ACTIVE' : 'FIXTURE',
  };
}
