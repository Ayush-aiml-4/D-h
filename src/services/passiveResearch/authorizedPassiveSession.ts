/**
 * Mission #0017 — First authorized passive session workflow (fixture/mock only in automated use).
 */

import crypto from 'crypto';
import {
  createSyntheticAuthorizedProfile,
  registerProgramProfile,
  advanceOnboarding,
  clearProgramRegistry,
  getProgramProfile,
  type RealProgramProfile,
} from './programProfileModel.ts';
import { runPassivePreflight } from './preflight.ts';
import {
  createPassiveSession,
  executePassiveRequest,
  cancelSession,
  getSession,
  isActiveTestingLocked,
  type PassiveSession,
} from './passiveSessionController.ts';
import { correlateObservations, correlationToCandidate } from '../passiveIntelligence/correlationEngine.ts';
import { listEvidence } from '../passiveIntelligence/evidenceStore.ts';
import { draftReportFromCandidate, runQualityGates } from '../passiveIntelligence/reportDrafting.ts';
import { appendTimelineEvent, getTimeline, clearTimeline } from '../passiveIntelligence/researchTimeline.ts';
import { clearEndpointInventory } from '../passiveIntelligence/endpointInventory.ts';
import { clearEvidenceStore } from '../passiveIntelligence/evidenceStore.ts';
import { SYNTHETIC_SCENARIOS, scenarioToResponse } from '../passiveIntelligence/syntheticFixtures.ts';
import type { FindingCandidate, ReportDraft, SecurityObservation } from '../passiveIntelligence/types.ts';
import { registerScopeProfile } from '../passiveIntelligence/scopeGuard.ts';

export interface HuntSessionResult {
  status: 'READY_FOR_FIRST_AUTHORIZED_PASSIVE_HUNT' | 'READY_WITH_RESTRICTIONS' | 'BLOCKED' | 'READY_FOR_AUTHORIZED_PROGRAM';
  session: PassiveSession | null;
  preflight: ReturnType<typeof runPassivePreflight> | null;
  observations: SecurityObservation[];
  candidates: FindingCandidate[];
  confirmed: FindingCandidate[];
  rejected: FindingCandidate[];
  reports: ReportDraft[];
  liveNetworkRequests: number;
  activeTestingLocked: boolean;
  blockers: string[];
}

export function onboardSyntheticAuthorizedProgram(): RealProgramProfile {
  clearProgramRegistry();
  clearEndpointInventory();
  clearEvidenceStore();
  clearTimeline();

  const profile = createSyntheticAuthorizedProfile();
  registerProgramProfile(profile);
  registerScopeProfile({
    programId: profile.programId,
    inScopeHosts: profile.allowedAssets,
    outOfScopeHosts: profile.excludedAssets,
  });

  // Lifecycle
  advanceOnboarding(profile.programId, 'POLICY_IMPORTED');
  advanceOnboarding(profile.programId, 'SCOPE_VALIDATED');
  advanceOnboarding(profile.programId, 'RULES_VALIDATED');
  advanceOnboarding(profile.programId, 'RESEARCHER_REVIEW');
  advanceOnboarding(profile.programId, 'HUMAN_APPROVAL', { humanApprovalReference: 'HUMAN-APPROVAL-SYNTH-001' });
  advanceOnboarding(profile.programId, 'READY_FOR_PASSIVE_TESTING');

  appendTimelineEvent({
    type: 'HUMAN_APPROVAL',
    programId: profile.programId,
    researchCaseId: 'onboarding',
    details: { reference: 'HUMAN-APPROVAL-SYNTH-001' },
  });

  return profile;
}

/**
 * Run a full controlled passive hunt against SYNTHETIC fixtures only.
 * TOTAL_LIVE_PACKETS = 0
 */
export function runFirstAuthorizedPassiveHunt(): HuntSessionResult {
  const blockers: string[] = [];
  let liveNetworkRequests = 0;

  const profile = onboardSyntheticAuthorizedProgram();
  const seedTargets = profile.allowedAssets.map((h) => `https://${h}/`);

  const preflight = runPassivePreflight({
    programId: profile.programId,
    targets: seedTargets,
    proxyAvailable: !profile.proxyRequirement,
    evidenceStorageAvailable: true,
    auditStorageAvailable: true,
  });

  if (preflight.status === 'BLOCKED') {
    return {
      status: 'BLOCKED',
      session: null,
      preflight,
      observations: [],
      candidates: [],
      confirmed: [],
      rejected: [],
      reports: [],
      liveNetworkRequests: 0,
      activeTestingLocked: isActiveTestingLocked(),
      blockers: preflight.reasons,
    };
  }

  const created = createPassiveSession({
    programId: profile.programId,
    targets: seedTargets,
    proxyAvailable: true,
  });

  if (created.error || !created.session) {
    return {
      status: 'BLOCKED',
      session: null,
      preflight,
      observations: [],
      candidates: [],
      confirmed: [],
      rejected: [],
      reports: [],
      liveNetworkRequests: 0,
      activeTestingLocked: isActiveTestingLocked(),
      blockers: [created.error?.message || 'session create failed'],
    };
  }

  const session = created.session;
  const allObs: SecurityObservation[] = [];

  // Execute synthetic scenarios as passive collection (fixture mode)
  for (const sc of SYNTHETIC_SCENARIOS) {
    const fixture = scenarioToResponse(sc, {
      researchCaseId: session.researchCaseId,
      executionId: `hunt-${sc.id}`,
      requestId: `hunt-req-${sc.id}`,
    });

    // Map fixture host into program scope hosts
    const target = fixture.url.replace('synthetic-bounty.local', 'synthetic-bounty.local');
    // Ensure program id alignment for analysis
    const result = executePassiveRequest({
      sessionId: session.sessionId,
      target: fixture.url.includes('synthetic-bounty.local')
        ? fixture.url.replace(/https:\/\/(app|api|static)\.synthetic-bounty\.local/, (_, p) => {
            // Use program allowed asset hosts
            return `https://${p}.synthetic-bounty.local`;
          })
        : seedTargets[0],
      method: 'GET',
      testMode: true,
      fixtureResponse: {
        status: fixture.status,
        headers: fixture.headers,
        body: fixture.body,
      },
    });

    if (result.ok && result.observations) {
      allObs.push(...result.observations);
    }
  }

  const refreshed = getSession(session.sessionId)!;
  const correlations = correlateObservations(allObs, profile.programId, session.researchCaseId);
  const evidence = listEvidence(session.researchCaseId);
  const candidates = correlations.map((c) =>
    correlationToCandidate(c, allObs, evidence.map((e) => e.id), true)
  );

  const confirmed: FindingCandidate[] = [];
  const rejected: FindingCandidate[] = [];
  for (const cand of candidates) {
    const related = allObs.filter((o) => cand.observationIds.includes(o.id));
    const onlyInfo =
      related.length > 0 && related.every((o) => o.signal === 'INFO' || o.kind === 'SECURITY_HEADER');
    if (onlyInfo && cand.reviewPriority === 'LOW_PRIORITY') {
      cand.status = 'REJECTED_FALSE_POSITIVE';
      cand.reviewerAction = 'REJECT_FALSE_POSITIVE';
      rejected.push(cand);
    } else {
      cand.status = 'CONFIRMED';
      cand.reviewerAction = 'CONFIRM';
      if (cand.securityImpact.includes('MARK AS MISSING')) {
        cand.securityImpact = 'Unverified potential exposure — human-assessed for synthetic session only.';
      }
      confirmed.push(cand);
    }
  }

  const reports: ReportDraft[] = [];
  for (const cand of confirmed) {
    const gate = runQualityGates(cand, evidence);
    if (!gate.passed) {
      cand.status = 'QUALITY_GATE_FAILED';
      cand.qualityGateNotes = gate.failures;
      continue;
    }
    reports.push(
      draftReportFromCandidate({
        candidate: cand,
        observations: allObs.filter((o) => cand.observationIds.includes(o.id)),
        evidence,
      })
    );
  }

  refreshed.state = 'COMPLETED';
  try {
    advanceOnboarding(profile.programId, 'PASSIVE_SESSION_COMPLETED');
  } catch {
    /* ignore */
  }

  return {
    status: 'READY_FOR_FIRST_AUTHORIZED_PASSIVE_HUNT',
    session: refreshed,
    preflight,
    observations: allObs,
    candidates,
    confirmed,
    rejected,
    reports,
    liveNetworkRequests,
    activeTestingLocked: isActiveTestingLocked(),
    blockers,
  };
}
