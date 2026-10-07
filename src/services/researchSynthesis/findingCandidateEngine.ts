import crypto from 'crypto';
import {
  ResearchObservation,
  SynthesizedFindingCandidate,
  ObservationCluster,
} from '../../types/researchSynthesis.ts';
import { synthesizeRootCauseAndChain } from './rootCauseAttackChainEngine.ts';
import { analyzeAggregatedImpact, aggregateConfidence, isFalsePositiveCluster } from './impactConfidenceEngine.ts';
import { evaluateReportQualityGates } from './reportDraftingEngine.ts';
import { resolveTargetScope, evaluateFindingEligibility } from '../programProfileService.ts';

export function computeSynthesizedEvidenceHash(
  observations: ResearchObservation[],
  rootCause: string,
  attackChainSummary: string
): string {
  const payload = JSON.stringify({
    observations: observations.map((o) => ({
      id: o.observationId,
      type: o.observationType,
      target: o.target,
      behavior: o.observedBehavior,
      evidence: o.evidenceReferences,
    })),
    rootCause,
    attackChainSummary,
  });

  return crypto.createHash('sha256').update(payload).digest('hex');
}

export function createFindingCandidateFromObservations(
  observations: ResearchObservation[],
  cluster?: ObservationCluster
): SynthesizedFindingCandidate | null {
  if (!observations || observations.length === 0) {
    return null;
  }

  // False positive cluster suppression check
  if (isFalsePositiveCluster(observations)) {
    return null;
  }

  const { rootCause, vulnerabilityClass, cweId, attackChain, primaryObservation } =
    synthesizeRootCauseAndChain(observations);

  const impact = analyzeAggregatedImpact(observations);
  const confidence = aggregateConfidence(observations, impact);

  // If confidence is NO_FINDING, suppress candidate creation
  if (confidence === 'NO_FINDING') {
    return null;
  }

  // Evaluate Target Scope via Program Profile
  const scopeEval = resolveTargetScope(primaryObservation.programId, primaryObservation.target);
  const scopeDecision = scopeEval.decision;

  // Evaluate Finding Eligibility via Program Profile
  const eligibilityEval = evaluateFindingEligibility(
    primaryObservation.programId,
    vulnerabilityClass,
    { title: vulnerabilityClass, cwe: cweId, description: rootCause }
  );

  let programEligibility: 'BOUNTY_ELIGIBLE' | 'INELIGIBLE' | 'REVIEW_REQUIRED' = 'INELIGIBLE';
  if (eligibilityEval.isEligible) {
    programEligibility = 'BOUNTY_ELIGIBLE';
  } else if (eligibilityEval.classification === 'IMPACT_DEPENDENT') {
    programEligibility = 'REVIEW_REQUIRED';
  }

  // Gather all unique evidence references
  const evidenceReferences = Array.from(
    new Set(observations.flatMap((o) => o.evidenceReferences))
  );

  const evidenceHash = computeSynthesizedEvidenceHash(
    observations,
    rootCause,
    attackChain.summary
  );

  const preconditions = [
    `Valid researcher credentials and active test environment on ${primaryObservation.target}`,
    primaryObservation.actorContext.accountRole
      ? `Actor authorized in role ${primaryObservation.actorContext.accountRole}`
      : 'Standard user context',
  ];

  const reproductionSteps = attackChain.steps.map(
    (step) => `Step ${step.stepOrder}: ${step.actor} -> ${step.action} on ${step.resource}`
  );

  const findingId = `find-synth-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  const title = `[${vulnerabilityClass}] on ${primaryObservation.asset || primaryObservation.target}`;

  const candidate: SynthesizedFindingCandidate = {
    findingId,
    programId: primaryObservation.programId,
    target: primaryObservation.target,
    title,
    vulnerabilityClass,
    cweId,
    severity: impact.technicalSeverity,
    rootCause,
    attackChain,
    preconditions,
    reproductionSteps,
    expectedBehavior: primaryObservation.expectedBehavior,
    observedBehavior: primaryObservation.observedBehavior,
    impact,
    confidence,
    evidenceReferences,
    evidenceHash,
    affectedAsset: primaryObservation.asset || primaryObservation.target,
    scopeDecision,
    policyDecision: scopeDecision === 'ALLOW' ? 'AUTHORIZED' : 'UNAUTHORIZED',
    programEligibility,
    duplicateGroupId: cluster?.clusterId,
    reportReadiness: {
      isReady: false,
      qualityScore: 0,
      passedGates: [],
      missingGates: [],
      gateDetails: [],
    },
    createdAt: new Date().toISOString(),
  };

  // Evaluate quality gates
  candidate.reportReadiness = evaluateReportQualityGates(candidate, {
    summary: `${title} - ${rootCause}`,
    reproductionSteps,
    securityImpact: impact.summary,
    remediation: 'Implement strict server-side authorization checks.',
  });

  return candidate;
}
