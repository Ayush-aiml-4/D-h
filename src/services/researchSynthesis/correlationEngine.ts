import {
  ResearchObservation,
  ObservationCluster,
  ObservationClusterGroupType,
  CorrelationReason,
} from '../../types/researchSynthesis.ts';

export function calculateCorrelation(
  obsA: ResearchObservation,
  obsB: ResearchObservation
): { isCorrelated: boolean; reasons: CorrelationReason[]; strength: number } {
  const reasons: CorrelationReason[] = [];
  let strength = 0;

  // 1. Same research case
  if (obsA.researchCaseId && obsB.researchCaseId && obsA.researchCaseId === obsB.researchCaseId) {
    reasons.push('SAME_CASE');
    strength += 2;
  }

  // 2. Shared resource identifier
  if (
    obsA.resourceIdentifier &&
    obsB.resourceIdentifier &&
    obsA.resourceIdentifier.toLowerCase() === obsB.resourceIdentifier.toLowerCase()
  ) {
    reasons.push('SHARED_RESOURCE');
    strength += 4;
  }

  // 3. Shared workflow identifier
  if (obsA.workflowId && obsB.workflowId && obsA.workflowId === obsB.workflowId) {
    reasons.push('SHARED_WORKFLOW');
    strength += 4;
  }

  // 4. Shared actor context
  const actorA = obsA.actorContext.accountIdentifier;
  const actorB = obsB.actorContext.accountIdentifier;
  if (actorA && actorB && actorA === actorB) {
    reasons.push('SHARED_ACTOR');
    strength += 2;
  }

  // 5. Shared evidence provenance
  const sharedEvidence = obsA.evidenceReferences.filter((ref) =>
    obsB.evidenceReferences.includes(ref)
  );
  if (sharedEvidence.length > 0) {
    reasons.push('EVIDENCE_PROVENANCE');
    strength += 3;
  }

  // 6. Cross-engine pipeline chain (e.g. Authz -> Workflow or Authn -> Authz on same asset/target)
  if (
    obsA.target === obsB.target &&
    obsA.provenance.engine !== obsB.provenance.engine &&
    (obsA.resourceIdentifier === obsB.resourceIdentifier || obsA.researchCaseId === obsB.researchCaseId)
  ) {
    reasons.push('CROSS_ENGINE_CHAIN');
    strength += 3;
  }

  // Non-correlation rule: Same target domain alone without shared resource, case, actor, or evidence is NOT correlated
  const isCorrelated = strength >= 4 || (reasons.includes('SHARED_RESOURCE') && reasons.includes('SAME_CASE'));

  return {
    isCorrelated,
    reasons,
    strength,
  };
}

export function clusterObservations(observations: ResearchObservation[]): ObservationCluster[] {
  if (!observations || observations.length === 0) {
    return [];
  }

  const visited = new Set<string>();
  const clusters: ObservationCluster[] = [];

  for (let i = 0; i < observations.length; i++) {
    const obs = observations[i];
    if (visited.has(obs.observationId)) continue;

    visited.add(obs.observationId);
    const clusterObs: ResearchObservation[] = [obs];
    const combinedReasons = new Set<CorrelationReason>();

    for (let j = 0; j < observations.length; j++) {
      if (i === j) continue;
      const candidate = observations[j];
      if (visited.has(candidate.observationId)) continue;

      const { isCorrelated, reasons } = calculateCorrelation(obs, candidate);
      if (isCorrelated) {
        visited.add(candidate.observationId);
        clusterObs.push(candidate);
        reasons.forEach((r) => combinedReasons.add(r));
      }
    }

    // Determine group type
    let groupType: ObservationClusterGroupType = 'SINGLE_FINDING';
    let rationale = '';

    const hasHighConfidence = clusterObs.some((o) => o.confidence === 'HIGH_CONFIDENCE');
    const hasAnyEvidence = clusterObs.some((o) => o.evidenceReferences.length > 0);

    if (!hasAnyEvidence && !hasHighConfidence) {
      groupType = 'INSUFFICIENT_EVIDENCE';
      rationale = 'Observations lack sufficient verifiable evidence references to form a finding candidate.';
    } else if (clusterObs.length === 1) {
      groupType = 'INDEPENDENT_FINDINGS';
      rationale = 'Independent finding with distinct resource, actor, and workflow boundary.';
    } else {
      const hasDistinctVulnTypes = new Set(clusterObs.map((o) => o.observationType)).size > 1;
      const isTightChain = combinedReasons.has('SHARED_RESOURCE') || combinedReasons.has('CROSS_ENGINE_CHAIN') || combinedReasons.has('SHARED_WORKFLOW');

      if (isTightChain && clusterObs.length > 1) {
        groupType = 'SINGLE_FINDING';
        rationale = 'Multi-step vulnerability chain targeting the same operational resource or workflow.';
      } else if (hasDistinctVulnTypes) {
        groupType = 'RELATED_FINDINGS';
        rationale = 'Related observations within the same research case sharing context.';
      } else {
        groupType = 'SINGLE_FINDING';
        rationale = 'Duplicate or overlapping observations of the same underlying security condition.';
      }
    }

    clusters.push({
      clusterId: `cluster-${Date.now()}-${clusters.length + 1}`,
      groupType,
      primaryObservationId: obs.observationId,
      observationIds: clusterObs.map((o) => o.observationId),
      reasons: Array.from(combinedReasons),
      rationale,
      sharedIdentifiers: {
        caseId: obs.researchCaseId,
        resource: obs.resourceIdentifier,
        actor: obs.actorContext.accountIdentifier,
        target: obs.target,
        workflowId: obs.workflowId,
      },
    });
  }

  return clusters;
}
