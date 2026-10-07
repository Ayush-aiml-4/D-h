import {
  ResearchObservation,
  SynthesisResult,
  SynthesizedFindingCandidate,
  ReportDraft,
} from '../../types/researchSynthesis.ts';
import { recordAuditEvent } from '../auditService.ts';
import { buildEvidenceGraph } from './evidenceGraphService.ts';
import { clusterObservations } from './correlationEngine.ts';
import { createFindingCandidateFromObservations } from './findingCandidateEngine.ts';
import { deduplicateCandidates } from './duplicateSuppressionEngine.ts';
import { generateReportDraft } from './reportDraftingEngine.ts';

export async function synthesizeResearchCase(input: {
  caseId: string;
  observations: ResearchObservation[];
  programId?: string;
  target?: string;
  actorId?: string;
  dryRun?: boolean;
}): Promise<SynthesisResult> {
  const startTime = Date.now();
  const actorId = input.actorId || 'researcher-ayush-001';

  // 1. Build Evidence Graph
  const evidenceGraph = buildEvidenceGraph(input.observations);

  // 2. Cluster observations into correlated groups
  const clusters = clusterObservations(input.observations);

  // 3. Synthesize candidate per cluster
  const rawCandidates: SynthesizedFindingCandidate[] = [];
  const obsMap = new Map<string, ResearchObservation>(
    input.observations.map((o) => [o.observationId, o])
  );

  clusters.forEach((cluster) => {
    if (cluster.groupType === 'INSUFFICIENT_EVIDENCE') return;

    const clusterObs = cluster.observationIds
      .map((id) => obsMap.get(id))
      .filter((o): o is ResearchObservation => o !== undefined);

    const candidate = createFindingCandidateFromObservations(clusterObs, cluster);
    if (candidate) {
      rawCandidates.push(candidate);
    }
  });

  // 4. Deduplicate candidates
  const { uniqueCandidates } = deduplicateCandidates(rawCandidates);

  // 5. Generate structured report drafts
  const reportDrafts: ReportDraft[] = uniqueCandidates.map((c) => generateReportDraft(c));

  // 6. Record Audit Event
  const auditEvidenceHashes = uniqueCandidates.map((c) => c.evidenceHash);

  await recordAuditEvent({
    action: input.dryRun ? 'RESEARCH_SYNTHESIS_DRY_RUN' : 'RESEARCH_SYNTHESIS_EXECUTED',
    userId: actorId,
    entityType: 'CASE',
    entityId: input.caseId,
    success: true,
    metadata: {
      totalObservations: input.observations.length,
      clustersCount: clusters.length,
      candidatesCount: uniqueCandidates.length,
      readyReportsCount: reportDrafts.filter((r) => r.readinessStatus === 'REPORT_READY').length,
      dryRun: Boolean(input.dryRun),
    },
  });

  const executionTimeMs = Date.now() - startTime;

  return {
    caseId: input.caseId,
    evidenceGraph,
    clusters,
    candidates: uniqueCandidates,
    reportDrafts,
    totalObservations: input.observations.length,
    totalCandidates: uniqueCandidates.length,
    readyReportsCount: reportDrafts.filter((r) => r.readinessStatus === 'REPORT_READY').length,
    auditEvidenceHashes,
    executionTimeMs,
  };
}
