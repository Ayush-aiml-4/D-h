import crypto from 'crypto';
import {
  SecurityObservation,
  CorrelationResult,
  ReviewPriority,
  FindingCandidate,
  ConfidenceLevel,
} from './types.ts';
import { prioritizeReview } from './prioritization.ts';

export function correlateObservations(
  observations: SecurityObservation[],
  programId: string,
  researchCaseId: string
): CorrelationResult[] {
  const results: CorrelationResult[] = [];
  const byKind = new Map<string, SecurityObservation[]>();
  for (const o of observations) {
    const list = byKind.get(o.kind) || [];
    list.push(o);
    byKind.set(o.kind, list);
  }

  // CORS + auth endpoint interest
  const cors = byKind.get('CORS_OBSERVATION') || [];
  const interestingCors = cors.filter((c) => c.signal === 'HIGH_SIGNAL' || c.signal === 'MEDIUM_SIGNAL');
  const authEndpoints = observations.filter(
    (o) => o.kind === 'ENDPOINT_INTEREST' || /auth|login|oauth/i.test(o.title + o.observedBehavior)
  );

  if (interestingCors.length && authEndpoints.length) {
    const ids = [...interestingCors, ...authEndpoints].map((o) => o.id);
    results.push({
      id: `corr-${crypto.randomBytes(4).toString('hex')}`,
      title: 'CORS signal near authentication-related surface',
      observationIds: ids,
      rationale: [
        'CORS observation with elevated signal',
        'Authentication-related endpoint or behavior nearby',
        'Combination elevates review priority — not automatic vulnerability',
      ],
      reviewPriority: 'REVIEW',
      candidateClass: 'CORS_AUTH_SURFACE',
      confidence: 'MEDIUM',
      programId,
      researchCaseId,
      timestamp: new Date().toISOString(),
    });
  }

  // Verbose error + internal hostname + stack
  const verbose = byKind.get('VERBOSE_ERROR') || [];
  const internal = byKind.get('INTERNAL_HOSTNAME') || [];
  const disclosure = byKind.get('INFORMATION_DISCLOSURE') || [];
  if (verbose.length && (internal.length || disclosure.length)) {
    const ids = [...verbose, ...internal, ...disclosure].map((o) => o.id);
    results.push({
      id: `corr-${crypto.randomBytes(4).toString('hex')}`,
      title: 'Information disclosure candidate cluster',
      observationIds: ids,
      rationale: [
        'Verbose error / stack trace observed',
        internal.length ? 'Internal hostname indicator present' : 'Additional disclosure signal present',
        'Cluster suggests INFORMATION_DISCLOSURE_CANDIDATE for human review',
      ],
      reviewPriority: 'REVIEW_NOW',
      candidateClass: 'INFORMATION_DISCLOSURE_CANDIDATE',
      confidence: 'HIGH',
      programId,
      researchCaseId,
      timestamp: new Date().toISOString(),
    });
  }

  // Source map alone
  const sm = byKind.get('SOURCE_MAP') || [];
  if (sm.length) {
    results.push({
      id: `corr-${crypto.randomBytes(4).toString('hex')}`,
      title: 'Public source map exposure signal',
      observationIds: sm.map((o) => o.id),
      rationale: ['Source map reference observed in authorized response'],
      reviewPriority: 'REVIEW',
      candidateClass: 'SOURCE_MAP_EXPOSURE',
      confidence: 'HIGH',
      programId,
      researchCaseId,
      timestamp: new Date().toISOString(),
    });
  }

  // Elevated header signals alone stay low priority unless combined
  const headers = (byKind.get('SECURITY_HEADER') || []).filter(
    (o) => o.signal === 'MEDIUM_SIGNAL' || o.signal === 'HIGH_SIGNAL'
  );
  if (headers.length >= 3) {
    results.push({
      id: `corr-${crypto.randomBytes(4).toString('hex')}`,
      title: 'Multiple security-header hardening gaps',
      observationIds: headers.map((o) => o.id),
      rationale: ['Several missing or weak security headers observed on same target set'],
      reviewPriority: 'LOW_PRIORITY',
      candidateClass: 'HEADER_HARDENING',
      confidence: 'MEDIUM',
      programId,
      researchCaseId,
      timestamp: new Date().toISOString(),
    });
  }

  return results;
}

export function correlationToCandidate(
  corr: CorrelationResult,
  observations: SecurityObservation[],
  evidenceIds: string[],
  scopeConfirmed: boolean
): FindingCandidate {
  const related = observations.filter((o) => corr.observationIds.includes(o.id));
  const priority = prioritizeReview({
    confidence: corr.confidence,
    evidenceQuality: evidenceIds.length > 0 ? 'HIGH' : 'LOW',
    reproducibility: related.length > 1 ? 'MEDIUM' : 'LOW',
    scopeConfirmed,
    securityRelevance: corr.candidateClass.includes('DISCLOSURE') ? 'HIGH' : 'MEDIUM',
    correlationStrength: corr.observationIds.length >= 3 ? 'HIGH' : 'MEDIUM',
  });

  return {
    id: `fc-${crypto.randomBytes(5).toString('hex')}`,
    title: corr.title,
    status: 'NEEDS_REVIEW',
    reviewPriority: priority,
    vulnerabilityClass: corr.candidateClass,
    cwe: corr.candidateClass.includes('DISCLOSURE')
      ? 'CWE-200'
      : corr.candidateClass.includes('CORS')
        ? 'CWE-942'
        : corr.candidateClass.includes('SOURCE_MAP')
          ? 'CWE-540'
          : undefined,
    affectedAsset: related[0]?.sourceUrl || 'unknown',
    observedBehavior: related.map((o) => o.observedBehavior).join(' | ').slice(0, 800),
    expectedBehavior: related.map((o) => o.expectedBehavior).join(' | ').slice(0, 800),
    securityImpact: 'MARK AS MISSING — human must assess impact; engine does not invent impact',
    confidence: corr.confidence,
    observationIds: corr.observationIds,
    evidenceIds,
    correlationId: corr.id,
    programId: corr.programId,
    researchCaseId: corr.researchCaseId,
    scopeConfirmed,
    qualityGateNotes: [],
    createdAt: new Date().toISOString(),
    synthetic: true,
  };
}
