import crypto from 'crypto';
import { FindingCandidate, ReportDraft, EvidenceArtifact, SecurityObservation } from './types.ts';

export function draftReportFromCandidate(params: {
  candidate: FindingCandidate;
  observations: SecurityObservation[];
  evidence: EvidenceArtifact[];
}): ReportDraft {
  const { candidate, observations, evidence } = params;
  const missing: string[] = [];

  const title = candidate.title || (missing.push('Title'), 'MARK AS MISSING');
  const summary = candidate.observedBehavior
    ? `Synthetic research observation summary for ${candidate.affectedAsset}: ${candidate.observedBehavior.slice(0, 240)}`
    : (missing.push('Summary'), 'MARK AS MISSING');
  const impact =
    candidate.securityImpact && !candidate.securityImpact.includes('MARK AS MISSING')
      ? candidate.securityImpact
      : (missing.push('Security Impact'), 'MARK AS MISSING — requires human assessment');
  const expected = candidate.expectedBehavior || (missing.push('Expected Behavior'), 'MARK AS MISSING');
  const observed = candidate.observedBehavior || (missing.push('Observed Behavior'), 'MARK AS MISSING');

  const reproduction: string[] = [];
  if (evidence.length) {
    for (const e of evidence) {
      reproduction.push(`Perform authorized ${e.method} request to ${e.url} (status ${e.status})`);
    }
  } else {
    missing.push('Reproduction Steps');
    reproduction.push('MARK AS MISSING');
  }

  const evidenceLines = evidence.map(
    (e) => `Evidence ${e.id} sha256=${e.sha256} url=${e.url} integrity=${e.integrityValid}`
  );
  if (!evidenceLines.length) {
    missing.push('Evidence');
    evidenceLines.push('MARK AS MISSING');
  }

  const remediation =
    candidate.vulnerabilityClass.includes('HEADER')
      ? 'Review and deploy recommended security headers per organization policy.'
      : candidate.vulnerabilityClass.includes('SOURCE_MAP')
        ? 'Remove public source maps from production builds or restrict access.'
        : candidate.vulnerabilityClass.includes('DISCLOSURE')
          ? 'Suppress verbose errors and internal host details in external responses.'
          : candidate.vulnerabilityClass.includes('CORS')
            ? 'Tighten Access-Control-Allow-Origin; avoid wildcard with credentials.'
            : (missing.push('Suggested Remediation'), 'MARK AS MISSING');

  return {
    id: `rpt-${crypto.randomBytes(5).toString('hex')}`,
    findingCandidateId: candidate.id,
    title,
    summary,
    affectedAsset: candidate.affectedAsset,
    vulnerabilityClass: candidate.vulnerabilityClass,
    cwe: candidate.cwe || 'MARK AS MISSING',
    technicalDescription: observations.map((o) => `[${o.kind}] ${o.observedBehavior}`).join('\n') || 'MARK AS MISSING',
    observedBehavior: observed,
    expectedBehavior: expected,
    securityImpact: impact,
    reproductionSteps: reproduction,
    evidence: evidenceLines,
    suggestedRemediation: remediation,
    scopeConfirmation: candidate.scopeConfirmed
      ? 'Scope confirmed against program in-scope assets (SYNTHETIC TEST DATA)'
      : 'MARK AS MISSING — scope not confirmed',
    confidence: candidate.confidence,
    missingSections: missing,
    synthetic: true,
    createdAt: new Date().toISOString(),
  };
}

/** 14 quality gates for finding promotion */
export function runQualityGates(candidate: FindingCandidate, evidence: EvidenceArtifact[]): {
  passed: boolean;
  failures: string[];
} {
  const failures: string[] = [];
  if (!candidate.scopeConfirmed) failures.push('SCOPE_NOT_CONFIRMED');
  if (!candidate.observedBehavior || candidate.observedBehavior.includes('MARK AS MISSING'))
    failures.push('MISSING_OBSERVED_BEHAVIOR');
  if (!candidate.expectedBehavior || candidate.expectedBehavior.includes('MARK AS MISSING'))
    failures.push('MISSING_EXPECTED_BEHAVIOR');
  if (!candidate.securityImpact || candidate.securityImpact.includes('MARK AS MISSING'))
    failures.push('MISSING_SECURITY_IMPACT');
  if (!candidate.vulnerabilityClass) failures.push('MISSING_VULNERABILITY_CLASS');
  if (!evidence.length) failures.push('MISSING_EVIDENCE');
  if (evidence.some((e) => !e.integrityValid)) failures.push('EVIDENCE_INTEGRITY_FAILED');
  if (!candidate.observationIds.length) failures.push('MISSING_OBSERVATIONS');
  if (candidate.status === 'REJECTED_FALSE_POSITIVE') failures.push('REJECTED_FALSE_POSITIVE');
  if (!candidate.affectedAsset) failures.push('MISSING_AFFECTED_ASSET');
  if (candidate.confidence === 'LOW' && candidate.reviewPriority === 'INFORMATIONAL')
    failures.push('INSUFFICIENT_CONFIDENCE');
  // Secret leakage check on evidence
  for (const e of evidence) {
    if (/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(e.bodySnippetRedacted)) {
      failures.push('SECRET_LEAKAGE_IN_EVIDENCE');
    }
  }
  if (candidate.title.toLowerCase().includes('duplicate')) failures.push('DUPLICATE_FINDING');
  if (!candidate.programId) failures.push('MISSING_PROGRAM');

  return { passed: failures.length === 0, failures };
}
