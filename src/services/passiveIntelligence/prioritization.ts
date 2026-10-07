import { ReviewPriority, ConfidenceLevel } from './types.ts';

export function prioritizeReview(input: {
  confidence: ConfidenceLevel;
  evidenceQuality: ConfidenceLevel;
  reproducibility: ConfidenceLevel;
  scopeConfirmed: boolean;
  securityRelevance: ConfidenceLevel;
  correlationStrength: ConfidenceLevel;
}): ReviewPriority {
  if (!input.scopeConfirmed) return 'INFORMATIONAL';

  const score = (c: ConfidenceLevel) => (c === 'HIGH' ? 3 : c === 'MEDIUM' ? 2 : 1);
  const total =
    score(input.confidence) +
    score(input.evidenceQuality) +
    score(input.reproducibility) +
    score(input.securityRelevance) +
    score(input.correlationStrength);

  if (total >= 13) return 'REVIEW_NOW';
  if (total >= 10) return 'REVIEW';
  if (total >= 7) return 'LOW_PRIORITY';
  return 'INFORMATIONAL';
}
