import {
  ResearchObservation,
  ImpactDimension,
  ImpactAnalysisResult,
  ConfidenceRating,
} from '../../types/researchSynthesis.ts';
import { SeverityLevel } from '../../types.ts';

export function analyzeAggregatedImpact(
  observations: ResearchObservation[]
): ImpactAnalysisResult {
  const dimensionsSet = new Set<ImpactDimension>();
  let hasSufficientEvidence = false;

  observations.forEach((obs) => {
    if (obs.evidenceReferences.length > 0) {
      hasSufficientEvidence = true;
    }

    switch (obs.observationType) {
      case 'CROSS_ACCOUNT_ACCESS':
      case 'AUTHZ_BOUNDARY_WEAKNESS':
        dimensionsSet.add('AUTHORIZATION');
        dimensionsSet.add('ACCOUNT_BOUNDARY');
        dimensionsSet.add('RESOURCE_OWNERSHIP');
        dimensionsSet.add('CONFIDENTIALITY');
        break;
      case 'AUTHN_BYPASS':
      case 'UNAUTHENTICATED_ACCESS':
        dimensionsSet.add('AUTHORIZATION');
        dimensionsSet.add('ACCOUNT_BOUNDARY');
        dimensionsSet.add('CONFIDENTIALITY');
        break;
      case 'FORBIDDEN_WORKFLOW_TRANSITION':
      case 'BUSINESS_INVARIANT_VIOLATION':
      case 'UNEXPECTED_STATE_TRANSITION':
        dimensionsSet.add('WORKFLOW_CONTROL');
        dimensionsSet.add('INTEGRITY');
        break;
      case 'OUTBOUND_SSRF_INTERACTION':
      case 'METADATA_ACCESS_ATTEMPT':
        dimensionsSet.add('SERVER_SIDE_INTERACTION');
        dimensionsSet.add('CONFIDENTIALITY');
        break;
      case 'SQL_INJECTION_DIFFERENTIAL':
        dimensionsSet.add('CONFIDENTIALITY');
        dimensionsSet.add('INTEGRITY');
        dimensionsSet.add('SENSITIVE_DATA');
        break;
      case 'XSS_HTML_EXECUTION':
        dimensionsSet.add('CONFIDENTIALITY');
        dimensionsSet.add('INTEGRITY');
        break;
      case 'PATH_TRAVERSAL_READ':
        dimensionsSet.add('CONFIDENTIALITY');
        dimensionsSet.add('SENSITIVE_DATA');
        break;
      case 'PARAMETER_REFLECTION':
        // Benign reflection alone does not add high-impact dimensions
        dimensionsSet.add('CONFIDENTIALITY');
        break;
      default:
        dimensionsSet.add('INTEGRITY');
    }
  });

  const dimensions = Array.from(dimensionsSet);

  // Compute severity deterministically from concrete dimensions and evidence
  let technicalSeverity: SeverityLevel = 'Low';

  const hasMetadataOrSQLi = observations.some(
    (o) =>
      o.observationType === 'METADATA_ACCESS_ATTEMPT' ||
      o.observationType === 'SQL_INJECTION_DIFFERENTIAL' ||
      (o.observationType === 'CROSS_ACCOUNT_ACCESS' && dimensionsSet.has('SENSITIVE_DATA'))
  );

  const hasAuthZorWorkflow = observations.some(
    (o) =>
      o.observationType === 'CROSS_ACCOUNT_ACCESS' ||
      o.observationType === 'AUTHN_BYPASS' ||
      o.observationType === 'FORBIDDEN_WORKFLOW_TRANSITION' ||
      o.observationType === 'OUTBOUND_SSRF_INTERACTION'
  );

  if (hasMetadataOrSQLi) {
    technicalSeverity = 'Critical';
  } else if (hasAuthZorWorkflow) {
    technicalSeverity = 'High';
  } else if (observations.some((o) => o.observationType === 'XSS_HTML_EXECUTION' || o.observationType === 'PATH_TRAVERSAL_READ')) {
    technicalSeverity = 'Medium';
  } else {
    technicalSeverity = 'Low';
  }

  const summary = `Impact across ${dimensions.length} security dimensions (${dimensions.join(', ')}) with ${technicalSeverity} technical severity.`;

  return {
    dimensions,
    summary,
    technicalSeverity,
    hasSufficientEvidence,
  };
}

export function aggregateConfidence(
  observations: ResearchObservation[],
  impactResult: ImpactAnalysisResult
): ConfidenceRating {
  if (!observations || observations.length === 0) {
    return 'NO_FINDING';
  }

  // False-positive suppression check:
  // If all observations are merely reflections or unverified responses without invariant breaches
  const isOnlyReflection = observations.every(
    (o) => o.observationType === 'PARAMETER_REFLECTION' || o.confidence === 'LOW_CONFIDENCE'
  );
  if (isOnlyReflection && !impactResult.hasSufficientEvidence) {
    return 'LOW_CONFIDENCE';
  }

  const highConfidenceCount = observations.filter((o) => o.confidence === 'HIGH_CONFIDENCE').length;
  const hasEvidence = observations.some((o) => o.evidenceReferences.length > 0);

  if (highConfidenceCount >= 1 && hasEvidence && impactResult.hasSufficientEvidence) {
    return 'HIGH_CONFIDENCE';
  }

  if (hasEvidence) {
    return 'MEDIUM_CONFIDENCE';
  }

  return 'LOW_CONFIDENCE';
}

export function isFalsePositiveCluster(observations: ResearchObservation[]): boolean {
  // 1. All observations are benign parameter reflections
  const allReflections = observations.every((o) => o.observationType === 'PARAMETER_REFLECTION');
  if (allReflections) return true;

  // 2. Observations claim SSRF but zero outbound interactions occurred
  const fakeSsrf = observations.every(
    (o) => o.observationType === 'OUTBOUND_SSRF_INTERACTION' && o.evidenceReferences.length === 0
  );
  if (fakeSsrf) return true;

  // 3. Observations have NO_FINDING confidence
  const allNoFinding = observations.every((o) => o.confidence === 'NO_FINDING');
  if (allNoFinding) return true;

  return false;
}
