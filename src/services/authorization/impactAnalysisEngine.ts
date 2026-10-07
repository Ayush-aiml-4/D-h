import {
  DifferentialAnalysisResult,
  FindingCandidate,
  AuthorizationHypothesis,
} from '../../types/authorizationResearch.ts';
import { SeverityLevel } from '../../types.ts';
import { computeEvidenceHash } from '../evidenceService.ts';
import { sanitizeAndRedact } from '../capabilities/utils.ts';

export class ImpactAnalysisEngine {
  /**
   * Promotes a verified differential result to a high-quality Finding Candidate.
   */
  public generateFindingCandidate(params: {
    diffResult: DifferentialAnalysisResult;
    hypothesis: AuthorizationHypothesis;
    caseId: string;
    programId: string;
    targetAsset: string;
  }): FindingCandidate {
    const { diffResult, hypothesis, caseId, programId, targetAsset } = params;

    let severity: SeverityLevel = 'Medium';
    if (diffResult.impactAssessment.overallImpact === 'CRITICAL') {
      severity = 'Critical';
    } else if (diffResult.impactAssessment.overallImpact === 'HIGH') {
      severity = 'High';
    } else if (diffResult.impactAssessment.overallImpact === 'MEDIUM') {
      severity = 'Medium';
    } else {
      severity = 'Low';
    }

    const title = diffResult.vulnerabilityType
      ? `${diffResult.vulnerabilityType} on ${hypothesis.endpoint}`
      : `Authorization Boundary Failure on ${hypothesis.endpoint}`;

    const whatWeFound = `${diffResult.explanation} The endpoint returned HTTP ${diffResult.comparisonResult.statusCode} with unauthorized data access.`;
    const whyItMatters = `Authorization boundary violations allow unauthorized researchers/adversaries to access, exfiltrate, or manipulate data belonging to other tenants or privileged users. ${diffResult.impactAssessment.reasoning}`;

    const reproductionSteps = [
      `1. Authenticate with baseline session context '${hypothesis.baselineContext.contextLabel}' to verify valid resource access to '${hypothesis.targetResource.resourceId}'.`,
      `2. Prepare cross-context request using comparison session '${hypothesis.comparisonContext.contextLabel}' (${hypothesis.comparisonContext.accountRole}).`,
      `3. Send ${hypothesis.httpMethod} request to '${hypothesis.endpoint}' with parameter id='${hypothesis.targetResource.resourceId}'.`,
      `4. Observe HTTP ${diffResult.comparisonResult.statusCode} response containing owner data or sensitive fields without authorized ownership.`,
    ];

    const recommendedFix = this.deriveRemediation(diffResult.researchClass);

    // Sanitize evidence data
    const rawEvidence = {
      researchClass: diffResult.researchClass,
      endpoint: hypothesis.endpoint,
      httpMethod: hypothesis.httpMethod,
      resourceId: hypothesis.targetResource.resourceId,
      ownerAccount: hypothesis.targetResource.ownerAccount,
      baselineStatus: diffResult.baselineResult.statusCode,
      comparisonStatus: diffResult.comparisonResult.statusCode,
      sensitiveFields: diffResult.differences.sensitiveFieldsExposed,
      comparisonResponseSnippet: diffResult.comparisonResult.responseBody,
    };

    const { sanitized } = sanitizeAndRedact(rawEvidence);
    const evidenceHash = computeEvidenceHash(sanitized, `cap-${hypothesis.researchClass.toLowerCase()}`, targetAsset);

    return {
      candidateId: `fnd-cand-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      caseId,
      programId,
      targetAsset,
      title,
      category: 'Authorization & Access Control',
      severity,
      confidence: diffResult.confidence === 'HIGH_CONFIDENCE' ? 95 : 75,
      cwe: diffResult.cwe || 'CWE-639',
      owasp: diffResult.owasp || 'API1:2023 - Broken Object Level Authorization',
      whatWeFound,
      whyItMatters,
      reproductionSteps,
      evidenceHash,
      sanitizedEvidence: sanitized,
      impact: diffResult.impactAssessment.reasoning,
      recommendedFix,
      createdAt: new Date().toISOString(),
    };
  }

  private deriveRemediation(researchClass: string): string {
    switch (researchClass) {
      case 'BOLA_IDOR':
      case 'HORIZONTAL_AUTH':
        return 'Implement strict object-level ownership checks at the data layer before returning records. Verify that session.user.id matches resource.owner_id on every database lookup.';
      case 'VERTICAL_ESCALATION':
        return 'Enforce robust role-based access control (RBAC) middleware or policy decorators on all administrative endpoints. Deny requests by default unless the caller possesses verified administrative privileges.';
      case 'UNAUTHENTICATED_ACCESS':
        return 'Require authenticated session tokens or API keys on all endpoints handling sensitive tenant data. Ensure unauthenticated requests receive HTTP 401 Unauthorized.';
      default:
        return 'Enforce fail-closed authorization verification and parameter validation on all incoming API requests.';
    }
  }
}

export const impactAnalysisEngine = new ImpactAnalysisEngine();
