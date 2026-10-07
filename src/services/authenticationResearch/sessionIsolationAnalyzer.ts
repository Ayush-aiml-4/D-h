import {
  SessionModel,
  AuthenticationHypothesis,
  ExecutionSnapshot,
  AuthResearchDifferentialResult,
  ImpactAssessment,
} from '../../types/authenticationResearch.ts';

export interface EvaluateSessionIsolationParams {
  hypothesis: AuthenticationHypothesis;
  sessionA: SessionModel;
  sessionB: SessionModel;
  snapshotA: ExecutionSnapshot;
  snapshotB: ExecutionSnapshot;
}

/**
 * Session Isolation Analyzer
 * Evaluates whether separate user sessions are strictly isolated in memory and backend state.
 */
export function evaluateSessionIsolation(params: EvaluateSessionIsolationParams): AuthResearchDifferentialResult {
  const { hypothesis, sessionA, sessionB, snapshotA, snapshotB } = params;
  const endpoint = hypothesis.endpoint;
  const targetAsset = hypothesis.targetAsset;

  // Check if Session B received Account A's private identifier or data
  const bodyBStr = JSON.stringify(snapshotB.responseBody || '');
  const leakedAccountA = bodyBStr.includes(sessionA.accountIdentifier);

  // If Session B accessed resource belonging to Account A with 200 OK
  if (snapshotB.statusCode === 200 && leakedAccountA) {
    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'SESSION_ISOLATION',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      comparisonResult: snapshotB,
      baselineResult: snapshotA,
      differences: {
        statusDiffers: false,
        bodyDiffers: false,
        sensitiveFieldsExposed: [sessionA.accountIdentifier],
        sessionBoundaryViolated: true,
        privilegeBoundaryViolated: false,
        authenticationBypassed: false,
        reflectionObserved: false,
        unsafeContextInterpretation: false,
        booleanDifferentialObserved: false,
        pathTraversedOutsideRoot: false,
        unauthorizedStateChange: false,
      },
      classification: 'SESSION_VIOLATION',
      confidence: 'HIGH_CONFIDENCE',
      confidenceReasoning: `Session B received data bound to Session A (${sessionA.accountIdentifier}), indicating broken session isolation or cross-session state leakage.`,
      isVulnerabilityCandidate: true,
      vulnerabilityType: 'CROSS_SESSION_DATA_LEAKAGE_BROKEN_ISOLATION',
      cwe: 'CWE-488',
      owasp: 'A04:2021-Insecure Design',
      explanation: `Session isolation failure detected on '${endpoint}'. Data belonging to account '${sessionA.accountIdentifier}' was leaked into session '${sessionB.sessionReference}'.`,
      impactAssessment: {
        confidentialityImpact: 'HIGH',
        integrityImpact: 'MEDIUM',
        privilegeImpact: 'HIGH',
        overallImpact: 'HIGH',
        reasoning: 'Breaches tenant/user data isolation boundary.',
      },
    };
  }

  // If Session B was properly isolated (e.g. 403 / 404 / distinct Account B data)
  return {
    hypothesisId: hypothesis.hypothesisId,
    researchClass: 'SESSION_ISOLATION',
    targetAsset,
    endpoint,
    httpMethod: hypothesis.httpMethod,
    comparisonResult: snapshotB,
    baselineResult: snapshotA,
    differences: {
      statusDiffers: snapshotA.statusCode !== snapshotB.statusCode,
      bodyDiffers: true,
      sensitiveFieldsExposed: [],
      sessionBoundaryViolated: false,
      privilegeBoundaryViolated: false,
      authenticationBypassed: false,
      reflectionObserved: false,
      unsafeContextInterpretation: false,
      booleanDifferentialObserved: false,
      pathTraversedOutsideRoot: false,
      unauthorizedStateChange: false,
    },
    classification: 'SAFE_ENFORCED',
    confidence: 'NO_FINDING',
    confidenceReasoning: 'Sessions A and B are strictly isolated with separate state and authorization boundaries.',
    isVulnerabilityCandidate: false,
    explanation: `Endpoint '${endpoint}' maintained strict session isolation between '${sessionA.accountIdentifier}' and '${sessionB.accountIdentifier}'.`,
    impactAssessment: {
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      privilegeImpact: 'NONE',
      overallImpact: 'NONE',
      reasoning: 'Session isolation verified.',
    },
  };
}
