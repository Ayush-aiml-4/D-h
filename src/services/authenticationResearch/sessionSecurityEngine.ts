import {
  SessionModel,
  SessionState,
  AuthenticationHypothesis,
  ExecutionSnapshot,
  AuthResearchDifferentialResult,
  ImpactAssessment,
  ConfidenceRating,
} from '../../types/authenticationResearch.ts';

export interface EvaluateSessionSecurityParams {
  hypothesis: AuthenticationHypothesis;
  session: SessionModel;
  testedSnapshot: ExecutionSnapshot;
  baselineSnapshot?: ExecutionSnapshot;
}

/**
 * Session Security Engine
 * Evaluates session lifecycle security (invalidation, expiration, revocation).
 */
export function evaluateSessionSecurity(params: EvaluateSessionSecurityParams): AuthResearchDifferentialResult {
  const { hypothesis, session, testedSnapshot, baselineSnapshot } = params;
  const endpoint = hypothesis.endpoint;
  const targetAsset = hypothesis.targetAsset;

  // If session is INVALIDATED or EXPIRED
  const isTerminatedSession = session.state === 'INVALIDATED' || session.state === 'EXPIRED' || session.state === 'REVOKED';

  // 1. If terminated session gets 401/403, session security is enforced (Suppress)
  if (isTerminatedSession && (testedSnapshot.statusCode === 401 || testedSnapshot.statusCode === 403)) {
    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'SESSION_INVALIDATION',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedSessionState: session.state,
      comparisonResult: testedSnapshot,
      baselineResult: baselineSnapshot,
      differences: {
        statusDiffers: true,
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
      confidenceReasoning: `Session in state '${session.state}' properly rejected with HTTP ${testedSnapshot.statusCode}.`,
      isVulnerabilityCandidate: false,
      explanation: `Session invalidation enforced: Request using ${session.state} session was rejected.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'Server rejected invalid session.',
      },
    };
  }

  // 2. If terminated session gets 200 OK on protected resource (Vulnerability Candidate)
  if (isTerminatedSession && testedSnapshot.statusCode === 200) {
    const isLogoutFailure = session.state === 'INVALIDATED';
    const isExpirationFailure = session.state === 'EXPIRED';

    const vulnType = isLogoutFailure
      ? 'INSUFFICIENT_SESSION_EXPIRATION_POST_LOGOUT'
      : 'EXPIRED_SESSION_TOKEN_ACCEPTED';

    const cwe = isLogoutFailure ? 'CWE-613' : 'CWE-613';
    const owasp = 'A07:2021-Identification and Authentication Failures';

    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'SESSION_INVALIDATION',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedSessionState: session.state,
      comparisonResult: testedSnapshot,
      baselineResult: baselineSnapshot,
      differences: {
        statusDiffers: false,
        bodyDiffers: false,
        sensitiveFieldsExposed: ['session_data'],
        sessionBoundaryViolated: true,
        privilegeBoundaryViolated: false,
        authenticationBypassed: true,
        reflectionObserved: false,
        unsafeContextInterpretation: false,
        booleanDifferentialObserved: false,
        pathTraversedOutsideRoot: false,
        unauthorizedStateChange: false,
      },
      classification: 'SESSION_VIOLATION',
      confidence: 'HIGH_CONFIDENCE',
      confidenceReasoning: `Protected endpoint allowed access using ${session.state} session reference without backend session termination.`,
      isVulnerabilityCandidate: true,
      vulnerabilityType: vulnType,
      cwe,
      owasp,
      explanation: `Session invalidation flaw detected on '${endpoint}'. The session was explicitly ${session.state}, yet the backend continued to honor requests and serve protected data.`,
      impactAssessment: {
        confidentialityImpact: 'HIGH',
        integrityImpact: 'MEDIUM',
        privilegeImpact: 'HIGH',
        overallImpact: 'HIGH',
        reasoning: 'Allows session replay or zombie session exploitation post-logout or after session lifetime expiry.',
      },
    };
  }

  // Fallback
  return {
    hypothesisId: hypothesis.hypothesisId,
    researchClass: 'SESSION_INVALIDATION',
    targetAsset,
    endpoint,
    httpMethod: hypothesis.httpMethod,
    testedSessionState: session.state,
    comparisonResult: testedSnapshot,
    baselineResult: baselineSnapshot,
    differences: {
      statusDiffers: false,
      bodyDiffers: false,
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
    classification: 'NO_VULNERABILITY',
    confidence: 'NO_FINDING',
    confidenceReasoning: 'Active session functioned as authorized.',
    isVulnerabilityCandidate: false,
    explanation: 'Active session behaved normally.',
    impactAssessment: {
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      privilegeImpact: 'NONE',
      overallImpact: 'NONE',
      reasoning: 'Active session.',
    },
  };
}
