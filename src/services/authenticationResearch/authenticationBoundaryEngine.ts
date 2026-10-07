import {
  AuthenticationHypothesis,
  ExecutionSnapshot,
  AuthResearchDifferentialResult,
  ImpactAssessment,
  ConfidenceRating,
} from '../../types/authenticationResearch.ts';

export interface EvaluateAuthBoundaryParams {
  hypothesis: AuthenticationHypothesis;
  unauthSnapshot: ExecutionSnapshot;
  authSnapshot?: ExecutionSnapshot;
}

/**
 * Extracts sensitive fields from response body.
 */
function extractSensitiveFields(body: any): string[] {
  if (!body || typeof body !== 'object') return [];
  const sensitiveKeys = [
    'email',
    'phone',
    'phonenumber',
    'address',
    'shippingaddress',
    'creditcard',
    'cardnumber',
    'upi',
    'bankaccount',
    'password',
    'ssn',
    'token',
    'jwt',
    'secret',
    'adminsettings',
    'apikey',
    'privatekey',
    'privatenotes',
    'totalamount',
    'salary',
  ];

  const found: string[] = [];
  const str = JSON.stringify(body).toLowerCase();

  for (const key of sensitiveKeys) {
    if (str.includes(`"${key}"`) || str.includes(`'${key}'`)) {
      found.push(key);
    }
  }

  return found;
}

/**
 * Authentication Boundary Engine
 * Evaluates whether endpoints requiring authentication can be accessed unauthenticated.
 */
export function evaluateAuthenticationBoundary(params: EvaluateAuthBoundaryParams): AuthResearchDifferentialResult {
  const { hypothesis, unauthSnapshot, authSnapshot } = params;
  const endpoint = hypothesis.endpoint;
  const targetAsset = hypothesis.targetAsset;

  // 1. If endpoint is intentionally public, access is expected (Suppress)
  if (hypothesis.sensitivity === 'PUBLIC' || hypothesis.expectedBehavior === 'ALLOW') {
    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'AUTHENTICATION_BOUNDARY',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedAuthState: 'UNAUTHENTICATED',
      comparisonResult: unauthSnapshot,
      baselineResult: authSnapshot,
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
      classification: 'SAFE_ENFORCED',
      confidence: 'NO_FINDING',
      confidenceReasoning: 'Endpoint is categorized as PUBLIC; unauthenticated access is intended behavior.',
      isVulnerabilityCandidate: false,
      explanation: `Endpoint '${endpoint}' is a public resource and intentionally accessible without authentication.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'Intentionally public catalog or endpoint.',
      },
    };
  }

  // 2. If unauthenticated request received 401 or 403, boundary is enforced (Suppress)
  if (unauthSnapshot.statusCode === 401 || unauthSnapshot.statusCode === 403) {
    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'AUTHENTICATION_BOUNDARY',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedAuthState: 'UNAUTHENTICATED',
      comparisonResult: unauthSnapshot,
      baselineResult: authSnapshot,
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
      confidenceReasoning: `HTTP ${unauthSnapshot.statusCode} properly returned for unauthenticated caller.`,
      isVulnerabilityCandidate: false,
      explanation: `Authentication boundary strictly enforced on '${endpoint}'. Server rejected unauthenticated request with HTTP ${unauthSnapshot.statusCode}.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'Protected endpoint access was correctly blocked.',
      },
    };
  }

  // 3. Unauthenticated request received 200 OK on a protected endpoint (Vulnerability Candidate)
  if (unauthSnapshot.statusCode === 200) {
    const sensitiveFields = extractSensitiveFields(unauthSnapshot.responseBody);
    const hasSensitiveData = sensitiveFields.length > 0;

    const confidence: ConfidenceRating = hasSensitiveData ? 'HIGH_CONFIDENCE' : 'MEDIUM_CONFIDENCE';
    const impact: ImpactAssessment = {
      confidentialityImpact: hasSensitiveData ? 'HIGH' : 'MEDIUM',
      integrityImpact: hypothesis.httpMethod === 'GET' ? 'NONE' : 'HIGH',
      privilegeImpact: 'HIGH',
      overallImpact: hasSensitiveData ? 'HIGH' : 'MEDIUM',
      reasoning: hasSensitiveData
        ? `Exposed protected customer/system fields without authentication: ${sensitiveFields.join(', ')}`
        : 'Protected business function accessible without authentication credentials.',
    };

    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'AUTHENTICATION_BOUNDARY',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedAuthState: 'UNAUTHENTICATED',
      comparisonResult: unauthSnapshot,
      baselineResult: authSnapshot,
      differences: {
        statusDiffers: false,
        bodyDiffers: false,
        sensitiveFieldsExposed: sensitiveFields,
        sessionBoundaryViolated: false,
        privilegeBoundaryViolated: false,
        authenticationBypassed: true,
        reflectionObserved: false,
        unsafeContextInterpretation: false,
        booleanDifferentialObserved: false,
        pathTraversedOutsideRoot: false,
        unauthorizedStateChange: hypothesis.httpMethod !== 'GET',
      },
      classification: 'AUTH_BYPASS',
      confidence,
      confidenceReasoning: 'Unauthenticated HTTP request succeeded with 200 OK on protected resource exposing sensitive data or function.',
      isVulnerabilityCandidate: true,
      vulnerabilityType: 'BROKEN_AUTHENTICATION_ENDPOINT_BYPASS',
      cwe: 'CWE-306',
      owasp: 'A07:2021-Identification and Authentication Failures',
      explanation: `Authentication bypass detected on '${endpoint}'. Endpoint requires authentication but responded with 200 OK to unauthenticated request.`,
      impactAssessment: impact,
    };
  }

  // Fallback
  return {
    hypothesisId: hypothesis.hypothesisId,
    researchClass: 'AUTHENTICATION_BOUNDARY',
    targetAsset,
    endpoint,
    httpMethod: hypothesis.httpMethod,
    testedAuthState: 'UNAUTHENTICATED',
    comparisonResult: unauthSnapshot,
    baselineResult: authSnapshot,
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
    confidenceReasoning: 'No authentication vulnerability observed.',
    isVulnerabilityCandidate: false,
    explanation: 'No security defect detected.',
    impactAssessment: {
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      privilegeImpact: 'NONE',
      overallImpact: 'NONE',
      reasoning: 'Standard behavior.',
    },
  };
}
