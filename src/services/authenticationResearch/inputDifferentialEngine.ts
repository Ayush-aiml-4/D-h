import {
  ControlledParameter,
  ExecutionSnapshot,
  AuthResearchDifferentialResult,
  AuthenticationHypothesis,
} from '../../types/authenticationResearch.ts';
import { analyzeXssResponse } from './xssResearchAdapter.ts';
import { analyzeInjectionDifferential } from './injectionResearchAdapter.ts';
import { analyzePathTraversal } from './pathTraversalResearchAdapter.ts';

export interface EvaluateInputDifferentialParams {
  hypothesis: AuthenticationHypothesis;
  parameter: ControlledParameter;
  payloadString: string;
  baselineSnapshot: ExecutionSnapshot;
  mutatedSnapshot: ExecutionSnapshot;
  falseSnapshot?: ExecutionSnapshot;
  resolvedPath?: string;
  allowedRoot?: string;
}

/**
 * Input Differential Engine
 * Routes controlled input test snapshots to the appropriate context-aware adapter.
 */
export function evaluateInputDifferential(params: EvaluateInputDifferentialParams): AuthResearchDifferentialResult {
  const {
    hypothesis,
    parameter,
    payloadString,
    baselineSnapshot,
    mutatedSnapshot,
    falseSnapshot,
    resolvedPath,
    allowedRoot,
  } = params;

  const endpoint = hypothesis.endpoint;
  const targetAsset = hypothesis.targetAsset;

  // 1. XSS Research Class
  if (hypothesis.researchClass === 'INPUT_XSS') {
    const xssResult = analyzeXssResponse({
      endpoint,
      parameterName: parameter.parameterName,
      payloadString,
      context: parameter.securityContext,
      snapshot: mutatedSnapshot,
    });

    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'INPUT_XSS',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedParameter: parameter.parameterName,
      testedPayload: payloadString,
      baselineResult: baselineSnapshot,
      comparisonResult: mutatedSnapshot,
      differences: {
        statusDiffers: baselineSnapshot.statusCode !== mutatedSnapshot.statusCode,
        bodyDiffers: xssResult.evidence.reflectedInBody,
        sensitiveFieldsExposed: [],
        sessionBoundaryViolated: false,
        privilegeBoundaryViolated: false,
        authenticationBypassed: false,
        reflectionObserved: xssResult.evidence.reflectedInBody,
        unsafeContextInterpretation: xssResult.evidence.executableContextDetected,
        booleanDifferentialObserved: false,
        pathTraversedOutsideRoot: false,
        unauthorizedStateChange: false,
      },
      classification: xssResult.classification,
      confidence: xssResult.confidence,
      confidenceReasoning: xssResult.confidenceReasoning,
      isVulnerabilityCandidate: xssResult.isVulnerability,
      vulnerabilityType: xssResult.vulnerabilityType,
      cwe: xssResult.cwe,
      owasp: xssResult.owasp,
      explanation: xssResult.explanation,
      impactAssessment: xssResult.impactAssessment,
      sanitizedEvidence: xssResult.evidence,
    };
  }

  // 2. Injection Research Class
  if (hypothesis.researchClass === 'INPUT_INJECTION') {
    const injResult = analyzeInjectionDifferential({
      endpoint,
      parameterName: parameter.parameterName,
      context: parameter.securityContext,
      baselineSnapshot,
      trueSnapshot: mutatedSnapshot,
      falseSnapshot,
      errorSnapshot: mutatedSnapshot.errorDetected ? mutatedSnapshot : undefined,
    });

    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'INPUT_INJECTION',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedParameter: parameter.parameterName,
      testedPayload: payloadString,
      baselineResult: baselineSnapshot,
      comparisonResult: mutatedSnapshot,
      differences: {
        statusDiffers: baselineSnapshot.statusCode !== mutatedSnapshot.statusCode,
        bodyDiffers: true,
        sensitiveFieldsExposed: [],
        sessionBoundaryViolated: false,
        privilegeBoundaryViolated: false,
        authenticationBypassed: false,
        reflectionObserved: false,
        unsafeContextInterpretation: false,
        booleanDifferentialObserved: injResult.evidence.booleanTrueMatchedBaseline && injResult.evidence.booleanFalseDiverged,
        pathTraversedOutsideRoot: false,
        unauthorizedStateChange: false,
      },
      classification: injResult.classification,
      confidence: injResult.confidence,
      confidenceReasoning: injResult.confidenceReasoning,
      isVulnerabilityCandidate: injResult.isVulnerability,
      vulnerabilityType: injResult.vulnerabilityType,
      cwe: injResult.cwe,
      owasp: injResult.owasp,
      explanation: injResult.explanation,
      impactAssessment: injResult.impactAssessment,
      sanitizedEvidence: injResult.evidence,
    };
  }

  // 3. Path Traversal Research Class
  if (hypothesis.researchClass === 'INPUT_PATH_TRAVERSAL') {
    const pathResult = analyzePathTraversal({
      endpoint,
      parameterName: parameter.parameterName,
      requestedPath: payloadString,
      allowedRoot: allowedRoot || '/fixtures/allowed-root',
      resolvedPath: resolvedPath || (payloadString.includes('../') ? '/fixtures/outside-root/canary.json' : '/fixtures/allowed-root/doc.json'),
      snapshot: mutatedSnapshot,
    });

    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: 'INPUT_PATH_TRAVERSAL',
      targetAsset,
      endpoint,
      httpMethod: hypothesis.httpMethod,
      testedParameter: parameter.parameterName,
      testedPayload: payloadString,
      baselineResult: baselineSnapshot,
      comparisonResult: mutatedSnapshot,
      differences: {
        statusDiffers: baselineSnapshot.statusCode !== mutatedSnapshot.statusCode,
        bodyDiffers: pathResult.evidence.outsideAllowedRoot,
        sensitiveFieldsExposed: pathResult.evidence.outsideAllowedRoot ? ['fixture_canary'] : [],
        sessionBoundaryViolated: false,
        privilegeBoundaryViolated: false,
        authenticationBypassed: false,
        reflectionObserved: false,
        unsafeContextInterpretation: false,
        booleanDifferentialObserved: false,
        pathTraversedOutsideRoot: pathResult.evidence.outsideAllowedRoot,
        unauthorizedStateChange: false,
      },
      classification: pathResult.classification,
      confidence: pathResult.confidence,
      confidenceReasoning: pathResult.confidenceReasoning,
      isVulnerabilityCandidate: pathResult.isVulnerability,
      vulnerabilityType: pathResult.vulnerabilityType,
      cwe: pathResult.cwe,
      owasp: pathResult.owasp,
      explanation: pathResult.explanation,
      impactAssessment: pathResult.impactAssessment,
      sanitizedEvidence: pathResult.evidence,
    };
  }

  // Fallback
  return {
    hypothesisId: hypothesis.hypothesisId,
    researchClass: hypothesis.researchClass,
    targetAsset,
    endpoint,
    httpMethod: hypothesis.httpMethod,
    testedParameter: parameter.parameterName,
    testedPayload: payloadString,
    baselineResult: baselineSnapshot,
    comparisonResult: mutatedSnapshot,
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
    confidenceReasoning: 'No differential observed.',
    isVulnerabilityCandidate: false,
    explanation: 'No security defect detected.',
    impactAssessment: {
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      privilegeImpact: 'NONE',
      overallImpact: 'NONE',
      reasoning: 'Standard response.',
    },
  };
}
