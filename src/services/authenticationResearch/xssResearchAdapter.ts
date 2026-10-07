import {
  XssClassification,
  ConfidenceRating,
  SecurityContextType,
  ExecutionSnapshot,
  ImpactAssessment,
} from '../../types/authenticationResearch.ts';

export interface XssAnalysisInput {
  endpoint: string;
  parameterName: string;
  payloadString: string;
  context: SecurityContextType;
  snapshot: ExecutionSnapshot;
}

export interface XssAnalysisResult {
  classification: XssClassification;
  confidence: ConfidenceRating;
  confidenceReasoning: string;
  isVulnerability: boolean;
  vulnerabilityType?: string;
  cwe?: string;
  owasp?: string;
  explanation: string;
  impactAssessment: ImpactAssessment;
  evidence: {
    endpoint: string;
    parameter: string;
    payload: string;
    context: SecurityContextType;
    reflectedInBody: boolean;
    encodedSafely: boolean;
    executableContextDetected: boolean;
  };
}

/**
 * Checks whether HTML special characters have been entity-encoded.
 */
function isHtmlEncoded(responseContent: string, payload: string): boolean {
  const encodedPayload = payload
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/'/g, '&#x27;');

  return responseContent.includes('&lt;') || responseContent.includes('&gt;') || responseContent.includes('&quot;');
}

/**
 * XSS Research Adapter
 * Evaluates reflection and encoding safety across HTML/attribute/JS/JSON contexts.
 */
export function analyzeXssResponse(input: XssAnalysisInput): XssAnalysisResult {
  const { endpoint, parameterName, payloadString, context, snapshot } = input;
  const rawBody = typeof snapshot.responseBody === 'string'
    ? snapshot.responseBody
    : JSON.stringify(snapshot.responseBody || '');

  const containsRawPayload = rawBody.includes(payloadString);
  const containsEncoded = isHtmlEncoded(rawBody, payloadString);

  // Scenario 1: Not reflected at all
  if (!containsRawPayload && !containsEncoded) {
    return {
      classification: 'NO_REFLECTION',
      confidence: 'NO_FINDING',
      confidenceReasoning: 'Parameter value was not reflected in the HTTP response.',
      isVulnerability: false,
      explanation: `Input parameter '${parameterName}' is not reflected in the response output.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'No reflection observed.',
      },
      evidence: {
        endpoint,
        parameter: parameterName,
        payload: payloadString,
        context,
        reflectedInBody: false,
        encodedSafely: false,
        executableContextDetected: false,
      },
    };
  }

  // Scenario 2: Safely HTML / entity encoded
  if (!containsRawPayload && containsEncoded) {
    return {
      classification: 'SAFE_ENCODED',
      confidence: 'NO_FINDING',
      confidenceReasoning: 'Payload special characters were properly entity-encoded before rendering.',
      isVulnerability: false,
      explanation: `Input parameter '${parameterName}' was safely entity-encoded by the application output filter.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'Defensive encoding prevents script interpretation in browser DOM.',
      },
      evidence: {
        endpoint,
        parameter: parameterName,
        payload: payloadString,
        context,
        reflectedInBody: true,
        encodedSafely: true,
        executableContextDetected: false,
      },
    };
  }

  // Scenario 3: Reflected raw payload
  // Analyze context safety
  const isJsonContext = context === 'JSON' || snapshot.contentType.includes('application/json');
  const isHtmlContext = context === 'HTML_BODY' || context === 'HTML_ATTRIBUTE' || snapshot.contentType.includes('text/html');

  if (isJsonContext && !snapshot.contentType.includes('text/html')) {
    // In JSON APIs, reflection is standard and safe unless rendered as HTML
    return {
      classification: 'REFLECTED_ONLY',
      confidence: 'LOW_CONFIDENCE',
      confidenceReasoning: 'Reflection observed in JSON response data. Not directly executable in HTML DOM without client-side unsafe innerHTML sinking.',
      isVulnerability: false,
      explanation: `Input parameter '${parameterName}' is reflected in JSON response, but enclosed in application/json MIME boundary.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'JSON context does not lead to direct browser script execution.',
      },
      evidence: {
        endpoint,
        parameter: parameterName,
        payload: payloadString,
        context,
        reflectedInBody: true,
        encodedSafely: false,
        executableContextDetected: false,
      },
    };
  }

  // If in HTML context and raw unencoded payload appears:
  if (isHtmlContext && containsRawPayload) {
    const hasTagCharacters = payloadString.includes('<') || payloadString.includes('>') || payloadString.includes('"');

    if (hasTagCharacters) {
      return {
        classification: 'HIGH_CONFIDENCE_XSS',
        confidence: 'HIGH_CONFIDENCE',
        confidenceReasoning: 'Unsanitized HTML/script markers reflected unencoded in text/html context, enabling DOM script injection.',
        isVulnerability: true,
        vulnerabilityType: 'CROSS_SITE_SCRIPTING_REFLECTED',
        cwe: 'CWE-79',
        owasp: 'A03:2021-Injection',
        explanation: `Reflected Cross-Site Scripting (XSS) detected on endpoint '${endpoint}' via parameter '${parameterName}'. Special characters (<, >, \") were rendered unencoded into the HTML document.`,
        impactAssessment: {
          confidentialityImpact: 'HIGH',
          integrityImpact: 'HIGH',
          privilegeImpact: 'MEDIUM',
          overallImpact: 'HIGH',
          reasoning: 'Allows execution of arbitrary JavaScript in the victim browser context, enabling session hijacking and DOM manipulation.',
        },
        evidence: {
          endpoint,
          parameter: parameterName,
          payload: payloadString,
          context,
          reflectedInBody: true,
          encodedSafely: false,
          executableContextDetected: true,
        },
      };
    }

    return {
      classification: 'REFLECTED_ONLY',
      confidence: 'LOW_CONFIDENCE',
      confidenceReasoning: 'Alphanumeric marker reflected in HTML without HTML meta-characters.',
      isVulnerability: false,
      explanation: `Alphanumeric probe '${payloadString}' was reflected in HTML body. Special character encoding verification required.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'Alphanumeric reflection does not establish script execution capability.',
      },
      evidence: {
        endpoint,
        parameter: parameterName,
        payload: payloadString,
        context,
        reflectedInBody: true,
        encodedSafely: false,
        executableContextDetected: false,
      },
    };
  }

  // Fallback: Potential XSS observation
  return {
    classification: 'POTENTIAL_XSS',
    confidence: 'MEDIUM_CONFIDENCE',
    confidenceReasoning: 'Unencoded marker reflected in non-standard context. Additional browser rendering verification recommended.',
    isVulnerability: false,
    explanation: `Parameter '${parameterName}' is reflected without evident encoding in context '${context}'.`,
    impactAssessment: {
      confidentialityImpact: 'LOW',
      integrityImpact: 'LOW',
      privilegeImpact: 'NONE',
      overallImpact: 'LOW',
      reasoning: 'Potential context breakout requires further manual verification.',
    },
    evidence: {
      endpoint,
      parameter: parameterName,
      payload: payloadString,
      context,
      reflectedInBody: true,
      encodedSafely: false,
      executableContextDetected: false,
    },
  };
}
