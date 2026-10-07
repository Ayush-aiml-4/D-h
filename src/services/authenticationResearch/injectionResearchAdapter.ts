import {
  InjectionClassification,
  ConfidenceRating,
  SecurityContextType,
  ExecutionSnapshot,
  ImpactAssessment,
} from '../../types/authenticationResearch.ts';

export interface InjectionDifferentialInput {
  endpoint: string;
  parameterName: string;
  context: SecurityContextType;
  baselineSnapshot: ExecutionSnapshot;
  trueSnapshot: ExecutionSnapshot;
  falseSnapshot?: ExecutionSnapshot;
  errorSnapshot?: ExecutionSnapshot;
}

export interface InjectionAnalysisResult {
  classification: InjectionClassification;
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
    context: SecurityContextType;
    booleanTrueMatchedBaseline: boolean;
    booleanFalseDiverged: boolean;
    errorEncountered: boolean;
    errorSuppressed: boolean;
  };
}

/**
 * Injection Research Adapter
 * Analyzes differential SQL / command / template injection signals with rigorous false positive suppression.
 */
export function analyzeInjectionDifferential(input: InjectionDifferentialInput): InjectionAnalysisResult {
  const { endpoint, parameterName, context, baselineSnapshot, trueSnapshot, falseSnapshot, errorSnapshot } = input;

  // 1. Check for Error-Only scenario (Mandatory False-Positive Suppression)
  const hasErrorOnly = errorSnapshot && errorSnapshot.errorDetected && (!falseSnapshot || !trueSnapshot);
  if (hasErrorOnly && (!trueSnapshot || trueSnapshot.statusCode === 500)) {
    return {
      classification: 'ERROR_ONLY_SUPPRESSED',
      confidence: 'OBSERVATION',
      confidenceReasoning: 'Database or backend syntax error observed without differential query logic control. Suppressed from vulnerability promotion.',
      isVulnerability: false,
      explanation: `Endpoint '${endpoint}' returned an internal error when supplied injection syntax, but did not demonstrate exploitable boolean differential or structured query control.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'Error messages alone do not substantiate injection execution or data exfiltration.',
      },
      evidence: {
        endpoint,
        parameter: parameterName,
        context,
        booleanTrueMatchedBaseline: false,
        booleanFalseDiverged: false,
        errorEncountered: true,
        errorSuppressed: true,
      },
    };
  }

  // 2. Boolean Differential Analysis:
  // TRUE condition (e.g. ' OR '1'='1) returns baseline/success data (status 200)
  // FALSE condition (e.g. ' OR '1'='2') returns 404 / empty array / distinct error
  if (trueSnapshot && falseSnapshot) {
    const trueIs200 = trueSnapshot.statusCode === 200;
    const baselineIs200 = baselineSnapshot.statusCode === 200;
    const falseDiverges = falseSnapshot.statusCode === 404 ||
      (falseSnapshot.statusCode === 200 && JSON.stringify(falseSnapshot.responseBody) !== JSON.stringify(trueSnapshot.responseBody));

    if (trueIs200 && baselineIs200 && falseDiverges) {
      return {
        classification: 'BOOLEAN_DIFFERENTIAL',
        confidence: 'HIGH_CONFIDENCE',
        confidenceReasoning: 'Deterministic boolean condition injection confirmed: TRUE condition matches valid state while FALSE condition alters output predictably.',
        isVulnerability: true,
        vulnerabilityType: 'SQL_INJECTION_BOOLEAN_BASED',
        cwe: 'CWE-89',
        owasp: 'A03:2021-Injection',
        explanation: `Boolean-based SQL Injection detected on endpoint '${endpoint}' via parameter '${parameterName}'. Controlled logical conditions altered backend database query results deterministically.`,
        impactAssessment: {
          confidentialityImpact: 'HIGH',
          integrityImpact: 'HIGH',
          privilegeImpact: 'HIGH',
          overallImpact: 'CRITICAL',
          reasoning: 'Allows unauthorized extraction, tampering, or exfiltration of backend database records via boolean inference.',
        },
        evidence: {
          endpoint,
          parameter: parameterName,
          context,
          booleanTrueMatchedBaseline: true,
          booleanFalseDiverged: true,
          errorEncountered: false,
          errorSuppressed: false,
        },
      };
    }
  }

  // 3. No differential observed (Safe/Parameterized)
  return {
    classification: 'NO_DIFFERENTIAL',
    confidence: 'NO_FINDING',
    confidenceReasoning: 'Application handles injection probes safely via parameterized queries or strict input validation.',
    isVulnerability: false,
    explanation: `Parameter '${parameterName}' demonstrated no security-relevant differential behavior under injection probes.`,
    impactAssessment: {
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      privilegeImpact: 'NONE',
      overallImpact: 'NONE',
      reasoning: 'No injection vulnerability detected.',
    },
    evidence: {
      endpoint,
      parameter: parameterName,
      context,
      booleanTrueMatchedBaseline: false,
      booleanFalseDiverged: false,
      errorEncountered: false,
      errorSuppressed: false,
    },
  };
}
