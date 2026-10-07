import {
  PathTraversalClassification,
  ConfidenceRating,
  ExecutionSnapshot,
  ImpactAssessment,
} from '../../types/authenticationResearch.ts';

export interface PathTraversalAnalysisInput {
  endpoint: string;
  parameterName: string;
  requestedPath: string;
  allowedRoot: string;
  resolvedPath: string;
  snapshot: ExecutionSnapshot;
}

export interface PathTraversalAnalysisResult {
  classification: PathTraversalClassification;
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
    requestedPath: string;
    allowedRoot: string;
    resolvedPath: string;
    outsideAllowedRoot: boolean;
  };
}

/**
 * Path Traversal Research Adapter
 * Analyzes path canonicalization against isolated fixture roots without host filesystem access.
 */
export function analyzePathTraversal(input: PathTraversalAnalysisInput): PathTraversalAnalysisResult {
  const { endpoint, parameterName, requestedPath, allowedRoot, resolvedPath, snapshot } = input;

  const isOutsideRoot = !resolvedPath.startsWith(allowedRoot);
  const containsSensitiveCanary = typeof snapshot.responseBody === 'string'
    ? snapshot.responseBody.includes('DH_CANARY_FIXTURE')
    : JSON.stringify(snapshot.responseBody || '').includes('DH_CANARY_FIXTURE');

  // Scenario 1: Vulnerable - Path resolves outside allowed root and returns file content
  if (isOutsideRoot && (snapshot.statusCode === 200 || containsSensitiveCanary)) {
    return {
      classification: 'ESCAPED_ROOT_TRAVERSAL',
      confidence: 'HIGH_CONFIDENCE',
      confidenceReasoning: 'Requested path successfully resolved outside designated sandbox root directory, retrieving unauthorized fixture file.',
      isVulnerability: true,
      vulnerabilityType: 'PATH_TRAVERSAL_ARBITRARY_FILE_READ',
      cwe: 'CWE-22',
      owasp: 'A01:2021-Broken Access Control',
      explanation: `Path traversal vulnerability detected on endpoint '${endpoint}' via parameter '${parameterName}'. Supplied relative traversal path '${requestedPath}' resolved to '${resolvedPath}', outside allowed directory '${allowedRoot}'.`,
      impactAssessment: {
        confidentialityImpact: 'HIGH',
        integrityImpact: 'NONE',
        privilegeImpact: 'MEDIUM',
        overallImpact: 'HIGH',
        reasoning: 'Allows unauthorized access and extraction of sensitive system files and configurations outside the intended document root.',
      },
      evidence: {
        endpoint,
        parameter: parameterName,
        requestedPath,
        allowedRoot,
        resolvedPath,
        outsideAllowedRoot: true,
      },
    };
  }

  // Scenario 2: Canonicalization Blocked (400 / 403 / 404)
  if (snapshot.statusCode === 400 || snapshot.statusCode === 403 || snapshot.statusCode === 404) {
    return {
      classification: 'CANONICALIZATION_BLOCKED',
      confidence: 'NO_FINDING',
      confidenceReasoning: 'Server properly detected and blocked path traversal sequence.',
      isVulnerability: false,
      explanation: `Endpoint '${endpoint}' safely rejected relative path traversal probe with HTTP ${snapshot.statusCode}.`,
      impactAssessment: {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'Input validation or framework path canonicalization prevented directory escape.',
      },
      evidence: {
        endpoint,
        parameter: parameterName,
        requestedPath,
        allowedRoot,
        resolvedPath,
        outsideAllowedRoot: false,
      },
    };
  }

  // Scenario 3: Confined to root / safely normalized
  return {
    classification: 'CONFINED_TO_ROOT',
    confidence: 'NO_FINDING',
    confidenceReasoning: 'Resolved path is strictly contained within designated allowed root directory.',
    isVulnerability: false,
    explanation: `Requested path '${requestedPath}' resolved safely inside root '${allowedRoot}'.`,
    impactAssessment: {
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      privilegeImpact: 'NONE',
      overallImpact: 'NONE',
      reasoning: 'Path properly sanitized and bounded within document sandbox.',
    },
    evidence: {
      endpoint,
      parameter: parameterName,
      requestedPath,
      allowedRoot,
      resolvedPath,
      outsideAllowedRoot: false,
    },
  };
}
