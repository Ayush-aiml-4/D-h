import {
  SafePayload,
  PayloadSafetyClass,
  SecurityContextType,
  PayloadRiskTier,
} from '../../types/authenticationResearch.ts';

/**
 * DEVILHUNT #0005 SAFE PAYLOAD REGISTRY
 *
 * All payloads are strictly non-destructive proof-of-concept markers.
 * Destructive payloads, mass fuzzing sweeps, and real exploitation vectors are strictly prohibited.
 */
export const SAFE_PAYLOAD_REGISTRY: SafePayload[] = [
  // 1. Passive / Reflection Markers
  {
    payloadId: 'payload-passive-marker-01',
    category: 'PASSIVE_MARKER',
    name: 'Standard Benign Marker',
    payloadString: 'devilhunt-safe-marker-005',
    purpose: 'Verify benign parameter reflection without altering execution syntax',
    expectedObservation: 'Exact alphanumeric string reflected in response without side effects',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['HTML_BODY', 'HTML_ATTRIBUTE', 'JSON', 'URL', 'SQL_CLAUSE'],
  },
  {
    payloadId: 'payload-reflect-marker-02',
    category: 'REFLECTION_MARKER',
    name: 'Alphanumeric Boundary Marker',
    payloadString: 'dh_test_ref_9921',
    purpose: 'Identify parameter reflection locations and context boundaries',
    expectedObservation: 'Alphanumeric marker reflected in response body or attributes',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['HTML_BODY', 'HTML_ATTRIBUTE', 'JAVASCRIPT', 'JSON', 'URL'],
  },

  // 2. Encoding / Context Tests
  {
    payloadId: 'payload-encoding-test-01',
    category: 'ENCODING_TEST',
    name: 'HTML Character Boundary Probe',
    payloadString: 'dh<probe>"\'&',
    purpose: 'Test whether HTML special characters (<, >, ", \', &) are safely encoded',
    expectedObservation: 'Characters properly HTML-entity-encoded (&lt;, &gt;, &quot;, &#39;, &amp;)',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['HTML_BODY', 'HTML_ATTRIBUTE'],
  },
  {
    payloadId: 'payload-context-json-01',
    category: 'CONTEXT_TEST',
    name: 'JSON Special Character Probe',
    payloadString: 'dh"\\probe\n\r',
    purpose: 'Test JSON serializer escaping for quote and backslash characters',
    expectedObservation: 'Properly escaped string inside JSON response payload',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['JSON', 'JAVASCRIPT'],
  },

  // 3. Controlled XSS Proof-of-Concept Markers (Non-destructive synthetic markers)
  {
    payloadId: 'payload-xss-synthetic-01',
    category: 'CONTROLLED_XSS_TEST',
    name: 'Controlled Script Tag Marker',
    payloadString: '<devilhunt-poc-xss id="dh-xss-test-01">',
    purpose: 'Demonstrate unencoded HTML tag injection in HTML body context without executing active script',
    expectedObservation: 'Unencoded custom HTML tag reflected in browser DOM context',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['HTML_BODY'],
  },
  {
    payloadId: 'payload-xss-attribute-02',
    category: 'CONTROLLED_XSS_TEST',
    name: 'Controlled Attribute Breakout Marker',
    payloadString: '" data-dh-probe="xss-test-attr',
    purpose: 'Demonstrate unencoded HTML attribute breakout without executing JavaScript',
    expectedObservation: 'Attribute delimiter closed and new harmless data attribute inserted',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['HTML_ATTRIBUTE'],
  },
  {
    payloadId: 'payload-xss-js-context-03',
    category: 'CONTROLLED_XSS_TEST',
    name: 'Controlled JS Context Boundary Probe',
    payloadString: '";/*dh_safe_probe*/',
    purpose: 'Demonstrate unescaped string literal boundary in inline JavaScript context',
    expectedObservation: 'JavaScript comment syntax placed outside string literal',
    riskTier: 'APPROVAL_REQUIRED',
    approvalRequired: true,
    contexts: ['JAVASCRIPT'],
  },

  // 4. Controlled Injection Proof-of-Concept Tests
  {
    payloadId: 'payload-sqli-boolean-true-01',
    category: 'CONTROLLED_INJECTION_TEST',
    name: 'Controlled SQL Boolean TRUE Probe',
    payloadString: "' OR 'DEVILHUNT_EQ'='DEVILHUNT_EQ",
    purpose: 'Test for boolean differential by supplying deterministic identical TRUE clause',
    expectedObservation: 'Query returns matching records without syntax error',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['SQL_CLAUSE'],
  },
  {
    payloadId: 'payload-sqli-boolean-false-02',
    category: 'CONTROLLED_INJECTION_TEST',
    name: 'Controlled SQL Boolean FALSE Probe',
    payloadString: "' OR 'DEVILHUNT_NEQ'='DEVILHUNT_DIFFERENT",
    purpose: 'Test for boolean differential by supplying deterministic FALSE clause',
    expectedObservation: 'Query returns zero records or 404 response without syntax error',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['SQL_CLAUSE'],
  },
  {
    payloadId: 'payload-cmdi-safe-echo-01',
    category: 'CONTROLLED_INJECTION_TEST',
    name: 'Controlled Command Safe Marker',
    payloadString: ';echo DH_SAFE_MARKER',
    purpose: 'Test for command argument concatenation using safe non-destructive echo',
    expectedObservation: 'Exact marker string output without system modification or state disruption',
    riskTier: 'APPROVAL_REQUIRED',
    approvalRequired: true,
    contexts: ['SHELL_ARGUMENT'],
  },

  // 5. Path Canonicalization & Traversal Tests
  {
    payloadId: 'payload-traversal-probe-01',
    category: 'PATH_CANONICALIZATION_TEST',
    name: 'Controlled Safe Fixture Traversal Probe',
    payloadString: '../../devilhunt-fixture-root/safe-canary.json',
    purpose: 'Test path canonicalization against isolated local test directory',
    expectedObservation: 'Rejection or path confinement to allowed base root',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['FILE_PATH'],
  },
  {
    payloadId: 'payload-traversal-encoded-02',
    category: 'PATH_CANONICALIZATION_TEST',
    name: 'URL-Encoded Relative Traversal Probe',
    payloadString: '%2e%2e%2fdevilhunt-fixture-root%2fsafe-canary.json',
    purpose: 'Test whether URL-encoded traversal sequences bypass basic normalization filters',
    expectedObservation: 'Server safely decodes and bounds the path within allowed root',
    riskTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    contexts: ['FILE_PATH', 'URL'],
  },
];

/**
 * Retrieves safe payloads suitable for a specific security context.
 */
export function getSafePayloadsForContext(context: SecurityContextType): SafePayload[] {
  return SAFE_PAYLOAD_REGISTRY.filter((p) => p.contexts.includes(context));
}

/**
 * Retrieves safe payloads by category.
 */
export function getSafePayloadsByCategory(category: PayloadSafetyClass): SafePayload[] {
  return SAFE_PAYLOAD_REGISTRY.filter((p) => p.category === category);
}

/**
 * Validates whether a custom payload string is safe (strictly rejecting destructive patterns).
 */
export function validatePayloadSafety(payloadString: string): { isSafe: boolean; reason?: string } {
  const lower = payloadString.toLowerCase();

  // Strict Prohibitions
  const forbiddenPatterns = [
    'drop table',
    'truncate table',
    'delete from',
    'insert into',
    'update ',
    'shutdown',
    'rm -rf',
    'curl ',
    'wget ',
    'nc -',
    'bash -i',
    '/etc/passwd',
    '/etc/shadow',
    'document.cookie',
    'window.location',
    'eval(',
    'fetch(',
  ];

  for (const pattern of forbiddenPatterns) {
    if (lower.includes(pattern)) {
      return {
        isSafe: false,
        reason: `FORBIDDEN_PAYLOAD_PATTERN: Payload contains prohibited string '${pattern}'. Only non-destructive markers permitted.`,
      };
    }
  }

  return { isSafe: true };
}

/**
 * Retrieves payload by identifier.
 */
export function getPayloadById(payloadId: string): SafePayload | undefined {
  return SAFE_PAYLOAD_REGISTRY.find((p) => p.payloadId === payloadId);
}
