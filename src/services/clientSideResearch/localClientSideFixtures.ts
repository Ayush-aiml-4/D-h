import {
  SourceDefinition,
  SinkDefinition,
  TransformationStep,
  BrowserExecutionEvidence,
  StoredXssWorkflowStep,
  ClientSideResearchEvaluation,
  StoredXssWorkflowEvaluation,
} from '../../types/clientSideResearch.ts';
import { createSourceDefinition } from './sourceSinkAnalyzer.ts';
import { resolveSinkDefinition } from './outputContextAnalyzer.ts';
import { evaluateTransformationStep, classifyEncoding } from './transformationAnalyzer.ts';
import { createBrowserExecutionEvidence } from './browserEvidenceModel.ts';
import { evaluateXssDifferential } from './xssDifferentialEngine.ts';
import { evaluateClientSideImpact, evaluateClientSideConfidence } from './xssImpactConfidenceEngine.ts';
import { buildDataFlowTrace } from './sourceSinkAnalyzer.ts';

// -------------------------------------------------------------
// FIXTURE A: Secure Reflected HTML Fixture
// -------------------------------------------------------------
export function createFixtureA_SecureReflectedHtml(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'search_term',
    value: '<script>alert(1)</script>',
  });
  const sink = resolveSinkDefinition('textContent');
  const step = evaluateTransformationStep(
    1,
    'HTML_ENCODING',
    source.value,
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    'HTML_TEXT'
  );
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_TEXT', '<p>Search results: &lt;script&gt;alert(1)&lt;/script&gt;</p>');
  const { classification, sanitizerStatus, isProperlyNeutralized } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_TEXT', [step]);
  const differential = evaluateXssDifferential(source.value, dataFlow.renderedOutput, 'HTML_TEXT', classification);
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_TEXT',
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: false,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: false,
    executionEvidenceEstablished: false,
    impactEstablished: false,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-a-secure-html',
    researchCaseId: 'case-fix-a',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Tracking Portal',
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_TEXT',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'Application correctly applies HTML entity encoding before rendering parameter.',
    cweId: 'CWE-79',
    remediation: 'Maintain strict context-aware HTML entity encoding.',
  };
}

// -------------------------------------------------------------
// FIXTURE B: Vulnerable Reflected HTML Fixture
// -------------------------------------------------------------
export function createFixtureB_VulnerableReflectedHtml(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'q',
    value: '<img src=x onerror=console.log("XSS_EVIDENCE_B")>',
  });
  const sink = resolveSinkDefinition('innerHTML');
  const step = evaluateTransformationStep(1, 'NONE', source.value, source.value, 'HTML_TEXT');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_TEXT', `<div>Results for: ${source.value}</div>`);
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_TEXT', [step]);
  const differential = evaluateXssDifferential(source.value, dataFlow.renderedOutput, 'HTML_TEXT', classification);
  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_B_VULN_HTML',
    correlationId: 'corr-fix-b-001',
    sourceMarker: source.value,
    sink: 'INNER_HTML',
    executionMarker: 'XSS_EVIDENCE_B',
    executedContext: 'HTML_TEXT',
  });
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'HTML_TEXT',
    evidence,
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: true,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: true,
    executionEvidenceEstablished: true,
    impactEstablished: true,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-b-vuln-html',
    researchCaseId: 'case-fix-b',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Partner Search',
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'HTML_TEXT',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    evidence,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'Unencoded query parameter directly reflected into innerHTML text container.',
    cweId: 'CWE-79',
    remediation: 'Replace innerHTML assignment with textContent or apply strict HTML entity encoding.',
  };
}

// -------------------------------------------------------------
// FIXTURE C: Secure Attribute Fixture
// -------------------------------------------------------------
export function createFixtureC_SecureAttribute(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'user_title',
    value: 'test" onfocus="alert(1)',
  });
  const sink = resolveSinkDefinition('setAttribute');
  const step = evaluateTransformationStep(1, 'ATTRIBUTE_ENCODING', source.value, 'test&quot; onfocus=&quot;alert(1)', 'HTML_ATTRIBUTE');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_ATTRIBUTE', '<input type="text" value="test&quot; onfocus=&quot;alert(1)">');
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_ATTRIBUTE', [step]);
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_ATTRIBUTE',
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: false,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: false,
    executionEvidenceEstablished: false,
    impactEstablished: false,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-c-secure-attr',
    researchCaseId: 'case-fix-c',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Supplier Settings',
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_ATTRIBUTE',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'Attribute quotes properly escaped preventing attribute breakout.',
    cweId: 'CWE-79',
    remediation: 'Ensure all HTML attributes are properly quoted and quote-escaped.',
  };
}

// -------------------------------------------------------------
// FIXTURE D: Vulnerable Attribute Fixture
// -------------------------------------------------------------
export function createFixtureD_VulnerableAttribute(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'redirect_tab',
    value: 'main" autofocus onfocus="console.log(\'XSS_EVIDENCE_D\')',
  });
  const sink = resolveSinkDefinition('innerHTML');
  const step = evaluateTransformationStep(1, 'NONE', source.value, source.value, 'HTML_ATTRIBUTE');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_ATTRIBUTE', `<input name="tab" value="${source.value}">`);
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_ATTRIBUTE', [step]);
  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_D_VULN_ATTR',
    correlationId: 'corr-fix-d-001',
    sourceMarker: source.value,
    sink: 'INNER_HTML',
    executionMarker: 'XSS_EVIDENCE_D',
    executedContext: 'HTML_ATTRIBUTE',
  });
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'HTML_ATTRIBUTE',
    evidence,
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: true,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: true,
    executionEvidenceEstablished: true,
    impactEstablished: true,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-d-vuln-attr',
    researchCaseId: 'case-fix-d',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Supplier Portal Tab View',
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'HTML_ATTRIBUTE',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    evidence,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'Unescaped double quote allows breakout from input value attribute into autofocus event handler.',
    cweId: 'CWE-79',
    remediation: 'HTML-attribute encode double quotes and ampersands in attribute values.',
  };
}

// -------------------------------------------------------------
// FIXTURE E: Secure JavaScript Context Fixture
// -------------------------------------------------------------
export function createFixtureE_SecureJsContext(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'callback_name',
    value: "test'; alert(1); //",
  });
  const sink = resolveSinkDefinition('eval');
  const step = evaluateTransformationStep(1, 'JAVASCRIPT_ESCAPING', source.value, "test\\'; alert(1); //", 'JAVASCRIPT_STRING');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'JAVASCRIPT_STRING', "<script>var name = 'test\\'; alert(1); //';</script>");
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'JAVASCRIPT_STRING', [step]);
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'JAVASCRIPT_STRING',
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: false,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: false,
    executionEvidenceEstablished: false,
    impactEstablished: false,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-e-secure-js',
    researchCaseId: 'case-fix-e',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Partner Analytics',
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'JAVASCRIPT_STRING',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'JavaScript string escaping safely neutralizes quote breakout.',
    cweId: 'CWE-79',
    remediation: 'Use JSON.stringify or unicode escaping when embedding variables in inline scripts.',
  };
}

// -------------------------------------------------------------
// FIXTURE F: Vulnerable JavaScript Context Fixture
// -------------------------------------------------------------
export function createFixtureF_VulnerableJsContext(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'partner_session',
    value: "abc'; console.log('XSS_EVIDENCE_F'); //",
  });
  const sink = resolveSinkDefinition('eval');
  const step = evaluateTransformationStep(1, 'NONE', source.value, source.value, 'JAVASCRIPT_STRING');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'JAVASCRIPT_CODE', `<script>var sess = '${source.value}';</script>`);
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'JAVASCRIPT_STRING', [step]);
  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_F_VULN_JS',
    correlationId: 'corr-fix-f-001',
    sourceMarker: source.value,
    sink: 'EVAL',
    executionMarker: 'XSS_EVIDENCE_F',
    executedContext: 'JAVASCRIPT_CODE',
  });
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'JAVASCRIPT_CODE',
    evidence,
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: true,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: true,
    executionEvidenceEstablished: true,
    impactEstablished: true,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-f-vuln-js',
    researchCaseId: 'case-fix-f',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Partner Init Script',
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'JAVASCRIPT_CODE',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    evidence,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'Unescaped variable injection in inline script literal allows string termination and arbitrary JS code execution.',
    cweId: 'CWE-79',
    remediation: 'Pass state via data-* attributes or parse via JSON.parse with proper encoding.',
  };
}

// -------------------------------------------------------------
// FIXTURE G: Secure DOM Fixture
// -------------------------------------------------------------
export function createFixtureG_SecureDom(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'URL_FRAGMENT',
    name: 'location.hash',
    value: '#payload=<script>alert(1)</script>',
  });
  const sink = resolveSinkDefinition('textContent');
  const step = evaluateTransformationStep(1, 'SANITIZATION', source.value, 'payload=alert(1)', 'HTML_TEXT');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_TEXT', 'payload=alert(1)');
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_TEXT', [step]);
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_TEXT',
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: false,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: false,
    executionEvidenceEstablished: false,
    impactEstablished: false,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-g-secure-dom',
    researchCaseId: 'case-fix-g',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Supplier Navigation Router',
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_TEXT',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'DOM hash parameter rendered via safe textContent sink after sanitization.',
    cweId: 'CWE-79',
    remediation: 'Continue using textContent or sanitized framework data bindings.',
  };
}

// -------------------------------------------------------------
// FIXTURE H: Vulnerable DOM Fixture
// -------------------------------------------------------------
export function createFixtureH_VulnerableDom(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'URL_FRAGMENT',
    name: 'location.hash',
    value: '#<img src=x onerror=console.log("XSS_EVIDENCE_H")>',
  });
  const sink = resolveSinkDefinition('innerHTML');
  const step = evaluateTransformationStep(1, 'NONE', source.value, source.value.substring(1), 'HTML_TEXT');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_TEXT', source.value.substring(1));
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_TEXT', [step]);
  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_H_VULN_DOM',
    correlationId: 'corr-fix-h-001',
    sourceMarker: source.value,
    sink: 'INNER_HTML',
    executionMarker: 'XSS_EVIDENCE_H',
    executedContext: 'HTML_TEXT',
  });
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'DOM_XSS',
    isVulnerable: true,
    context: 'HTML_TEXT',
    evidence,
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: true,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: true,
    executionEvidenceEstablished: true,
    impactEstablished: true,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-h-vuln-dom',
    researchCaseId: 'case-fix-h',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Supplier Navigation Router',
    vulnerabilityType: 'DOM_XSS',
    isVulnerable: true,
    context: 'HTML_TEXT',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    evidence,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'DOM location.hash directly written to element.innerHTML without sanitization.',
    cweId: 'CWE-79',
    remediation: 'Sanitize location hash before writing to innerHTML or assign to textContent instead.',
  };
}

// -------------------------------------------------------------
// FIXTURE I: Secure Stored XSS Workflow
// -------------------------------------------------------------
export function createFixtureI_SecureStoredWorkflow(): StoredXssWorkflowEvaluation {
  const steps: StoredXssWorkflowStep[] = [
    {
      stepNumber: 1,
      stage: 'INPUT_CREATED',
      actorId: 'attacker-001',
      role: 'STANDARD_USER',
      action: 'Submit comment payload <script>alert(1)</script>',
      state: 'DRAFT_CREATED',
      payloadSnapshot: '<script>alert(1)</script>',
    },
    {
      stepNumber: 2,
      stage: 'STORED',
      actorId: 'attacker-001',
      role: 'STANDARD_USER',
      action: 'Save comment to database record CM-100',
      state: 'RECORD_PERSISTED',
      payloadSnapshot: '<script>alert(1)</script>',
    },
    {
      stepNumber: 3,
      stage: 'RETRIEVED',
      actorId: 'victim-001',
      role: 'STANDARD_USER',
      action: 'Retrieve comment CM-100 via GET /api/v1/comments/100',
      state: 'RECORD_FETCHED',
      payloadSnapshot: '<script>alert(1)</script>',
    },
    {
      stepNumber: 4,
      stage: 'RENDERED',
      actorId: 'victim-001',
      role: 'STANDARD_USER',
      action: 'Render comment in UI with HTML entity encoding &lt;script&gt;',
      state: 'SAFE_RENDERED',
      payloadSnapshot: '&lt;script&gt;alert(1)&lt;/script&gt;',
    },
  ];

  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_I_SECURE_STORED',
    correlationId: 'corr-fix-i-001',
    sourceMarker: '<script>alert(1)</script>',
    sink: 'SAFE_TEXT_CONTENT',
    executionMarker: 'NONE',
    executedContext: 'HTML_TEXT',
    executionLog: ['Input stored safely', 'Retrieved by victim', 'Safely encoded upon render'],
  });

  return {
    workflowId: 'wf-stored-secure-01',
    researchCaseId: 'case-fix-i',
    steps,
    isVulnerable: false,
    impactScope: 'SAME_USER',
    attackerActor: 'attacker-001',
    victimActor: 'victim-001',
    rootCause: 'Stored payload is safely HTML encoded during retrieval and rendering.',
    confidence: 'NO_FINDING',
    evidence,
  };
}

// -------------------------------------------------------------
// FIXTURE J: Vulnerable Stored XSS Workflow
// -------------------------------------------------------------
export function createFixtureJ_VulnerableStoredWorkflow(): StoredXssWorkflowEvaluation {
  const steps: StoredXssWorkflowStep[] = [
    {
      stepNumber: 1,
      stage: 'INPUT_CREATED',
      actorId: 'attacker-001',
      role: 'SUPPLIER',
      action: 'Submit supplier profile description with payload <img src=x onerror=console.log("XSS_STORED_J")>',
      state: 'INPUT_SUBMITTED',
      payloadSnapshot: '<img src=x onerror=console.log("XSS_STORED_J")>',
    },
    {
      stepNumber: 2,
      stage: 'STORED',
      actorId: 'attacker-001',
      role: 'SUPPLIER',
      action: 'Database persists unencoded HTML payload in supplier profile table',
      state: 'STORED_RAW',
      payloadSnapshot: '<img src=x onerror=console.log("XSS_STORED_J")>',
    },
    {
      stepNumber: 3,
      stage: 'RETRIEVED',
      actorId: 'victim-customer-01',
      role: 'CUSTOMER',
      action: 'Customer views supplier profile page /supplier/12345',
      state: 'RECORD_RETRIEVED',
      payloadSnapshot: '<img src=x onerror=console.log("XSS_STORED_J")>',
    },
    {
      stepNumber: 4,
      stage: 'RENDERED',
      actorId: 'victim-customer-01',
      role: 'CUSTOMER',
      action: 'Frontend renders supplier description directly using element.innerHTML',
      state: 'RAW_HTML_RENDERED',
      payloadSnapshot: '<img src=x onerror=console.log("XSS_STORED_J")>',
    },
    {
      stepNumber: 5,
      stage: 'EXECUTION',
      actorId: 'victim-customer-01',
      role: 'CUSTOMER',
      action: 'Browser executes injected onerror handler in victim customer session',
      state: 'CODE_EXECUTED',
      evidenceRef: 'ev-stored-j-exec-001',
      payloadSnapshot: 'XSS_STORED_J',
    },
  ];

  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_J_VULN_STORED',
    correlationId: 'corr-fix-j-001',
    sourceMarker: '<img src=x onerror=console.log("XSS_STORED_J")>',
    sink: 'INNER_HTML',
    executionMarker: 'XSS_STORED_J',
    executedContext: 'HTML_TEXT',
  });

  return {
    workflowId: 'wf-stored-vuln-01',
    researchCaseId: 'case-fix-j',
    steps,
    isVulnerable: true,
    impactScope: 'CROSS_USER',
    attackerActor: 'attacker-001 [SUPPLIER]',
    victimActor: 'victim-customer-01 [CUSTOMER]',
    rootCause: 'Stored supplier description rendered via innerHTML without server or client side sanitization, leading to cross-user execution.',
    confidence: 'HIGH_CONFIDENCE',
    evidence,
  };
}

// -------------------------------------------------------------
// FIXTURE K: Sanitized Input Fixture (DOMPurify Clean)
// -------------------------------------------------------------
export function createFixtureK_SanitizedInput(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'FORM_INPUT',
    name: 'rich_description',
    value: '<b>Hello</b><script>alert(1)</script><img src=x onerror=alert(2)>',
  });
  const sink = resolveSinkDefinition('innerHTML');
  const step = evaluateTransformationStep(1, 'SANITIZATION', source.value, '<b>Hello</b><img src="x">', 'HTML_TEXT');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_TEXT', '<b>Hello</b><img src="x">');
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_TEXT', [step]);
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_TEXT',
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: false,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: false,
    executionEvidenceEstablished: false,
    impactEstablished: false,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-k-sanitized',
    researchCaseId: 'case-fix-k',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Product Catalog Rich Editor',
    vulnerabilityType: 'SAFE_TRANSFORMATION',
    isVulnerable: false,
    context: 'HTML_TEXT',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'DOMPurify sanitizer successfully stripped executable elements while preserving harmless markup.',
    cweId: 'CWE-79',
    remediation: 'Maintain current DOMPurify configuration with strict hook settings.',
  };
}

// -------------------------------------------------------------
// FIXTURE L: Incorrectly Encoded Input Fixture (URL-encoded in HTML Text)
// -------------------------------------------------------------
export function createFixtureL_IncorrectlyEncodedInput(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'msg',
    value: '<script>console.log("XSS_EVIDENCE_L")</script>',
  });
  const sink = resolveSinkDefinition('innerHTML');
  // App mistakenly URL-encodes instead of HTML-encoding, but client JavaScript decodes it with decodeURIComponent before innerHTML
  const step1 = evaluateTransformationStep(1, 'URL_ENCODING', source.value, '%3Cscript%3Econsole.log(%22XSS_EVIDENCE_L%22)%3C/script%3E', 'HTML_TEXT');
  const step2 = evaluateTransformationStep(2, 'DECODING', step1.outputSnippet, source.value, 'HTML_TEXT');
  const dataFlow = buildDataFlowTrace(source, [step1, step2], sink, 'HTML_TEXT', `<div>Notification: ${source.value}</div>`);
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_TEXT', [step1, step2]);
  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_L_INCORRECT_ENCODING',
    correlationId: 'corr-fix-l-001',
    sourceMarker: source.value,
    sink: 'INNER_HTML',
    executionMarker: 'XSS_EVIDENCE_L',
    executedContext: 'HTML_TEXT',
  });
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'HTML_TEXT',
    evidence,
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: true,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: true,
    executionEvidenceEstablished: true,
    impactEstablished: true,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-l-incorrect-enc',
    researchCaseId: 'case-fix-l',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Notification Banner',
    vulnerabilityType: 'REFLECTED_XSS',
    isVulnerable: true,
    context: 'HTML_TEXT',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    evidence,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'Wrong context encoding: URL encoding was applied on the server but decoded on client before writing to innerHTML.',
    cweId: 'CWE-79',
    remediation: 'Use HTML entity encoding rather than URL encoding for HTML document text nodes.',
  };
}

// -------------------------------------------------------------
// FIXTURE M: Cross-User Stored XSS Fixture (Privileged Context)
// -------------------------------------------------------------
export function createFixtureM_CrossUserStoredPrivileged(): StoredXssWorkflowEvaluation {
  const steps: StoredXssWorkflowStep[] = [
    {
      stepNumber: 1,
      stage: 'INPUT_CREATED',
      actorId: 'attacker-supplier-01',
      role: 'SUPPLIER',
      action: 'Submit support ticket subject <svg onload=console.log("XSS_PRIVILEGED_M")>',
      state: 'TICKET_CREATED',
      payloadSnapshot: '<svg onload=console.log("XSS_PRIVILEGED_M")>',
    },
    {
      stepNumber: 2,
      stage: 'STORED',
      actorId: 'attacker-supplier-01',
      role: 'SUPPLIER',
      action: 'Ticket stored in support ticket queue database',
      state: 'STORED_IN_DB',
      payloadSnapshot: '<svg onload=console.log("XSS_PRIVILEGED_M")>',
    },
    {
      stepNumber: 3,
      stage: 'RETRIEVED',
      actorId: 'admin-support-agent',
      role: 'ADMIN_SUPPORT',
      action: 'Support agent opens support portal /admin/tickets/view/99281',
      state: 'RETRIEVED_BY_ADMIN',
      payloadSnapshot: '<svg onload=console.log("XSS_PRIVILEGED_M")>',
    },
    {
      stepNumber: 4,
      stage: 'RENDERED',
      actorId: 'admin-support-agent',
      role: 'ADMIN_SUPPORT',
      action: 'Admin dashboard renders ticket subject via raw table cell innerHTML',
      state: 'RENDERED_IN_ADMIN_UI',
      payloadSnapshot: '<svg onload=console.log("XSS_PRIVILEGED_M")>',
    },
    {
      stepNumber: 5,
      stage: 'EXECUTION',
      actorId: 'admin-support-agent',
      role: 'ADMIN_SUPPORT',
      action: 'JavaScript executes in privileged admin support agent browser session',
      state: 'PRIVILEGED_CODE_EXECUTION',
      evidenceRef: 'ev-admin-xss-m-001',
      payloadSnapshot: 'XSS_PRIVILEGED_M',
    },
  ];

  const evidence = createBrowserExecutionEvidence({
    fixtureId: 'FIXTURE_M_PRIVILEGED_STORED',
    correlationId: 'corr-fix-m-001',
    sourceMarker: '<svg onload=console.log("XSS_PRIVILEGED_M")>',
    sink: 'INNER_HTML',
    executionMarker: 'XSS_PRIVILEGED_M',
    executedContext: 'HTML_TEXT',
  });

  return {
    workflowId: 'wf-stored-admin-01',
    researchCaseId: 'case-fix-m',
    steps,
    isVulnerable: true,
    impactScope: 'PRIVILEGED_USER_CONTEXT',
    attackerActor: 'attacker-supplier-01 [SUPPLIER]',
    victimActor: 'admin-support-agent [ADMIN_SUPPORT]',
    rootCause: 'Unsanitized ticket subject stored by low-privileged supplier triggers script execution in high-privileged admin console.',
    confidence: 'HIGH_CONFIDENCE',
    evidence,
  };
}

// -------------------------------------------------------------
// FIXTURE N: False-Positive Reflection Fixture (Harmless Reflection)
// -------------------------------------------------------------
export function createFixtureN_FalsePositiveReflection(): ClientSideResearchEvaluation {
  const source = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'filter',
    value: 'cotton_shirts',
  });
  const sink = resolveSinkDefinition('textContent');
  const step = evaluateTransformationStep(1, 'NONE', source.value, source.value, 'HTML_TEXT');
  const dataFlow = buildDataFlowTrace(source, [step], sink, 'HTML_TEXT', '<p>Active filter: cotton_shirts</p>');
  const { classification, sanitizerStatus } = classifyEncoding(source.value, dataFlow.renderedOutput, 'HTML_TEXT', [step]);
  const impact = evaluateClientSideImpact({
    vulnerabilityType: 'SUPPRESSED_FALSE_POSITIVE',
    isVulnerable: false,
    context: 'HTML_TEXT',
    dataFlow,
  });
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable: false,
    sourceIdentified: true,
    dataFlowEstablished: true,
    unsafeSinkOrContextEstablished: false,
    executionEvidenceEstablished: false,
    impactEstablished: false,
    isDeterministic: true,
  });

  return {
    evaluationId: 'eval-fix-n-false-pos',
    researchCaseId: 'case-fix-n',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Public Catalog',
    vulnerabilityType: 'SUPPRESSED_FALSE_POSITIVE',
    isVulnerable: false,
    context: 'HTML_TEXT',
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause: 'Harmless parameter reflection in safe text content without executable syntax or breakout.',
    cweId: 'CWE-79',
    remediation: 'No remediation needed for safe text node reflection.',
  };
}
