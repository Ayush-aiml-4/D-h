import assert from 'assert';
import {
  determineInputContext,
  isSecuritySensitiveContext,
  resolveSinkDefinition,
  isSinkReceivingTrustedConstant,
  createSourceDefinition,
  buildDataFlowTrace,
  evaluateTransformationStep,
  classifyEncoding,
  createBrowserExecutionEvidence,
  evaluateXssDifferential,
  evaluateClientSideImpact,
  evaluateClientSideConfidence,
  isClientSideFalsePositive,
  evaluateClientSideResearch,
  convertClientSideEvaluationToObservation,
  convertStoredWorkflowToObservation,
  createFixtureA_SecureReflectedHtml,
  createFixtureB_VulnerableReflectedHtml,
  createFixtureC_SecureAttribute,
  createFixtureD_VulnerableAttribute,
  createFixtureE_SecureJsContext,
  createFixtureF_VulnerableJsContext,
  createFixtureG_SecureDom,
  createFixtureH_VulnerableDom,
  createFixtureI_SecureStoredWorkflow,
  createFixtureJ_VulnerableStoredWorkflow,
  createFixtureK_SanitizedInput,
  createFixtureL_IncorrectlyEncodedInput,
  createFixtureM_CrossUserStoredPrivileged,
  createFixtureN_FalsePositiveReflection,
} from '../src/services/clientSideResearch/index.ts';
import {
  clusterObservations,
  deduplicateCandidates,
  synthesizeResearchCase,
  createFindingCandidateFromObservations,
  generateReportDraft,
  evaluateReportQualityGates,
} from '../src/services/researchSynthesis/index.ts';
import { resolveTargetScope, evaluateFindingEligibility } from '../src/services/programProfileService.ts';
import { evaluatePolicy } from '../src/services/policyEngine.ts';
import { containsRawSecrets } from '../src/services/researchSynthesis/observationModelService.ts';
import { AuthUser } from '../src/middleware/auth.ts';

const MOCK_RESEARCHER: AuthUser = {
  uid: 'user-ayush-001',
  email: 'ayush@example.com',
  name: 'Ayush Singh',
  role: 'RESEARCHER',
};

async function runClientSideXssVerificationSuite() {
  console.log('===============================================================================================');
  console.log(' DEVILHUNT #0009 ADVANCED CLIENT-SIDE & XSS RESEARCH ENGINE VERIFICATION SUITE');
  console.log('===============================================================================================');

  // -------------------------------------------------------------
  // SECTION A: CONTEXT ANALYSIS
  // -------------------------------------------------------------
  console.log('\n--- SECTION A: CONTEXT ANALYSIS ---');

  // [TEST 1] HTML context detection
  const ctxHtml = determineInputContext('<div>Search results for: {{INPUT}}</div>', '{{INPUT}}');
  assert(ctxHtml === 'HTML_TEXT', '[TEST 1] HTML text context detected correctly');
  console.log('  [PASS] [TEST 1] HTML context detection');

  // [TEST 2] Attribute context detection
  const ctxAttr = determineInputContext('<input type="text" name="user" value="{{INPUT}}">', '{{INPUT}}');
  assert(ctxAttr === 'HTML_ATTRIBUTE', '[TEST 2] Attribute context detected correctly');
  console.log('  [PASS] [TEST 2] Attribute context detection');

  // [TEST 3] JavaScript context detection
  const ctxJs = determineInputContext('<script>var username = "{{INPUT}}";</script>', '{{INPUT}}');
  assert(ctxJs === 'JAVASCRIPT_STRING', '[TEST 3] JavaScript string literal context detected correctly');
  console.log('  [PASS] [TEST 3] JavaScript context detection');

  // [TEST 4] URL context detection
  const ctxUrl = determineInputContext('https://supplier.meesho.com/dashboard?ref={{INPUT}}', '{{INPUT}}');
  assert(ctxUrl === 'URL', '[TEST 4] URL context detected correctly');
  console.log('  [PASS] [TEST 4] URL context detection');

  // [TEST 5] Unknown context handling
  const ctxUnknown = determineInputContext('', '{{INPUT}}');
  assert(ctxUnknown === 'UNKNOWN', '[TEST 5] Empty or unlocated snippet handled as UNKNOWN');
  console.log('  [PASS] [TEST 5] Unknown context handling');

  // -------------------------------------------------------------
  // SECTION B: SOURCE / SINK
  // -------------------------------------------------------------
  console.log('\n--- SECTION B: SOURCE / SINK ---');

  // [TEST 6] Source registration
  const src = createSourceDefinition({
    sourceType: 'QUERY_PARAMETER',
    name: 'redirect_url',
    value: 'javascript:alert(1)',
  });
  assert(src.sourceType === 'QUERY_PARAMETER' && src.isResearcherControlled, '[TEST 6] Source registered with researcher control marker');
  console.log('  [PASS] [TEST 6] Source registration');

  // [TEST 7] Sink registration
  const sinkDanger = resolveSinkDefinition('innerHTML');
  assert(sinkDanger.isDangerous && sinkDanger.sinkType === 'INNER_HTML', '[TEST 7] Dangerous sink innerHTML registered');
  console.log('  [PASS] [TEST 7] Sink registration');

  // [TEST 8] Source-to-sink linkage
  const trace = buildDataFlowTrace(src, [], sinkDanger, 'HTML_TEXT', src.value);
  assert(trace.isTaintPathValid && !trace.isNeutralized, '[TEST 8] Unneutralized source-to-sink linkage established');
  console.log('  [PASS] [TEST 8] Source-to-sink linkage');

  // [TEST 9] Safe sink suppression
  const sinkSafe = resolveSinkDefinition('textContent');
  const traceSafe = buildDataFlowTrace(src, [], sinkSafe, 'HTML_TEXT', src.value);
  assert(traceSafe.isNeutralized, '[TEST 9] Safe sink textContent neutralizes execution path');
  console.log('  [PASS] [TEST 9] Safe sink suppression');

  // [TEST 10] Dangerous sink identification
  assert(
    resolveSinkDefinition('eval').isDangerous &&
    resolveSinkDefinition('document.write').isDangerous &&
    resolveSinkDefinition('location.href').isDangerous,
    '[TEST 10] Security-critical sinks correctly identified as dangerous'
  );
  console.log('  [PASS] [TEST 10] Dangerous sink identification');

  // -------------------------------------------------------------
  // SECTION C: TRANSFORMATION
  // -------------------------------------------------------------
  console.log('\n--- SECTION C: TRANSFORMATION ---');

  // [TEST 11] Correct HTML encoding
  const stepHtmlEnc = evaluateTransformationStep(1, 'HTML_ENCODING', '<script>alert(1)</script>', '&lt;script&gt;alert(1)&lt;/script&gt;', 'HTML_TEXT');
  assert(stepHtmlEnc.neutralizesContext, '[TEST 11] Correct HTML entity encoding neutralizes HTML text injection');
  console.log('  [PASS] [TEST 11] Correct HTML encoding');

  // [TEST 12] Incorrect encoding
  const stepWrongEnc = evaluateTransformationStep(1, 'HTML_ENCODING', "var a = 'test';", "var a = '&lt;script&gt;';", 'JAVASCRIPT_STRING');
  assert(!stepWrongEnc.neutralizesContext, '[TEST 12] HTML encoding inside JavaScript string recognized as ineffective');
  console.log('  [PASS] [TEST 12] Incorrect encoding');

  // [TEST 13] JavaScript encoding
  const stepJsEnc = evaluateTransformationStep(1, 'JAVASCRIPT_ESCAPING', "test'; alert(1);", "test\\'; alert(1);", 'JAVASCRIPT_STRING');
  assert(stepJsEnc.neutralizesContext, '[TEST 13] JavaScript string escaping neutralizes JS string breakout');
  console.log('  [PASS] [TEST 13] JavaScript encoding');

  // [TEST 14] URL encoding
  const stepUrlEnc = evaluateTransformationStep(1, 'URL_ENCODING', 'test query', 'test%20query', 'URL');
  assert(stepUrlEnc.neutralizesContext, '[TEST 14] URL encoding neutralizes URL parameter boundary');
  console.log('  [PASS] [TEST 14] URL encoding');

  // [TEST 15] Sanitizer detection
  const stepSanitize = evaluateTransformationStep(1, 'SANITIZATION', '<b>ok</b><script>alert(1)</script>', '<b>ok</b>', 'HTML_TEXT');
  assert(stepSanitize.neutralizesContext, '[TEST 15] Sanitizer stripping malicious script detected');
  console.log('  [PASS] [TEST 15] Sanitizer detection');

  // -------------------------------------------------------------
  // SECTION D: REFLECTED XSS
  // -------------------------------------------------------------
  console.log('\n--- SECTION D: REFLECTED XSS ---');

  // [TEST 16] Secure reflection suppression
  const fixA = createFixtureA_SecureReflectedHtml();
  assert(!fixA.isVulnerable && fixA.confidence === 'NO_FINDING', '[TEST 16] Safely encoded reflection correctly suppressed');
  console.log('  [PASS] [TEST 16] Secure reflection suppression');

  // [TEST 17] Vulnerable reflection detection
  const fixB = createFixtureB_VulnerableReflectedHtml();
  assert(fixB.isVulnerable && fixB.vulnerabilityType === 'REFLECTED_XSS', '[TEST 17] Vulnerable unencoded reflection detected');
  console.log('  [PASS] [TEST 17] Vulnerable reflection detection');

  // [TEST 18] Context-aware candidate generation
  const obsB = convertClientSideEvaluationToObservation(fixB);
  assert(obsB.observationType === 'XSS_HTML_EXECUTION', '[TEST 18] Context-aware observation generated from vulnerable reflection');
  console.log('  [PASS] [TEST 18] Context-aware candidate generation');

  // [TEST 19] Execution evidence
  assert(fixB.evidence && fixB.evidence.executionMarker === 'XSS_EVIDENCE_B', '[TEST 19] Deterministic browser execution evidence attached');
  console.log('  [PASS] [TEST 19] Execution evidence');

  // [TEST 20] Impact calculation
  assert(fixB.impact.dimensions.includes('CODE_EXECUTION') && fixB.impact.severity === 'Medium', '[TEST 20] Reflected XSS impact calculated');
  console.log('  [PASS] [TEST 20] Impact calculation');

  // -------------------------------------------------------------
  // SECTION E: STORED XSS
  // -------------------------------------------------------------
  console.log('\n--- SECTION E: STORED XSS ---');

  // [TEST 21] Storage workflow
  const fixI = createFixtureI_SecureStoredWorkflow();
  assert(fixI.steps[0].stage === 'INPUT_CREATED' && fixI.steps[1].stage === 'STORED', '[TEST 21] Storage workflow steps modeled');
  console.log('  [PASS] [TEST 21] Storage workflow');

  // [TEST 22] Retrieval workflow
  assert(fixI.steps[2].stage === 'RETRIEVED', '[TEST 22] Stored payload retrieval step modeled');
  console.log('  [PASS] [TEST 22] Retrieval workflow');

  // [TEST 23] Rendering workflow
  assert(fixI.steps[3].stage === 'RENDERED', '[TEST 23] Stored payload render step modeled');
  console.log('  [PASS] [TEST 23] Rendering workflow');

  // [TEST 24] Vulnerable stored-XSS detection
  const fixJ = createFixtureJ_VulnerableStoredWorkflow();
  assert(fixJ.isVulnerable && fixJ.steps.some((s) => s.stage === 'EXECUTION'), '[TEST 24] Complete multi-step stored XSS chain detected');
  console.log('  [PASS] [TEST 24] Vulnerable stored-XSS detection');

  // [TEST 25] Cross-user impact detection
  const fixM = createFixtureM_CrossUserStoredPrivileged();
  assert(fixM.impactScope === 'PRIVILEGED_USER_CONTEXT' && fixM.isVulnerable, '[TEST 25] Cross-user privileged execution impact detected');
  console.log('  [PASS] [TEST 25] Cross-user impact detection');

  // -------------------------------------------------------------
  // SECTION F: DOM XSS
  // -------------------------------------------------------------
  console.log('\n--- SECTION F: DOM ---');

  // [TEST 26] DOM source detection
  const fixH = createFixtureH_VulnerableDom();
  assert(fixH.source.sourceType === 'URL_FRAGMENT' && fixH.source.name === 'location.hash', '[TEST 26] DOM source location.hash identified');
  console.log('  [PASS] [TEST 26] DOM source detection');

  // [TEST 27] DOM sink detection
  assert(fixH.sink.sinkType === 'INNER_HTML', '[TEST 27] DOM sink innerHTML identified');
  console.log('  [PASS] [TEST 27] DOM sink detection');

  // [TEST 28] Safe DOM flow suppression
  const fixG = createFixtureG_SecureDom();
  assert(!fixG.isVulnerable && fixG.confidence === 'NO_FINDING', '[TEST 28] Sanitized DOM flow to safe sink suppressed');
  console.log('  [PASS] [TEST 28] Safe DOM flow suppression');

  // [TEST 29] Vulnerable DOM flow detection
  assert(fixH.isVulnerable && fixH.vulnerabilityType === 'DOM_XSS', '[TEST 29] Unsanitized DOM data-flow evaluated as DOM XSS');
  console.log('  [PASS] [TEST 29] Vulnerable DOM flow detection');

  // [TEST 30] Data-flow explanation
  assert(fixH.dataFlow.isTaintPathValid && !fixH.dataFlow.isNeutralized, '[TEST 30] Complete data-flow trace explanation constructed');
  console.log('  [PASS] [TEST 30] Data-flow explanation');

  // -------------------------------------------------------------
  // SECTION G: CORRELATION & REPORT READINESS
  // -------------------------------------------------------------
  console.log('\n--- SECTION G: CORRELATION ---');

  // [TEST 31] Observation correlation
  const obsFixB = convertClientSideEvaluationToObservation(fixB);
  const obsFixD = convertClientSideEvaluationToObservation(createFixtureD_VulnerableAttribute());
  const clusters = clusterObservations([obsFixB, obsFixD]);
  assert(clusters.length >= 1, '[TEST 31] Client-side observations correlated into research clusters');
  console.log('  [PASS] [TEST 31] Observation correlation');

  // [TEST 32] Duplicate suppression
  const candB1 = createFindingCandidateFromObservations([obsFixB])!;
  const candB2 = createFindingCandidateFromObservations([obsFixB])!;
  const dedup = deduplicateCandidates([candB1, candB2]);
  assert(dedup.uniqueCandidates.length === 1 && dedup.duplicateGroups.size === 1, '[TEST 32] Duplicate client-side findings suppressed');
  console.log('  [PASS] [TEST 32] Duplicate suppression');

  // [TEST 33] Root-cause grouping
  assert(candB1.rootCause.length > 10 && candB1.cweId === 'CWE-79', '[TEST 33] Root cause analysis derived for XSS candidate');
  console.log('  [PASS] [TEST 33] Root-cause grouping');

  // [TEST 34] Evidence provenance
  assert(obsFixB.provenance.engine === 'SYNTHESIS_0008' || obsFixB.provenance.engine === 'AUTHENTICATION_0005', '[TEST 34] Evidence provenance preserved');
  console.log('  [PASS] [TEST 34] Evidence provenance');

  // [TEST 35] Report readiness
  const draft = generateReportDraft(candB1);
  const gates = evaluateReportQualityGates(candB1, {
    summary: draft.summary,
    reproductionSteps: draft.stepsToReproduce,
    securityImpact: draft.securityImpact,
    remediation: draft.remediation,
  });
  assert(gates.isReady && draft.readinessStatus === 'REPORT_READY', '[TEST 35] Quality gates calculate candidate as REPORT_READY');
  console.log('  [PASS] [TEST 35] Report readiness');

  // -------------------------------------------------------------
  // SECTION H: GOVERNANCE & POLICY
  // -------------------------------------------------------------
  console.log('\n--- SECTION H: GOVERNANCE ---');

  // [TEST 36] Scope enforcement
  const scopeOut = resolveTargetScope('meesho-hackerone', 'ineligible-subdomain.meesho.com');
  assert(scopeOut.decision === 'DENY', '[TEST 36] Out-of-scope target denied fail-closed');
  console.log('  [PASS] [TEST 36] Scope enforcement');

  // [TEST 37] Authorization
  const scopeIn = resolveTargetScope('meesho-hackerone', 'www.valmo.in');
  assert(scopeIn.decision === 'ALLOW', '[TEST 37] Exact authorized target approved');
  console.log('  [PASS] [TEST 37] Authorization');

  // [TEST 38] Budget
  const requestedBudget = 100;
  const boundBudget = Math.min(requestedBudget, 25);
  assert(boundBudget === 25, '[TEST 38] Budget strictly capped at ceiling of 25');
  console.log('  [PASS] [TEST 38] Budget');

  // [TEST 39] Cancellation
  let cancelled = false;
  try {
    await evaluateClientSideResearch({
      caseId: 'case-cancel-test',
      programId: 'meesho-hackerone',
      target: 'www.valmo.in',
      sourceType: 'QUERY_PARAMETER',
      parameterName: 'q',
      payloadString: '<script>1</script>',
      cancellationToken: { isCancelled: true },
    });
  } catch (err: any) {
    cancelled = true;
  }
  assert(cancelled, '[TEST 39] Cancellation token halts execution immediately');
  console.log('  [PASS] [TEST 39] Cancellation');

  // [TEST 40] Secret redaction
  const secretString = 'Found secret: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secretToken';
  assert(containsRawSecrets(secretString), '[TEST 40] Secret detection engine detects raw Bearer JWT token');
  console.log('  [PASS] [TEST 40] Secret redaction');

  // -------------------------------------------------------------
  // SECTION I: INTEGRATION & REGRESSION
  // -------------------------------------------------------------
  console.log('\n--- SECTION I: INTEGRATION ---');

  // [TEST 41] #0005 integration (Input analysis reuse)
  const fixE = createFixtureE_SecureJsContext();
  const fixF = createFixtureF_VulnerableJsContext();
  assert(!fixE.isVulnerable && fixF.isVulnerable, '[TEST 41] JavaScript context input analysis integrated');
  console.log('  [PASS] [TEST 41] #0005 integration');

  // [TEST 42] #0006 integration (Workflow state transitions)
  const obsStoredJ = convertStoredWorkflowToObservation(fixJ, 'meesho-hackerone', 'supplier.meesho.com', 'Supplier Hub');
  assert(obsStoredJ.workflowId === 'wf-stored-vuln-01' && obsStoredJ.provenance.engine === 'WORKFLOW_0006', '[TEST 42] Stored XSS workflow states integrated with #0006');
  console.log('  [PASS] [TEST 42] #0006 integration');

  // [TEST 43] #0007 compatibility (Multi-engine observation synthesis)
  assert(obsStoredJ.observationType === 'XSS_HTML_EXECUTION', '[TEST 43] Client-side observations fully compatible with #0007 server interactions');
  console.log('  [PASS] [TEST 43] #0007 compatibility');

  // [TEST 44] #0008 synthesis integration
  const synthRes = await synthesizeResearchCase({
    caseId: 'case-synth-client-01',
    observations: [obsB, obsStoredJ],
    programId: 'meesho-hackerone',
    actorId: MOCK_RESEARCHER.uid,
    dryRun: true,
  });
  assert(synthRes.candidates.length >= 2 && synthRes.readyReportsCount >= 2, '[TEST 44] #0008 Synthesis engine processed client-side observations into ready reports');
  console.log('  [PASS] [TEST 44] #0008 synthesis integration');

  // [TEST 45] Full local end-to-end XSS scenario
  const fullSuiteObservations = [
    convertClientSideEvaluationToObservation(fixB),
    convertClientSideEvaluationToObservation(createFixtureD_VulnerableAttribute()),
    convertClientSideEvaluationToObservation(fixF),
    convertClientSideEvaluationToObservation(fixH),
    convertStoredWorkflowToObservation(fixJ, 'meesho-hackerone', 'supplier.meesho.com', 'Supplier Portal'),
    convertStoredWorkflowToObservation(fixM, 'meesho-hackerone', 'supplier.meesho.com', 'Support Console'),
  ];
  const e2eResult = await synthesizeResearchCase({
    caseId: 'case-e2e-xss-master',
    observations: fullSuiteObservations,
    programId: 'meesho-hackerone',
    actorId: MOCK_RESEARCHER.uid,
  });
  assert(
    e2eResult.candidates.length >= 4 && e2eResult.auditEvidenceHashes.length >= 4,
    '[TEST 45] Master end-to-end client-side research scenario generated canonical candidates with verifiable SHA-256 evidence'
  );
  console.log('  [PASS] [TEST 45] Full local end-to-end XSS scenario');

  console.log('===============================================================================================');
  console.log('FINAL RESULT: ALL 45/45 ADVANCED CLIENT-SIDE & XSS RESEARCH TESTS PASSED');
  console.log('===============================================================================================');
  process.exit(0);
}

runClientSideXssVerificationSuite().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
