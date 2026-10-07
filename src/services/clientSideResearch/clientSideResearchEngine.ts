import {
  ClientSideResearchEvaluation,
  StoredXssWorkflowEvaluation,
  ClientSideContextType,
  ClientSideSourceType,
  TransformationStep,
} from '../../types/clientSideResearch.ts';
import { ResearchObservation } from '../../types/researchSynthesis.ts';
import { createObservation } from '../researchSynthesis/observationModelService.ts';
import { resolveTargetScope, evaluateFindingEligibility } from '../programProfileService.ts';
import { evaluatePolicy } from '../policyEngine.ts';
import { AuthUser } from '../../middleware/auth.ts';
import { recordAuditEvent } from '../auditService.ts';
import { BadRequestError } from '../../utils/errors.ts';
import { determineInputContext } from './inputContextAnalyzer.ts';
import { resolveSinkDefinition } from './outputContextAnalyzer.ts';
import { createSourceDefinition, buildDataFlowTrace } from './sourceSinkAnalyzer.ts';
import { evaluateTransformationStep, classifyEncoding } from './transformationAnalyzer.ts';
import { createBrowserExecutionEvidence } from './browserEvidenceModel.ts';
import { evaluateXssDifferential } from './xssDifferentialEngine.ts';
import { evaluateClientSideImpact, evaluateClientSideConfidence } from './xssImpactConfidenceEngine.ts';

export interface CancellationToken {
  isCancelled: boolean;
}

export interface ClientSideResearchRequest {
  caseId: string;
  programId: string;
  target: string;
  asset?: string;
  sourceType: ClientSideSourceType;
  parameterName: string;
  payloadString: string;
  templateSnippet?: string;
  sinkName?: string;
  transformations?: Array<{ type: string; output: string }>;
  actorContext?: {
    researcherId: string;
    accountIdentifier?: string;
    accountRole?: string;
  };
  dryRun?: boolean;
  budgetLimit?: number;
  cancellationToken?: CancellationToken;
}

/**
 * Converts a client-side evaluation into a standard ResearchObservation for #0008 synthesis.
 */
export function convertClientSideEvaluationToObservation(
  evaluation: ClientSideResearchEvaluation
): ResearchObservation {
  const observationType = evaluation.isVulnerable ? 'XSS_HTML_EXECUTION' : 'PARAMETER_REFLECTION';
  const confidence = evaluation.confidence;

  const impactIndicators = evaluation.impact.dimensions.map((d) => `IMPACT_${d}`);

  const evidenceReferences = evaluation.evidence ? [evaluation.evidence.evidenceId] : [];

  return createObservation({
    researchCaseId: evaluation.researchCaseId,
    programId: evaluation.programId,
    target: evaluation.target,
    asset: evaluation.asset,
    capability: `CLIENT_SIDE_${evaluation.vulnerabilityType}`,
    actorContext: {
      researcherId: evaluation.source.actorIdentifier || 'researcher-001',
      accountIdentifier: evaluation.source.actorIdentifier,
      accountRole: 'STANDARD_USER',
    },
    observationType,
    expectedBehavior: `Expected application to enforce context-aware encoding in ${evaluation.context} context`,
    observedBehavior: evaluation.rootCause,
    impactIndicators,
    evidenceReferences,
    confidence,
    provenance: {
      engine: 'SYNTHESIS_0008',
      fixtureId: evaluation.evaluationId,
      stepNumber: 1,
    },
    resourceIdentifier: evaluation.source.name,
    metadata: {
      vulnerabilityType: evaluation.vulnerabilityType,
      context: evaluation.context,
      sink: evaluation.sink.sinkType,
      encoding: evaluation.encodingClassification,
      sanitizer: evaluation.sanitizerStatus,
      evidenceHash: evaluation.evidence?.evidenceHash,
    },
  });
}

/**
 * Converts a stored XSS workflow evaluation into a standard ResearchObservation.
 */
export function convertStoredWorkflowToObservation(
  workflow: StoredXssWorkflowEvaluation,
  programId: string,
  target: string,
  asset: string
): ResearchObservation {
  const lastStep = workflow.steps[workflow.steps.length - 1];

  return createObservation({
    researchCaseId: workflow.researchCaseId,
    programId,
    target,
    asset,
    capability: 'CLIENT_SIDE_STORED_XSS',
    actorContext: {
      researcherId: workflow.attackerActor,
      accountIdentifier: workflow.attackerActor,
      accountRole: 'SUPPLIER',
    },
    observationType: workflow.isVulnerable ? 'XSS_HTML_EXECUTION' : 'BUSINESS_INVARIANT_VIOLATION',
    expectedBehavior: 'Stored user input must be sanitized and HTML-encoded before rendering across user sessions',
    observedBehavior: workflow.rootCause,
    impactIndicators: [
      'IMPACT_CODE_EXECUTION',
      'IMPACT_DATA_INTEGRITY',
      'IMPACT_CROSS_USER_IMPACT',
      'IMPACT_ACCOUNT_IMPACT',
    ],
    evidenceReferences: [workflow.evidence.evidenceId],
    confidence: workflow.confidence,
    provenance: {
      engine: 'WORKFLOW_0006',
      fixtureId: workflow.workflowId,
      stepNumber: workflow.steps.length,
    },
    resourceIdentifier: 'stored-entity-description',
    workflowId: workflow.workflowId,
    metadata: {
      vulnerabilityType: 'STORED_XSS',
      impactScope: workflow.impactScope,
      stepsCount: workflow.steps.length,
      evidenceHash: workflow.evidence.evidenceHash,
    },
  });
}

/**
 * Master client-side research evaluator.
 */
export async function evaluateClientSideResearch(
  request: ClientSideResearchRequest
): Promise<ClientSideResearchEvaluation> {
  // 1. Cancellation check
  if (request.cancellationToken?.isCancelled) {
    throw new BadRequestError('Client-side research operation cancelled by token');
  }

  // 2. Budget bounding
  const maxBudget = 25;
  const budget = Math.min(request.budgetLimit || 10, maxBudget);

  // 3. Scope Gate via Program Profile
  const scopeDecision = resolveTargetScope(request.programId, request.target);
  if (scopeDecision.decision === 'DENY') {
    await recordAuditEvent({
      action: 'POLICY_EVALUATE_BLOCK',
      userId: request.actorContext?.researcherId || 'researcher-001',
      entityType: 'POLICY',
      entityId: request.programId,
      success: false,
      metadata: { target: request.target, reason: scopeDecision.reason },
    });
    throw new BadRequestError(`Target '${request.target}' is outside authorized program scope: ${scopeDecision.reason}`);
  }

  // 4. Policy Gate on Prohibited Operations
  const mockUser: AuthUser = {
    uid: request.actorContext?.researcherId || 'researcher-001',
    email: request.actorContext?.accountIdentifier || 'researcher@example.com',
    name: 'Researcher',
    role: (request.actorContext?.accountRole as any) || 'RESEARCHER',
  };
  const policyResult = await evaluatePolicy(mockUser, {
    programId: request.programId,
    target: request.target,
    operation: 'READ_ONLY_RESEARCH',
  });
  if (policyResult.decision === 'BLOCK') {
    throw new BadRequestError(`Policy engine denied execution: ${policyResult.reason}`);
  }

  // 5. Context determination
  const template = request.templateSnippet || `<div>${request.payloadString}</div>`;
  const context = determineInputContext(template, request.payloadString);

  // 6. Source definition
  const source = createSourceDefinition({
    sourceType: request.sourceType,
    name: request.parameterName,
    value: request.payloadString,
    actorIdentifier: request.actorContext?.accountIdentifier,
  });

  // 7. Sink definition
  const sink = resolveSinkDefinition(request.sinkName || 'innerHTML');

  // 8. Transformations
  const steps: TransformationStep[] = [];
  if (request.transformations && request.transformations.length > 0) {
    request.transformations.forEach((t, idx) => {
      const step = evaluateTransformationStep(
        idx + 1,
        t.type as any,
        source.value,
        t.output,
        context
      );
      steps.push(step);
    });
  } else {
    steps.push(evaluateTransformationStep(1, 'NONE', source.value, source.value, context));
  }

  const renderedOutput = steps[steps.length - 1]?.outputSnippet || source.value;
  const dataFlow = buildDataFlowTrace(source, steps, sink, context, renderedOutput);

  // 9. Encoding and Sanitization Classification
  const { classification, sanitizerStatus, isProperlyNeutralized } = classifyEncoding(
    source.value,
    renderedOutput,
    context,
    steps
  );

  // 10. Differential Analysis
  const differential = evaluateXssDifferential(source.value, renderedOutput, context, classification);

  const isVulnerable =
    !isProperlyNeutralized &&
    sink.isDangerous &&
    differential.isExecutableContext &&
    differential.hasBreakout;

  const vulnerabilityType = isVulnerable
    ? 'REFLECTED_XSS'
    : isProperlyNeutralized
    ? 'SAFE_TRANSFORMATION'
    : 'BENIGN_REFLECTION';

  // 11. Evidence generation
  let evidence;
  if (isVulnerable) {
    evidence = createBrowserExecutionEvidence({
      fixtureId: `exec-${Date.now()}`,
      correlationId: `corr-${request.caseId}`,
      sourceMarker: source.value,
      sink: sink.sinkType,
      executionMarker: 'EVIDENCE_CONFIRMED',
      executedContext: context,
    });
  }

  // 12. Impact calculation
  const impact = evaluateClientSideImpact({
    vulnerabilityType,
    isVulnerable,
    context,
    evidence,
    dataFlow,
  });

  // 13. Confidence evaluation
  const { confidence, reasoning } = evaluateClientSideConfidence({
    isVulnerable,
    sourceIdentified: true,
    dataFlowEstablished: dataFlow.isTaintPathValid,
    unsafeSinkOrContextEstablished: sink.isDangerous && differential.isExecutableContext,
    executionEvidenceEstablished: Boolean(evidence),
    impactEstablished: impact.hasSufficientEvidence,
    isDeterministic: true,
  });

  const evaluationId = `eval-client-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const rootCause = isVulnerable
    ? `Unencoded source '${source.name}' reached dangerous sink '${sink.apiName}' in ${context} context, leading to arbitrary JavaScript execution.`
    : `Input parameter '${source.name}' is safely handled in ${context} context (${classification}).`;

  const evaluation: ClientSideResearchEvaluation = {
    evaluationId,
    researchCaseId: request.caseId,
    programId: request.programId,
    target: request.target,
    asset: request.asset || request.target,
    vulnerabilityType,
    isVulnerable,
    context,
    source,
    sink,
    dataFlow,
    encodingClassification: classification,
    sanitizerStatus,
    evidence,
    impact,
    confidence,
    confidenceReasoning: reasoning,
    rootCause,
    cweId: 'CWE-79',
    remediation: 'Apply context-appropriate HTML entity or attribute encoding, or utilize safe textContent / DOMPurify sanitization.',
  };

  // Convert to observation
  evaluation.observation = convertClientSideEvaluationToObservation(evaluation);

  // 14. Audit logging
  await recordAuditEvent({
    action: request.dryRun ? 'CLIENT_SIDE_RESEARCH_DRY_RUN' : 'CLIENT_SIDE_RESEARCH_EXECUTED',
    userId: request.actorContext?.researcherId || 'researcher-001',
    entityType: 'CASE',
    entityId: request.caseId,
    success: true,
    metadata: {
      vulnerabilityType,
      isVulnerable,
      confidence,
      evidenceHash: evidence?.evidenceHash,
      dryRun: Boolean(request.dryRun),
      budgetUsed: budget,
    },
  });

  return evaluation;
}
