import {
  WorkflowDefinition,
  WorkflowTransitionEvaluation,
  WorkflowImpactDimension,
  WorkflowConfidenceLevel,
  WorkflowFindingCandidate,
  WorkflowSecurityInvariant,
} from '../../types/workflowResearch.ts';
import { SeverityLevel } from '../../types.ts';
import { computeEvidenceHash } from '../evidenceService.ts';

export function determineWorkflowImpactAndConfidence(
  evaluation: WorkflowTransitionEvaluation,
  workflowDef: WorkflowDefinition
): {
  impactDimensions: WorkflowImpactDimension[];
  confidence: WorkflowConfidenceLevel;
  severity: SeverityLevel;
  vulnerabilityType: string;
  cweId: string;
} {
  const impacts = new Set<WorkflowImpactDimension>();

  if (!evaluation.isAuthorized) {
    impacts.add('AUTHORIZATION');
    impacts.add('ACCOUNT_BOUNDARY');
  }

  for (const inv of evaluation.violatedInvariants) {
    switch (inv.type) {
      case 'OWNERSHIP_INVARIANT':
        impacts.add('RESOURCE_OWNERSHIP');
        impacts.add('AUTHORIZATION');
        break;
      case 'TERMINAL_STATE_INVARIANT':
      case 'STATUS_INVARIANT':
      case 'STATE_INVARIANT':
      case 'SEQUENCE_INVARIANT':
        impacts.add('STATE_INTEGRITY');
        impacts.add('WORKFLOW_CONTROL');
        break;
      case 'SINGLE_USE_INVARIANT':
      case 'QUANTITY_INVARIANT':
      case 'BUSINESS_RULE_INVARIANT':
      case 'CONCURRENCY_INVARIANT':
        impacts.add('FINANCIAL');
        impacts.add('INTEGRITY');
        break;
      case 'AUTHORIZATION_INVARIANT':
        impacts.add('AUTHORIZATION');
        break;
    }
  }

  const impactList = Array.from(impacts);

  // Confidence mapping
  let confidence: WorkflowConfidenceLevel = 'NO_FINDING';
  if (evaluation.status === 'VIOLATION') {
    if (evaluation.violatedInvariants.length > 0 || !evaluation.isValidTransition || !evaluation.isAuthorized) {
      confidence = 'HIGH_CONFIDENCE';
    } else {
      confidence = 'MEDIUM_CONFIDENCE';
    }
  } else if (evaluation.status === 'SUPPRESSED') {
    confidence = 'NO_FINDING';
  } else {
    confidence = 'OBSERVATION';
  }

  // CWE and Severity mapping
  let cweId = 'CWE-840'; // Business Logic Errors
  let vulnerabilityType = 'BUSINESS_LOGIC_STATE_TRANSITION_VIOLATION';
  let severity: SeverityLevel = 'Medium';

  if (impactList.includes('RESOURCE_OWNERSHIP') || impactList.includes('AUTHORIZATION')) {
    cweId = 'CWE-639';
    vulnerabilityType = 'WORKFLOW_AUTHORIZATION_BYPASS';
    severity = 'High';
  } else if (impactList.includes('FINANCIAL')) {
    cweId = 'CWE-840';
    vulnerabilityType = 'BUSINESS_LOGIC_FINANCIAL_INVARIANT_VIOLATION';
    severity = 'High';
  } else if (impactList.includes('WORKFLOW_CONTROL')) {
    cweId = 'CWE-841'; // Improper Enforcement of Behavioral Workflow
    severity = 'Medium';
    vulnerabilityType = 'WORKFLOW_SEQUENCE_BYPASS';
  }

  return {
    impactDimensions: impactList,
    confidence,
    severity,
    vulnerabilityType,
    cweId,
  };
}

export function createWorkflowFindingCandidate(
  researchCaseId: string,
  researchExecutionId: string,
  workflowDef: WorkflowDefinition,
  evaluation: WorkflowTransitionEvaluation,
  stepNumber: number,
  observedResponseStatus: number,
  observedResponseBody: any
): WorkflowFindingCandidate {
  const { impactDimensions, confidence, severity, vulnerabilityType, cweId } =
    determineWorkflowImpactAndConfidence(evaluation, workflowDef);

  const primaryViolation = evaluation.violatedInvariants[0]?.reason || 'Forbidden workflow transition accepted';

  const reproductionSteps = [
    `1. Establish workflow research context for target '${workflowDef.target}' under program '${workflowDef.programId}'.`,
    `2. Advance workflow '${workflowDef.workflowId}' to state '${evaluation.fromState}'.`,
    `3. Using actor '${evaluation.actor.actorId}' (Role: ${evaluation.actor.role}), invoke action '${evaluation.actionId}'.`,
    `4. Observe that server accepted the transition to '${evaluation.toState}' (HTTP ${observedResponseStatus}) in violation of security invariant.`,
  ];

  const remediation = [
    `Enforce server-side workflow state machine validation before applying transition '${evaluation.actionId}'.`,
    `Verify that current resource state is an explicit member of allowed origin states for '${evaluation.actionId}'.`,
    `Enforce atomic server-side authorization and ownership checks at every step of multi-step operations.`,
  ].join(' ');

  const evidenceSummary = {
    workflowId: workflowDef.workflowId,
    stepNumber,
    actor: evaluation.actor.actorId,
    fromState: evaluation.fromState,
    action: evaluation.actionId,
    toState: evaluation.toState,
    violatedInvariant: evaluation.violatedInvariants.map(i => i.type).join(', ') || 'INVALID_TRANSITION',
    observedBehavior: `HTTP ${observedResponseStatus}: Server accepted transition (${primaryViolation})`,
  };

  const evidenceHash = computeEvidenceHash(
    evidenceSummary,
    'active-workflow-state-validation',
    workflowDef.target
  );

  return {
    candidateId: `cand-wf-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    researchCaseId,
    researchExecutionId,
    workflowId: workflowDef.workflowId,
    target: workflowDef.target,
    vulnerabilityType,
    cweId,
    severity,
    confidence,
    impactDimensions,
    title: `[${vulnerabilityType}] on ${workflowDef.workflowName} (${evaluation.fromState} -> ${evaluation.toState})`,
    description: `Workflow state transition security invariant breached during step ${stepNumber}: ${primaryViolation}`,
    reproductionSteps,
    remediation,
    evidenceSummary,
    evidenceHash,
    createdAt: new Date().toISOString(),
  };
}
