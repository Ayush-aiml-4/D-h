import {
  WorkflowDefinition,
  WorkflowTrace,
  WorkflowDifferentialResult,
  WorkflowSecurityInvariant,
} from '../../types/workflowResearch.ts';

export function compareWorkflowTraces(
  workflowDef: WorkflowDefinition,
  baselineTrace: WorkflowTrace,
  evaluatedTrace: WorkflowTrace
): WorkflowDifferentialResult {
  let hasStateDrift = false;
  let hasUnexpectedTransition = false;
  let hasAuthorizationBypass = false;
  let hasInvariantBreach = false;
  let hasReplayViolation = false;
  let hasConcurrencyViolation = false;
  const breachedInvariants: WorkflowSecurityInvariant[] = [];
  const explanationParts: string[] = [];

  const maxSteps = Math.max(baselineTrace.steps.length, evaluatedTrace.steps.length);

  for (let i = 0; i < maxSteps; i++) {
    const baseStep = baselineTrace.steps[i];
    const evalStep = evaluatedTrace.steps[i];

    if (!evalStep) break;

    // Check unexpected transition (e.g. CREATED -> COMPLETED directly when transitions forbid it)
    const allowed = workflowDef.transitions.some(
      t => t.fromState === evalStep.fromState && t.actionId === evalStep.action.actionId && t.toState === evalStep.toState
    );

    if (!allowed && evalStep.fromState !== evalStep.toState) {
      hasUnexpectedTransition = true;
      explanationParts.push(
        `Step ${evalStep.stepNumber}: Unexpected transition '${evalStep.fromState}' -> '${evalStep.toState}' via action '${evalStep.action.actionId}'`
      );
    }

    if (baseStep && baseStep.stateAfter !== evalStep.stateAfter) {
      hasStateDrift = true;
      explanationParts.push(
        `Step ${evalStep.stepNumber}: State drift detected (Expected '${baseStep.stateAfter}', Observed '${evalStep.stateAfter}')`
      );
    }

    if (evalStep.action.isPrivileged && evalStep.actor.role !== 'ADMIN_USER' && evalStep.actor.role !== 'PRIVILEGED_USER') {
      if (evalStep.responseStatus >= 200 && evalStep.responseStatus < 300) {
        hasAuthorizationBypass = true;
        explanationParts.push(
          `Step ${evalStep.stepNumber}: Privileged action '${evalStep.action.actionId}' succeeded for role '${evalStep.actor.role}'`
        );
      }
    }

    if (evalStep.action.isOwnerOnly && evalStep.actor.actorId !== 'acc-owner') {
      if (evalStep.responseStatus >= 200 && evalStep.responseStatus < 300) {
        hasAuthorizationBypass = true;
        explanationParts.push(
          `Step ${evalStep.stepNumber}: Owner-only action '${evalStep.action.actionId}' succeeded for peer actor '${evalStep.actor.actorId}'`
        );
      }
    }
  }

  return {
    workflowId: workflowDef.workflowId,
    scenarioName: evaluatedTrace.scenarioName,
    baselineTrace,
    evaluatedTrace,
    hasStateDrift,
    hasUnexpectedTransition,
    hasAuthorizationBypass,
    hasInvariantBreach: hasInvariantBreach || hasUnexpectedTransition || hasAuthorizationBypass,
    hasReplayViolation,
    hasConcurrencyViolation,
    breachedInvariants,
    explanation: explanationParts.length > 0 ? explanationParts.join('; ') : 'Workflow traces conformant.',
  };
}
