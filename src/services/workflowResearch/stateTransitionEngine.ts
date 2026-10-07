import {
  WorkflowDefinition,
  WorkflowStateInstance,
  WorkflowAction,
  WorkflowTransitionEvaluation,
  WorkflowTransitionRecord,
  WorkflowSecurityInvariant,
} from '../../types/workflowResearch.ts';
import { findAllowedTransition, getInvariantsForTransition } from './workflowDefinitionService.ts';
import { evaluateInvariant } from './invariantEngine.ts';

export function evaluateStateTransition(
  workflowDef: WorkflowDefinition,
  currentState: WorkflowStateInstance,
  action: WorkflowAction,
  history: WorkflowTransitionRecord[] = []
): WorkflowTransitionEvaluation {
  const transitionRule = findAllowedTransition(workflowDef, currentState.currentState, action.actionId);
  const isValidTransition = !!transitionRule;
  const targetState = transitionRule ? transitionRule.toState : action.toState;

  // Determine authorized status
  let isAuthorized = true;
  if (action.isOwnerOnly && currentState.resource.ownerActorId !== currentState.actor.actorId) {
    isAuthorized = false;
  }
  if (action.isPrivileged && currentState.actor.role !== 'ADMIN_USER' && currentState.actor.role !== 'PRIVILEGED_USER') {
    isAuthorized = false;
  }
  if (transitionRule?.allowedRoles && !transitionRule.allowedRoles.includes(currentState.actor.role) && currentState.actor.role !== 'ADMIN_USER') {
    isAuthorized = false;
  }

  // Get invariants
  const transitionInvariants: WorkflowSecurityInvariant[] = transitionRule
    ? getInvariantsForTransition(workflowDef, transitionRule)
    : workflowDef.invariants.filter(i => 
        (i.enforceAtStates && i.enforceAtStates.includes(currentState.currentState)) ||
        (i.enforceAtActions && i.enforceAtActions.includes(action.actionId))
      );

  const violatedInvariants: { invariantId: string; type: any; reason: string }[] = [];

  for (const inv of transitionInvariants) {
    const res = evaluateInvariant(inv, {
      currentState,
      targetState,
      action,
      actor: currentState.actor,
      resource: currentState.resource,
      history,
    });
    if (!res.passed) {
      violatedInvariants.push({
        invariantId: inv.invariantId,
        type: inv.type,
        reason: res.reason || 'Invariant evaluation failed',
      });
    }
  }

  const invariantsPassed = violatedInvariants.length === 0;
  const expectedOutcome = (isValidTransition && isAuthorized && invariantsPassed) ? 'ALLOW' : 'DENY';
  
  return {
    actionId: action.actionId,
    fromState: currentState.currentState,
    toState: targetState,
    actor: currentState.actor,
    resource: currentState.resource,
    isValidTransition,
    isAuthorized,
    invariantsPassed,
    violatedInvariants,
    expectedOutcome,
    observedOutcome: 'ALLOW', // To be updated upon observation comparison
    status: expectedOutcome === 'ALLOW' ? 'CONFORMANT' : 'SUPPRESSED',
  };
}

export function applyStateTransition(
  workflowDef: WorkflowDefinition,
  currentState: WorkflowStateInstance,
  action: WorkflowAction,
  targetStateOverride?: string
): WorkflowStateInstance {
  const transitionRule = findAllowedTransition(workflowDef, currentState.currentState, action.actionId);
  const nextState = targetStateOverride || (transitionRule ? transitionRule.toState : action.toState);
  const isTerminal = (workflowDef.terminalStates || []).includes(nextState);

  const updatedResource = {
    ...currentState.resource,
    currentStatus: nextState,
    attributes: {
      ...currentState.resource.attributes,
      ...(action.parameters || {}),
    },
  };

  return {
    ...currentState,
    stateInstanceId: `state-${workflowDef.workflowId}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    currentState: nextState,
    resource: updatedResource,
    isTerminal,
    stepNumber: currentState.stepNumber + 1,
  };
}
