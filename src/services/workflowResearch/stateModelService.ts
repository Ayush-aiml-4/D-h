import {
  WorkflowActor,
  WorkflowResource,
  WorkflowStateInstance,
  WorkflowDefinition,
} from '../../types/workflowResearch.ts';

export function createWorkflowStateInstance(
  workflowDef: WorkflowDefinition,
  actor: WorkflowActor,
  resource: WorkflowResource,
  customState?: string,
  stepNumber: number = 0
): WorkflowStateInstance {
  const state = customState || workflowDef.initialState;
  const isTerminal = (workflowDef.terminalStates || []).includes(state);

  return {
    stateInstanceId: `state-${workflowDef.workflowId}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    workflowId: workflowDef.workflowId,
    currentState: state,
    actor: {
      actorId: actor.actorId,
      actorLabel: actor.actorLabel,
      role: actor.role,
      credentialReference: actor.credentialReference,
      sessionReference: actor.sessionReference,
    },
    resource: {
      resourceId: resource.resourceId,
      resourceType: resource.resourceType,
      ownerActorId: resource.ownerActorId,
      initialStatus: resource.initialStatus,
      currentStatus: resource.currentStatus,
      attributes: JSON.parse(JSON.stringify(resource.attributes || {})),
    },
    isTerminal,
    stepNumber,
    data: {},
  };
}

export function validateActorIntegrity(actor: WorkflowActor): { valid: boolean; error?: string } {
  if (!actor.actorId || !actor.role || !actor.credentialReference) {
    return { valid: false, error: 'Actor missing required fields' };
  }
  // Enforce zero raw secrets in credential reference
  if (
    actor.credentialReference.startsWith('Bearer ') ||
    actor.credentialReference.includes('eyJ') ||
    actor.credentialReference.length > 100 ||
    /password|secret|key/i.test(actor.credentialReference) && !actor.credentialReference.startsWith('cred-ref-')
  ) {
    return { valid: false, error: 'Actor contains raw secret instead of safe indirect reference' };
  }
  return { valid: true };
}

export function serializeStateSnapshot(state: WorkflowStateInstance): string {
  return JSON.stringify({
    workflowId: state.workflowId,
    currentState: state.currentState,
    actorId: state.actor.actorId,
    role: state.actor.role,
    resourceId: state.resource.resourceId,
    ownerActorId: state.resource.ownerActorId,
    attributes: state.resource.attributes,
    stepNumber: state.stepNumber,
  });
}
