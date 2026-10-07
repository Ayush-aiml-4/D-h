import {
  WorkflowDefinition,
  WorkflowStateInstance,
  WorkflowAction,
  WorkflowActor,
  WorkflowTransitionEvaluation,
} from '../../types/workflowResearch.ts';
import { evaluateStateTransition } from './stateTransitionEngine.ts';

export function evaluateWorkflowAuthorization(
  workflowDef: WorkflowDefinition,
  currentState: WorkflowStateInstance,
  action: WorkflowAction,
  actingActor: WorkflowActor
): {
  isAuthorized: boolean;
  expectedOutcome: 'ALLOW' | 'DENY';
  violationReason?: string;
  authorizationType: 'OWNER_ONLY' | 'ROLE_BASED' | 'PRIVILEGE_TIER' | 'PUBLIC';
} {
  let authorizationType: 'OWNER_ONLY' | 'ROLE_BASED' | 'PRIVILEGE_TIER' | 'PUBLIC' = 'PUBLIC';

  if (action.isOwnerOnly) {
    authorizationType = 'OWNER_ONLY';
    if (currentState.resource.ownerActorId !== actingActor.actorId) {
      return {
        isAuthorized: false,
        expectedOutcome: 'DENY',
        violationReason: `Cross-account access denied: Resource '${currentState.resource.resourceId}' owned by '${currentState.resource.ownerActorId}', accessed by '${actingActor.actorId}'`,
        authorizationType,
      };
    }
  }

  if (action.isPrivileged) {
    authorizationType = 'PRIVILEGE_TIER';
    if (actingActor.role !== 'ADMIN_USER' && actingActor.role !== 'PRIVILEGED_USER') {
      return {
        isAuthorized: false,
        expectedOutcome: 'DENY',
        violationReason: `Privilege escalation blocked: Action '${action.actionId}' requires privileged role, actor role is '${actingActor.role}'`,
        authorizationType,
      };
    }
  }

  if (action.requiredRole && actingActor.role !== action.requiredRole && actingActor.role !== 'ADMIN_USER') {
    authorizationType = 'ROLE_BASED';
    return {
      isAuthorized: false,
      expectedOutcome: 'DENY',
      violationReason: `Role mismatch: Action '${action.actionId}' requires '${action.requiredRole}', actor has '${actingActor.role}'`,
      authorizationType,
    };
  }

  return {
    isAuthorized: true,
    expectedOutcome: 'ALLOW',
    authorizationType,
  };
}

export function evaluateMultiStepAuthorizationTrace(
  workflowDef: WorkflowDefinition,
  initialState: WorkflowStateInstance,
  steps: { action: WorkflowAction; actor: WorkflowActor }[]
): {
  stepsEvaluated: number;
  allAuthorized: boolean;
  firstUnauthorizedStepIndex?: number;
  unauthorizedReason?: string;
} {
  let currentState = initialState;

  for (let i = 0; i < steps.length; i++) {
    const { action, actor } = steps[i];
    const auth = evaluateWorkflowAuthorization(workflowDef, { ...currentState, actor }, action, actor);
    if (!auth.isAuthorized) {
      return {
        stepsEvaluated: i + 1,
        allAuthorized: false,
        firstUnauthorizedStepIndex: i,
        unauthorizedReason: auth.violationReason,
      };
    }
  }

  return {
    stepsEvaluated: steps.length,
    allAuthorized: true,
  };
}
