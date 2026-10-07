import {
  WorkflowDefinition,
  WorkflowAction,
  WorkflowTransitionRule,
  WorkflowSecurityInvariant,
} from '../../types/workflowResearch.ts';

const workflowRegistry = new Map<string, WorkflowDefinition>();

export function registerWorkflowDefinition(def: WorkflowDefinition): WorkflowDefinition {
  if (!def.workflowId || !def.workflowName || !def.initialState) {
    throw new Error('Invalid workflow definition: missing required fields');
  }
  if (!def.states || !def.states.includes(def.initialState)) {
    throw new Error(`Invalid workflow definition: initial state '${def.initialState}' not in declared states`);
  }
  // Validate terminal states
  if (def.terminalStates) {
    for (const term of def.terminalStates) {
      if (!def.states.includes(term)) {
        throw new Error(`Invalid workflow definition: terminal state '${term}' not in declared states`);
      }
    }
  }

  workflowRegistry.set(def.workflowId, JSON.parse(JSON.stringify(def)));
  return def;
}

export function getWorkflowDefinition(workflowId: string): WorkflowDefinition | undefined {
  const def = workflowRegistry.get(workflowId);
  return def ? JSON.parse(JSON.stringify(def)) : undefined;
}

export function listWorkflowDefinitions(): WorkflowDefinition[] {
  return Array.from(workflowRegistry.values()).map(d => JSON.parse(JSON.stringify(d)));
}

export function clearWorkflowRegistry(): void {
  workflowRegistry.clear();
}

export function findAllowedTransition(
  def: WorkflowDefinition,
  fromState: string,
  actionId: string
): WorkflowTransitionRule | undefined {
  return def.transitions.find(t => t.fromState === fromState && t.actionId === actionId);
}

export function isTerminalState(def: WorkflowDefinition, state: string): boolean {
  return (def.terminalStates || []).includes(state);
}

export function getActionDefinition(def: WorkflowDefinition, actionId: string): WorkflowAction | undefined {
  return def.actions.find(a => a.actionId === actionId);
}

export function getInvariantsForTransition(
  def: WorkflowDefinition,
  transition: WorkflowTransitionRule
): WorkflowSecurityInvariant[] {
  const invariantIds = new Set(transition.invariants || []);
  return def.invariants.filter(i => invariantIds.has(i.invariantId));
}
