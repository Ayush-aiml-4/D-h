import {
  WorkflowSecurityInvariant,
  WorkflowInvariantContext,
  WorkflowInvariantType,
} from '../../types/workflowResearch.ts';

export function evaluateInvariant(
  invariant: WorkflowSecurityInvariant,
  context: WorkflowInvariantContext
): { passed: boolean; reason?: string; impact?: string } {
  // If custom rule function is provided, evaluate it first
  if (invariant.ruleFn) {
    const res = invariant.ruleFn(context);
    return {
      passed: res.valid,
      reason: res.reason,
      impact: res.impact,
    };
  }

  const { currentState, action, actor, resource, history = [] } = context;

  switch (invariant.type) {
    case 'OWNERSHIP_INVARIANT': {
      if (action.isOwnerOnly && resource.ownerActorId !== actor.actorId) {
        return {
          passed: false,
          reason: `Actor '${actor.actorId}' is not the owner of resource '${resource.resourceId}' (Owner: '${resource.ownerActorId}')`,
          impact: 'RESOURCE_OWNERSHIP',
        };
      }
      return { passed: true };
    }

    case 'TERMINAL_STATE_INVARIANT':
    case 'STATUS_INVARIANT': {
      if (currentState.isTerminal) {
        return {
          passed: false,
          reason: `Cannot perform action '${action.actionId}' on resource in terminal state '${currentState.currentState}'`,
          impact: 'STATE_INTEGRITY',
        };
      }
      return { passed: true };
    }

    case 'AUTHORIZATION_INVARIANT': {
      if (action.isPrivileged && actor.role !== 'ADMIN_USER' && actor.role !== 'PRIVILEGED_USER') {
        return {
          passed: false,
          reason: `Actor role '${actor.role}' is not authorized for privileged action '${action.actionId}'`,
          impact: 'AUTHORIZATION',
        };
      }
      if (action.requiredRole && actor.role !== action.requiredRole && actor.role !== 'ADMIN_USER') {
        return {
          passed: false,
          reason: `Actor role '${actor.role}' does not match required role '${action.requiredRole}'`,
          impact: 'AUTHORIZATION',
        };
      }
      return { passed: true };
    }

    case 'SINGLE_USE_INVARIANT': {
      if (action.isSingleUse || action.replayPolicy === 'REPLAY_REJECTED') {
        const previousSuccessfulExecutions = history.filter(
          h => h.actionId === action.actionId && h.status === 'SUCCESS'
        );
        if (previousSuccessfulExecutions.length > 0 || resource.currentStatus === 'CONSUMED') {
          return {
            passed: false,
            reason: `Action '${action.actionId}' is single-use and has already been executed/consumed`,
            impact: 'FINANCIAL',
          };
        }
      }
      return { passed: true };
    }

    case 'QUANTITY_INVARIANT': {
      const amount = resource.attributes?.amount ?? action.parameters?.amount;
      const quantity = resource.attributes?.quantity ?? action.parameters?.quantity;
      
      if (amount !== undefined && (amount < 0 || isNaN(amount))) {
        return {
          passed: false,
          reason: `Amount '${amount}' violates positive quantity invariant`,
          impact: 'FINANCIAL',
        };
      }
      if (quantity !== undefined && (quantity <= 0 || !Number.isInteger(quantity))) {
        return {
          passed: false,
          reason: `Quantity '${quantity}' must be a positive integer`,
          impact: 'FINANCIAL',
        };
      }
      return { passed: true };
    }

    case 'STATE_INVARIANT': {
      if (!action.fromStates.includes(currentState.currentState)) {
        return {
          passed: false,
          reason: `Action '${action.actionId}' cannot be executed from state '${currentState.currentState}' (allowed: ${action.fromStates.join(', ')})`,
          impact: 'WORKFLOW_CONTROL',
        };
      }
      return { passed: true };
    }

    case 'SEQUENCE_INVARIANT': {
      // Check if preceding required actions/states were completed
      if (action.fromStates && !action.fromStates.includes(currentState.currentState)) {
        return {
          passed: false,
          reason: `Sequence violation: action '${action.actionId}' requires prior state in [${action.fromStates.join(', ')}], found '${currentState.currentState}'`,
          impact: 'WORKFLOW_CONTROL',
        };
      }
      return { passed: true };
    }

    case 'BUSINESS_RULE_INVARIANT': {
      // Default business rule checks (e.g. line items sum vs total, coupon percentage limit)
      if (resource.attributes?.lineItems && resource.attributes?.totalAmount !== undefined) {
        const sum = (resource.attributes.lineItems as any[]).reduce((acc, item) => acc + (item.price * (item.quantity || 1)), 0);
        if (Math.abs(sum - resource.attributes.totalAmount) > 0.01) {
          return {
            passed: false,
            reason: `Business rule violation: line items total (${sum}) does not match order total (${resource.attributes.totalAmount})`,
            impact: 'FINANCIAL',
          };
        }
      }
      return { passed: true };
    }

    case 'CONCURRENCY_INVARIANT': {
      const balance = resource.attributes?.balance;
      const requestedDebit = action.parameters?.debitAmount || action.parameters?.amount;
      if (balance !== undefined && requestedDebit !== undefined && requestedDebit > balance) {
        return {
          passed: false,
          reason: `Concurrency invariant breach: requested debit ${requestedDebit} exceeds available balance ${balance}`,
          impact: 'FINANCIAL',
        };
      }
      return { passed: true };
    }

    default:
      return { passed: true };
  }
}
