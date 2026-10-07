import {
  WorkflowDefinition,
  WorkflowActor,
  WorkflowResource,
  WorkflowAction,
} from '../../types/workflowResearch.ts';

// 1. Standard Order Management Workflow Definition
export const ORDER_WORKFLOW_DEFINITION: WorkflowDefinition = {
  workflowId: 'wf-order-fulfillment-01',
  workflowName: 'E-Commerce Order Fulfillment Workflow',
  programId: 'meesho-hackerone',
  target: 'www.valmo.in',
  initialState: 'CREATED',
  terminalStates: ['COMPLETED', 'CANCELLED', 'REFUNDED'],
  states: ['CREATED', 'PAID', 'PROCESSING', 'SHIPPED', 'DELIVERED', 'COMPLETED', 'CANCELLED', 'REFUNDED'],
  sensitivity: 'FINANCIAL',
  maxRequestBudget: 25,
  actions: [
    {
      actionId: 'act-pay-order',
      actionName: 'Pay Order',
      fromStates: ['CREATED'],
      toState: 'PAID',
      isOwnerOnly: true,
      replayPolicy: 'REPLAY_REJECTED',
    },
    {
      actionId: 'act-process-order',
      actionName: 'Process Order for Dispatch',
      fromStates: ['PAID'],
      toState: 'PROCESSING',
      requiredRole: 'SUPPLIER',
      replayPolicy: 'REPLAY_ALLOWED',
    },
    {
      actionId: 'act-ship-order',
      actionName: 'Ship Order',
      fromStates: ['PROCESSING', 'PAID'],
      toState: 'SHIPPED',
      requiredRole: 'SUPPLIER',
      replayPolicy: 'REPLAY_REJECTED',
    },
    {
      actionId: 'act-complete-order',
      actionName: 'Complete Order Delivery',
      fromStates: ['SHIPPED'],
      toState: 'COMPLETED',
      replayPolicy: 'REPLAY_REJECTED',
    },
    {
      actionId: 'act-cancel-order',
      actionName: 'Cancel Order',
      fromStates: ['CREATED', 'PAID'],
      toState: 'CANCELLED',
      isOwnerOnly: true,
      replayPolicy: 'REPLAY_REJECTED',
    },
    {
      actionId: 'act-direct-complete-bypass',
      actionName: 'Direct Complete Order Bypass (Skipping Payment)',
      fromStates: ['CREATED'],
      toState: 'COMPLETED',
      replayPolicy: 'REPLAY_REJECTED',
    },
    {
      actionId: 'act-admin-force-refund',
      actionName: 'Admin Force Refund',
      fromStates: ['PAID', 'SHIPPED', 'COMPLETED'],
      toState: 'REFUNDED',
      isPrivileged: true,
      replayPolicy: 'REPLAY_REJECTED',
    },
  ],
  transitions: [
    {
      fromState: 'CREATED',
      actionId: 'act-pay-order',
      toState: 'PAID',
      isOwnerOnly: true,
      invariants: ['inv-order-owner', 'inv-order-amount-positive'],
    },
    {
      fromState: 'PAID',
      actionId: 'act-ship-order',
      toState: 'SHIPPED',
      invariants: ['inv-status-paid'],
    },
    {
      fromState: 'SHIPPED',
      actionId: 'act-complete-order',
      toState: 'COMPLETED',
      invariants: ['inv-status-shipped'],
    },
    {
      fromState: 'CREATED',
      actionId: 'act-cancel-order',
      toState: 'CANCELLED',
      isOwnerOnly: true,
      invariants: ['inv-order-owner'],
    },
    {
      fromState: 'COMPLETED',
      actionId: 'act-admin-force-refund',
      toState: 'REFUNDED',
      invariants: ['inv-admin-auth'],
    },
  ],
  invariants: [
    {
      invariantId: 'inv-order-owner',
      type: 'OWNERSHIP_INVARIANT',
      name: 'Order Owner Only',
      description: 'Only the creator of the order can initiate payment or cancellation',
      expectedResult: 'ALLOW',
    },
    {
      invariantId: 'inv-order-amount-positive',
      type: 'QUANTITY_INVARIANT',
      name: 'Order Amount Positive',
      description: 'Order amount must be greater than zero',
      expectedResult: 'ALLOW',
    },
    {
      invariantId: 'inv-terminal-completed',
      type: 'TERMINAL_STATE_INVARIANT',
      name: 'Terminal Completed Invariant',
      description: 'No state modifications allowed once order is completed',
      enforceAtStates: ['COMPLETED'],
      expectedResult: 'DENY',
    },
    {
      invariantId: 'inv-admin-auth',
      type: 'AUTHORIZATION_INVARIANT',
      name: 'Admin Authorization Invariant',
      description: 'Only administrators can perform forced refunds',
      expectedResult: 'ALLOW',
    },
  ],
};

// 2. Coupon Redemption Workflow Definition
export const COUPON_WORKFLOW_DEFINITION: WorkflowDefinition = {
  workflowId: 'wf-coupon-redemption-02',
  workflowName: 'Single-Use Promotional Coupon Redemption',
  programId: 'meesho-hackerone',
  target: 'www.valmo.in',
  initialState: 'UNUSED',
  terminalStates: ['CONSUMED', 'EXPIRED'],
  states: ['UNUSED', 'APPLIED', 'CONSUMED', 'EXPIRED'],
  sensitivity: 'FINANCIAL',
  maxRequestBudget: 20,
  actions: [
    {
      actionId: 'act-apply-coupon',
      actionName: 'Apply Coupon',
      fromStates: ['UNUSED'],
      toState: 'APPLIED',
      isSingleUse: true,
      replayPolicy: 'REPLAY_REJECTED',
    },
    {
      actionId: 'act-consume-coupon',
      actionName: 'Consume Coupon on Checkout',
      fromStates: ['APPLIED'],
      toState: 'CONSUMED',
      isSingleUse: true,
      replayPolicy: 'REPLAY_REJECTED',
    },
  ],
  transitions: [
    {
      fromState: 'UNUSED',
      actionId: 'act-apply-coupon',
      toState: 'APPLIED',
      invariants: ['inv-coupon-single-use'],
    },
    {
      fromState: 'APPLIED',
      actionId: 'act-consume-coupon',
      toState: 'CONSUMED',
      invariants: ['inv-coupon-single-use'],
    },
  ],
  invariants: [
    {
      invariantId: 'inv-coupon-single-use',
      type: 'SINGLE_USE_INVARIANT',
      name: 'Coupon Single Use Invariant',
      description: 'Promotional coupons cannot be re-applied or consumed multiple times',
      expectedResult: 'ALLOW',
    },
  ],
};

// Dispatch local mock request against workflow fixtures
export interface LocalWorkflowDispatchResult {
  status: number;
  data: any;
  stateAfter: string;
}

export function dispatchLocalWorkflowRequest(
  workflowDef: WorkflowDefinition,
  action: WorkflowAction,
  actor: WorkflowActor,
  resource: WorkflowResource,
  currentState: string,
  scenario: 'SECURE' | 'VULNERABLE_TRANSITION' | 'VULNERABLE_OWNERSHIP' | 'VULNERABLE_REPLAY' | 'VULNERABLE_RULE' | 'VULNERABLE_PRIVILEGE' | 'VULNERABLE_TERMINAL'
): LocalWorkflowDispatchResult {
  // Scenario 1: SECURE implementation (Strict adherence to state machine)
  if (scenario === 'SECURE') {
    if (action.isOwnerOnly && resource.ownerActorId !== actor.actorId) {
      return { status: 403, data: { error: 'Forbidden: You do not own this order' }, stateAfter: currentState };
    }
    if (action.isPrivileged && actor.role !== 'ADMIN_USER' && actor.role !== 'PRIVILEGED_USER') {
      return { status: 403, data: { error: 'Forbidden: Admin privileges required' }, stateAfter: currentState };
    }
    if ((workflowDef.terminalStates || []).includes(currentState)) {
      return { status: 400, data: { error: 'Bad Request: Order in terminal state cannot be modified' }, stateAfter: currentState };
    }
    if (!action.fromStates.includes(currentState)) {
      return { status: 400, data: { error: `Invalid transition from state '${currentState}'` }, stateAfter: currentState };
    }
    return { status: 200, data: { success: true, newStatus: action.toState }, stateAfter: action.toState };
  }

  // Scenario 2: VULNERABLE_TRANSITION (Bypasses required steps, e.g. CREATED -> COMPLETED)
  if (scenario === 'VULNERABLE_TRANSITION') {
    if (action.actionId === 'act-direct-complete-bypass') {
      return { status: 200, data: { success: true, newStatus: 'COMPLETED', note: 'Direct transition bypass accepted' }, stateAfter: 'COMPLETED' };
    }
  }

  // Scenario 3: VULNERABLE_OWNERSHIP (Cross-account modification permitted)
  if (scenario === 'VULNERABLE_OWNERSHIP') {
    if (action.isOwnerOnly && resource.ownerActorId !== actor.actorId) {
      return { status: 200, data: { success: true, newStatus: action.toState, note: 'IDOR / Cross-account update accepted' }, stateAfter: action.toState };
    }
  }

  // Scenario 4: VULNERABLE_REPLAY (Coupon re-consumption permitted)
  if (scenario === 'VULNERABLE_REPLAY') {
    return { status: 200, data: { success: true, newStatus: action.toState, note: 'Replay consumption accepted' }, stateAfter: action.toState };
  }

  // Scenario 5: VULNERABLE_PRIVILEGE (Standard user permitted admin force refund)
  if (scenario === 'VULNERABLE_PRIVILEGE') {
    if (action.isPrivileged && actor.role === 'STANDARD_USER') {
      return { status: 200, data: { success: true, newStatus: 'REFUNDED', note: 'Vertical privilege bypass accepted' }, stateAfter: 'REFUNDED' };
    }
  }

  // Scenario 6: VULNERABLE_TERMINAL (Allows mutation after completion)
  if (scenario === 'VULNERABLE_TERMINAL') {
    return { status: 200, data: { success: true, newStatus: 'CANCELLED', note: 'Terminal state mutation accepted' }, stateAfter: 'CANCELLED' };
  }

  // Default fallback
  return { status: 200, data: { success: true, newStatus: action.toState }, stateAfter: action.toState };
}
