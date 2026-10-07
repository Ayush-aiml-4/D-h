import {
  WorkflowResource,
  WorkflowAction,
  WorkflowActor,
} from '../../types/workflowResearch.ts';

export interface ConcurrencySimulationResult {
  resourceId: string;
  initialBalance: number;
  operations: {
    actorId: string;
    actionId: string;
    requestedAmount: number;
    simulatedSuccess: boolean;
  }[];
  finalBalance: number;
  expectedFinalBalance: number;
  hasRaceConditionAnomaly: boolean;
  explanation: string;
}

export function simulateSafeLocalConcurrency(
  resource: WorkflowResource,
  action: WorkflowAction,
  actors: WorkflowActor[],
  debitAmount: number,
  isVulnerableSimulation: boolean = false
): ConcurrencySimulationResult {
  const initialBalance = Number(resource.attributes?.balance ?? 100);
  const expectedMaxAllowedOperations = Math.floor(initialBalance / debitAmount);

  let currentBalance = initialBalance;
  const operations: ConcurrencySimulationResult['operations'] = [];

  for (let i = 0; i < actors.length; i++) {
    const actor = actors[i];
    if (isVulnerableSimulation) {
      // Vulnerable race condition simulation: checks state concurrently before decrementing
      if (initialBalance >= debitAmount) {
        currentBalance -= debitAmount;
        operations.push({
          actorId: actor.actorId,
          actionId: action.actionId,
          requestedAmount: debitAmount,
          simulatedSuccess: true,
        });
      } else {
        operations.push({
          actorId: actor.actorId,
          actionId: action.actionId,
          requestedAmount: debitAmount,
          simulatedSuccess: false,
        });
      }
    } else {
      // Secure serialized execution: atomic deduction with balance check
      if (currentBalance >= debitAmount) {
        currentBalance -= debitAmount;
        operations.push({
          actorId: actor.actorId,
          actionId: action.actionId,
          requestedAmount: debitAmount,
          simulatedSuccess: true,
        });
      } else {
        operations.push({
          actorId: actor.actorId,
          actionId: action.actionId,
          requestedAmount: debitAmount,
          simulatedSuccess: false,
        });
      }
    }
  }

  const expectedFinalBalance = Math.max(0, initialBalance - (expectedMaxAllowedOperations * debitAmount));
  const successfulOps = operations.filter(o => o.simulatedSuccess).length;
  const hasRaceConditionAnomaly = successfulOps > expectedMaxAllowedOperations || currentBalance < 0;

  return {
    resourceId: resource.resourceId,
    initialBalance,
    operations,
    finalBalance: currentBalance,
    expectedFinalBalance,
    hasRaceConditionAnomaly,
    explanation: hasRaceConditionAnomaly
      ? `Race condition invariant breached: Allowed ${successfulOps} debit operations of $${debitAmount} on starting balance $${initialBalance} (Final balance: $${currentBalance})`
      : `Serialized concurrency safe: ${successfulOps} of ${actors.length} debit operations succeeded cleanly within balance limits.`,
  };
}
