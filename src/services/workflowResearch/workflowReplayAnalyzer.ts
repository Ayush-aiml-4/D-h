import {
  WorkflowAction,
  WorkflowResource,
  WorkflowStateInstance,
  ReplayPolicy,
  WorkflowTransitionRecord,
} from '../../types/workflowResearch.ts';

export interface ReplayAnalysisResult {
  actionId: string;
  replayPolicy: ReplayPolicy;
  isReplayAttempt: boolean;
  replayCount: number;
  expectedHandling: 'ACCEPT' | 'REJECT';
  actualHandling: 'ACCEPT' | 'REJECT';
  isVulnerableReplay: boolean;
  explanation: string;
}

export function analyzeWorkflowReplay(
  action: WorkflowAction,
  resource: WorkflowResource,
  currentState: WorkflowStateInstance,
  history: WorkflowTransitionRecord[]
): ReplayAnalysisResult {
  const previousExecutions = history.filter(h => h.actionId === action.actionId && h.status === 'SUCCESS');
  const replayCount = previousExecutions.length;
  const isReplayAttempt = replayCount > 0;

  let expectedHandling: 'ACCEPT' | 'REJECT' = 'ACCEPT';
  if (action.isSingleUse || action.replayPolicy === 'REPLAY_REJECTED' || resource.currentStatus === 'CONSUMED') {
    expectedHandling = 'REJECT';
  }

  return {
    actionId: action.actionId,
    replayPolicy: action.replayPolicy,
    isReplayAttempt,
    replayCount,
    expectedHandling,
    actualHandling: 'ACCEPT', // Baseline expectation
    isVulnerableReplay: false,
    explanation: isReplayAttempt
      ? `Action '${action.actionId}' has been executed ${replayCount} previous times (Policy: ${action.replayPolicy})`
      : `First execution of action '${action.actionId}'`,
  };
}

export function evaluateReplayVulnerability(
  action: WorkflowAction,
  expectedHandling: 'ACCEPT' | 'REJECT',
  observedResponseStatus: number,
  observedStatus: 'SUCCESS' | 'REJECTED'
): {
  isVulnerable: boolean;
  confidence: 'HIGH_CONFIDENCE' | 'LOW_CONFIDENCE' | 'NO_FINDING';
  reason?: string;
} {
  const wasAccepted = observedStatus === 'SUCCESS' && observedResponseStatus >= 200 && observedResponseStatus < 300;

  if (expectedHandling === 'REJECT' && wasAccepted) {
    return {
      isVulnerable: true,
      confidence: 'HIGH_CONFIDENCE',
      reason: `Replay invariant violation: Action '${action.actionId}' was expected to be REJECTED upon replay, but server accepted the operation with HTTP ${observedResponseStatus}`,
    };
  }

  return {
    isVulnerable: false,
    confidence: 'NO_FINDING',
  };
}
