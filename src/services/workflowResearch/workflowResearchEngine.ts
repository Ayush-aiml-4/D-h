import { AuthUser } from '../../middleware/auth.ts';
import {
  WorkflowDefinition,
  WorkflowActor,
  WorkflowResource,
  WorkflowAction,
  WorkflowResearchHypothesis,
  WorkflowResearchResult,
  WorkflowFindingCandidate,
  WorkflowStateInstance,
  WorkflowTransitionEvaluation,
  WorkflowTransitionRecord,
  CancellationToken,
} from '../../types/workflowResearch.ts';
import { resolveTargetScope, evaluateProgramProfilePolicy } from '../programProfileService.ts';
import { getWorkflowDefinition, registerWorkflowDefinition } from './workflowDefinitionService.ts';
import { createWorkflowStateInstance } from './stateModelService.ts';
import { evaluateStateTransition, applyStateTransition } from './stateTransitionEngine.ts';
import { evaluateWorkflowAuthorization } from './workflowAuthorizationEngine.ts';
import { analyzeWorkflowReplay, evaluateReplayVulnerability } from './workflowReplayAnalyzer.ts';
import { simulateSafeLocalConcurrency } from './workflowConcurrencyAnalyzer.ts';
import { validateOrderLineItemsIntegrity } from './businessRuleEngine.ts';
import { createWorkflowFindingCandidate } from './workflowImpactAnalysisEngine.ts';
import { dispatchLocalWorkflowRequest, ORDER_WORKFLOW_DEFINITION, COUPON_WORKFLOW_DEFINITION } from './localWorkflowFixtures.ts';
import { recordAuditEvent } from '../auditService.ts';
import { sanitizeAndRedact } from '../capabilities/utils.ts';

// Auto-register baseline workflow definitions
registerWorkflowDefinition(ORDER_WORKFLOW_DEFINITION);
registerWorkflowDefinition(COUPON_WORKFLOW_DEFINITION);

export interface ExecuteWorkflowResearchOptions {
  user: AuthUser;
  caseId: string;
  workflowId: string;
  hypotheses: WorkflowResearchHypothesis[];
  dryRun?: boolean;
  maxBudget?: number;
  cancellationToken?: CancellationToken;
  scenarioType?: 'SECURE' | 'VULNERABLE_TRANSITION' | 'VULNERABLE_OWNERSHIP' | 'VULNERABLE_REPLAY' | 'VULNERABLE_RULE' | 'VULNERABLE_PRIVILEGE' | 'VULNERABLE_TERMINAL';
}

export async function executeWorkflowResearch(
  options: ExecuteWorkflowResearchOptions
): Promise<WorkflowResearchResult> {
  const {
    user,
    caseId,
    workflowId,
    hypotheses,
    dryRun = false,
    maxBudget = 25,
    cancellationToken,
    scenarioType = 'SECURE',
  } = options;

  const executionId = `wf-exec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const workflowDef = getWorkflowDefinition(workflowId);

  if (!workflowDef) {
    throw new Error(`Workflow definition '${workflowId}' not found in registry`);
  }

  // 1. Program Scope & Policy Enforcement (Fail-Closed)
  const targetScope = resolveTargetScope(workflowDef.programId, workflowDef.target);
  const capabilityId = 'active-workflow-state-validation';

  const policyDecision = await evaluateProgramProfilePolicy(
    user,
    {
      programId: workflowDef.programId,
      target: workflowDef.target,
      operation: capabilityId,
    }
  );

  if (policyDecision.decision === 'BLOCK') {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: workflowDef.programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      metadata: { target: workflowDef.target, reason: policyDecision.reason },
    });
    return {
      executionId,
      caseId,
      workflowId,
      programId: workflowDef.programId,
      target: workflowDef.target,
      status: 'BLOCKED',
      dryRun,
      totalStepsExecuted: 0,
      totalHypothesesTested: 0,
      violationsDetected: 0,
      candidatesGenerated: [],
      evidenceHashes: [],
      auditEventCount: 1,
      executionLogs: [`Workflow research BLOCKED by policy: ${policyDecision.reason}`],
    };
  }

  // Record workflow execution start
  await recordAuditEvent({
    userId: user.uid,
    entityType: 'CASE',
    entityId: caseId,
    action: dryRun ? 'WORKFLOW_RESEARCH_DRY_RUN' : 'WORKFLOW_RESEARCH_EXECUTED',
    success: true,
    metadata: sanitizeAndRedact({
      executionId,
      workflowId,
      programId: workflowDef.programId,
      target: workflowDef.target,
      dryRun,
      scenarioType,
    }),
  });

  const candidates: WorkflowFindingCandidate[] = [];
  const executionLogs: string[] = [];
  let totalStepsExecuted = 0;
  let violationsDetected = 0;

  if (dryRun) {
    executionLogs.push(`[DRY RUN] Workflow research plan compiled for '${workflowDef.workflowName}' (0 network requests executed)`);
    return {
      executionId,
      caseId,
      workflowId,
      programId: workflowDef.programId,
      target: workflowDef.target,
      status: 'COMPLETED',
      dryRun: true,
      totalStepsExecuted: 0,
      totalHypothesesTested: hypotheses.length,
      violationsDetected: 0,
      candidatesGenerated: [],
      evidenceHashes: [],
      auditEventCount: 1,
      executionLogs,
    };
  }

  // 2. Execute Research Hypotheses
  for (const hyp of hypotheses) {
    if (cancellationToken?.isCancelled) {
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'CASE',
        entityId: caseId,
        action: 'WORKFLOW_RESEARCH_CANCELLED',
        success: true,
        metadata: { executionId, workflowId, cancelledAtHypothesis: hyp.hypothesisId },
      });
      return {
        executionId,
        caseId,
        workflowId,
        programId: workflowDef.programId,
        target: workflowDef.target,
        status: 'CANCELLED',
        dryRun: false,
        totalStepsExecuted,
        totalHypothesesTested: hypotheses.indexOf(hyp),
        violationsDetected,
        candidatesGenerated: candidates,
        evidenceHashes: candidates.map(c => c.evidenceHash),
        auditEventCount: 2,
        executionLogs,
      };
    }

    if (totalStepsExecuted >= maxBudget) {
      executionLogs.push(`[BUDGET] Execution budget ceiling reached (${maxBudget} steps).`);
      break;
    }

    const defaultActor = hyp.actors[0] || {
      actorId: 'acc-owner',
      actorLabel: 'ACCOUNT_A',
      role: 'STANDARD_USER',
      credentialReference: 'cred-ref-user-a',
    };

    let currentStateInstance = createWorkflowStateInstance(
      workflowDef,
      defaultActor,
      hyp.initialResource
    );

    const history: WorkflowTransitionRecord[] = [];

    // Check special hypothesis types
    if (hyp.testType === 'CONCURRENCY_RACE') {
      const sim = simulateSafeLocalConcurrency(
        hyp.initialResource,
        workflowDef.actions[0],
        hyp.actors,
        50,
        scenarioType === 'VULNERABLE_RULE' || scenarioType === 'VULNERABLE_TRANSITION'
      );
      if (sim.hasRaceConditionAnomaly) {
        violationsDetected++;
        const dummyEval: WorkflowTransitionEvaluation = {
          actionId: workflowDef.actions[0].actionId,
          fromState: currentStateInstance.currentState,
          toState: currentStateInstance.currentState,
          actor: defaultActor,
          resource: hyp.initialResource,
          isValidTransition: false,
          isAuthorized: true,
          invariantsPassed: false,
          violatedInvariants: [{
            invariantId: 'inv-concurrency-race',
            type: 'CONCURRENCY_INVARIANT',
            reason: sim.explanation,
          }],
          expectedOutcome: 'DENY',
          observedOutcome: 'ALLOW',
          status: 'VIOLATION',
        };
        const candidate = createWorkflowFindingCandidate(
          caseId,
          executionId,
          workflowDef,
          dummyEval,
          1,
          200,
          { anomaly: true, sim }
        );
        candidates.push(candidate);
      }
      continue;
    }

    if (hyp.testType === 'BUSINESS_RULE') {
      const ruleRes = validateOrderLineItemsIntegrity(hyp.initialResource);
      if (!ruleRes.valid) {
        violationsDetected++;
        const dummyEval: WorkflowTransitionEvaluation = {
          actionId: 'act-validate-order-items',
          fromState: currentStateInstance.currentState,
          toState: currentStateInstance.currentState,
          actor: defaultActor,
          resource: hyp.initialResource,
          isValidTransition: true,
          isAuthorized: true,
          invariantsPassed: false,
          violatedInvariants: [{
            invariantId: 'inv-order-total-sum',
            type: 'BUSINESS_RULE_INVARIANT',
            reason: ruleRes.reason || 'Line items sum mismatch',
          }],
          expectedOutcome: 'DENY',
          observedOutcome: 'ALLOW',
          status: 'VIOLATION',
        };
        const candidate = createWorkflowFindingCandidate(
          caseId,
          executionId,
          workflowDef,
          dummyEval,
          1,
          200,
          { ruleViolation: true, ruleRes }
        );
        candidates.push(candidate);
      }
      continue;
    }

    // Step-by-step sequence evaluation
    for (let stepIdx = 0; stepIdx < hyp.actionsSequence.length; stepIdx++) {
      if (totalStepsExecuted >= maxBudget) break;
      totalStepsExecuted++;

      const seqItem = hyp.actionsSequence[stepIdx];
      const actionDef = workflowDef.actions.find(a => a.actionId === seqItem.actionId) || {
        actionId: seqItem.actionId,
        actionName: seqItem.actionId,
        fromStates: [currentStateInstance.currentState],
        toState: 'COMPLETED',
        replayPolicy: 'REPLAY_REJECTED' as const,
      };

      const actingActor = hyp.actors.find(a => a.actorId === seqItem.actorId) || defaultActor;
      currentStateInstance.actor = actingActor;

      // 1. Evaluate Transition Expectation
      const evaluation = evaluateStateTransition(workflowDef, currentStateInstance, actionDef, history);

      // 2. Dispatch Local Mock Request
      const dispatchResult = dispatchLocalWorkflowRequest(
        workflowDef,
        actionDef,
        actingActor,
        currentStateInstance.resource,
        currentStateInstance.currentState,
        scenarioType
      );

      const observedOutcome = dispatchResult.status >= 200 && dispatchResult.status < 300 ? 'ALLOW' : 'DENY';
      evaluation.observedOutcome = observedOutcome;

      // 3. Replay Check
      const replayAnalysis = analyzeWorkflowReplay(actionDef, currentStateInstance.resource, currentStateInstance, history);
      if (replayAnalysis.isReplayAttempt) {
        const replayVuln = evaluateReplayVulnerability(
          actionDef,
          replayAnalysis.expectedHandling,
          dispatchResult.status,
          dispatchResult.status >= 200 ? 'SUCCESS' : 'REJECTED'
        );
        if (replayVuln.isVulnerable) {
          evaluation.violatedInvariants.push({
            invariantId: 'inv-replay-consumed',
            type: 'SINGLE_USE_INVARIANT',
            reason: replayVuln.reason || 'Replay invariant breached',
          });
        }
      }

      // Record in history
      history.push({
        step: stepIdx + 1,
        fromState: currentStateInstance.currentState,
        actionId: actionDef.actionId,
        toState: dispatchResult.stateAfter,
        actorId: actingActor.actorId,
        timestamp: new Date().toISOString(),
        status: observedOutcome === 'ALLOW' ? 'SUCCESS' : 'REJECTED',
        responseStatus: dispatchResult.status,
        responsePayload: dispatchResult.data,
      });

      // 4. Compare Expectation vs Observed
      if (evaluation.expectedOutcome === 'DENY' && observedOutcome === 'ALLOW') {
        evaluation.status = 'VIOLATION';
        violationsDetected++;

        const candidate = createWorkflowFindingCandidate(
          caseId,
          executionId,
          workflowDef,
          evaluation,
          stepIdx + 1,
          dispatchResult.status,
          dispatchResult.data
        );
        candidates.push(candidate);
        executionLogs.push(`[VIOLATION DETECTED] Step ${stepIdx + 1}: ${candidate.title}`);
      } else {
        evaluation.status = 'CONFORMANT';
      }

      // Advance state
      currentStateInstance = applyStateTransition(
        workflowDef,
        currentStateInstance,
        actionDef,
        dispatchResult.stateAfter
      );
    }
  }

  return {
    executionId,
    caseId,
    workflowId,
    programId: workflowDef.programId,
    target: workflowDef.target,
    status: 'COMPLETED',
    dryRun: false,
    totalStepsExecuted,
    totalHypothesesTested: hypotheses.length,
    violationsDetected,
    candidatesGenerated: candidates,
    evidenceHashes: candidates.map(c => c.evidenceHash),
    auditEventCount: 2,
    executionLogs,
  };
}
