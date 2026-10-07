import { AuthUser } from '../../middleware/auth.ts';
import {
  AuthorizationHypothesis,
  AuthorizationResearchExecutionParams,
  AuthorizationResearchExecutionResult,
  DifferentialAnalysisResult,
  FindingCandidate,
  DifferentialExecutionSnapshot,
} from '../../types/authorizationResearch.ts';
import { resolveTargetScope, evaluateProgramProfilePolicy } from '../programProfileService.ts';
import { responseDifferentialEngine } from './responseDifferentialEngine.ts';
import { impactAnalysisEngine } from './impactAnalysisEngine.ts';
import { dispatchLocalFixtureRequest } from './localAuthFixtures.ts';
import { recordAuditEvent } from '../auditService.ts';
import { computeEvidenceHash } from '../evidenceService.ts';
import { sanitizeAndRedact } from '../capabilities/utils.ts';
import {
  BadRequestError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
} from '../../utils/errors.ts';

export class AuthorizationResearchEngine {
  /**
   * Executes authorized authorization and API research across hypotheses with scope gating,
   * budget limits, cancellation, and evidence recording.
   */
  public async executeResearch(
    user: AuthUser,
    params: AuthorizationResearchExecutionParams,
    requestId: string = `req-auth-${Date.now()}`
  ): Promise<AuthorizationResearchExecutionResult> {
    const startTime = Date.now();
    const {
      programId,
      caseId,
      target,
      researchClass,
      hypotheses,
      requestBudget = 10,
      dryRun = false,
      allowLocalFixtureTarget = false,
      cancellationToken,
    } = params;

    if (!user || !user.uid) {
      throw new ForbiddenError('AUTH_REQUIRED: Authenticated researcher context is required');
    }
    if (!programId) {
      throw new BadRequestError('PROGRAM_ID_REQUIRED: programId is required');
    }
    if (!target) {
      throw new BadRequestError('TARGET_REQUIRED: Target asset is required');
    }
    if (!hypotheses || hypotheses.length === 0) {
      throw new BadRequestError('HYPOTHESES_REQUIRED: At least one authorization hypothesis is required');
    }

    const executionId = `exec-auth-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    // 1. Program Profile & Scope Authorization Evaluation (#0003.5-C)
    // If testing on local fixture target, allow when explicitly requested
    let policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED' | 'DENY' = 'ALLOW';
    let programName = programId;

    if (!allowLocalFixtureTarget) {
      const scopeResult = resolveTargetScope(programId, target);
      policyDecision = scopeResult.decision;
      programName = (scopeResult as any).programName || programId;

      if (scopeResult.decision === 'DENY' || scopeResult.decision === 'BLOCK') {
        await recordAuditEvent({
          userId: user.uid,
          entityType: 'POLICY',
          entityId: programId,
          action: 'POLICY_EVALUATE_BLOCK',
          success: false,
          previousState: 'REQUESTED',
          newState: 'BLOCKED',
          requestId,
          metadata: { target, reason: scopeResult.reason },
        });

        throw new ForbiddenError(`SCOPE_DENIED: Target '${target}' is out-of-scope for program '${programId}' (${scopeResult.reason})`);
      }

      // Check capability policy
      const capPolicy = await evaluateProgramProfilePolicy(
        user,
        {
          programId,
          target,
          operation: `cap-${researchClass.toLowerCase()}`,
        },
        requestId
      );

      if (capPolicy.decision === 'BLOCK') {
        throw new ForbiddenError(`CAPABILITY_BLOCKED: Capability '${researchClass}' is prohibited on program '${programId}'`);
      }
    }

    // 2. Dry-Run Handling
    if (dryRun) {
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'CASE',
        entityId: caseId,
        action: 'AUTH_RESEARCH_DRY_RUN',
        success: true,
        previousState: 'PLANNED',
        newState: 'DRY_RUN_COMPLETED',
        requestId,
        metadata: { target, researchClass, hypothesesCount: hypotheses.length },
      });

      return {
        executionId,
        programId,
        programName,
        caseId,
        target,
        researchClass,
        policyDecision,
        status: 'COMPLETED',
        totalRequestsExecuted: 0,
        requestBudget,
        hypothesesEvaluated: hypotheses.length,
        differentialResults: [],
        findingCandidates: [],
        evidenceRecords: [],
        auditEventsRecorded: 1,
        dryRun: true,
        executedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime,
      };
    }

    // 3. Controlled Execution across hypotheses
    let executedRequestsCount = 0;
    const differentialResults: DifferentialAnalysisResult[] = [];
    const findingCandidates: FindingCandidate[] = [];
    const evidenceRecords: any[] = [];
    let isCancelled = false;
    let cancellationReason: string | undefined;

    for (const hypothesis of hypotheses) {
      // Check cancellation token
      if (cancellationToken?.isCancelled) {
        isCancelled = true;
        cancellationReason = cancellationToken.reason || 'User cancelled authorization research';
        break;
      }

      // Check request budget
      if (executedRequestsCount + 2 > requestBudget) {
        break;
      }

      // Execute Baseline Request (Baseline Context e.g. Owner Account A)
      const baselineSnapshot = this.dispatchSnapshot(hypothesis, hypothesis.baselineContext);
      executedRequestsCount++;

      // Check cancellation before comparison
      if (cancellationToken?.isCancelled) {
        isCancelled = true;
        cancellationReason = cancellationToken.reason || 'User cancelled authorization research';
        break;
      }

      // Execute Comparison Request (Comparison Context e.g. Peer Account B or Unauthenticated)
      const comparisonSnapshot = this.dispatchSnapshot(hypothesis, hypothesis.comparisonContext);
      executedRequestsCount++;

      // Run differential analysis
      const diffResult = responseDifferentialEngine.analyzeDifferential({
        hypothesis,
        baselineSnapshot,
        comparisonSnapshot,
      });

      // Compute and attach evidence hash
      const { sanitized: sanitizedBaseline } = sanitizeAndRedact(baselineSnapshot.responseBody);
      const { sanitized: sanitizedComparison } = sanitizeAndRedact(comparisonSnapshot.responseBody);

      const evidencePayload = {
        hypothesisId: hypothesis.hypothesisId,
        researchClass: hypothesis.researchClass,
        target: hypothesis.targetAsset,
        endpoint: hypothesis.endpoint,
        baseline: {
          context: hypothesis.baselineContext.contextLabel,
          status: baselineSnapshot.statusCode,
          body: sanitizedBaseline,
        },
        comparison: {
          context: hypothesis.comparisonContext.contextLabel,
          status: comparisonSnapshot.statusCode,
          body: sanitizedComparison,
        },
      };

      const evidenceHash = computeEvidenceHash(
        evidencePayload,
        `cap-${hypothesis.researchClass.toLowerCase()}`,
        target
      );
      diffResult.evidenceHash = evidenceHash;

      differentialResults.push(diffResult);

      evidenceRecords.push({
        evidenceId: `ev-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        hypothesisId: hypothesis.hypothesisId,
        evidenceHash,
        evidencePayload,
        capturedAt: new Date().toISOString(),
      });

      // If vulnerability candidate detected, generate structured finding candidate
      if (diffResult.isVulnerabilityCandidate) {
        const finding = impactAnalysisEngine.generateFindingCandidate({
          diffResult,
          hypothesis,
          caseId,
          programId,
          targetAsset: target,
        });
        findingCandidates.push(finding);
      }
    }

    const finalStatus = isCancelled ? 'CANCELLED' : 'COMPLETED';

    // Record audit event
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'CASE',
      entityId: caseId,
      action: isCancelled ? 'AUTH_RESEARCH_CANCELLED' : 'AUTH_RESEARCH_EXECUTED',
      success: true,
      previousState: 'RUNNING',
      newState: finalStatus,
      requestId,
      metadata: {
        target,
        researchClass,
        executedRequestsCount,
        findingCandidatesCount: findingCandidates.length,
        isCancelled,
      },
    });

    return {
      executionId,
      programId,
      programName,
      caseId,
      target,
      researchClass,
      policyDecision,
      status: finalStatus,
      totalRequestsExecuted: executedRequestsCount,
      requestBudget,
      hypothesesEvaluated: differentialResults.length,
      differentialResults,
      findingCandidates,
      evidenceRecords,
      auditEventsRecorded: 1,
      dryRun: false,
      executedAt: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      cancellationReason,
    };
  }

  private dispatchSnapshot(
    hypothesis: AuthorizationHypothesis,
    context: any
  ): DifferentialExecutionSnapshot {
    // Dispatch against local fixture handler
    return dispatchLocalFixtureRequest({
      endpoint: hypothesis.endpoint,
      method: hypothesis.httpMethod,
      context,
      resource: hypothesis.targetResource,
      parameters: hypothesis.mutatedParameters,
    });
  }
}

export const authorizationResearchEngine = new AuthorizationResearchEngine();
