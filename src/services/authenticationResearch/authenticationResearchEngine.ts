import { AuthUser } from '../../middleware/auth.ts';
import {
  AuthenticationHypothesis,
  AuthenticationResearchExecutionParams,
  AuthenticationResearchExecutionResult,
  AuthResearchDifferentialResult,
  FindingCandidate,
  ExecutionSnapshot,
  SessionModel,
  ControlledParameter,
} from '../../types/authenticationResearch.ts';
import { resolveTargetScope, evaluateProgramProfilePolicy } from '../programProfileService.ts';
import { evaluateAuthenticationBoundary } from './authenticationBoundaryEngine.ts';
import { evaluateSessionSecurity } from './sessionSecurityEngine.ts';
import { evaluateSessionIsolation } from './sessionIsolationAnalyzer.ts';
import { evaluateInputDifferential } from './inputDifferentialEngine.ts';
import { dispatchLocalAuthFixtureRequest } from './localAuthenticationFixtures.ts';
import { enforceRequestBudget } from './inputResearchEngine.ts';
import { recordAuditEvent } from '../auditService.ts';
import { computeEvidenceHash } from '../evidenceService.ts';
import { sanitizeAndRedact } from '../capabilities/utils.ts';
import {
  BadRequestError,
  ForbiddenError,
} from '../../utils/errors.ts';

export class AuthenticationResearchEngine {
  /**
   * Executes authorized authentication, session, and input security research across hypotheses
   * with program profile scope gating, budget limits, cancellation, and evidence recording.
   */
  public async executeResearch(
    user: AuthUser,
    params: AuthenticationResearchExecutionParams,
    requestId: string = `req-auth-res-${Date.now()}`
  ): Promise<AuthenticationResearchExecutionResult> {
    const startTime = Date.now();
    const {
      programId,
      caseId,
      target,
      researchClass,
      hypotheses,
      requestBudget: rawBudget = 15,
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
      throw new BadRequestError('HYPOTHESES_REQUIRED: At least one hypothesis is required');
    }

    const requestBudget = enforceRequestBudget(rawBudget, 30);
    const executionId = `exec-auth-res-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    // 1. Program Profile & Scope Authorization Evaluation (#0003.5-C)
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
          requestId,
          metadata: {
            target,
            researchClass,
            reason: `Target '${target}' is OUT_OF_SCOPE for program '${programId}'`,
          },
        });
        throw new ForbiddenError(`TARGET_OUT_OF_SCOPE: Target '${target}' is not authorized for research under program '${programId}'`);
      }

      // Check capability policy
      const capPolicy = await evaluateProgramProfilePolicy(
        user,
        {
          programId,
          target,
          operation: `cap-${researchClass.toLowerCase().replace(/_/g, '-')}`,
        },
        requestId
      );

      if (capPolicy.decision === 'BLOCK') {
        throw new ForbiddenError(`CAPABILITY_BLOCKED: Capability '${researchClass}' is prohibited on program '${programId}'`);
      }
    }

    // 2. Handle Dry-Run Mode
    if (dryRun) {
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'CASE',
        entityId: caseId,
        action: 'AUTH_RESEARCH_DRY_RUN',
        success: true,
        requestId,
        metadata: {
          executionId,
          programId,
          target,
          researchClass,
          hypothesesCount: hypotheses.length,
          requestBudget,
          policyDecision,
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
        status: 'COMPLETED',
        totalRequestsExecuted: 0,
        requestBudget,
        hypothesesEvaluated: 0,
        differentialResults: [],
        findingCandidates: [],
        evidenceRecords: [],
        auditEventsRecorded: 1,
        dryRun: true,
        executedAt: new Date().toISOString(),
        durationMs: Date.now() - startTime,
      };
    }

    // 3. Execute Hypotheses
    const differentialResults: AuthResearchDifferentialResult[] = [];
    const findingCandidates: FindingCandidate[] = [];
    const evidenceRecords: any[] = [];
    let executedRequestsCount = 0;
    let isCancelled = false;
    let cancellationReason: string | undefined;

    for (const hypothesis of hypotheses) {
      if (cancellationToken?.isCancelled) {
        isCancelled = true;
        cancellationReason = cancellationToken.reason || 'Research cancelled by researcher';
        break;
      }

      if (executedRequestsCount >= requestBudget) {
        break;
      }

      let diffResult: AuthResearchDifferentialResult;

      // Handle Authentication Boundary
      if (hypothesis.researchClass === 'AUTHENTICATION_BOUNDARY') {
        const unauthSnapshot = dispatchLocalAuthFixtureRequest({
          endpoint: hypothesis.endpoint,
          method: hypothesis.httpMethod,
          context: hypothesis.authContext,
        });
        executedRequestsCount++;

        let authSnapshot: ExecutionSnapshot | undefined;
        if (executedRequestsCount < requestBudget) {
          authSnapshot = dispatchLocalAuthFixtureRequest({
            endpoint: hypothesis.endpoint,
            method: hypothesis.httpMethod,
            context: {
              contextId: 'ctx-std',
              contextLabel: 'STANDARD_USER',
              researcherId: user.uid,
              programId,
              caseId,
              accountIdentifier: 'acc-standard-user',
              accountRole: 'STANDARD_USER',
              authState: 'AUTHENTICATED',
              credentialReference: 'cred-ref-std',
              sessionReference: 'sess-ref-std',
              authorizationScopes: ['read'],
            },
          });
          executedRequestsCount++;
        }

        diffResult = evaluateAuthenticationBoundary({
          hypothesis,
          unauthSnapshot,
          authSnapshot,
        });
      }
      // Handle Session Invalidation & Expiration
      else if (hypothesis.researchClass === 'SESSION_INVALIDATION') {
        const session = hypothesis.sessionModel || {
          sessionId: 'sess-test',
          sessionReference: 'sess-ref-test',
          accountIdentifier: 'acc-user-a',
          accountRole: 'STANDARD_USER',
          state: 'INVALIDATED',
          createdAt: new Date().toISOString(),
          lastActiveAt: new Date().toISOString(),
          expiresAt: new Date().toISOString(),
          credentialReference: 'cred-ref-test',
        };

        const testedSnapshot = dispatchLocalAuthFixtureRequest({
          endpoint: hypothesis.endpoint,
          method: hypothesis.httpMethod,
          session,
        });
        executedRequestsCount++;

        diffResult = evaluateSessionSecurity({
          hypothesis,
          session,
          testedSnapshot,
        });
      }
      // Handle Session Isolation
      else if (hypothesis.researchClass === 'SESSION_ISOLATION') {
        const sessionA: SessionModel = {
          sessionId: 'sess-a',
          sessionReference: 'sess-ref-a',
          accountIdentifier: 'acc-user-a',
          accountRole: 'STANDARD_USER',
          state: 'ACTIVE',
          createdAt: new Date().toISOString(),
          lastActiveAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          credentialReference: 'cred-ref-a',
        };
        const sessionB: SessionModel = {
          sessionId: 'sess-b',
          sessionReference: 'sess-ref-b',
          accountIdentifier: 'acc-user-b',
          accountRole: 'STANDARD_USER',
          state: 'ACTIVE',
          createdAt: new Date().toISOString(),
          lastActiveAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          credentialReference: 'cred-ref-b',
        };

        const snapshotA = dispatchLocalAuthFixtureRequest({
          endpoint: hypothesis.endpoint,
          method: hypothesis.httpMethod,
          session: sessionA,
        });
        executedRequestsCount++;

        const snapshotB = dispatchLocalAuthFixtureRequest({
          endpoint: hypothesis.endpoint,
          method: hypothesis.httpMethod,
          session: sessionB,
        });
        executedRequestsCount++;

        diffResult = evaluateSessionIsolation({
          hypothesis,
          sessionA,
          sessionB,
          snapshotA,
          snapshotB,
        });
      }
      // Handle Privilege State Transition
      else if (hypothesis.researchClass === 'PRIVILEGE_STATE_TRANSITION') {
        const testedSnapshot = dispatchLocalAuthFixtureRequest({
          endpoint: hypothesis.endpoint,
          method: hypothesis.httpMethod,
          context: hypothesis.authContext,
        });
        executedRequestsCount++;

        const isStandardUser = hypothesis.authContext?.accountRole === 'STANDARD_USER';
        const allowsAdminAction = testedSnapshot.statusCode === 200;

        if (isStandardUser && allowsAdminAction) {
          diffResult = {
            hypothesisId: hypothesis.hypothesisId,
            researchClass: 'PRIVILEGE_STATE_TRANSITION',
            targetAsset: hypothesis.targetAsset,
            endpoint: hypothesis.endpoint,
            httpMethod: hypothesis.httpMethod,
            comparisonResult: testedSnapshot,
            differences: {
              statusDiffers: false,
              bodyDiffers: false,
              sensitiveFieldsExposed: ['adminOperation'],
              sessionBoundaryViolated: false,
              privilegeBoundaryViolated: true,
              authenticationBypassed: false,
              reflectionObserved: false,
              unsafeContextInterpretation: false,
              booleanDifferentialObserved: false,
              pathTraversedOutsideRoot: false,
              unauthorizedStateChange: true,
            },
            classification: 'PRIVILEGE_VIOLATION',
            confidence: 'HIGH_CONFIDENCE',
            confidenceReasoning: 'Standard non-privileged role executed restricted administrative function without authorization check.',
            isVulnerabilityCandidate: true,
            vulnerabilityType: 'VERTICAL_PRIVILEGE_ESCALATION_ADMIN_BYPASS',
            cwe: 'CWE-280',
            owasp: 'A01:2021-Broken Access Control',
            explanation: `Vertical privilege boundary violation detected on '${hypothesis.endpoint}'. Standard user successfully executed administrative operation.`,
            impactAssessment: {
              confidentialityImpact: 'HIGH',
              integrityImpact: 'HIGH',
              privilegeImpact: 'HIGH',
              overallImpact: 'HIGH',
              reasoning: 'Allows non-privileged users to modify system-wide administrative state.',
            },
          };
        } else {
          diffResult = {
            hypothesisId: hypothesis.hypothesisId,
            researchClass: 'PRIVILEGE_STATE_TRANSITION',
            targetAsset: hypothesis.targetAsset,
            endpoint: hypothesis.endpoint,
            httpMethod: hypothesis.httpMethod,
            comparisonResult: testedSnapshot,
            differences: {
              statusDiffers: true,
              bodyDiffers: true,
              sensitiveFieldsExposed: [],
              sessionBoundaryViolated: false,
              privilegeBoundaryViolated: false,
              authenticationBypassed: false,
              reflectionObserved: false,
              unsafeContextInterpretation: false,
              booleanDifferentialObserved: false,
              pathTraversedOutsideRoot: false,
              unauthorizedStateChange: false,
            },
            classification: 'SAFE_ENFORCED',
            confidence: 'NO_FINDING',
            confidenceReasoning: `HTTP ${testedSnapshot.statusCode} returned; privilege boundary enforced.`,
            isVulnerabilityCandidate: false,
            explanation: `Privilege boundary strictly enforced on '${hypothesis.endpoint}'.`,
            impactAssessment: {
              confidentialityImpact: 'NONE',
              integrityImpact: 'NONE',
              privilegeImpact: 'NONE',
              overallImpact: 'NONE',
              reasoning: 'Access control properly restricted.',
            },
          };
        }
      }
      // Handle Input Security (XSS, Injection, Path Traversal)
      else {
        const param = hypothesis.controlledParameter || {
          parameterName: 'test_param',
          parameterType: 'QUERY',
          baseValue: 'default',
          securityContext: 'HTML_BODY',
          testPayloads: [],
        };

        const activeTestPayload =
          param.testPayloads.find(
            (p) =>
              (hypothesis.researchClass === 'INPUT_XSS' && p.category === 'CONTROLLED_XSS_TEST') ||
              (hypothesis.researchClass === 'INPUT_INJECTION' && p.category === 'CONTROLLED_INJECTION_TEST') ||
              (hypothesis.researchClass === 'INPUT_PATH_TRAVERSAL' && p.category === 'PATH_CANONICALIZATION_TEST') ||
              p.category === 'ENCODING_TEST'
          ) || param.testPayloads[0];

        const payload =
          activeTestPayload?.payloadString ||
          (hypothesis.researchClass === 'INPUT_XSS'
            ? '<devilhunt-poc-xss id="dh-xss-test-01">'
            : hypothesis.researchClass === 'INPUT_INJECTION'
            ? "' OR 'DEVILHUNT_EQ'='DEVILHUNT_EQ"
            : '../../devilhunt-fixture-root/safe-canary.json');

        const baselineSnapshot = dispatchLocalAuthFixtureRequest({
          endpoint: hypothesis.endpoint,
          method: hypothesis.httpMethod,
          parameterName: param.parameterName,
          payloadValue: param.baseValue,
        });
        executedRequestsCount++;

        const mutatedSnapshot = dispatchLocalAuthFixtureRequest({
          endpoint: hypothesis.endpoint,
          method: hypothesis.httpMethod,
          parameterName: param.parameterName,
          payloadValue: payload,
        });
        executedRequestsCount++;

        let falseSnapshot: ExecutionSnapshot | undefined;
        if (hypothesis.researchClass === 'INPUT_INJECTION' && executedRequestsCount < requestBudget) {
          falseSnapshot = dispatchLocalAuthFixtureRequest({
            endpoint: hypothesis.endpoint,
            method: hypothesis.httpMethod,
            parameterName: param.parameterName,
            payloadValue: "' OR 'DEVILHUNT_NEQ'='DEVILHUNT_DIFFERENT",
          });
          executedRequestsCount++;
        }

        diffResult = evaluateInputDifferential({
          hypothesis,
          parameter: param,
          payloadString: payload,
          baselineSnapshot,
          mutatedSnapshot,
          falseSnapshot,
        });
      }

      // Compute Deterministic Evidence Hash & Record Evidence
      const { sanitized: sanitizedResponse } = sanitizeAndRedact(diffResult.comparisonResult.responseBody);
      const evidencePayload = {
        hypothesisId: hypothesis.hypothesisId,
        researchClass: hypothesis.researchClass,
        target: hypothesis.targetAsset,
        endpoint: hypothesis.endpoint,
        classification: diffResult.classification,
        confidence: diffResult.confidence,
        status: diffResult.comparisonResult.statusCode,
        sanitizedResponse,
      };

      const evidenceHash = computeEvidenceHash(
        evidencePayload,
        `cap-${hypothesis.researchClass.toLowerCase().replace(/_/g, '-')}`,
        target
      );
      diffResult.evidenceHash = evidenceHash;
      diffResult.sanitizedEvidence = { ...diffResult.sanitizedEvidence, evidencePayload };

      differentialResults.push(diffResult);

      evidenceRecords.push({
        evidenceId: `ev-res-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        hypothesisId: hypothesis.hypothesisId,
        evidenceHash,
        evidencePayload,
        capturedAt: new Date().toISOString(),
      });

      // Generate Finding Candidate if candidate identified
      if (diffResult.isVulnerabilityCandidate) {
        const candidateId = `cand-auth-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        const confidenceScore = diffResult.confidence === 'HIGH_CONFIDENCE' ? 0.95 : 0.75;

        findingCandidates.push({
          candidateId,
          caseId,
          programId,
          targetAsset: target,
          title: `[${diffResult.vulnerabilityType || diffResult.researchClass}] on ${diffResult.endpoint}`,
          category: diffResult.researchClass,
          severity: diffResult.impactAssessment.overallImpact === 'CRITICAL' ? 'Critical' : 'High',
          confidence: confidenceScore,
          confidenceRating: diffResult.confidence,
          cwe: diffResult.cwe || 'CWE-284',
          owasp: diffResult.owasp || 'A01:2021-Broken Access Control',
          whatWeFound: diffResult.explanation,
          whyItMatters: diffResult.impactAssessment.reasoning,
          reproductionSteps: [
            `1. Send ${diffResult.httpMethod} request to ${diffResult.endpoint}`,
            `2. Evaluate response status (${diffResult.comparisonResult.statusCode}) and observe security differential`,
            `3. Verify evidence with SHA-256 integrity hash: ${evidenceHash}`,
          ],
          evidenceHash,
          sanitizedEvidence: evidencePayload,
          impact: diffResult.impactAssessment.reasoning,
          recommendedFix: `Implement centralized server-side access control, session validation, and strict output encoding on endpoint ${diffResult.endpoint}.`,
          createdAt: new Date().toISOString(),
        });
      }
    }

    // 4. Record Structured Audit Event
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'CASE',
      entityId: caseId,
      action: isCancelled ? 'AUTH_RESEARCH_CANCELLED' : 'AUTH_RESEARCH_EXECUTED',
      success: true,
      requestId,
      metadata: {
        executionId,
        programId,
        target,
        researchClass,
        hypothesesEvaluated: differentialResults.length,
        totalRequestsExecuted: executedRequestsCount,
        findingCandidatesCount: findingCandidates.length,
        isCancelled,
        cancellationReason,
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
      status: isCancelled ? 'CANCELLED' : 'COMPLETED',
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
}

export const authenticationResearchEngine = new AuthenticationResearchEngine();
