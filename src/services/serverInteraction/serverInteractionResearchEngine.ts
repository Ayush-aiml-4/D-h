import { AuthUser } from '../../middleware/auth.ts';
import {
  SSRFHypothesis,
  SSRFResearchResult,
  SSRFFindingCandidate,
  ServerInteractionEvidence,
  CancellationToken,
} from '../../types/serverInteractionResearch.ts';
import { resolveTargetScope, evaluateProgramProfilePolicy } from '../programProfileService.ts';
import { parseCanonicalUrl } from './urlParserService.ts';
import { dnsResolver } from './dnsResolutionModel.ts';
import { evaluateDestinationPolicy } from './ssrfPolicyEngine.ts';
import { evaluateRedirectChain } from './redirectAnalysisEngine.ts';
import { interactionRecorder } from './blindInteractionRecorder.ts';
import { evaluateSSRFDifferential } from './ssrfDifferentialEngine.ts';
import { createSSRFFindingCandidate } from './ssrfImpactAnalysisEngine.ts';
import {
  executeVulnerableUrlFetch,
  executeSecureUrlFetch,
} from './localServerInteractionFixtures.ts';
import { recordAuditEvent } from '../auditService.ts';
import { sanitizeAndRedact } from '../capabilities/utils.ts';

export interface ExecuteSSRFResearchParams {
  user: AuthUser;
  programId: string;
  target: string;
  caseId: string;
  hypotheses: SSRFHypothesis[];
  requestBudget?: number;
  useSecureFixture?: boolean;
  dryRun?: boolean;
  cancellationToken?: CancellationToken;
}

export async function executeSSRFResearch(
  params: ExecuteSSRFResearchParams
): Promise<SSRFResearchResult> {
  const {
    user,
    programId,
    target,
    caseId,
    hypotheses,
    requestBudget = 20,
    useSecureFixture = false,
    dryRun = false,
    cancellationToken,
  } = params;

  const executionId = `exec-ssrf-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const capabilityId = 'active-server-interaction-ssrf';

  // 1. Program profile scope & policy evaluation
  const targetScope = resolveTargetScope(programId, target);
  const policyDecision = await evaluateProgramProfilePolicy(user, {
    programId,
    target,
    operation: capabilityId,
  });

  if (policyDecision.decision === 'BLOCK') {
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      metadata: { target, reason: policyDecision.reason },
    });
    return {
      executionId,
      programId,
      target,
      status: 'BLOCKED',
      totalHypotheses: hypotheses.length,
      evaluatedHypotheses: 0,
      findings: [],
      suppressedCount: 0,
      networkRequestsCount: 0,
      evidenceList: [],
      summary: `Research execution blocked by policy: ${policyDecision.reason}`,
    };
  }

  // 2. Budget ceiling bounding (Max 20)
  const effectiveBudget = Math.min(requestBudget, 20);

  // 3. Record start of research
  await recordAuditEvent({
    userId: user.uid,
    entityType: 'CASE',
    entityId: caseId,
    action: dryRun ? 'SSRF_RESEARCH_DRY_RUN' : 'SSRF_RESEARCH_EXECUTED',
    success: true,
    metadata: sanitizeAndRedact({
      executionId,
      programId,
      target,
      hypothesisCount: hypotheses.length,
      dryRun,
    }),
  });

  // If dry-run, simulate without executing fixtures
  if (dryRun) {
    return {
      executionId,
      programId,
      target,
      status: 'COMPLETED',
      totalHypotheses: hypotheses.length,
      evaluatedHypotheses: hypotheses.length,
      findings: [],
      suppressedCount: hypotheses.length,
      networkRequestsCount: 0,
      evidenceList: [],
      summary: 'Dry run completed successfully with 0 network requests executed.',
    };
  }

  const findings: SSRFFindingCandidate[] = [];
  const evidenceList: ServerInteractionEvidence[] = [];
  let evaluatedHypotheses = 0;
  let suppressedCount = 0;
  let networkRequestsCount = 0;

  for (const hyp of hypotheses) {
    if (cancellationToken?.isCancelled) {
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'CASE',
        entityId: caseId,
        action: 'SSRF_RESEARCH_CANCELLED',
        success: true,
        metadata: { executionId, cancelledAtHypothesis: hyp.hypothesisId },
      });
      return {
        executionId,
        programId,
        target,
        status: 'CANCELLED',
        totalHypotheses: hypotheses.length,
        evaluatedHypotheses,
        findings,
        suppressedCount,
        networkRequestsCount,
        evidenceList,
        summary: 'SSRF research execution cancelled by user.',
        cancellationReason: 'USER_ABORT',
      };
    }

    if (networkRequestsCount >= effectiveBudget) {
      break;
    }

    evaluatedHypotheses++;
    const requestId = `req-ssrf-${Date.now()}-${evaluatedHypotheses}`;

    // Canonical URL parsing
    const parsedUrl = parseCanonicalUrl(hyp.testUrl);
    const dnsStep = hyp.dnsRebindingSimulation ? 1 : 0;
    const resolution = dnsResolver.resolve(parsedUrl.canonicalHostname, dnsStep);
    const destPolicy = evaluateDestinationPolicy(parsedUrl, resolution);

    // Execute through chosen fixture
    const correlationToken = hyp.correlationToken || `token-${executionId}-${hyp.hypothesisId}`;
    const serverRequest = {
      requestId,
      url: hyp.testUrl,
      correlationToken,
    };

    networkRequestsCount++;
    const fetchResult = useSecureFixture
      ? executeSecureUrlFetch(serverRequest, dnsStep)
      : executeVulnerableUrlFetch(serverRequest, dnsStep);

    // Retrieve observations
    const observations = interactionRecorder.findObservationsByToken(correlationToken);

    // Differential evaluation
    const differential = evaluateSSRFDifferential({
      intendedDestinationClass: hyp.intendedDestinationClass,
      policyDecision: destPolicy,
      serverSideInteractions: observations,
      responseStatus: fetchResult.statusCode,
      responseBodySnippet: fetchResult.body,
    });

    if (differential.hasAnomaly && differential.confidence === 'HIGH_CONFIDENCE') {
      const candidate = createSSRFFindingCandidate({
        researchCaseId: caseId,
        executionId,
        requestId,
        target,
        targetEndpoint: hyp.targetEndpoint,
        inputParameter: hyp.inputParameter,
        suppliedUrl: hyp.testUrl,
        parsedUrl,
        resolution,
        redirectChain: fetchResult.redirectHops || [],
        policyDecision: destPolicy,
        observations,
        responseSnippet: fetchResult.body,
        capabilityId,
      });
      findings.push(candidate);
    } else {
      suppressedCount++;
    }

    // Build structured sanitized evidence
    evidenceList.push({
      researchCaseId: caseId,
      executionId,
      requestId,
      target,
      suppliedUrl: hyp.testUrl,
      canonicalUrl: parsedUrl.canonicalUrl,
      resolutionResult: resolution,
      destinationClass: resolution.destinationClass,
      redirectChain: fetchResult.redirectHops || [],
      interactionCorrelation: {
        isCorrelated: observations.some(o => o.isCorrelated),
        correlationToken,
        observationId: observations[0]?.interactionId,
      },
      policyDecision: destPolicy,
      observedBehavior: `HTTP ${fetchResult.statusCode}: ${fetchResult.body.substring(0, 100)}`,
      impact: differential.impact,
      confidence: differential.confidence,
      evidenceHash: `hash-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
      sanitizedHeaders: (sanitizeAndRedact(fetchResult.headers).sanitized as Record<string, string>) || {},
    });
  }

  return {
    executionId,
    programId,
    target,
    status: 'COMPLETED',
    totalHypotheses: hypotheses.length,
    evaluatedHypotheses,
    findings,
    suppressedCount,
    networkRequestsCount,
    evidenceList,
    summary: `SSRF Research completed: Evaluated ${evaluatedHypotheses} hypotheses, discovered ${findings.length} findings, suppressed ${suppressedCount} false positives.`,
  };
}
