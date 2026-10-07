import { Router, Response } from 'express';
import { AuthRequest, requireAuth } from '../middleware/auth.ts';
import {
  validateRequest,
  paramIdSchema,
  createHuntBodySchema,
  createReportBodySchema,
  startDiscoveryBodySchema,
  assetsQuerySchema,
  attackSurfaceQuerySchema,
  evaluateCapabilityBodySchema,
  capabilitiesQuerySchema,
  evaluateCapabilityFrameworkSchema,
  researchAnalyzeBodySchema,
  researchValidateBodySchema,
  transitionFindingBodySchema,
  addEvidenceBodySchema,
  transitionReportBodySchema,
  transitionEvidenceBodySchema,
  createCaseBodySchema,
  transitionCaseBodySchema,
  createActivityBodySchema,
  transitionDisclosureBodySchema,
  approveDisclosureBodySchema,
  disclosuresQuerySchema,
  exportPackageQuerySchema,
  createExecutionBodySchema,
  executionsQuerySchema,
  cancelExecutionBodySchema,
  createActiveExecutionBodySchema,
  requestApprovalBodySchema,
  confirmApprovalBodySchema,
  activeExecutionsQuerySchema,
  cancelActiveExecutionBodySchema,
} from '../middleware/validate.ts';
import {
  listProgramProfiles,
  getProgramProfile,
  resolveTargetScope,
  evaluateFindingEligibility,
  executeDryRunCapability,
} from '../services/programProfileService.ts';
import {
  executeCapability,
  getExecutionById,
  listExecutions,
  cancelExecution,
} from '../services/researchExecutionService.ts';
import {
  executeActiveCapability,
  getActiveExecutionById,
  listActiveExecutions,
  cancelActiveExecution,
  listAllActiveCapabilityDefinitions,
} from '../services/execution/activeTesting/activeTestingService.ts';
import {
  createApprovalRequirement,
  confirmApprovalRequirement,
} from '../services/execution/activeTesting/approvalService.ts';
import {
  resolveActiveCapability,
} from '../services/execution/activeTesting/activeCapabilityRegistry.ts';
import {
  createDisclosurePackage,
  getDisclosureById,
  listDisclosures,
  transitionDisclosureStatus,
  approveDisclosurePackage,
  recordManualSubmission,
  exportDisclosurePackage,
} from '../services/disclosureIntelligenceService.ts';
import {
  authorizationResearchEngine,
  responseDifferentialEngine,
  createAccountAContext,
  createAccountBContext,
  createStandardUserContext,
  createPrivilegedUserContext,
  createUnauthenticatedContext,
  dispatchLocalFixtureRequest,
} from '../services/authorization/index.ts';
import {
  authenticationResearchEngine,
  SAFE_PAYLOAD_REGISTRY,
  dispatchLocalAuthFixtureRequest,
  createLocalAuthFixtureEnvironment,
} from '../services/authenticationResearch/index.ts';
import {
  listWorkflowDefinitions,
  getWorkflowDefinition,
  executeWorkflowResearch,
  evaluateStateTransition,
  createWorkflowStateInstance,
} from '../services/workflowResearch/index.ts';
import {
  parseCanonicalUrl,
  classifyDestination,
  dnsResolver,
  evaluateDestinationPolicy,
  evaluateRedirectChain,
  executeSSRFResearch,
} from '../services/serverInteraction/index.ts';
import { mutationRateLimiter } from '../middleware/security.ts';
import {
  createResearchCase,
  getResearchCases,
  getResearchCaseById,
  transitionCaseStatus,
  createResearchActivity,
  getCaseActivities,
} from '../services/caseService.ts';
import {
  listCapabilities,
  getCapability,
  evaluateResearchCapability as evaluateCapabilityFrameworkService,
  analyzeResearchCapabilityService,
} from '../services/capabilityService.ts';
import { validateFinding } from '../services/validation/validationService.ts';
import {
  getPrograms,
  getProgramById,
  getProgramAssets,
} from '../services/programService.ts';
import {
  getHunts,
  getHuntById,
  createHunt,
  updateHuntStatus,
} from '../services/huntService.ts';
import {
  getFindings,
  getFindingById,
  updateFindingStatus,
  getFindingTimeline,
  getFindingEvidence,
} from '../services/findingService.ts';
import {
  getReports,
  getReportById,
  createReportForFinding,
  updateReportStatus,
} from '../services/reportService.ts';
import {
  createEvidence,
  getEvidenceForFinding,
  transitionEvidenceStatus,
} from '../services/evidenceService.ts';
import {
  generateReportIntelligenceForFinding,
  assembleReportIntelligence,
  transitionReportStatusIntelligence,
} from '../services/reportIntelligenceService.ts';
import {
  startDiscovery,
  getDiscoverySession,
  stopDiscovery,
  getAssets,
} from '../services/discoveryService.ts';
import {
  buildAttackSurfaceGraph,
  evaluateResearchCapability,
} from '../services/attackSurfaceService.ts';
import { getHistorySessions } from '../services/historyService.ts';
import { getAuditEvents, AuditFilterParams } from '../services/auditService.ts';
import { getRewardMetrics } from '../services/rewardService.ts';
import { evaluatePolicy } from '../services/policyEngine.ts';
import { logger } from '../utils/logger.ts';
import { AppError, isDatabaseError } from '../utils/errors.ts';
import securityProgramRouter from './securityProgram.ts';
import devilHuntConsoleRouter from './devilHuntConsole.ts';

const router = Router();

// Apply auth middleware to all v1 API routes
router.use(requireAuth);

// Internal security-program operations (authenticated)
router.use('/security-program', securityProgramRouter);
router.use('/devil-hunt', devilHuntConsoleRouter);

// Handle standard error response securely without leaking credentials or stack traces
export const handleError = (req: AuthRequest, res: Response, err: any) => {
  const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
  
  logger.error('API_REQUEST_ERROR', {
    requestId: reqId,
    route: req.originalUrl,
    method: req.method,
    error: err instanceof Error ? err.message : String(err),
  });

  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      error: {
        code: err.code,
        message: err.message,
        requestId: reqId,
        ...(err.details ? { details: err.details } : {}),
      },
    });
  }

  if (isDatabaseError(err)) {
    return res.status(503).json({
      error: {
        code: 'SERVICE_UNAVAILABLE',
        message: 'Database service is temporarily unavailable',
        requestId: reqId,
      },
    });
  }

  let statusCode = 500;
  let code = 'INTERNAL_ERROR';
  let message = 'An internal server error occurred';

  if (err && typeof err === 'object') {
    const errMessage = String(err.message || '');

    if (
      errMessage.includes('FORBIDDEN') ||
      errMessage.includes('CORS Policy') ||
      errMessage.includes('UNAUTHORIZED_RESEARCHER') ||
      errMessage.includes('DISCOVERY_POLICY_BLOCKED')
    ) {
      statusCode = 403;
      code = 'FORBIDDEN';
      message = errMessage;
    } else if (
      errMessage.includes('NOT_FOUND') ||
      errMessage.includes('SESSION_NOT_FOUND') ||
      errMessage.includes('PROGRAM_NOT_FOUND')
    ) {
      statusCode = 404;
      code = 'NOT_FOUND';
      message = errMessage;
    } else if (
      errMessage.includes('INVALID_STATE_TRANSITION') ||
      errMessage.includes('ACTIVE_SESSION_EXISTS')
    ) {
      statusCode = 409;
      code = 'CONFLICT';
      message = errMessage;
    } else if (
      errMessage.includes('INVALID_PROGRAM') ||
      errMessage.includes('INACTIVE_PROGRAM') ||
      errMessage.includes('Invalid input') ||
      errMessage.includes('Mass assignment blocked') ||
      errMessage.includes('BAD_REQUEST')
    ) {
      statusCode = 400;
      code = 'BAD_REQUEST';
      message = errMessage;
    } else if (
      errMessage.includes('UNAUTHENTICATED') ||
      errMessage.includes('UNAUTHORIZED') ||
      errMessage.includes('INVALID_TOKEN')
    ) {
      statusCode = 401;
      code = 'UNAUTHORIZED';
      message = errMessage;
    } else if (errMessage.includes('TOO_MANY_REQUESTS')) {
      statusCode = 429;
      code = 'TOO_MANY_REQUESTS';
      message = errMessage;
    }
  }

  res.status(statusCode).json({
    error: {
      code,
      message,
      requestId: reqId,
    },
  });
};

// ================= POLICY AUTHORIZATION EVALUATION ENDPOINT =================
router.post(
  '/research/policy/evaluate',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      // Security Guard: Client-supplied researcherId, scopeStatus, policyStatus MUST NEVER BE TRUSTED!
      // Extract only validated inputs from req.body, ignoring any user identity or status overrides in body.
      const { programId, target, operation } = req.body || {};
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

      const result = await evaluatePolicy(
        req.user!,
        { programId, target, operation },
        reqId
      );

      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/research/validate',
  mutationRateLimiter,
  validateRequest({ body: researchValidateBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { findingId, validationId, observationOverride } = req.body;
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

      const result = await validateFinding(
        req.user!,
        { findingId, validationId, observationOverride },
        reqId
      );

      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= DISCOVERY & ASSETS ENDPOINTS =================
router.post(
  '/discovery/start',
  mutationRateLimiter,
  validateRequest({ body: startDiscoveryBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { programId, target, operation } = req.body;
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

      const session = await startDiscovery(req.user!, {
        programId,
        target,
        operation,
        requestId: reqId,
      });

      res.status(201).json(session);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/discovery/:id',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const session = await getDiscoverySession(req.user!, req.params.id);
      res.json(session);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/discovery/:id/stop',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const session = await stopDiscovery(req.user!, req.params.id, reqId);
      res.json(session);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/assets',
  validateRequest({ query: assetsQuerySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const filters = {
        programId: req.query.programId as string | undefined,
        discoverySessionId: req.query.discoverySessionId as string | undefined,
        type: req.query.type as string | undefined,
        status: req.query.status as string | undefined,
        scopeId: req.query.scopeId as string | undefined,
      };

      const result = await getAssets(req.user!, filters);
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= ATTACK SURFACE ENDPOINTS =================
router.get(
  '/attack-surface',
  validateRequest({ query: attackSurfaceQuerySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const programId = req.query.programId as string | undefined;
      const graph = await buildAttackSurfaceGraph(req.user!, { programId });
      res.json(graph);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/attack-surface/evaluate-capability',
  mutationRateLimiter,
  validateRequest({ body: evaluateCapabilityBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { programId, target, capability } = req.body;
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

      const result = await evaluateResearchCapability(req.user!, {
        programId,
        target,
        capability,
        requestId: reqId,
      });

      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= CAPABILITY FRAMEWORK ENDPOINTS =================
router.get(
  '/capabilities',
  validateRequest({ query: capabilitiesQuerySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const filter = {
        category: req.query.category as string | undefined,
        status: req.query.status as string | undefined,
      };
      const capabilities = listCapabilities(filter);
      res.json(capabilities);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/capabilities/:id',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const capability = getCapability(req.params.id);
      if (!capability) {
        const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
        return res.status(404).json({
          error: {
            code: 'NOT_FOUND',
            message: `Capability '${req.params.id}' not found`,
            requestId: reqId,
          },
        });
      }
      res.json(capability);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/capabilities/evaluate',
  mutationRateLimiter,
  validateRequest({ body: evaluateCapabilityFrameworkSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { programId, target, capabilityId, capability, assetId } = req.body;
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

      const result = await evaluateCapabilityFrameworkService(req.user!, {
        programId,
        target,
        capabilityId: capabilityId || capability || 'cap-asset-discovery',
        assetId,
        requestId: reqId,
      });

      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/research/analyze',
  mutationRateLimiter,
  validateRequest({ body: researchAnalyzeBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { programId, target, capabilityId, capability, assetId, observationData } = req.body;
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

      const result = await analyzeResearchCapabilityService(req.user!, {
        programId,
        target,
        capabilityId: capabilityId || capability,
        assetId,
        observationData,
        requestId: reqId,
      });

      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/research/validate',
  mutationRateLimiter,
  validateRequest({ body: researchValidateBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { findingId, validationId, observationOverride } = req.body;
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

      const result = await validateFinding(
        req.user!,
        { findingId, validationId, observationOverride },
        reqId
      );

      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= PROGRAM ENDPOINTS =================
router.get('/programs', async (req: AuthRequest, res: Response) => {
  try {
    const data = await getPrograms();
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get('/programs/:id', validateRequest({ params: paramIdSchema }), async (req: AuthRequest, res: Response) => {
  try {
    const prog = await getProgramById(req.params.id);
    if (!prog) {
      const reqId = req.id || 'no-request-id';
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Program not found', requestId: reqId } });
    }
    res.json(prog);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get('/programs/:id/assets', validateRequest({ params: paramIdSchema }), async (req: AuthRequest, res: Response) => {
  try {
    const prog = await getProgramById(req.params.id);
    if (!prog) {
      const reqId = req.id || 'no-request-id';
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Program not found', requestId: reqId } });
    }
    const assets = await getProgramAssets(req.params.id);
    res.json(assets);
  } catch (err) {
    handleError(req, res, err);
  }
});

// ================= HUNT ENDPOINTS =================
router.get('/hunts', async (req: AuthRequest, res: Response) => {
  try {
    const data = await getHunts(req.user!);
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get('/hunts/:id', validateRequest({ params: paramIdSchema }), async (req: AuthRequest, res: Response) => {
  try {
    const hunt = await getHuntById(req.params.id, req.user!);
    if (!hunt) {
      const reqId = req.id || 'no-request-id';
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Hunt not found', requestId: reqId } });
    }
    res.json(hunt);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/hunts',
  mutationRateLimiter,
  validateRequest({ body: createHuntBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { programId, assetId, targetDomain } = req.body;

      const result = await createHunt(
        {
          programId,
          assetId,
          targetDomain,
        },
        req.user!
      );
      res.status(result.isExisting ? 200 : 201).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/hunts/:id/start',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateHuntStatus(req.params.id, 'Hunting', req.user!, 'Policy enforcer initialized');
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/hunts/:id/pause',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateHuntStatus(req.params.id, 'Paused', req.user!, 'Session paused by researcher');
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/hunts/:id/resume',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateHuntStatus(req.params.id, 'Hunting', req.user!, 'Session resumed by researcher');
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/hunts/:id/stop',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateHuntStatus(req.params.id, 'Stopped', req.user!, 'Session terminated by operator');
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/hunts/:id/complete',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateHuntStatus(req.params.id, 'Completed', req.user!, 'Session complete');
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= FINDING ENDPOINTS =================
router.get('/findings', async (req: AuthRequest, res: Response) => {
  try {
    const data = await getFindings(req.user!);
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get('/findings/:id', validateRequest({ params: paramIdSchema }), async (req: AuthRequest, res: Response) => {
  try {
    const finding = await getFindingById(req.params.id, req.user!);
    if (!finding) {
      const reqId = req.id || 'no-request-id';
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Finding not found', requestId: reqId } });
    }
    res.json(finding);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/findings/:id/review',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateFindingStatus(req.params.id, 'Under review', req.user!, req.id);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/findings/:id/transition',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: transitionFindingBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateFindingStatus(req.params.id, req.body.status, req.user!, req.id);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/findings/:id/validate',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateFindingStatus(req.params.id, 'Validated', req.user!, req.id);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/findings/:id/verify',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateFindingStatus(req.params.id, 'Verified', req.user!, req.id);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/findings/:id/timeline',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const timeline = await getFindingTimeline(req.params.id, req.user!);
      res.json(timeline);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/findings/:id/evidence',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const evidence = await getEvidenceForFinding(req.params.id, req.user!);
      res.json(evidence);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/findings/:id/evidence',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: addEvidenceBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const created = await createEvidence(
        req.user!,
        {
          findingId: req.params.id,
          observation: req.body.observation,
          observationType: req.body.observationType,
          source: req.body.source,
          capabilityId: req.body.capabilityId,
          assetId: req.body.assetId,
        },
        reqId
      );
      res.status(201).json(created);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/evidence/:id/transition',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: transitionEvidenceBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const updated = await transitionEvidenceStatus(
        req.params.id,
        req.body.status,
        req.user!,
        reqId
      );
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= REPORT ENDPOINTS =================
router.get('/reports', async (req: AuthRequest, res: Response) => {
  try {
    const data = await getReports(req.user!);
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get('/reports/:id', validateRequest({ params: paramIdSchema }), async (req: AuthRequest, res: Response) => {
  try {
    const reportIntel = await assembleReportIntelligence(req.params.id, req.user!);
    res.json(reportIntel);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/reports/:id/generate',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: createReportBodySchema.optional() }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const { title, summary } = req.body || {};
      const result = await generateReportIntelligenceForFinding(
        req.params.id,
        req.user!,
        title,
        summary,
        reqId
      );
      res.status(200).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/reports/:id/transition',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: transitionReportBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const updated = await transitionReportStatusIntelligence(
        req.params.id,
        req.body.status,
        req.user!,
        reqId
      );
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/findings/:id/report',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: createReportBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const { title, summary } = req.body || {};
      const result = await createReportForFinding(req.params.id, req.user!, title, summary);
      res.status(result.isExisting ? 200 : 201).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/reports/:id/ready',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateReportStatus(req.params.id, 'Ready', req.user!);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/reports/:id/submit',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateReportStatus(req.params.id, 'Submitted', req.user!);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/reports/:id/accept',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateReportStatus(req.params.id, 'Accepted', req.user!);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/reports/:id/reject',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateReportStatus(req.params.id, 'Rejected', req.user!);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/reports/:id/resolve',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const updated = await updateReportStatus(req.params.id, 'Resolved', req.user!);
      res.json(updated);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= HISTORY & AUDIT ENDPOINTS =================
router.get('/history', async (req: AuthRequest, res: Response) => {
  try {
    const data = await getHistorySessions(req.user!);
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
});

const handleGetAuditEvents = async (req: AuthRequest, res: Response) => {
  try {
    const filters: AuditFilterParams = {
      entityType: req.query.entityType as string,
      entityId: req.query.entityId as string,
      action: req.query.action as string,
      actor: req.query.actor as string,
      startDate: req.query.startDate as string,
      endDate: req.query.endDate as string,
    };

    const data = await getAuditEvents(req.user!, filters);
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
};

router.get('/audit-events', handleGetAuditEvents);
router.get('/audit', handleGetAuditEvents);

router.get('/metrics/rewards', async (req: AuthRequest, res: Response) => {
  try {
    const data = await getRewardMetrics(req.user!);
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
});

// ================= RESEARCH CASE & CAMPAIGN ENDPOINTS =================
router.get('/cases', async (req: AuthRequest, res: Response) => {
  try {
    const programId = req.query.programId as string | undefined;
    const data = await getResearchCases(req.user!, programId);
    res.json(data);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get(
  '/cases/:id',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const data = await getResearchCaseById(req.params.id, req.user!);
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/cases',
  mutationRateLimiter,
  validateRequest({ body: createCaseBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const data = await createResearchCase(req.user!, req.body, reqId);
      res.status(201).json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/cases/:id/transition',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: transitionCaseBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const data = await transitionCaseStatus(req.params.id, req.body.status, req.user!, reqId);
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/cases/:id/activities',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const data = await getCaseActivities(req.params.id, req.user!);
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/cases/:id/activities',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: createActivityBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const data = await createResearchActivity(
        req.user!,
        {
          caseId: req.params.id,
          ...req.body,
        },
        reqId
      );
      res.status(201).json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ================= DISCLOSURE & SUBMISSION INTELLIGENCE ENDPOINTS =================
router.get(
  '/disclosures',
  validateRequest({ query: disclosuresQuerySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const filters = {
        findingId: req.query.findingId as string | undefined,
        caseId: req.query.caseId as string | undefined,
        programId: req.query.programId as string | undefined,
      };
      const data = await listDisclosures(req.user!, filters);
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/disclosures/:id',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const data = await getDisclosureById(req.user!, req.params.id);
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/findings/:id/disclosure',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const data = await createDisclosurePackage(req.user!, req.params.id, reqId);
      res.status(201).json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/disclosures/:id/transition',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: transitionDisclosureBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const data = await transitionDisclosureStatus(
        req.user!,
        req.params.id,
        req.body.status,
        reqId
      );
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/disclosures/:id/approve',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: approveDisclosureBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const data = await approveDisclosurePackage(req.user!, req.params.id, reqId);
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/disclosures/:id/submit',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const data = await recordManualSubmission(req.user!, req.params.id, reqId);
      res.json(data);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/disclosures/:id/package',
  validateRequest({ params: paramIdSchema, query: exportPackageQuerySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const pkg = await getDisclosureById(req.user!, req.params.id);
      const format = (req.query.format as any) || 'markdown';
      const rendered = exportDisclosurePackage(pkg, format);

      if (format === 'html') {
        res.setHeader('Content-Type', 'text/html');
        res.send(rendered);
      } else if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.send(rendered);
      } else {
        res.setHeader('Content-Type', 'text/plain');
        res.send(rendered);
      }
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// Controlled Research Capability Execution Pipeline
router.post(
  '/executions',
  mutationRateLimiter,
  validateRequest({ body: createExecutionBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const result = await executeCapability(req.user!, req.body, reqId);
      res.status(201).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/executions',
  validateRequest({ query: executionsQuerySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const results = await listExecutions(req.user!, req.query as any);
      res.json(results);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/executions/:id',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const result = await getExecutionById(req.params.id, req.user!);
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/executions/:id/cancel',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: cancelExecutionBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const result = await cancelExecution(req.params.id, req.user!, reqId);
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ==========================================
// DEVILHUNT GOVERNED ACTIVE SECURITY TESTING
// ==========================================

router.get('/active-testing/capabilities', async (req: AuthRequest, res: Response) => {
  try {
    const capabilities = listAllActiveCapabilityDefinitions();
    res.json(capabilities);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/active-testing/approvals/request',
  mutationRateLimiter,
  validateRequest({ body: requestApprovalBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const capability = resolveActiveCapability(req.body.capabilityId);
      const approval = await createApprovalRequirement(
        req.user!,
        req.body.programId,
        req.body.assetId,
        capability,
        req.body.target || 'target-asset',
        reqId
      );
      res.status(201).json(approval);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/active-testing/approvals/confirm',
  mutationRateLimiter,
  validateRequest({ body: confirmApprovalBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const confirmed = await confirmApprovalRequirement(req.user!, req.body.approvalId, reqId);
      res.json(confirmed);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/active-testing/execute',
  mutationRateLimiter,
  validateRequest({ body: createActiveExecutionBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const result = await executeActiveCapability(req.user!, req.body, reqId);
      res.status(201).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/active-testing/executions',
  validateRequest({ query: activeExecutionsQuerySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const results = await listActiveExecutions(req.user!, req.query as any);
      res.json(results);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get(
  '/active-testing/executions/:id',
  validateRequest({ params: paramIdSchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const result = await getActiveExecutionById(req.params.id, req.user!);
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/active-testing/executions/:id/cancel',
  mutationRateLimiter,
  validateRequest({ params: paramIdSchema, body: cancelActiveExecutionBodySchema }),
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const result = await cancelActiveExecution(req.params.id, req.user!, req.body.reason, reqId);
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ==========================================
// PROGRAM PROFILES & SCOPE AUTHORIZATION
// ==========================================

router.get('/program-profiles', async (req: AuthRequest, res: Response) => {
  try {
    const profiles = listProgramProfiles();
    res.json(profiles);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get('/program-profiles/:id', async (req: AuthRequest, res: Response) => {
  try {
    const profile = getProgramProfile(req.params.id);
    if (!profile) {
      const reqId = (req as any).id || 'no-request-id';
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Program profile '${req.params.id}' not found`, requestId: reqId },
      });
    }
    res.json(profile);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/program-profiles/:id/evaluate-scope',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const { target } = req.body || {};
      const result = resolveTargetScope(req.params.id, target);
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/program-profiles/:id/evaluate-finding',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const { category, title, cwe, description } = req.body || {};
      const result = evaluateFindingEligibility(req.params.id, category || '', {
        title,
        cwe,
        description,
      });
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/program-profiles/:id/dry-run',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const { target, capabilityId, operation, simulatedPayload } = req.body || {};
      const result = await executeDryRunCapability(
        req.user!,
        {
          programId: req.params.id,
          target,
          capabilityId: capabilityId || 'cap-asset-discovery',
          operation,
          simulatedPayload,
        },
        reqId
      );
      res.json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// ==========================================
// AUTHORIZATION & API RESEARCH ENGINE
// ==========================================

router.post(
  '/auth-research/execute',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const result = await authorizationResearchEngine.executeResearch(
        req.user!,
        req.body,
        reqId
      );
      res.status(200).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get('/auth-research/context-templates', async (req: AuthRequest, res: Response) => {
  try {
    const researcherId = req.user?.uid || 'user-researcher';
    const programId = (req.query.programId as string) || 'meesho-hackerone';
    const caseId = (req.query.caseId as string) || 'case-01';

    const templates = [
      createAccountAContext({ researcherId, programId, caseId }),
      createAccountBContext({ researcherId, programId, caseId }),
      createStandardUserContext({ researcherId, programId, caseId }),
      createPrivilegedUserContext({ researcherId, programId, caseId }),
      createUnauthenticatedContext({ researcherId, programId, caseId }),
    ];

    res.json(templates);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/auth-research/fixtures/dispatch',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const { endpoint, method, context, resource, parameters } = req.body || {};
      const snapshot = dispatchLocalFixtureRequest({
        endpoint: endpoint || '/api/fixtures/orders/ord-1001-account-a',
        method: method || 'GET',
        context,
        resource,
        parameters,
      });
      res.json(snapshot);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// =========================================================================
// DEVILHUNT #0005: AUTHENTICATION, SESSION & INPUT SECURITY RESEARCH ENGINE
// =========================================================================

router.post(
  '/auth-session-research/execute',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const reqId = (req as any).id || (req.headers['x-request-id'] as string) || 'no-request-id';
      const result = await authenticationResearchEngine.executeResearch(
        req.user!,
        req.body,
        reqId
      );
      res.status(200).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.get('/auth-session-research/safe-payloads', async (req: AuthRequest, res: Response) => {
  try {
    res.json(SAFE_PAYLOAD_REGISTRY);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/auth-session-research/fixtures/dispatch',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const { endpoint, method, context, session, parameterName, payloadValue } = req.body || {};
      const snapshot = dispatchLocalAuthFixtureRequest({
        endpoint: endpoint || '/api/fixtures/auth/secure-profile',
        method: method || 'GET',
        context,
        session,
        parameterName,
        payloadValue,
      });
      res.json(snapshot);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// =========================================================================
// DEVILHUNT #0006 — WORKFLOW & BUSINESS LOGIC RESEARCH ENDPOINTS
// =========================================================================

router.get('/workflow-research/definitions', async (req: AuthRequest, res: Response) => {
  try {
    res.json(listWorkflowDefinitions());
  } catch (err) {
    handleError(req, res, err);
  }
});

router.get('/workflow-research/definitions/:id', async (req: AuthRequest, res: Response) => {
  try {
    const def = getWorkflowDefinition(req.params.id);
    if (!def) {
      res.status(404).json({ error: 'Workflow definition not found' });
      return;
    }
    res.json(def);
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/workflow-research/execute',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const result = await executeWorkflowResearch({
        user: req.user!,
        caseId: req.body?.caseId || `case-${Date.now()}`,
        workflowId: req.body?.workflowId || 'wf-order-fulfillment-01',
        hypotheses: req.body?.hypotheses || [],
        dryRun: req.body?.dryRun || false,
        maxBudget: req.body?.maxBudget || 25,
        scenarioType: req.body?.scenarioType || 'SECURE',
      });
      res.status(200).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// =========================================================================
// DEVILHUNT #0007 — SERVER-SIDE INTERACTION & SSRF RESEARCH ENDPOINTS
// =========================================================================

router.get('/server-interaction/classify', async (req: AuthRequest, res: Response) => {
  try {
    const rawUrl = (req.query.url as string) || '';
    const parsed = parseCanonicalUrl(rawUrl);
    const resolution = dnsResolver.resolve(parsed.canonicalHostname);
    const policy = evaluateDestinationPolicy(parsed, resolution);

    res.json({
      rawUrl,
      parsed,
      resolution,
      policy,
      destinationClass: resolution.destinationClass,
    });
  } catch (err) {
    handleError(req, res, err);
  }
});

router.post(
  '/server-interaction/dry-run',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const result = await executeSSRFResearch({
        user: req.user!,
        programId: req.body?.programId || 'meesho-hackerone',
        target: req.body?.target || 'www.valmo.in',
        caseId: req.body?.caseId || `case-dry-${Date.now()}`,
        hypotheses: req.body?.hypotheses || [],
        dryRun: true,
      });
      res.status(200).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

import {
  synthesizeResearchCase,
  clusterObservations,
  generateReportDraft,
  evaluateReportQualityGates,
  normalizeObservation,
} from '../services/researchSynthesis/index.ts';

import {
  determineInputContext,
  resolveSinkDefinition,
  createSourceDefinition,
  buildDataFlowTrace,
  evaluateTransformationStep,
  classifyEncoding,
  evaluateClientSideResearch,
  createFixtureB_VulnerableReflectedHtml,
  createFixtureH_VulnerableDom,
  createFixtureJ_VulnerableStoredWorkflow,
} from '../services/clientSideResearch/index.ts';

router.post(
  '/server-interaction/evaluate',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const result = await executeSSRFResearch({
        user: req.user!,
        programId: req.body?.programId || 'meesho-hackerone',
        target: req.body?.target || 'www.valmo.in',
        caseId: req.body?.caseId || `case-eval-${Date.now()}`,
        hypotheses: req.body?.hypotheses || [],
        requestBudget: req.body?.requestBudget || 20,
        useSecureFixture: req.body?.useSecureFixture || false,
        dryRun: false,
      });
      res.status(200).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// DEVILHUNT #0008 Research Synthesis & Finding Correlation Routes
router.post(
  '/research-synthesis/correlate',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const rawObs = req.body?.observations || [];
      const normalizedObs = rawObs.map(normalizeObservation);
      const clusters = clusterObservations(normalizedObs);
      res.status(200).json({
        totalObservations: normalizedObs.length,
        clustersCount: clusters.length,
        clusters,
      });
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/research-synthesis/synthesize',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const rawObs = req.body?.observations || [];
      const normalizedObs = rawObs.map(normalizeObservation);
      const result = await synthesizeResearchCase({
        caseId: req.body?.caseId || `case-synth-${Date.now()}`,
        observations: normalizedObs,
        programId: req.body?.programId || 'meesho-hackerone',
        target: req.body?.target,
        actorId: req.user?.uid,
        dryRun: Boolean(req.body?.dryRun),
      });
      res.status(200).json(result);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/research-synthesis/draft-report',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const candidate = req.body?.candidate;
      if (!candidate) {
        return res.status(400).json({ error: 'Candidate required' });
      }
      const draft = generateReportDraft(candidate);
      res.status(200).json(draft);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/research-synthesis/validate-readiness',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const candidate = req.body?.candidate;
      const draftContent = req.body?.draftContent || {
        summary: candidate?.rootCause || '',
        reproductionSteps: candidate?.reproductionSteps || [],
        securityImpact: candidate?.impact?.summary || '',
        remediation: candidate?.remediation || '',
      };
      if (!candidate) {
        return res.status(400).json({ error: 'Candidate required' });
      }
      const readiness = evaluateReportQualityGates(candidate, draftContent);
      res.status(200).json(readiness);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

// DEVILHUNT #0009 Client-Side & XSS Research Routes
router.post(
  '/client-side/analyze-context',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const template = req.body?.templateSnippet || '';
      const placeholder = req.body?.placeholder || '';
      const context = determineInputContext(template, placeholder);
      res.status(200).json({
        context,
        isSecuritySensitive: context !== 'UNKNOWN' && context !== 'URL' && context !== 'CSS',
      });
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/client-side/analyze-dataflow',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const { source: rawSource, sinkName, transformations: rawTransforms, targetContext } = req.body || {};
      const source = createSourceDefinition({
        sourceType: rawSource?.sourceType || 'QUERY_PARAMETER',
        name: rawSource?.name || 'param',
        value: rawSource?.value || '',
        actorIdentifier: req.user?.uid,
      });
      const sink = resolveSinkDefinition(sinkName || 'innerHTML');
      const context = targetContext || 'HTML_TEXT';

      const steps = (rawTransforms || []).map((t: any, idx: number) =>
        evaluateTransformationStep(idx + 1, t.type, source.value, t.output, context)
      );

      const renderedOutput = steps[steps.length - 1]?.outputSnippet || source.value;
      const dataFlow = buildDataFlowTrace(source, steps, sink, context, renderedOutput);
      const { classification, sanitizerStatus, isProperlyNeutralized } = classifyEncoding(
        source.value,
        renderedOutput,
        context,
        steps
      );

      res.status(200).json({
        dataFlow,
        classification,
        sanitizerStatus,
        isProperlyNeutralized,
      });
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/client-side/evaluate-xss',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const evaluation = await evaluateClientSideResearch({
        caseId: req.body?.caseId || `case-xss-${Date.now()}`,
        programId: req.body?.programId || 'meesho-hackerone',
        target: req.body?.target || 'www.valmo.in',
        asset: req.body?.asset || 'Valmo Web',
        sourceType: req.body?.sourceType || 'QUERY_PARAMETER',
        parameterName: req.body?.parameterName || 'q',
        payloadString: req.body?.payloadString || '<script>alert(1)</script>',
        templateSnippet: req.body?.templateSnippet,
        sinkName: req.body?.sinkName,
        transformations: req.body?.transformations,
        actorContext: {
          researcherId: req.user?.uid || 'researcher-001',
          accountIdentifier: req.user?.email || 'researcher@example.com',
          accountRole: req.user?.role || 'RESEARCHER',
        },
        dryRun: Boolean(req.body?.dryRun),
      });
      res.status(200).json(evaluation);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/client-side/evaluate-dom',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const isFixture = req.body?.useFixture;
      const fixture = isFixture ? createFixtureH_VulnerableDom() : await evaluateClientSideResearch({
        caseId: req.body?.caseId || `case-dom-${Date.now()}`,
        programId: req.body?.programId || 'meesho-hackerone',
        target: req.body?.target || 'supplier.meesho.com',
        sourceType: 'URL_FRAGMENT',
        parameterName: 'location.hash',
        payloadString: req.body?.payloadString || '#<img src=x onerror=alert(1)>',
        sinkName: req.body?.sinkName || 'innerHTML',
        actorContext: {
          researcherId: req.user?.uid || 'researcher-001',
        },
        dryRun: Boolean(req.body?.dryRun),
      });
      res.status(200).json(fixture);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

router.post(
  '/client-side/evaluate-stored-workflow',
  mutationRateLimiter,
  async (req: AuthRequest, res: Response) => {
    try {
      const fixture = createFixtureJ_VulnerableStoredWorkflow();
      res.status(200).json(fixture);
    } catch (err) {
      handleError(req, res, err);
    }
  }
);

export default router;

