/**
 * Internal Security Program operations API.
 * Mounted under /api/v1 with requireAuth already applied by v1 router.
 * Config mutations restricted to ADMIN role.
 */
import { Router, Response } from 'express';
import { mutationRateLimiter } from '../middleware/security.ts';
import { AuthRequest } from '../middleware/auth.ts';
import {
  processSecurityReport,
  transitionReportDisclosure,
  getAllowedNextStates,
  enforceScopeForAsset,
  buildDashboardSnapshot,
  getReport,
  saveReport,
  listReports,
  queryReports,
  queryAudits,
  listScopeDecisions,
  listConfigChanges,
  listGlobalAudits,
  on_owner_input,
  getProgramConfig,
  setProgramConfig,
  appendConfigChange,
  calculateLaunchReadiness,
  BOUNTY_STATUS_DEFERRED,
} from '../services/securityProgram/index.ts';

const router = Router();

const MAX_TEXT = 20_000;
const MAX_STEPS = 50;

function clampStr(v: unknown, max = MAX_TEXT): string {
  if (typeof v !== 'string') return '';
  return v.length > max ? v.slice(0, max) : v;
}

function clampSteps(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.slice(0, MAX_STEPS).map((s) => clampStr(s, 2_000));
}


function reqId(req: AuthRequest): string {
  return req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
}

function requireAdmin(req: AuthRequest, res: Response): boolean {
  if (!req.user || req.user.role !== 'ADMIN') {
    res.status(403).json({
      error: {
        code: 'FORBIDDEN',
        message: 'Admin role required for program configuration',
        requestId: reqId(req),
      },
    });
    return false;
  }
  return true;
}

/** GET operational status / launch readiness */
router.get('/status', (req: AuthRequest, res: Response) => {
  const cfg = getProgramConfig();
  const launch = calculateLaunchReadiness(cfg);
  res.json({
    programStatus: launch.status === 'READY' ? 'launch_ready' : 'draft',
    launchReadiness: launch.status,
    blockers: launch.blockers,
    q4AssetCount: cfg.Q4_authorizedAssets.length,
    bountyStatus: BOUNTY_STATUS_DEFERRED,
    rewardModel: cfg.Q30_rewardModel,
    safeHarbor: cfg.Q34_safeHarbor,
    requestId: reqId(req),
  });
});

/** GET dashboard snapshot (read-only, no secrets) */
router.get('/dashboard', (req: AuthRequest, res: Response) => {
  const snap = buildDashboardSnapshot();
  res.json({ ...snap, requestId: reqId(req) });
});

/** GET reports list (metadata only; optional pagination/filters) */
router.get('/reports', (req: AuthRequest, res: Response) => {
  const q = {
    page: req.query.page !== undefined ? Number(req.query.page) : undefined,
    pageSize: req.query.pageSize !== undefined ? Number(req.query.pageSize) : undefined,
    validity: typeof req.query.validity === 'string' ? req.query.validity.slice(0, 64) : undefined,
    severity: typeof req.query.severity === 'string' ? req.query.severity.slice(0, 64) : undefined,
    scopeResult: typeof req.query.scopeResult === 'string' ? req.query.scopeResult.slice(0, 64) : undefined,
    disclosureStatus:
      typeof req.query.disclosureStatus === 'string' ? req.query.disclosureStatus.slice(0, 64) : undefined,
    remediationStatus:
      typeof req.query.remediationStatus === 'string' ? req.query.remediationStatus.slice(0, 64) : undefined,
  };
  // Backward compatible: no page params → full list (still metadata only)
  const usePaging = req.query.page !== undefined || req.query.pageSize !== undefined
    || q.validity || q.severity || q.scopeResult || q.disclosureStatus || q.remediationStatus;
  const mapped = (list: ReturnType<typeof listReports>) =>
    list.map((r) => ({
      report_id: r.report_id,
      asset: r.asset,
      scope_result: r.scope_result,
      validity: r.validity,
      severity: r.severity,
      duplicate_status: r.duplicate_status,
      bounty_status: r.bounty_status,
      disclosure_status: r.disclosure_status,
      remediation_status: r.remediation_status,
      researcher: r.researcher,
      submitted_at: r.submitted_at,
    }));
  if (!usePaging) {
    const reports = mapped(listReports());
    return res.json({ reports, count: reports.length, requestId: reqId(req) });
  }
  const result = queryReports(q);
  res.json({
    reports: mapped(result.items),
    count: result.total,
    page: result.page,
    pageSize: result.pageSize,
    requestId: reqId(req),
  });
});

/** GET single report */
router.get('/reports/:id', (req: AuthRequest, res: Response) => {
  const r = getReport(req.params.id);
  if (!r) {
    return res.status(404).json({
      error: { code: 'NOT_FOUND', message: 'Report not found', requestId: reqId(req) },
    });
  }
  // Strip potentially excessive evidence refs for response hygiene
  const safe = {
    ...r,
    evidence: r.evidence.map((e) => ({ kind: e.kind, redacted: e.redacted, ref: e.redacted ? e.ref : '[REDACTED]' })),
  };
  res.json({ report: safe, requestId: reqId(req) });
});

/** GET scope decisions */
router.get('/scope-decisions', (req: AuthRequest, res: Response) => {
  res.json({ decisions: listScopeDecisions(), requestId: reqId(req) });
});

/** GET audit events (optional pagination/filters; default last 100) */
router.get('/audits', (req: AuthRequest, res: Response) => {
  const hasPaging =
    req.query.page !== undefined ||
    req.query.pageSize !== undefined ||
    req.query.action !== undefined ||
    req.query.reportId !== undefined;
  if (!hasPaging) {
    return res.json({ events: listGlobalAudits().slice(-100), requestId: reqId(req) });
  }
  const result = queryAudits({
    page: req.query.page !== undefined ? Number(req.query.page) : undefined,
    pageSize: req.query.pageSize !== undefined ? Number(req.query.pageSize) : undefined,
    action: typeof req.query.action === 'string' ? req.query.action.slice(0, 128) : undefined,
    reportId: typeof req.query.reportId === 'string' ? req.query.reportId.slice(0, 200) : undefined,
  });
  res.json({
    events: result.items,
    count: result.total,
    page: result.page,
    pageSize: result.pageSize,
    requestId: reqId(req),
  });
});

/** POST check scope only */
router.post('/scope-check', (req: AuthRequest, res: Response) => {
  const asset = clampStr(req.body?.asset, 2048).trim();
  if (!asset) {
    return res.status(400).json({
      error: { code: 'BAD_REQUEST', message: 'asset required', requestId: reqId(req) },
    });
  }
  const result = enforceScopeForAsset(asset);
  res.json({ ...result, requestId: reqId(req) });
});

/** POST process security report (authenticated researchers) */
router.post('/reports/process', mutationRateLimiter, (req: AuthRequest, res: Response) => {
  const body = req.body || {};
  const asset = clampStr(body.asset, 2048).trim();
  if (!asset) {
    return res.status(400).json({
      error: { code: 'BAD_REQUEST', message: 'asset required', requestId: reqId(req) },
    });
  }
  const report_id =
    typeof body.report_id === 'string' && body.report_id.trim()
      ? body.report_id.trim()
      : `rpt_${Date.now()}`;
  const researcher = req.user?.email || req.user?.uid || 'unknown';

  const result = processSecurityReport({
    report_id,
    researcher,
    asset,
    endpoint: typeof body.endpoint === 'string' ? body.endpoint : undefined,
    reproduction_steps: clampSteps(body.reproduction_steps),
    expected_behavior: clampStr(body.expected_behavior),
    actual_behavior: clampStr(body.actual_behavior),
    proof_of_concept: clampStr(body.proof_of_concept),
    security_impact: clampStr(body.security_impact),
    attack_scenario: clampStr(body.attack_scenario),
    vulnerability_class: clampStr(body.vulnerability_class, 500),
    root_cause: clampStr(body.root_cause, 2000),
    preconditions: clampStr(body.preconditions),
  });

  const status =
    result.report.scope_result === 'OUT_OF_SCOPE'
      ? 422
      : result.hold
        ? 202
        : 200;

  res.status(status).json({
    stage: result.stage,
    stopped: result.stopped,
    hold: result.hold,
    messages: result.messages,
    report: {
      report_id: result.report.report_id,
      scope_result: result.report.scope_result,
      validity: result.report.validity,
      duplicate_status: result.report.duplicate_status,
      bounty_status: result.report.bounty_status,
      severity: result.report.severity,
      disclosure_status: result.report.disclosure_status,
    },
    requestId: reqId(req),
  });
});

/** POST owner configuration update — ADMIN only */
router.post('/config/update', mutationRateLimiter, (req: AuthRequest, res: Response) => {
  if (!requireAdmin(req, res)) return;
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!message) {
    return res.status(400).json({
      error: { code: 'BAD_REQUEST', message: 'message required', requestId: reqId(req) },
    });
  }
  const cfg = getProgramConfig();
  const result = on_owner_input(cfg, message, req.user?.uid || 'admin');
  setProgramConfig(result.config);
  if (result.audit) appendConfigChange(result.audit);
  res.json({
    message: result.message,
    needsClarification: result.needsClarification || null,
    launch: result.launch,
    requestId: reqId(req),
  });
});

/** GET config change log */
router.get('/config/changes', (req: AuthRequest, res: Response) => {
  if (!requireAdmin(req, res)) return;
  res.json({ changes: listConfigChanges(), requestId: reqId(req) });
});



/** POST explicit disclosure transition — ADMIN only */
router.post(
  '/reports/:id/disclosure-transition',
  mutationRateLimiter,
  (req: AuthRequest, res: Response) => {
    if (!requireAdmin(req, res)) return;
    const id = typeof req.params.id === 'string' ? req.params.id.trim() : '';
    if (!id || id.length > 200) {
      return res.status(400).json({
        error: { code: 'BAD_REQUEST', message: 'invalid report id', requestId: reqId(req) },
      });
    }
    const targetState =
      typeof req.body?.targetState === 'string' ? req.body.targetState.trim().slice(0, 64) : '';
    if (!targetState) {
      return res.status(400).json({
        error: { code: 'BAD_REQUEST', message: 'targetState required', requestId: reqId(req) },
      });
    }
    const report = getReport(id);
    if (!report) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: 'Report not found', requestId: reqId(req) },
      });
    }
    const before = report.disclosure_status;
    const result = transitionReportDisclosure(report, targetState);
    if (result.accepted) {
      saveReport(result.report);
    }
    const status = result.accepted ? 200 : 409;
    res.status(status).json({
      accepted: result.accepted,
      reason: result.reason,
      before,
      after: result.report.disclosure_status,
      report_id: result.report.report_id,
      requestId: reqId(req),
    });
  }
);




/** GET allowed next disclosure states — ADMIN (operational) */
router.get('/reports/:id/disclosure-transitions', (req: AuthRequest, res: Response) => {
  if (!requireAdmin(req, res)) return;
  const id = typeof req.params.id === 'string' ? req.params.id.trim() : '';
  if (!id || id.length > 200) {
    return res.status(400).json({
      error: { code: 'BAD_REQUEST', message: 'invalid report id', requestId: reqId(req) },
    });
  }
  const report = getReport(id);
  if (!report) {
    return res.status(404).json({
      error: { code: 'NOT_FOUND', message: 'Report not found', requestId: reqId(req) },
    });
  }
  const currentState = report.disclosure_status || 'reported';
  const allowedNextStates = getAllowedNextStates(currentState);
  res.json({
    report_id: report.report_id,
    currentState,
    allowedNextStates,
    requestId: reqId(req),
  });
});


export default router;
